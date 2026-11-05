// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The check of one bearer access token.
//!
//! The header names an algorithm of the configured set and a key of the
//! issuer's set; the signature verifies with that key (RFC 7515 §5.2); `iss`
//! is the configured issuer and `aud` contains a configured audience
//! (RFC 9068 §4); `exp`, `nbf` and `iat` hold within the clock skew
//! (RFC 7519 §4.1.4, §4.1.5, §4.1.6). Every failure is the same
//! [`Rejection::Invalid`] on the wire; its [`Reason`] reaches only the log.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use http::Extensions;
use jsonwebtoken::Validation;
use jsonwebtoken::errors::ErrorKind;
use serde_json::Map;
use serde_json::Value;

use crate::assurance::AssuranceSection;
use crate::federation::Context;
use crate::federation::FederationSection;
use crate::kind::IssuerKind;
use crate::kind::Unclassified;
use crate::kind::classify;
use crate::profile::Profile;
use crate::refusal::Reason;
use crate::resource::Caller;
use crate::resource::Rejection;
use crate::resource::ResourceServer;
use crate::resource::ResourceTypes;
use crate::scope::Scopes;

/// Returns the caller `token` authenticates under `server`.
pub(super) async fn validate(server: &ResourceServer, token: &str) -> Result<Caller, Rejection> {
    let settings = server.settings();
    let header =
        jsonwebtoken::decode_header(token).map_err(|_malformed| invalid(Reason::Malformed))?;
    if !settings.algorithms.contains(&header.alg) {
        return Err(invalid(Reason::Algorithm));
    }
    // NOTE: RFC 9068 §4 has the `typ` header checked; which values an issuer
    // writes is its profile's (`token_types`), compared without regard to case.
    if !settings.profile.accepts_type(header.typ.as_deref()) {
        return Err(invalid(Reason::Type));
    }
    let key = server
        .keys
        .find(header.kid.as_deref(), header.alg)
        .await
        .map_err(|source| Rejection::Unavailable {
            source: Arc::new(source),
        })?
        .ok_or_else(|| invalid(Reason::UnknownKey))?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[settings.issuer.as_str()]);
    validation.set_audience(&settings.audience);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.validate_nbf = true;
    validation.leeway = settings.clock_skew.as_secs();
    let data = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation)
        .map_err(|error| invalid(reason(error.kind())))?;
    let claims = data.claims;
    if settings
        .profile
        .required_claims
        .iter()
        .any(|name| !claims.contains_key(name))
    {
        return Err(invalid(Reason::MissingClaim));
    }
    let subject = text(&claims, "sub").ok_or_else(|| invalid(Reason::Subject))?;
    admit(
        claims,
        subject,
        &Admission {
            issuer: &settings.issuer,
            kind: settings.kind,
            profile: &settings.profile,
            assurance: settings.assurance.as_ref(),
            federation: settings.federation.as_ref(),
            audiences: &settings.audience,
            clock_skew: settings.clock_skew,
            scopeless_subjects: &settings.scopeless_subjects,
            role_claims: &settings.role_claims,
            resource_types: server.resource_types.as_ref(),
            extensions: &server.extensions,
        },
    )
}

/// What a verified token's claims are read under: the issuer that vouched
/// for them and the deployment's rules.
pub(super) struct Admission<'a> {
    /// The issuer the caller is attributed to.
    pub(super) issuer: &'a str,
    /// Whose tokens the issuer signs.
    pub(super) kind: IssuerKind,
    /// The issuer's profile the caller is classified and its scope read
    /// under.
    pub(super) profile: &'a Profile,
    /// The issuer's assurance mapping, when it has one.
    pub(super) assurance: Option<&'a AssuranceSection>,
    /// The `[[auth.federation]]` table of a `federation` issuer.
    pub(super) federation: Option<&'a FederationSection>,
    /// This node's audiences, which an `authorization_details` entry names.
    pub(super) audiences: &'a [String],
    /// The clock skew `iat` is checked with.
    pub(super) clock_skew: Duration,
    /// The subjects granted system-wide access without a clinical scope.
    pub(super) scopeless_subjects: &'a BTreeSet<String>,
    /// The claims the roles are read from.
    pub(super) role_claims: &'a [String],
    /// The resource types a clinical scope may name, when the product holds
    /// a table.
    pub(super) resource_types: Option<&'a ResourceTypes>,
    /// The product's values copied onto the caller.
    pub(super) extensions: &'a Extensions,
}

/// Returns the caller the verified `claims` of `subject` describe, the step
/// the JWT check and the introspection check share: `iat` within the clock
/// skew, a subject that is not blank, the caller's kind by the issuer's
/// profile, and the scope, the client and the `patient` launch context
/// read the same way.
pub(super) fn admit(
    claims: Map<String, Value>,
    subject: String,
    admission: &Admission<'_>,
) -> Result<Caller, Rejection> {
    if let Some(issued) = claims.get("iat").and_then(Value::as_i64) {
        let latest = jiff::Timestamp::now()
            .as_second()
            .saturating_add(i64::try_from(admission.clock_skew.as_secs()).unwrap_or(i64::MAX));
        if issued > latest {
            return Err(invalid(Reason::IssuedInFuture));
        }
    }
    // NOTE: RFC 9068 §2.2 requires `sub`, and RFC 7519 §4.1.2 has it identify a
    // principal, which a blank value does not.
    if subject.trim().is_empty() {
        return Err(invalid(Reason::BlankSubject));
    }
    let assurance = admission
        .assurance
        .map(|section| section.assess(&claims))
        .unwrap_or_default();
    let federation = admission.federation.map(|section| Context {
        section,
        audiences: admission.audiences,
        level: assurance.level,
        levels: admission.assurance.map(|assurance| &assurance.levels),
    });
    let classified = classify(
        admission.kind,
        admission.profile,
        federation.as_ref(),
        &claims,
    )
    .map_err(|reason| Rejection::Unclassified { reason })?;
    let scope_claim = if classified.app_only {
        admission
            .profile
            .app_only_scope_claim
            .as_ref()
            .unwrap_or(&admission.profile.scope_claim)
    } else {
        &admission.profile.scope_claim
    };
    let scope = scope_claim
        .read(&claims)
        .map_err(|_form| Rejection::Unclassified {
            reason: Unclassified::ScopeForm {
                claim: scope_claim.claim.clone(),
            },
        })?;
    let patient = text(&claims, "patient");
    let scopeless = admission.scopeless_subjects.contains(&subject);
    let scopes = match admission.resource_types {
        Some(known) => Scopes::parse_known(&scope, |name| known(name)),
        None => Scopes::parse(&scope),
    };
    let roles = crate::roles::from_claims(&claims, admission.role_claims);
    Ok(Caller::new(
        subject,
        classified.client,
        &scope,
        patient,
        scopeless,
        classified.kind,
    )
    .with_scopes(scopes)
    .with_roles(roles)
    .with_assurance(assurance)
    .with_person_key(
        text(&claims, &admission.profile.person_key),
        admission
            .profile
            .tenant_claim
            .as_deref()
            .and_then(|claim| text(&claims, claim)),
    )
    .with_issuer(admission.issuer.to_owned())
    .with_claims(claims)
    .with_extensions(admission.extensions.clone()))
}

/// Returns the string claim `name` of `claims`.
pub(super) fn text(claims: &Map<String, Value>, name: &str) -> Option<String> {
    claims.get(name).and_then(Value::as_str).map(str::to_owned)
}

/// Returns the rejection of a token that does not hold for `reason`.
pub(super) const fn invalid(reason: Reason) -> Rejection {
    Rejection::Invalid { reason }
}

/// Returns the debug-log reason of a failed decode.
const fn reason(kind: &ErrorKind) -> Reason {
    match kind {
        ErrorKind::InvalidSignature => Reason::Signature,
        ErrorKind::ExpiredSignature => Reason::Expired,
        ErrorKind::ImmatureSignature => Reason::NotYetValid,
        ErrorKind::InvalidIssuer => Reason::Issuer,
        ErrorKind::InvalidAudience => Reason::Audience,
        ErrorKind::MissingRequiredClaim(_) => Reason::MissingClaim,
        ErrorKind::InvalidAlgorithm => Reason::Algorithm,
        _ => Reason::Malformed,
    }
}
