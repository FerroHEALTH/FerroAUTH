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

use std::sync::Arc;

use jsonwebtoken::Validation;
use jsonwebtoken::errors::ErrorKind;
use serde_json::Map;
use serde_json::Value;

use crate::refusal::Reason;
use crate::resource::Caller;
use crate::resource::Rejection;
use crate::resource::ResourceServer;
use crate::resource::TokenProfile;

/// The `typ` values RFC 9068 §4 accepts.
const ACCESS_TOKEN_TYPES: [&str; 2] = ["at+jwt", "application/at+jwt"];

/// Returns the caller `token` authenticates under `server`.
pub(super) async fn validate(server: &ResourceServer, token: &str) -> Result<Caller, Rejection> {
    let settings = server.settings();
    let header =
        jsonwebtoken::decode_header(token).map_err(|_malformed| invalid(Reason::Malformed))?;
    if !settings.algorithms.contains(&header.alg) {
        return Err(invalid(Reason::Algorithm));
    }
    let access_token_type = header.typ.as_deref().is_some_and(|typ| {
        ACCESS_TOKEN_TYPES
            .iter()
            .any(|accepted| typ.eq_ignore_ascii_case(accepted))
    });
    match settings.profile {
        TokenProfile::Rfc9068 if !access_token_type => {
            return Err(invalid(Reason::Type));
        }
        // NOTE: no specification governs the `jwt` profile: our own design,
        // `typ` absent or `JWT` (RFC 7519 §5.1) or the access token type, and
        // a `typ` naming another kind refused (RFC 8725 §3.11).
        TokenProfile::Jwt
            if !access_token_type
                && !header
                    .typ
                    .as_deref()
                    .is_none_or(|typ| typ.eq_ignore_ascii_case("JWT")) =>
        {
            return Err(invalid(Reason::Type));
        }
        TokenProfile::Rfc9068 | TokenProfile::Jwt => {}
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
    if let Some(issued) = claims.get("iat").and_then(Value::as_i64) {
        let latest = jiff::Timestamp::now()
            .as_second()
            .saturating_add(i64::try_from(settings.clock_skew.as_secs()).unwrap_or(i64::MAX));
        if issued > latest {
            return Err(invalid(Reason::IssuedInFuture));
        }
    }
    if settings.profile == TokenProfile::Rfc9068
        && ["iat", "jti", "client_id"]
            .iter()
            .any(|name| !claims.contains_key(*name))
    {
        return Err(invalid(Reason::MissingClaim));
    }
    let subject = text(&claims, "sub").ok_or_else(|| invalid(Reason::Subject))?;
    // NOTE: RFC 9068 §2.2 requires `sub`, and RFC 7519 §4.1.2 has it identify a
    // principal, which a blank value does not.
    if subject.trim().is_empty() {
        return Err(invalid(Reason::BlankSubject));
    }
    let client_id = text(&claims, "client_id");
    let patient = text(&claims, "patient");
    let scope = scope_of(&claims, settings.profile);
    let scopeless = settings.scopeless_subjects.contains(&subject);
    let scopes = server.scopes(&scope);
    Ok(Caller::new(subject, client_id, &scope, patient, scopeless)
        .with_scopes(scopes)
        .with_issuer(settings.issuer.clone())
        .with_claims(claims))
}

/// Returns the string claim `name` of `claims`.
fn text(claims: &Map<String, Value>, name: &str) -> Option<String> {
    claims.get(name).and_then(Value::as_str).map(str::to_owned)
}

/// Returns the space-delimited scope of `claims`.
///
/// The `scope` claim is the RFC 9068 §2.2.3 form and the only one read
/// under that profile. Under the `jwt` profile an issuer that mints the
/// grant as the `scp` array instead (Entra ID) is read when `scope` is
/// absent (no specification governs `scp`: our own design, admitted only
/// outside the RFC 9068 profile).
fn scope_of(claims: &Map<String, Value>, profile: TokenProfile) -> String {
    if let Some(scope) = claims.get("scope").and_then(Value::as_str) {
        return scope.to_owned();
    }
    if profile == TokenProfile::Rfc9068 {
        return String::new();
    }
    claims
        .get("scp")
        .and_then(Value::as_array)
        .map(|tokens| {
            tokens
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

/// Returns the rejection of a token that does not hold for `reason`.
const fn invalid(reason: Reason) -> Rejection {
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

#[cfg(test)]
mod tests {
    use super::scope_of;
    use crate::resource::TokenProfile;
    use serde_json::json;

    #[test]
    fn scope_wins_and_scp_is_the_fallback_under_the_jwt_profile_alone() {
        let scope = json!({ "scope": "openid system/*.r", "scp": ["ignored"] });
        let claims = scope.as_object().expect("an object");
        assert_eq!("openid system/*.r", scope_of(claims, TokenProfile::Rfc9068));
        assert_eq!("openid system/*.r", scope_of(claims, TokenProfile::Jwt));
        let scp = json!({ "scp": ["openid", "system/*.r"] });
        let claims = scp.as_object().expect("an object");
        assert_eq!("", scope_of(claims, TokenProfile::Rfc9068));
        assert_eq!("openid system/*.r", scope_of(claims, TokenProfile::Jwt));
        let none = json!({});
        assert_eq!(
            "",
            scope_of(none.as_object().expect("an object"), TokenProfile::Jwt)
        );
    }
}
