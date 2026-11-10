// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The defaults of one `[[auth.issuer]]` table and of its
//! `[auth.issuer.introspection]` table, the profile keys it sets over its
//! preset, and the rules one table is checked against when `[auth]`
//! resolves.

use jsonwebtoken::Algorithm;

use crate::config::AuthMode;
use crate::config::ConfigError;
use crate::config::IntrospectionSection;
use crate::config::IssuerEntry;
use crate::kind::IssuerKind;
use crate::profile::Preset;
use crate::profile::ProfileKeys;
use crate::sender::SenderConstraint;
use ferrohealth_config::units::Duration;

impl Default for IssuerEntry {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            kind: None,
            profile: Preset::Rfc9068,
            audience: Vec::new(),
            algorithms: vec![
                Algorithm::RS256,
                Algorithm::RS384,
                Algorithm::PS256,
                Algorithm::PS384,
                Algorithm::ES256,
                Algorithm::ES384,
            ],
            clock_skew: Duration::from_secs(60),
            jwks_max_age: Duration::from_mins(10),
            jwks_refresh_interval: Duration::from_secs(60),
            jwks_file: String::new(),
            timeout: Duration::from_secs(10),
            mode: AuthMode::Jwt,
            introspection: None,
            assurance: None,
            sender_constraint: SenderConstraint::None,
            role_claims: None,
            person_key: None,
            tenant_claim: None,
            client_claims: None,
            app_only: None,
            guest: None,
            impersonation_marker: None,
            expect: None,
            user_claims: None,
            person_equality: None,
            unstable_claims: None,
            first_party_clients: None,
            delegates: None,
            max_actor_chain: None,
            representation: None,
            act_represents_patient: None,
            token_types: None,
            required_claims: None,
            scope_claim: None,
            app_only_scope_claim: None,
            adapter: None,
            max_onward_lifetime: None,
            onward_grant: None,
            onward_indicator: None,
            onward_parameters: None,
            onward_client_id: None,
            onward_subject_audience: None,
            onward_preview: None,
        }
    }
}

impl Default for IntrospectionSection {
    fn default() -> Self {
        Self {
            endpoint: ferrohealth_secret::secret_url::SecretUrl::default(),
            cache_max_age: Duration::from_secs(60),
            cache_capacity: 10_000,
            client: None,
            bearer: None,
        }
    }
}

impl IssuerEntry {
    /// Returns the profile keys this table sets over its preset.
    #[must_use]
    pub fn profile_keys(&self) -> ProfileKeys {
        ProfileKeys {
            person_key: self.person_key.clone(),
            tenant_claim: self.tenant_claim.clone(),
            client_claims: self.client_claims.clone(),
            app_only: self.app_only.clone(),
            guest: self.guest.clone(),
            impersonation_marker: self.impersonation_marker.clone(),
            expect: self.expect.clone(),
            user_claims: self.user_claims.clone(),
            person_equality: self.person_equality.clone(),
            unstable_claims: self.unstable_claims.clone(),
            first_party_clients: self.first_party_clients.clone(),
            delegates: self.delegates.clone(),
            max_actor_chain: self.max_actor_chain,
            representation: self.representation.clone(),
            act_represents_patient: self.act_represents_patient,
            token_types: self.token_types.clone(),
            required_claims: self.required_claims.clone(),
            scope_claim: self.scope_claim.clone(),
            app_only_scope_claim: self.app_only_scope_claim.clone(),
            adapter: self.adapter.clone(),
            max_onward_lifetime: self.max_onward_lifetime,
            onward_grant: self.onward_grant,
            onward_indicator: self.onward_indicator,
            onward_parameters: self.onward_parameters.clone(),
            onward_client_id: self.onward_client_id,
            onward_subject_audience: self.onward_subject_audience,
            onward_preview: self.onward_preview.clone(),
        }
    }
}

/// Checks the issuer-level rules of `entry` and returns its kind: an
/// identifier, a kind, and no `federation` issuer in this build.
pub(super) fn check_entry(entry: &IssuerEntry) -> Result<IssuerKind, ConfigError> {
    if entry.issuer.is_empty() {
        return Err(ConfigError::Missing { key: "auth.issuer" });
    }
    // NOTE: OpenID Connect Core 1.0 §1.2: an issuer identifier holds scheme, host, port and
    // path; userinfo is refused before any later error could quote the URL.
    if let Ok(url) = url::Url::parse(entry.issuer.trim())
        && (!url.username().is_empty() || url.password().is_some())
    {
        return Err(ConfigError::IssuerUserinfo {
            issuer: crate::config::mask_userinfo(&entry.issuer),
        });
    }
    if !entry.jwks_file.is_empty() {
        check_jwks_file(entry)?;
    }
    let kind = entry.kind.ok_or(ConfigError::Missing {
        key: "auth.issuer.kind",
    })?;
    if entry.mode == AuthMode::Jwt && entry.introspection.is_some() {
        return Err(ConfigError::Exclusive {
            left: "auth.issuer.introspection",
            right: "auth.issuer.mode = \"jwt\"",
        });
    }
    if !entry
        .role_claims
        .iter()
        .flatten()
        .all(|path| crate::roles::well_formed(path))
    {
        return Err(ConfigError::Missing {
            key: "auth.issuer.role_claims",
        });
    }
    Ok(kind)
}

/// The JWK members that carry private or symmetric key material, as the
/// example private and symmetric keys of RFC 7517 Appendix A.2 and A.3 show.
const SECRET_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Refuses a `jwks_file` that holds a symmetric key or private key
/// material, which a verifier never holds (RFC 7517 §5; RFC 8725 §3.1).
/// A file that cannot be read or parsed is left to the read of the key
/// set, which refuses it; no key value is ever quoted.
fn check_jwks_file(entry: &IssuerEntry) -> Result<(), ConfigError> {
    let Ok(text) = std::fs::read_to_string(&entry.jwks_file) else {
        return Ok(());
    };
    // NOTE: a file that is no JSON is legitimately left to the key set read, which refuses it.
    let Ok(set) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Ok(());
    };
    let keys = set
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    for (index, key) in keys.iter().enumerate() {
        let kid = key
            .get("kid")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        if key.get("kty").and_then(serde_json::Value::as_str) == Some("oct") {
            return Err(ConfigError::JwksSymmetricKey {
                issuer: entry.issuer.clone(),
                index,
                kid,
            });
        }
        if let Some(member) = SECRET_MEMBERS
            .iter()
            .find(|member| key.get(**member).is_some())
        {
            return Err(ConfigError::JwksPrivateKey {
                issuer: entry.issuer.clone(),
                index,
                kid,
                member,
            });
        }
    }
    Ok(())
}
