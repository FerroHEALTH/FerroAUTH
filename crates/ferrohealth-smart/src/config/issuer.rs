// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The defaults of one `[[auth.issuer]]` table and the profile keys it sets
//! over its preset.

use jsonwebtoken::Algorithm;

use crate::config::AuthMode;
use crate::config::IssuerEntry;
use crate::profile::Preset;
use crate::profile::ProfileKeys;
use crate::sender::SenderConstraint;

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
            clock_skew_seconds: 60,
            jwks_max_age_seconds: 600,
            jwks_refresh_interval_seconds: 60,
            jwks_file: String::new(),
            timeout_ms: 10_000,
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
            token_profile: None,
            acting_for_claim: None,
            client_tokens: None,
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
