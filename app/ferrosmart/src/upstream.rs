// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The upstream OpenID Connect provider a person logs in at, for login
//! only (`docs/architecture.md` §13.2): any provider, named by
//! configuration, reached through `ferrohealth-smart`'s relying party.
//!
//! What FerroSMART takes from the provider's ID Token is configured too:
//! the claim that holds the user's `fhirUser` and the claims that hold the
//! user's roles. The user's FerroSMART `sub` is pairwise per upstream
//! issuer (13.6 item 9).

use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use ferrohealth_secret::secret::Secret;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrohealth_smart::metadata::Http;
use ferrohealth_smart::oidc::{OidcError, Provider, RelyingParty};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use url::Url;

/// How long one call to the upstream provider may take. No specification
/// governs the value: our own design.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);

/// `[ferrosmart.upstream]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamSection {
    /// The provider's issuer identifier, whose discovery document names its
    /// endpoints (OpenID Connect Discovery 1.0 §4).
    pub issuer: String,
    /// The client FerroSMART is registered as at the provider.
    pub client_id: String,
    /// Its client secret, sent as HTTP Basic; unset for a public client
    /// that relies on PKCE alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<Secret>,
    /// The file holding the client secret.
    pub client_secret_file: Option<PathBuf>,
    /// The scopes FerroSMART asks the provider for, `openid` among them.
    pub scopes: Vec<String>,
    /// The dotted claim of the ID Token that holds the user's `fhirUser`
    /// URL; empty when the provider carries none, and FerroSMART then
    /// offers no `fhirUser` scope.
    pub fhir_user_claim: String,
    /// The dotted claims of the ID Token that hold the user's roles.
    pub role_claims: Vec<String>,
    /// The audiences an ID Token may name beside FerroSMART's client id, which
    /// FerroSMART trusts (OpenID Connect Core 1.0 §3.1.3.7 item 3), such as
    /// the project a provider adds; empty trusts none.
    pub trusted_audiences: Vec<String>,
    /// `[ferrosmart.upstream.private_key_jwt]`: FerroSMART authenticates
    /// with a JWT the current key of its own assertion ring signs, in place
    /// of a client secret (OpenID Connect Core 1.0 §9).
    pub private_key_jwt: Option<PrivateKeyJwtSection>,
}

/// `[ferrosmart.upstream.private_key_jwt]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivateKeyJwtSection {
    /// The algorithm the provider's registration of FerroSMART names, one
    /// the assertion keys sign with (RFC 7518 §3.1).
    pub algorithm: String,
    /// `[ferrosmart.upstream.private_key_jwt.keys]`: the ring of assertion
    /// keys, read as `[ferrosmart.keys]` is and never one of its keys, so a
    /// key that signs assertions never signs a token (RFC 8725 §3.12).
    pub keys: crate::config::KeysSection,
    /// The PEM X.509 certificate of the current key, for a provider that
    /// knows the key by its certificate; each assertion then names it by
    /// `x5t#S256` (RFC 7515 §4.1.8).
    pub certificate_file: Option<PathBuf>,
}

impl Default for PrivateKeyJwtSection {
    fn default() -> Self {
        Self {
            algorithm: String::from("RS256"),
            keys: crate::config::KeysSection::default(),
            certificate_file: None,
        }
    }
}

impl Default for UpstreamSection {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            client_id: String::new(),
            client_secret: None,
            client_secret_file: None,
            scopes: vec![String::from(ferrohealth_smart::oidc::OPENID)],
            fhir_user_claim: String::new(),
            role_claims: ferrohealth_smart::roles::default_claims(),
            trusted_audiences: Vec::new(),
            private_key_jwt: None,
        }
    }
}

/// How FerroSMART authenticates at the provider's token and revocation
/// endpoints.
#[derive(Debug, Clone)]
pub enum Authentication {
    /// A public client, PKCE alone (RFC 6749 §2.1).
    Public,
    /// A client secret, sent as HTTP Basic (RFC 6749 §2.3.1).
    Secret(SecretString),
    /// A JWT the assertion ring's current key signs (`private_key_jwt`,
    /// OpenID Connect Core 1.0 §9); the ring is published at
    /// [`crate::discovery::UPSTREAM_JWKS_ROUTE`].
    PrivateKeyJwt {
        /// The current key, at the registration's algorithm and naming its
        /// certificate when one is configured.
        signer: Box<AssertionKey>,
        /// The ring the key is current in.
        ring: std::sync::Arc<ferrohealth_smart::client::keys::KeyRing>,
    },
}

/// The upstream provider, resolved.
#[derive(Debug, Clone)]
pub struct Upstream {
    /// The issuer identifier.
    pub issuer: String,
    /// The client id at the provider.
    pub client_id: String,
    /// How FerroSMART authenticates at the provider.
    pub authentication: Authentication,
    /// The scopes asked for.
    pub scopes: Vec<String>,
    /// The claim of `fhirUser`, if any.
    pub fhir_user_claim: Option<String>,
    /// The claims of the roles.
    pub role_claims: Vec<String>,
    /// The audiences trusted beside the client id.
    pub trusted_audiences: Vec<String>,
}

impl Upstream {
    /// Discovers the provider and returns the relying party whose
    /// redirection endpoint is `callback`.
    ///
    /// # Errors
    /// Returns [`OidcError`] when the provider's metadata cannot be read or
    /// names no usable endpoints.
    pub async fn relying_party(&self, callback: Url) -> Result<RelyingParty, OidcError> {
        let http = Http::new(UPSTREAM_TIMEOUT)?;
        let provider = Provider::discover(&http, &self.issuer).await?;
        let party = RelyingParty::new(http, provider, self.client_id.clone(), callback)
            .with_scopes(self.scopes.iter().map(String::as_str))
            .with_trusted_audiences(self.trusted_audiences.iter().cloned());
        Ok(match &self.authentication {
            Authentication::Public => party,
            Authentication::Secret(secret) => party.with_client_secret(secret.clone()),
            Authentication::PrivateKeyJwt { signer, .. } => {
                party.with_private_key_jwt((**signer).clone())
            }
        })
    }
}

/// Returns the FerroSMART `sub` of the user `subject` of the provider
/// `issuer`.
///
/// It is the SHA-256 of the two, base64url, so two providers never
/// collide and the upstream identifier never reaches a resource server
/// (`docs/architecture.md` §13.6 item 9, our own design; OpenID Connect
/// Core 1.0 §8.1 describes pairwise identifiers).
#[must_use]
pub fn pairwise(issuer: &str, subject: &str) -> String {
    let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    context.update(issuer.as_bytes());
    context.update(&[0]);
    context.update(subject.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(context.finish().as_ref())
}

impl Upstream {
    /// Returns the JWK Set of the assertion keys, when FerroSMART
    /// authenticates with `private_key_jwt`.
    #[must_use]
    pub fn assertion_keys(&self) -> Option<serde_json::Value> {
        match &self.authentication {
            Authentication::PrivateKeyJwt { ring, .. } => Some(ring.published()),
            Authentication::Public | Authentication::Secret(_) => None,
        }
    }
}
