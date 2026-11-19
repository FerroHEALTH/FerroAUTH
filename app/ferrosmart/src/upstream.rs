// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The upstream identity providers a person logs in at, for login only.
//!
//! Each is a named `[[ferrosmart.upstream]]` entry with its protocol and
//! that protocol's settings (`docs/architecture.md` §13.2). OpenID Connect is
//! the one protocol today, reached through `ferrohealth-smart`'s relying
//! party; a second protocol is a second [`Protocol`] variant and a table of
//! its own, with no change to the entry or to the login flow.
//!
//! What FerroSMART takes from a provider's login is configured per entry
//! too: the claim that holds the user's `fhirUser` and the claims that hold
//! the user's roles. The user's FerroSMART `sub` is pairwise per upstream
//! issuer (13.6 item 9).

use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrohealth_smart::metadata::Http;
use ferrohealth_smart::oidc::{OidcError, Provider, RelyingParty};
use serde::{Deserialize, Serialize};
use url::Url;

/// How long one call to the upstream provider may take. No specification
/// governs the value: our own design.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);

/// One `[[ferrosmart.upstream]]` entry: a provider by name, with its
/// protocol and that protocol's table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamSection {
    /// The provider's name, which a client's `upstreams` list names; letters,
    /// digits and `-`.
    pub name: String,
    /// The words the chooser page shows for the provider; its name when
    /// empty.
    pub label: String,
    /// The protocol the person logs in by.
    pub protocol: Option<ProtocolName>,
    /// `[ferrosmart.upstream.oidc]`: the OpenID Connect settings, with
    /// `protocol = "oidc"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc: Option<OidcSection>,
}

/// The protocol of an upstream provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolName {
    /// OpenID Connect Core 1.0.
    Oidc,
}

/// `[ferrosmart.upstream.oidc]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OidcSection {
    /// The provider's issuer identifier, whose discovery document names its
    /// endpoints (OpenID Connect Discovery 1.0 §4).
    pub issuer: String,
    /// The client FerroSMART is registered as at the provider.
    pub client_id: String,
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
    /// `[ferrosmart.upstream.oidc.private_key_jwt]`: FerroSMART authenticates
    /// with a JWT the current key of its own assertion ring signs, the one
    /// client authentication it uses at a provider (OpenID Connect Core 1.0
    /// §9); a configuration without it is refused.
    pub private_key_jwt: Option<PrivateKeyJwtSection>,
}

/// `[ferrosmart.upstream.oidc.private_key_jwt]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivateKeyJwtSection {
    /// The algorithm the provider's registration of FerroSMART names, one
    /// the assertion keys sign with (RFC 7518 §3.1).
    pub algorithm: String,
    /// `[ferrosmart.upstream.oidc.private_key_jwt.keys]`: the ring of assertion
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

impl Default for OidcSection {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            client_id: String::new(),
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
///
/// A JWT the assertion ring's current key signs (`private_key_jwt`, OpenID
/// Connect Core 1.0 §9), the ring published at
/// [`crate::discovery::UPSTREAM_JWKS_ROUTE`].
#[derive(Debug, Clone)]
pub struct Authentication {
    /// The current key, at the registration's algorithm and naming its
    /// certificate when one is configured.
    pub signer: Box<AssertionKey>,
    /// The ring the key is current in.
    pub ring: std::sync::Arc<ferrohealth_smart::client::keys::KeyRing>,
}

/// An upstream provider, resolved.
#[derive(Debug, Clone)]
pub struct Upstream {
    /// Its name.
    pub name: String,
    /// The words the chooser page shows.
    pub label: String,
    /// The claim of `fhirUser`, if any.
    pub fhir_user_claim: Option<String>,
    /// The claims of the roles.
    pub role_claims: Vec<String>,
    /// The protocol, with its settings.
    pub protocol: Protocol,
}

/// The protocol of a resolved provider, with its settings: the seam a
/// second protocol joins at.
#[derive(Debug, Clone)]
pub enum Protocol {
    /// OpenID Connect.
    Oidc(OidcUpstream),
}

impl Upstream {
    /// Returns the provider's issuer: the OpenID Provider's issuer
    /// identifier, which a person's pairwise `sub` is derived under.
    #[must_use]
    pub fn issuer(&self) -> &str {
        match &self.protocol {
            Protocol::Oidc(oidc) => &oidc.issuer,
        }
    }

    /// Returns the JWK Set of the keys FerroSMART authenticates to the
    /// provider with, when it authenticates by a signed assertion.
    #[must_use]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "a provider of a second protocol (SAML 2.0, #688) signs no client assertion"
    )]
    pub fn assertion_keys(&self) -> Option<serde_json::Value> {
        match &self.protocol {
            Protocol::Oidc(oidc) => Some(oidc.authentication.ring.published()),
        }
    }
}

/// An OpenID Connect provider, resolved.
#[derive(Debug, Clone)]
pub struct OidcUpstream {
    /// The issuer identifier.
    pub issuer: String,
    /// The client id at the provider.
    pub client_id: String,
    /// How FerroSMART authenticates at the provider.
    pub authentication: Authentication,
    /// The scopes asked for.
    pub scopes: Vec<String>,
    /// The audiences trusted beside the client id.
    pub trusted_audiences: Vec<String>,
}

impl OidcUpstream {
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
        Ok(party.with_private_key_jwt((*self.authentication.signer).clone()))
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

/// How a person logs in at one provider: the protocol's own client.
#[derive(Debug)]
pub enum Login {
    /// The OpenID Connect relying party.
    Oidc(RelyingParty),
}

/// A provider people log in at: its settings and its login.
#[derive(Debug)]
pub struct LoginProvider {
    /// The settings.
    upstream: Upstream,
    /// The login.
    login: Login,
}

impl LoginProvider {
    /// Returns the provider's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.upstream.name
    }

    /// Returns the provider's settings.
    #[must_use]
    pub const fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    /// Returns the OpenID Connect relying party, when the provider speaks
    /// OpenID Connect.
    #[must_use]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "a provider of a second protocol (SAML 2.0, #688) has no relying party"
    )]
    pub const fn oidc(&self) -> Option<&RelyingParty> {
        match &self.login {
            Login::Oidc(party) => Some(party),
        }
    }

    /// Returns the origins the provider's own pages are served from: its
    /// issuer's and its end-session endpoint's.
    #[must_use]
    pub fn origins(&self) -> Vec<String> {
        let issuer = Url::parse(self.upstream.issuer()).ok();
        let end_session = self
            .oidc()
            .and_then(|party| party.provider().end_session_endpoint().cloned());
        origins_of(issuer.iter().chain(end_session.iter()))
    }
}

/// Returns the origins of `urls`, each once, in their order, leaving out an
/// opaque one, as a page's `form-action` or `frame-ancestors` names them.
pub fn origins_of<'a>(urls: impl Iterator<Item = &'a Url>) -> Vec<String> {
    let mut origins: Vec<String> = Vec::new();
    for url in urls {
        let origin = url.origin();
        if origin.is_tuple() && !origins.contains(&origin.ascii_serialization()) {
            origins.push(origin.ascii_serialization());
        }
    }
    origins
}

/// The providers people log in at, in the order the configuration names
/// them.
#[derive(Debug, Default)]
pub struct Providers {
    /// The providers.
    providers: Vec<LoginProvider>,
}

impl Providers {
    /// Discovers every provider `upstreams` names and returns their logins,
    /// each sending the browser back to `callback` and, after its own
    /// logout, to `post_logout` (RP-Initiated Logout 1.0 §3).
    ///
    /// # Errors
    /// Returns [`OidcError`] when a provider's metadata cannot be read or
    /// names no usable endpoints.
    pub async fn connect(
        upstreams: &[Upstream],
        callback: &Url,
        post_logout: &Url,
    ) -> Result<Self, OidcError> {
        let mut providers = Vec::with_capacity(upstreams.len());
        for upstream in upstreams {
            let login = match &upstream.protocol {
                Protocol::Oidc(oidc) => Login::Oidc(
                    oidc.relying_party(callback.clone())
                        .await?
                        .with_post_logout_redirect_uri(post_logout.clone()),
                ),
            };
            providers.push(LoginProvider {
                upstream: upstream.clone(),
                login,
            });
        }
        Ok(Self { providers })
    }

    /// Whether no provider is configured.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// Returns every provider, in configuration order.
    pub fn iter(&self) -> impl Iterator<Item = &LoginProvider> {
        self.providers.iter()
    }

    /// Returns the provider `name`.
    #[must_use]
    pub fn named(&self, name: &str) -> Option<&LoginProvider> {
        self.providers
            .iter()
            .find(|provider| provider.name() == name)
    }

    /// Returns the provider whose issuer is `issuer`.
    #[must_use]
    pub fn by_issuer(&self, issuer: &str) -> Option<&LoginProvider> {
        self.providers
            .iter()
            .find(|provider| provider.upstream.issuer() == issuer)
    }

    /// Returns the providers a person may log in at for the client that
    /// names `allowed`: those it names, or every provider when it names
    /// none.
    #[must_use]
    pub fn allowed(&self, allowed: &[String]) -> Vec<&LoginProvider> {
        self.providers
            .iter()
            .filter(|provider| {
                allowed.is_empty() || allowed.iter().any(|name| name == provider.name())
            })
            .collect()
    }
}
