// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The credential a product obtains for itself with the OAuth 2.0 client
//! credentials grant (RFC 6749 §4.4), cached and renewed before it expires.
//!
//! A product reaches an upstream under its own token for the upstream's
//! audience and never forwards a caller's token, because an access token
//! names the resource server it is for (RFC 9068 §4). The token endpoint is
//! configured outright or discovered from the issuer's metadata
//! ([`crate::metadata`]). The client authenticates with `client_secret_basic`
//! or `client_secret_post` (RFC 6749 §2.3.1), with a `private_key_jwt`
//! assertion (RFC 7523 §2.2, [`assertion`]), or with a client certificate
//! over mutual TLS (RFC 8705 §2). Extra trust roots and the client
//! certificate travel in [`Tls`]. `cache::TokenSource`, behind the default
//! `fetch` feature, fetches on first use, shares one fetch among concurrent callers, hands out the
//! bearer credential per attempt, and sends a call once more with a new
//! token when the upstream refuses the held one with `401`.
//!
//! A grant may bind its tokens ([`binding::TokenBinding`]): to a `DPoP` key
//! ([`dpop`]), whose proof every token request and every resource request
//! carries (RFC 9449), or to the client certificate it presents, which every
//! issued token that states a binding must name (RFC 8705 §3).
//!
//! `onward`, behind `fetch` as well, obtains a token for another service on behalf of a caller, by
//! token exchange (RFC 8693 §2.1) or the JWT bearer grant (RFC 7523 §2.1),
//! and refuses one that fails the onward check.

pub mod assertion;
pub mod binding;
#[cfg(feature = "fetch")]
pub mod cache;
pub mod dpop;
#[cfg(feature = "fetch")]
pub(crate) mod endpoint;
#[cfg(feature = "fetch")]
pub mod onward;

use std::sync::Arc;
use std::time::Duration;

use http::StatusCode;
use secrecy::SecretSlice;
use secrecy::SecretString;
use serde::Deserialize;
use serde::Serialize;
use url::Url;

use crate::client::assertion::AssertionKey;
use crate::client::binding::TokenBinding;
use crate::client::dpop::DpopKey;
use crate::metadata::DiscoveryError;

/// Where the token endpoint comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// The issuer identifier, whose metadata names the token endpoint
    /// (RFC 8414 §2). Kept as configured, because the metadata's `issuer`
    /// must be identical to it (RFC 8414 §3.3).
    Issuer(String),
    /// The token endpoint itself (RFC 6749 §3.2).
    Token(Url),
}

/// How the client authenticates to the token endpoint, configured and
/// never guessed from the server's metadata.
#[expect(
    clippy::enum_variant_names,
    reason = "the variants mirror the RFC 8705 §2 method names tls_client_auth and self_signed_tls_client_auth"
)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuth {
    /// HTTP Basic over the form-encoded client id and secret, the scheme every
    /// authorization server must support (RFC 6749 §2.3.1).
    #[default]
    ClientSecretBasic,
    /// The client id and secret as `client_id` and `client_secret` in the
    /// request body (RFC 6749 §2.3.1), for an authorization server that
    /// accepts nothing else.
    ClientSecretPost,
    /// A signed client assertion in the request body (RFC 7523 §2.2), the
    /// form RFC 9700 §2.5 recommends and SMART Backend Services requires.
    PrivateKeyJwt,
    /// A client certificate the authorization server checks against its
    /// PKI and the client's registered subject (RFC 8705 §2.1), with
    /// `client_id` in the request body.
    TlsClientAuth,
    /// A self-signed client certificate the authorization server checks
    /// against the client's registered keys (RFC 8705 §2.2), with
    /// `client_id` in the request body.
    SelfSignedTlsClientAuth,
}

impl ClientAuth {
    /// Returns whether the method authenticates with a client certificate
    /// over mutual TLS (RFC 8705 §2).
    #[must_use]
    pub const fn is_mutual_tls(self) -> bool {
        matches!(self, Self::TlsClientAuth | Self::SelfSignedTlsClientAuth)
    }
}

/// The `aud` a `private_key_jwt` assertion names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionAudience {
    /// The token endpoint URL the assertion is posted to, the value SMART
    /// App Launch 2.2.0, Client Authentication: Asymmetric, fixes.
    #[default]
    TokenEndpoint,
    /// The configured issuer identifier, a value RFC 7523 §3 item 3 also
    /// admits as identifying the authorization server, for an authorization
    /// server outside the SMART profile that asks for it.
    Issuer,
}

/// The TLS material of the token endpoint connection: trust roots added to
/// the built-in ones, and the client certificate of RFC 8705 mutual TLS.
///
/// The private key redacts itself in every `Debug` rendering.
#[derive(Debug, Clone, Default)]
pub struct Tls {
    /// PEM certificates trusted beside the built-in roots, for a token
    /// endpoint behind a private certificate authority.
    pub root_certificates: Option<Vec<u8>>,
    /// The client certificate chain and its private key, in PEM, presented
    /// in the TLS handshake (RFC 8705 §2).
    pub identity: Option<Arc<SecretSlice<u8>>>,
}

/// The lowest TLS version a connection negotiates, written `"1.2"` or
/// `"1.3"` in a configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Deserialize, Serialize)]
#[non_exhaustive]
pub enum TlsVersion {
    /// TLS 1.2 (RFC 5246), the lowest version the engine speaks.
    #[default]
    #[serde(rename = "1.2")]
    Tls12,
    /// TLS 1.3 (RFC 8446).
    #[serde(rename = "1.3")]
    Tls13,
}

/// How a connection reaches its server beyond its TLS material.
///
/// It names the lowest TLS version the connection negotiates, and the hosts
/// it reaches at a fixed address in place of resolving their names, for a
/// server whose name resolves only inside a private network (no
/// specification governs the override: our own design). An override replaces the name lookup only. The URL's port and the
/// certificate check against the host name stay as the URL names them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reach {
    min_tls_version: TlsVersion,
    resolve: Vec<(String, std::net::SocketAddr)>,
}

impl Reach {
    /// Returns this reach negotiating no TLS version below `version`.
    #[must_use]
    pub const fn with_min_tls_version(mut self, version: TlsVersion) -> Self {
        self.min_tls_version = version;
        self
    }

    /// Returns this reach reaching `host` at `address`.
    #[must_use]
    pub fn with_resolve(mut self, host: impl Into<String>, address: std::net::SocketAddr) -> Self {
        self.resolve.push((host.into(), address));
        self
    }

    /// The lowest TLS version the connection negotiates.
    #[must_use]
    pub const fn min_tls_version(&self) -> TlsVersion {
        self.min_tls_version
    }

    /// The hosts reached at a fixed address, each with its address.
    #[must_use]
    pub fn resolve(&self) -> &[(String, std::net::SocketAddr)] {
        &self.resolve
    }
}

/// Everything a product needs to obtain its upstream token.
///
/// The secret is a [`SecretString`] and the key redacts itself, so a
/// `Debug` rendering never carries either.
#[derive(Debug, Clone)]
pub struct ClientCredentials {
    /// Where the token endpoint comes from.
    pub endpoint: Endpoint,
    /// The client identifier (RFC 6749 §2.2).
    pub client_id: String,
    /// How the client authenticates to the token endpoint.
    pub client_auth: ClientAuth,
    /// The client secret, under `client_secret_basic` and
    /// `client_secret_post`.
    pub client_secret: Option<SecretString>,
    /// The key the client assertion is signed with, under
    /// `private_key_jwt`.
    pub assertion_key: Option<AssertionKey>,
    /// The `scope` request parameter (RFC 6749 §3.3), when the deployment
    /// asks for one.
    pub scope: Option<String>,
    /// The `audience` request parameter some authorization servers read in
    /// place of a resource indicator; no specification defines it for this
    /// grant, so it is sent only when configured.
    pub audience: Option<String>,
    /// The `resource` request parameter (RFC 8707 §2), the upstream the
    /// token is for.
    pub resource: Option<Url>,
    /// How long before the token expires a new one is fetched.
    pub refresh_margin: Duration,
    /// How long one call to the authorization server may take.
    pub timeout: Duration,
    /// The `aud` of a `private_key_jwt` assertion.
    pub assertion_audience: AssertionAudience,
    /// The trust roots and the client certificate of the token endpoint
    /// connection.
    pub tls: Tls,
    /// What the issued tokens are bound to, when they are sender-constrained
    /// (RFC 9449, RFC 8705 §3); `None` for bearer tokens.
    pub token_binding: Option<TokenBinding>,
}

impl ClientCredentials {
    /// Returns a grant for `client_id` with `client_secret` at `endpoint`.
    ///
    /// The client authenticates with HTTP Basic, sends no `scope`, `audience`
    /// or `resource`, renews its token 30 seconds before it expires, and
    /// gives the authorization server 10 seconds per call.
    #[must_use]
    pub fn new(endpoint: Endpoint, client_id: String, client_secret: SecretString) -> Self {
        Self {
            client_secret: Some(client_secret),
            ..Self::authenticating(endpoint, client_id, ClientAuth::default())
        }
    }

    /// Returns a grant for `client_id` at `endpoint` authenticating with a
    /// client assertion signed by `key`.
    #[must_use]
    pub fn with_private_key_jwt(endpoint: Endpoint, client_id: String, key: AssertionKey) -> Self {
        Self {
            assertion_key: Some(key),
            ..Self::authenticating(endpoint, client_id, ClientAuth::PrivateKeyJwt)
        }
    }

    /// Returns a grant for `client_id` at `endpoint` authenticating with
    /// the client certificate `identity` (PEM chain and key) over mutual
    /// TLS (RFC 8705 §2): [`ClientAuth::SelfSignedTlsClientAuth`] when
    /// `self_signed`, [`ClientAuth::TlsClientAuth`] otherwise.
    #[must_use]
    pub fn with_mutual_tls(
        endpoint: Endpoint,
        client_id: String,
        identity: Arc<SecretSlice<u8>>,
        self_signed: bool,
    ) -> Self {
        let client_auth = if self_signed {
            ClientAuth::SelfSignedTlsClientAuth
        } else {
            ClientAuth::TlsClientAuth
        };
        Self {
            tls: Tls {
                root_certificates: None,
                identity: Some(identity),
            },
            ..Self::authenticating(endpoint, client_id, client_auth)
        }
    }

    /// Returns a grant for `client_id` at `endpoint` authenticating with
    /// `client_auth`, holding no credential yet, with the defaults of
    /// [`ClientCredentials::new`].
    fn authenticating(endpoint: Endpoint, client_id: String, client_auth: ClientAuth) -> Self {
        Self {
            endpoint,
            client_id,
            client_auth,
            client_secret: None,
            assertion_key: None,
            scope: None,
            audience: None,
            resource: None,
            refresh_margin: Duration::from_secs(30),
            timeout: Duration::from_secs(10),
            assertion_audience: AssertionAudience::default(),
            tls: Tls::default(),
            token_binding: None,
        }
    }

    /// Returns this grant binding its tokens to `key`: every token request
    /// and every resource request carries a proof of it, and only a token of
    /// type `DPoP` is taken (RFC 9449 §5, §7.1).
    #[must_use]
    pub fn with_dpop(mut self, key: Arc<DpopKey>) -> Self {
        self.token_binding = Some(TokenBinding::Dpop(key));
        self
    }

    /// Returns this grant taking only tokens whose stated binding names the
    /// client certificate of its TLS identity (RFC 8705 §3).
    #[must_use]
    pub fn with_certificate_binding(mut self) -> Self {
        self.token_binding = Some(TokenBinding::Certificate);
        self
    }

    /// Returns the `DPoP` key the grant's tokens are bound to, when they are.
    #[must_use]
    pub fn dpop_key(&self) -> Option<&Arc<DpopKey>> {
        match &self.token_binding {
            Some(TokenBinding::Dpop(key)) => Some(key),
            Some(TokenBinding::Certificate) | None => None,
        }
    }

    /// Returns the thumbprint of the certificate a certificate-bound grant
    /// presents, when its tokens are bound to one and its identity holds one.
    pub(crate) fn bound_certificate(&self) -> Option<crate::sender::ClientCertificate> {
        match self.token_binding {
            Some(TokenBinding::Certificate) => self
                .tls
                .identity
                .as_deref()
                .and_then(binding::presented_certificate),
            Some(TokenBinding::Dpop(_)) | None => None,
        }
    }

    /// Checks that the grant carries the credential its method needs.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Credential`] naming what is missing: a secret,
    /// an assertion key, a client certificate under a mutual-TLS method or
    /// a certificate binding, or the issuer an issuer assertion audience
    /// names.
    pub fn validate(&self) -> Result<(), TokenError> {
        // NOTE: RFC 8705 §3, a certificate-bound token is bound to the certificate
        // the client presents, so a grant that presents none cannot take one.
        if matches!(self.token_binding, Some(TokenBinding::Certificate))
            && self.bound_certificate().is_none()
        {
            return Err(TokenError::Credential {
                what: "client certificate for the certificate binding",
            });
        }
        if self.client_auth == ClientAuth::PrivateKeyJwt
            && self.assertion_audience == AssertionAudience::Issuer
            && !matches!(self.endpoint, Endpoint::Issuer(_))
        {
            return Err(TokenError::Credential {
                what: "issuer for the assertion audience",
            });
        }
        match self.client_auth {
            ClientAuth::ClientSecretBasic | ClientAuth::ClientSecretPost
                if self.client_secret.is_none() =>
            {
                Err(TokenError::Credential {
                    what: "a client secret",
                })
            }
            ClientAuth::PrivateKeyJwt if self.assertion_key.is_none() => {
                Err(TokenError::Credential {
                    what: "an assertion key",
                })
            }
            ClientAuth::TlsClientAuth | ClientAuth::SelfSignedTlsClientAuth
                if self.tls.identity.is_none() =>
            {
                Err(TokenError::Credential {
                    what: "client certificate",
                })
            }
            _ => Ok(()),
        }
    }
}

/// The error response of a token endpoint (RFC 6749 §5.2).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct OAuthError {
    /// The error code: `invalid_request`, `invalid_client`, `invalid_grant`,
    /// `unauthorized_client`, `unsupported_grant_type` or `invalid_scope`.
    pub error: String,
    /// The human-readable description, when the server sent one.
    pub error_description: Option<String>,
    /// The page describing the error, when the server sent one.
    pub error_uri: Option<String>,
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.error_description.as_deref() {
            Some(description) => write!(f, "{} ({description})", self.error),
            None => f.write_str(&self.error),
        }
    }
}

/// A token the product could not obtain.
///
/// No variant carries the client secret, the key or a token.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    /// The metadata naming the token endpoint could not be read, or the
    /// token request never completed.
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    /// The grant lacks the credential its authentication method needs.
    #[error("the client credentials grant carries no {what}")]
    Credential {
        /// What is missing.
        what: &'static str,
    },
    /// The client assertion could not be signed.
    #[error("the client assertion could not be signed")]
    Assertion {
        /// Why.
        #[source]
        source: assertion::AssertionError,
    },
    /// The metadata names no token endpoint.
    #[error("the authorization server metadata names no token_endpoint")]
    NoTokenEndpoint,
    /// The metadata names a token endpoint that is not a URL.
    #[error("the authorization server metadata names a token endpoint that is not a URL")]
    TokenEndpointUrl {
        /// What the URL parser reported.
        #[source]
        source: url::ParseError,
    },
    /// The token endpoint answered anything other than `200`, with the OAuth
    /// error when the body carried one (RFC 6749 §5.2).
    #[error("the token endpoint answered {status}{}", oauth_clause(error.as_ref()))]
    Refused {
        /// The status it answered.
        status: StatusCode,
        /// The OAuth error, when the body was one.
        error: Option<OAuthError>,
        /// The body, as received.
        body: String,
    },
    /// The `200` body is not the access token response of RFC 6749 §5.1.
    #[error("the token endpoint answered a body that is not an access token response")]
    Malformed {
        /// What the JSON reader reported.
        #[source]
        source: serde_json::Error,
    },
    /// The token is not of the type the grant asks for: `Bearer` (RFC 6750),
    /// or `DPoP` for a grant whose tokens are bound to a `DPoP` key (RFC 9449
    /// §5).
    #[error("the token endpoint issued a token of type {found:?}; the grant asks for {expected}")]
    TokenType {
        /// The `token_type` the response named.
        found: String,
        /// The type the grant asks for.
        expected: &'static str,
    },
    /// The token cannot travel as an RFC 6750 §2.1 or RFC 9449 §7.1
    /// credential: it carries a byte outside the `b64token` alphabet.
    #[error("the issued token cannot travel as a credential")]
    Unusable,
    /// The `DPoP` proof of the token request could not be signed (RFC 9449
    /// §4.2); nothing was sent.
    #[error("the DPoP proof of the token request could not be signed")]
    Proof {
        /// Why.
        #[source]
        source: dpop::DpopError,
    },
    /// The issued token states a binding to another certificate than the
    /// one the grant presents, or to another confirmation method, so it was
    /// neither kept nor used (RFC 8705 §3).
    #[error("the issued token is not bound to the certificate the client presents (RFC 8705 §3)")]
    CertificateMismatch,
    /// The fetch ended without an outcome.
    #[error("the token fetch ended without an outcome")]
    Abandoned,
}

impl TokenError {
    /// Returns the status the authorization server answered, when the failure
    /// carries one.
    #[must_use]
    pub const fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Discovery(DiscoveryError::Status { status, .. })
            | Self::Refused { status, .. } => Some(*status),
            _ => None,
        }
    }
}

/// The upstream refused the token (`401`) and no new one could be obtained.
#[derive(Debug, thiserror::Error)]
#[error("the upstream refused the token (401) and no new token could be obtained")]
pub struct RenewalError {
    /// Why the new token could not be obtained.
    #[source]
    source: Arc<TokenError>,
}

impl RenewalError {
    /// Returns the renewal failure `source` caused.
    #[must_use]
    pub const fn new(source: Arc<TokenError>) -> Self {
        Self { source }
    }

    /// Returns why the new token could not be obtained.
    #[must_use]
    pub fn token_error(&self) -> &TokenError {
        &self.source
    }
}

/// Why a call under a token failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CallError<E> {
    /// No token could be obtained before the first attempt.
    #[error("no token could be obtained for the call")]
    Token {
        /// Why.
        #[source]
        source: Arc<TokenError>,
    },
    /// The upstream refused the token and no new one could be obtained.
    #[error(transparent)]
    Renewal(RenewalError),
    /// The call itself failed.
    #[error("the call failed")]
    Call {
        /// What the call reported.
        #[source]
        source: E,
    },
    /// The source's tokens are bound to a `DPoP` key, so a call that is
    /// handed the `Authorization` value alone cannot prove it; nothing was
    /// sent (RFC 9449 §7.1).
    #[error("the token is DPoP-bound and the call carries no proof; nothing was sent")]
    Unproven,
    /// The `DPoP` proof of the call could not be signed; nothing was sent.
    #[error("the DPoP proof of the call could not be signed")]
    Proof {
        /// Why.
        #[source]
        source: dpop::DpopError,
    },
}

/// Returns the OAuth clause of a refusal's display.
fn oauth_clause(error: Option<&OAuthError>) -> String {
    error.map_or_else(String::new, |error| format!(": {error}"))
}

#[cfg(test)]
mod tests {
    use super::{ClientAuth, ClientCredentials, Endpoint, OAuthError, TokenError};
    use http::StatusCode;
    use secrecy::SecretString;

    #[test]
    fn a_refusal_displays_the_oauth_error_and_its_description() {
        let error = TokenError::Refused {
            status: StatusCode::UNAUTHORIZED,
            error: Some(OAuthError {
                error: String::from("invalid_client"),
                error_description: Some(String::from("unknown client")),
                error_uri: None,
            }),
            body: String::new(),
        };
        assert_eq!(
            "the token endpoint answered 401 Unauthorized: invalid_client (unknown client)",
            error.to_string()
        );
        assert_eq!(Some(StatusCode::UNAUTHORIZED), error.status());
    }

    #[test]
    fn a_grant_needs_the_credential_of_its_method() {
        let mut grant = ClientCredentials::new(
            Endpoint::Issuer(String::from("https://as.example.org")),
            String::from("client"),
            SecretString::from("synthetic-pw"),
        );
        assert!(grant.validate().is_ok());
        grant.client_auth = ClientAuth::PrivateKeyJwt;
        assert!(matches!(
            grant.validate(),
            Err(TokenError::Credential {
                what: "an assertion key"
            })
        ));
        grant.client_auth = ClientAuth::ClientSecretPost;
        grant.client_secret = None;
        assert!(matches!(
            grant.validate(),
            Err(TokenError::Credential {
                what: "a client secret"
            })
        ));
        assert!(!format!("{grant:?}").contains("synthetic-pw"));
        grant.client_auth = ClientAuth::TlsClientAuth;
        assert!(matches!(
            grant.validate(),
            Err(TokenError::Credential {
                what: "client certificate"
            })
        ));
    }

    #[test]
    fn an_issuer_assertion_audience_needs_an_issuer() {
        let key = super::assertion::AssertionKey::from_pem(
            &aws_lc_rs::signature::EcdsaKeyPair::generate(
                &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            )
            .and_then(|pair| pair.to_pkcs8v1())
            .map(|der| pem(der.as_ref()))
            .expect("a generated key"),
            None,
            None,
        )
        .expect("a P-384 key");
        let mut grant = ClientCredentials::with_private_key_jwt(
            Endpoint::Token("https://as.example.org/token".parse().expect("a URL")),
            String::from("client"),
            key,
        );
        grant.assertion_audience = super::AssertionAudience::Issuer;
        assert!(matches!(
            grant.validate(),
            Err(TokenError::Credential {
                what: "issuer for the assertion audience"
            })
        ));
        grant.endpoint = Endpoint::Issuer(String::from("https://as.example.org"));
        assert!(grant.validate().is_ok());
    }

    fn pem(der: &[u8]) -> Vec<u8> {
        use base64::Engine as _;
        let body = base64::engine::general_purpose::STANDARD.encode(der);
        let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
        for line in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            out.push('\n');
        }
        out.push_str("-----END PRIVATE KEY-----\n");
        out.into_bytes()
    }
}
