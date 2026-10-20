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
//! or `client_secret_post` (RFC 6749 §2.3.1) or with a `private_key_jwt`
//! assertion (RFC 7523 §2.2, [`assertion`]). [`cache::TokenSource`] fetches
//! on first use, shares one fetch among concurrent callers, hands out the
//! bearer credential per attempt, and sends a call once more with a new
//! token when the upstream refuses the held one with `401`.

pub mod assertion;
#[cfg(feature = "fetch")]
pub mod cache;
#[cfg(feature = "fetch")]
mod endpoint;

use std::sync::Arc;
use std::time::Duration;

use http::StatusCode;
use secrecy::SecretString;
use serde::Deserialize;
use serde::Serialize;
use url::Url;

use crate::client::assertion::AssertionKey;
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
            endpoint,
            client_id,
            client_auth: ClientAuth::default(),
            client_secret: Some(client_secret),
            assertion_key: None,
            scope: None,
            audience: None,
            resource: None,
            refresh_margin: Duration::from_secs(30),
            timeout: Duration::from_secs(10),
        }
    }

    /// Returns a grant for `client_id` at `endpoint` authenticating with a
    /// client assertion signed by `key`.
    #[must_use]
    pub fn with_private_key_jwt(endpoint: Endpoint, client_id: String, key: AssertionKey) -> Self {
        Self {
            endpoint,
            client_id,
            client_auth: ClientAuth::PrivateKeyJwt,
            client_secret: None,
            assertion_key: Some(key),
            scope: None,
            audience: None,
            resource: None,
            refresh_margin: Duration::from_secs(30),
            timeout: Duration::from_secs(10),
        }
    }

    /// Checks that the grant carries the credential its method needs.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Credential`] naming what is missing.
    pub fn validate(&self) -> Result<(), TokenError> {
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
    /// The token is not a bearer token, the one type the product sends
    /// (RFC 6749 §7.1, RFC 6750).
    #[error("the token endpoint issued a token of type {found:?}; the product sends bearer tokens")]
    TokenType {
        /// The `token_type` the response named.
        found: String,
    },
    /// The token cannot travel as an RFC 6750 §2.1 bearer credential: it
    /// carries a byte outside the `b64token` alphabet.
    #[error("the issued token cannot travel as a bearer credential")]
    Unusable,
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
    }
}
