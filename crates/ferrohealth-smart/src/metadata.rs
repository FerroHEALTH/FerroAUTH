// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The authorization server metadata (RFC 8414 §2) and how it is found.
//!
//! The RFC 8414 §3 location is read first; a `404` there moves on to the
//! `OpenID` Connect Discovery 1.0 §4 location, and any other answer is final.
//! The document must name the configured issuer itself (RFC 8414 §3.3).
//! The resource server reads it for `jwks_uri` and the endpoints its SMART
//! discovery document republishes; the token client reads it for
//! `token_endpoint`.

#[cfg(feature = "fetch")]
use std::time::Duration;

use http::StatusCode;
use serde::Deserialize;
use serde::Serialize;
use url::Url;

/// The RFC 8414 §3 well-known suffix.
pub const OAUTH_METADATA: &str = "/.well-known/oauth-authorization-server";

/// The `OpenID` Connect Discovery 1.0 §4 well-known suffix.
pub const OPENID_CONFIGURATION: &str = "/.well-known/openid-configuration";

/// The most bytes a metadata or key set document may carry.
///
/// No specification governs the ceiling: our own design, so a misdirected
/// issuer URL cannot have the process read a file of any size.
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// The members of an authorization server metadata document a resource
/// server or a token client reads or republishes (RFC 8414 §2).
///
/// Every member but `issuer` is optional on the wire, so each is an
/// `Option`; a member the document does not carry is `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerMetadata {
    /// The issuer identifier the document describes.
    pub issuer: String,
    /// The key set URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// The authorization endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    /// The token endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    /// The client authentication methods of the token endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// The grant types the server supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,
    /// The dynamic client registration endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// The scopes the server supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    /// The response types the server supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types_supported: Option<Vec<String>>,
    /// The token introspection endpoint (RFC 7662).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    /// The token revocation endpoint (RFC 7009).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    /// The PKCE challenge methods the server supports (RFC 7636).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

impl ServerMetadata {
    /// Returns the grant types the server supports, the RFC 8414 §2 default
    /// `authorization_code` and `implicit` when the document names none.
    #[must_use]
    pub fn grant_types(&self) -> Vec<String> {
        self.grant_types_supported
            .clone()
            .unwrap_or_else(|| vec![String::from("authorization_code"), String::from("implicit")])
    }

    /// Returns the client authentication methods of the token endpoint, the
    /// RFC 8414 §2 default `client_secret_basic` when the document names
    /// none.
    #[must_use]
    pub fn token_endpoint_auth_methods(&self) -> Vec<String> {
        self.token_endpoint_auth_methods_supported
            .clone()
            .unwrap_or_else(|| vec![String::from("client_secret_basic")])
    }
}

/// A failure to reach or read the authorization server's metadata.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// The HTTP engine could not be built.
    #[cfg(feature = "fetch")]
    #[error("the HTTP engine of the authorization server client could not be built")]
    Build {
        /// What `reqwest` reported.
        #[source]
        source: reqwest::Error,
    },
    /// The configured issuer is not a URL.
    #[error("the configured issuer is not a URL")]
    IssuerUrl {
        /// What the URL parser reported.
        #[source]
        source: url::ParseError,
    },
    /// The issuer, or a location the metadata names, is not an `https` URL
    /// without a query or a fragment (RFC 8414 §2, `OpenID` Connect
    /// Discovery 1.0 §3), on a host that is no loopback.
    #[error("{what} is not an https URL without a query or fragment: {url}")]
    Insecure {
        /// What the URL is: the issuer or the metadata member.
        what: &'static str,
        /// The URL.
        url: String,
    },
    /// A request to the authorization server never completed, its timeout
    /// included.
    #[cfg(feature = "fetch")]
    #[error("the request to {url} could not be completed")]
    Transport {
        /// The URL that was called.
        url: Url,
        /// What `reqwest` reported.
        #[source]
        source: reqwest::Error,
    },
    /// The answer of the authorization server is larger than
    /// [`MAX_DOCUMENT_BYTES`].
    #[error("the answer of {url} is larger than {MAX_DOCUMENT_BYTES} bytes")]
    TooLarge {
        /// The URL that was called.
        url: Url,
    },
    /// No metadata document answered at either discovery location.
    #[error("the authorization server metadata at {url} answered {status}")]
    Status {
        /// The last location tried.
        url: Url,
        /// The status it answered.
        status: StatusCode,
        /// The body it answered, as received.
        body: String,
    },
    /// The metadata is not the JSON object RFC 8414 §3.2 describes.
    #[error("the authorization server metadata at {url} is not a metadata document")]
    Metadata {
        /// The location that answered it.
        url: Url,
        /// What the JSON reader reported.
        #[source]
        source: serde_json::Error,
    },
    /// The metadata names another issuer, which RFC 8414 §3.3 requires a
    /// client to refuse.
    #[error("the authorization server metadata names issuer {found:?}, not {expected:?}")]
    IssuerMismatch {
        /// The configured issuer.
        expected: String,
        /// The issuer the metadata named.
        found: String,
    },
}

/// Returns `issuer` as the URL RFC 8414 §2 describes: `https`, no query, no
/// fragment.
///
/// A loopback host (`localhost`, `127.0.0.1`, `::1`) may be plain `http`,
/// because a test issuer is one and its transport cannot be observed (no
/// specification governs the exception: our own design).
///
/// # Errors
///
/// Returns [`DiscoveryError::IssuerUrl`] for text that is no URL and
/// [`DiscoveryError::Insecure`] for a URL outside the rule.
pub fn issuer_url(issuer: &str) -> Result<Url, DiscoveryError> {
    let url: Url = issuer
        .parse()
        .map_err(|source| DiscoveryError::IssuerUrl { source })?;
    secure(&url, "the issuer")?;
    Ok(url)
}

/// Checks that `url` is `https` without a query or a fragment, or plain
/// `http` on a loopback host.
///
/// # Errors
///
/// Returns [`DiscoveryError::Insecure`] naming `what` otherwise.
pub fn secure(url: &Url, what: &'static str) -> Result<(), DiscoveryError> {
    let loopback = matches!(
        url.host(),
        Some(
            url::Host::Domain("localhost")
                | url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST)
                | url::Host::Ipv6(std::net::Ipv6Addr::LOCALHOST)
        )
    );
    let scheme_ok = url.scheme() == "https" || (loopback && url.scheme() == "http");
    if !scheme_ok || url.query().is_some() || url.fragment().is_some() {
        return Err(DiscoveryError::Insecure {
            what,
            url: url.to_string(),
        });
    }
    Ok(())
}

/// Returns the two metadata locations of `issuer`, the RFC 8414 one first.
///
/// RFC 8414 §3.1 inserts the suffix between the host and the path, after
/// removing a terminating `/`; `OpenID` Connect Discovery 1.0 §4 appends it to
/// the issuer, after removing a terminating `/`.
#[must_use]
pub fn locations(issuer: &Url) -> [Url; 2] {
    let path = issuer.path().trim_end_matches('/');
    let mut oauth = issuer.clone();
    oauth.set_path(&format!("{OAUTH_METADATA}{path}"));
    let mut openid = issuer.clone();
    openid.set_path(&format!("{path}{OPENID_CONFIGURATION}"));
    [oauth, openid]
}

/// The HTTP engine the authorization server is called through, behind the
/// `fetch` feature.
///
/// It follows no redirect: a metadata document, a key set or a token request
/// answered with a redirect is refused as the status it is, so a credential
/// never travels to a host the configuration did not name (no specification
/// governs this: our own design).
#[cfg(feature = "fetch")]
#[derive(Debug, Clone)]
pub struct Http {
    /// The engine.
    client: reqwest::Client,
}

#[cfg(feature = "fetch")]
impl Http {
    /// Returns an engine whose calls each take at most `timeout`.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::Build`] when the engine cannot be built.
    pub fn new(timeout: Duration) -> Result<Self, DiscoveryError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|source| DiscoveryError::Build { source })?;
        Ok(Self { client })
    }

    /// Returns the underlying engine, for the token request.
    pub(crate) const fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Returns the metadata of `issuer`.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::IssuerUrl`] or [`DiscoveryError::Insecure`]
    /// for an issuer outside the URL rule, [`DiscoveryError::Transport`]
    /// when neither location answers, [`DiscoveryError::Status`] when the
    /// last location tried answers anything but `200`,
    /// [`DiscoveryError::Metadata`] for a body that is no metadata document,
    /// and [`DiscoveryError::IssuerMismatch`] when the document names another
    /// issuer.
    pub async fn discover(&self, issuer: &str) -> Result<ServerMetadata, DiscoveryError> {
        let parsed = issuer_url(issuer)?;
        let [oauth, openid] = locations(&parsed);
        let (url, status, body) = match self.get(oauth).await? {
            (url, status, _) if status == StatusCode::NOT_FOUND => {
                tracing::debug!(%url, "no RFC 8414 metadata; reading the OpenID Connect location");
                self.get(openid).await?
            }
            answered => answered,
        };
        if status != StatusCode::OK {
            return Err(DiscoveryError::Status { url, status, body });
        }
        let metadata: ServerMetadata = serde_json::from_str(&body)
            .map_err(|source| DiscoveryError::Metadata { url, source })?;
        if metadata.issuer != issuer {
            return Err(DiscoveryError::IssuerMismatch {
                expected: issuer.to_owned(),
                found: metadata.issuer,
            });
        }
        Ok(metadata)
    }

    /// Returns the status and body `url` answers a `GET` with, the body
    /// capped at [`MAX_DOCUMENT_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::Transport`] when the call never completes
    /// and [`DiscoveryError::TooLarge`] when the body passes the cap.
    pub async fn get(&self, url: Url) -> Result<(Url, StatusCode, String), DiscoveryError> {
        let mut response = self
            .client
            .get(url.clone())
            .header(http::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|source| DiscoveryError::Transport {
                url: url.clone(),
                source,
            })?;
        let status = response.status();
        let mut bytes = Vec::new();
        loop {
            let chunk = response
                .chunk()
                .await
                .map_err(|source| DiscoveryError::Transport {
                    url: url.clone(),
                    source,
                })?;
            let Some(chunk) = chunk else { break };
            if bytes.len().saturating_add(chunk.len()) > MAX_DOCUMENT_BYTES {
                return Err(DiscoveryError::TooLarge { url });
            }
            bytes.extend_from_slice(&chunk);
        }
        let body = String::from_utf8_lossy(&bytes).into_owned();
        Ok((url, status, body))
    }
}

#[cfg(test)]
mod tests {
    use super::{DiscoveryError, issuer_url, locations};
    use url::Url;

    #[test]
    fn rfc_8414_inserts_the_suffix_and_openid_connect_appends_it() {
        let issuer: Url = "https://as.example.org/realms/ferro/"
            .parse()
            .expect("a valid URL");
        let [oauth, openid] = locations(&issuer);
        assert_eq!(
            "https://as.example.org/.well-known/oauth-authorization-server/realms/ferro",
            oauth.as_str()
        );
        assert_eq!(
            "https://as.example.org/realms/ferro/.well-known/openid-configuration",
            openid.as_str()
        );
    }

    #[test]
    fn an_issuer_without_a_path_reads_the_bare_suffixes() {
        let issuer: Url = "https://as.example.org".parse().expect("a valid URL");
        let [oauth, openid] = locations(&issuer);
        assert_eq!(
            "https://as.example.org/.well-known/oauth-authorization-server",
            oauth.as_str()
        );
        assert_eq!(
            "https://as.example.org/.well-known/openid-configuration",
            openid.as_str()
        );
    }

    #[test]
    fn an_issuer_is_https_without_query_or_fragment_and_loopback_may_be_http() {
        assert!(issuer_url("https://as.example.org/realms/ferro").is_ok());
        assert!(issuer_url("http://localhost:8080/realm").is_ok());
        assert!(issuer_url("http://127.0.0.1:8080").is_ok());
        assert!(issuer_url("http://[::1]:8080").is_ok());
        for bad in [
            "http://as.example.org",
            "https://as.example.org/?x=1",
            "https://as.example.org/#frag",
        ] {
            assert!(
                matches!(issuer_url(bad), Err(DiscoveryError::Insecure { .. })),
                "{bad}"
            );
        }
        assert!(matches!(
            issuer_url("not a url"),
            Err(DiscoveryError::IssuerUrl { .. })
        ));
    }
}
