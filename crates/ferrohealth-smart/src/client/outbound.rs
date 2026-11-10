// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The client of one outbound integration, built from its
//! [`EndpointSection`]: the HTTP engine with the table's TLS, timeouts and
//! no redirects, the authorization its `credentials` name, and its `retry`.
//!
//! A product hands [`OutboundClient::http`] and
//! [`OutboundClient::authorization`] to a protocol client of its own, or
//! sends through [`OutboundClient::send`], which applies both and the retry
//! table. A call is tried again when the integration could not be reached,
//! the try timed out, or it answered a `5xx`; any other answer is the
//! caller's. No specification governs the seam or the retry rule: our own
//! design.

use http::Method;
use url::Url;

use crate::basic::Credential;
use crate::client::CallError;
use crate::client::ClientCredentials;
use crate::client::PresentedTls;
use crate::client::TokenError;
use crate::client::binding::TokenBinding;
use crate::client::cache::TokenSource;
use crate::client::dpop;
use crate::config::ConfigError;
use crate::config::TlsBuilder;
use crate::config::credentials::Outbound;
use crate::config::endpoint::EndpointSection;
use crate::config::endpoint::RetrySection;

/// What every request to the integration carries.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Authorization {
    /// HTTP Basic (RFC 7617).
    Basic(Credential),
    /// A client credentials token, renewed once when the integration answers
    /// `401` (RFC 6750 §3.1).
    Bearer(TokenSource),
}

/// Why an outbound client could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OutboundError {
    /// The endpoint table, its TLS or its credential is refused.
    #[error("the endpoint table {key} is refused")]
    Config {
        /// The endpoint table's dotted key.
        key: &'static str,
        /// The rule the table breaks.
        #[source]
        source: Box<ConfigError>,
    },
    /// The HTTP engine could not be built.
    #[error("the HTTP client of {key} could not be built")]
    Build {
        /// The endpoint table's dotted key.
        key: &'static str,
        /// What the engine reported.
        #[source]
        source: reqwest::Error,
    },
    /// The token source of the client credentials grant could not be built.
    #[error("the token source of {key} could not be built")]
    Token {
        /// The endpoint table's dotted key.
        key: &'static str,
        /// What the source reported.
        #[source]
        source: Box<TokenError>,
    },
    /// The grant binds its tokens to a client certificate the connection to
    /// the integration does not present, so the integration would refuse
    /// every token it is issued (RFC 8705 §3).
    #[error("the grant of {key} binds its tokens to a certificate the connection does not present")]
    CertificateBinding {
        /// The endpoint table's dotted key.
        key: &'static str,
    },
}

/// Where the grant of an outbound client takes its TLS from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantTls {
    /// The grant's own `oauth.tls` table only.
    Own,
    /// The grant's own `oauth.tls` table when it names material, the
    /// connection's TLS otherwise.
    Shared,
}

/// Why a call through [`OutboundClient::send`] got no answer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SendError {
    /// The integration could not be reached, or the last try timed out.
    #[error("the integration could not be reached")]
    Transport(#[source] reqwest::Error),
    /// No token could be obtained, or a refused token could not be renewed.
    #[error("no token for the integration could be obtained")]
    Token(#[source] CallError<reqwest::Error>),
}

/// The client of one outbound integration.
#[derive(Debug, Clone)]
pub struct OutboundClient {
    url: Url,
    http: reqwest::Client,
    authorization: Option<Authorization>,
    retry: RetrySection,
}

impl OutboundClient {
    /// Returns the client `endpoint` describes, its TLS built by `tls`.
    ///
    /// `key` is the table's dotted key (`terminology.endpoint`), which a
    /// refusal names. The engine bounds a whole call by `timeout` and opening
    /// the connection by `connect_timeout`, follows no redirect, and presents
    /// the TLS configuration `tls` builds from the table's `tls`. The
    /// `credentials` table resolves to [`Authorization::Basic`] or, under a
    /// client credentials grant, [`Authorization::Bearer`] over a token
    /// source whose own TLS `tls` builds too.
    ///
    /// # Errors
    ///
    /// [`OutboundError::Config`] when [`EndpointSection::validate`] or
    /// [`crate::config::credentials::CredentialsSection::resolve_with_tls`]
    /// refuses the table or `tls` refuses its TLS,
    /// [`OutboundError::Build`] when the engine cannot be built, and
    /// [`OutboundError::Token`] when the token source cannot be built.
    pub fn build(
        endpoint: &EndpointSection,
        key: &'static str,
        tls: &dyn TlsBuilder,
    ) -> Result<Self, OutboundError> {
        Self::assemble(endpoint, key, tls, GrantTls::Own)
    }

    /// Returns the client `endpoint` describes, as
    /// [`OutboundClient::build`] does, except that a client credentials
    /// grant whose `oauth.tls` names no material presents the TLS
    /// configuration built from the table's `tls`: the connection's trust
    /// roots and the client certificate it presents to the integration.
    ///
    /// A mutual-TLS `client_auth` then authenticates at the token endpoint
    /// with the certificate the connection presents (RFC 8705 §2), and a
    /// `certificate_bound` grant binds its tokens to it, the certificate
    /// the integration checks every token's `cnf` against (RFC 8705 §3). An
    /// `oauth.tls` that names material is built as [`OutboundClient::build`]
    /// builds it.
    ///
    /// # Errors
    ///
    /// As [`OutboundClient::build`], with
    /// [`crate::config::credentials::CredentialsSection::resolve_sharing_tls`]
    /// resolving the credential, and [`OutboundError::CertificateBinding`]
    /// when a `certificate_bound` grant presents another certificate than
    /// the connection, or the connection presents none.
    pub fn build_sharing_tls(
        endpoint: &EndpointSection,
        key: &'static str,
        tls: &dyn TlsBuilder,
    ) -> Result<Self, OutboundError> {
        Self::assemble(endpoint, key, tls, GrantTls::Shared)
    }

    /// Returns the client `endpoint` describes, its grant's TLS taken as
    /// `grant_tls` says.
    fn assemble(
        endpoint: &EndpointSection,
        key: &'static str,
        tls: &dyn TlsBuilder,
        grant_tls: GrantTls,
    ) -> Result<Self, OutboundError> {
        let refused = |source: ConfigError| OutboundError::Config {
            key,
            source: Box::new(source),
        };
        let url = endpoint.validate().map_err(refused)?;
        let presented = crate::config::build_tls(tls, key, &endpoint.tls).map_err(refused)?;
        let mut builder = reqwest::Client::builder()
            .timeout(endpoint.timeout.get())
            .redirect(reqwest::redirect::Policy::none())
            .tls_backend_preconfigured(rustls::ClientConfig::clone(presented.config()));
        if let Some(connect) = endpoint.connect_timeout {
            builder = builder.connect_timeout(connect.get());
        }
        let http = builder
            .build()
            .map_err(|source| OutboundError::Build { key, source })?;
        let credential = match grant_tls {
            GrantTls::Own => endpoint.credentials.resolve_with_tls(tls),
            GrantTls::Shared => endpoint.credentials.resolve_sharing_tls(tls, &presented),
        };
        let authorization = match credential.map_err(refused)? {
            None => None,
            Some(Outbound::Basic(credential)) => Some(Authorization::Basic(credential)),
            Some(Outbound::Oauth(grant)) => {
                if grant_tls == GrantTls::Shared && !binding_agrees(&grant, &presented) {
                    return Err(OutboundError::CertificateBinding { key });
                }
                Some(Authorization::Bearer(TokenSource::new(*grant).map_err(
                    |source| OutboundError::Token {
                        key,
                        source: Box::new(source),
                    },
                )?))
            }
        };
        Ok(Self {
            url,
            http,
            authorization,
            retry: endpoint.retry,
        })
    }

    /// Returns the integration's URL, as the table names it.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// Returns the HTTP engine.
    #[must_use]
    pub const fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// Returns what every request carries, when the table names a
    /// credential.
    #[must_use]
    pub const fn authorization(&self) -> Option<&Authorization> {
        self.authorization.as_ref()
    }

    /// Returns the retry table.
    #[must_use]
    pub const fn retry(&self) -> &RetrySection {
        &self.retry
    }

    /// Sends a `method` request to `url`, shaped by `prepare`, with the
    /// authorization, and tries it again as the retry table allows.
    ///
    /// A try that could not reach the integration, timed out, or was
    /// answered `5xx` is tried again after the next of
    /// [`RetrySection::delays`], so `prepare` builds a request that is safe
    /// to repeat. The last answer is returned whatever its status: a `5xx`
    /// after the last try included. A token the integration refuses is
    /// renewed once, as [`TokenSource::send`] does, with a `DPoP` proof for
    /// a bound token.
    ///
    /// # Errors
    ///
    /// [`SendError::Transport`] when the last try got no answer, and
    /// [`SendError::Token`] when no token could be obtained or a refused one
    /// renewed.
    pub async fn send<F>(
        &self,
        method: &Method,
        url: &Url,
        prepare: F,
    ) -> Result<reqwest::Response, SendError>
    where
        F: Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    {
        let mut delays = self.retry.delays();
        loop {
            let outcome = self.try_once(method, url, &prepare).await;
            let again = match &outcome {
                Ok(response) => response.status().is_server_error(),
                Err(SendError::Transport(_)) => true,
                Err(SendError::Token(_)) => false,
            };
            match delays.next() {
                Some(delay) if again => {
                    tracing::warn!(
                        delay_ms = delay.as_millis(),
                        "retrying a call to an outbound integration"
                    );
                    tokio::time::sleep(delay).await;
                }
                _ => return outcome,
            }
        }
    }

    /// Sends one try.
    async fn try_once<F>(
        &self,
        method: &Method,
        url: &Url,
        prepare: &F,
    ) -> Result<reqwest::Response, SendError>
    where
        F: Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    {
        let request = || prepare(self.http.request(method.clone(), url.clone()));
        match &self.authorization {
            None => request().send().await.map_err(SendError::Transport),
            Some(Authorization::Basic(credential)) => request()
                .header(http::header::AUTHORIZATION, credential.header_value())
                .send()
                .await
                .map_err(SendError::Transport),
            Some(Authorization::Bearer(source)) => source
                .send(method, url, |attempt| {
                    let mut call =
                        request().header(http::header::AUTHORIZATION, attempt.authorization());
                    if let Some(proof) = attempt.proof() {
                        call = call.header(dpop::HEADER, proof);
                    }
                    call.send()
                })
                .await
                .map_err(|error| match error {
                    CallError::Call { source } => SendError::Transport(source),
                    other => SendError::Token(other),
                }),
        }
    }
}

/// Returns whether `grant` binds its tokens to nothing, to a `DPoP` key, or
/// to the certificate `connection` presents.
fn binding_agrees(grant: &ClientCredentials, connection: &PresentedTls) -> bool {
    // NOTE: RFC 8705 §3, resource requests "MUST be made over a mutually
    // authenticated TLS connection using the same certificate" as the token endpoint.
    match grant.token_binding {
        Some(TokenBinding::Certificate) => {
            let granted = grant
                .tls
                .presented
                .as_ref()
                .and_then(PresentedTls::certificate);
            granted.is_some() && granted == connection.certificate()
        }
        _ => true,
    }
}
