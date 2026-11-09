// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `idp-entra` adapter: the groups of a Microsoft Entra ID token whose
//! group claim was replaced by the groups overage claim, read from Microsoft
//! Graph.
//!
//! Above its limit ("150 for SAML tokens, 200 for JWT tokens") Entra ID
//! leaves the `groups` claim out and puts `_claim_names` and
//! `_claim_sources`, or `hasgroups`, in its place (Microsoft, "Access token
//! claims reference", §Groups overage claim). The URL in `_claim_sources` is
//! "an Azure AD Graph URL", and the same section tells a service to "use the
//! `idtyp` optional claim ... to construct a Microsoft Graph URL" instead.
//! So [`GraphAdapter`] never reads `_claim_sources`: it builds
//! `{base_url}/users/{oid}/getMemberObjects` for a user token and
//! `{base_url}/servicePrincipals/{oid}/getMemberObjects` for an app-only one,
//! from the configured base and the token's `oid` and `idtyp`, and sends the
//! `POST` the Microsoft Graph v1.0 reference `directoryObject:
//! getMemberObjects` describes under a client-credentials token of
//! [`TokenSource`].
//!
//! Each call answers one request: nothing is cached. The call has its own
//! budget, `timeout` (`2s` by default), which bounds the token fetch and the
//! Graph round trip together and lies outside a product's lookup budget, and
//! the answer is read up to `max_response_size`. A refusal is
//! [`AdapterError::Status`] with the status, a redacted excerpt of the error
//! body ([`BodyExcerpt`]) and, on a `429`, the
//! `Retry-After`; a call past the budget is [`AdapterError::Timeout`]; an
//! answer that does not read, or a token that cannot be obtained, is
//! [`AdapterError::Unreadable`]. Every user above the overage limit costs one
//! Graph round trip per request and draws on the application's Graph
//! throttling allowance. No specification governs the bounds: our own
//! design.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use http::HeaderMap;
use http::StatusCode;
use http::header;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use url::Url;

use crate::client::CallError;
use crate::client::TokenError;
use crate::client::cache::TokenSource;
use crate::config::ConfigError;
use crate::config::credentials::OauthSection;
use crate::metadata::DiscoveryError;
use crate::metadata::Http;
use crate::party::adapter::AdapterError;
use crate::party::adapter::BodyExcerpt;
use crate::party::adapter::IdpAdapter;
use crate::resource::Caller;

/// The adapter's name, which a profile's `adapter` names and the party
/// binding registers it under.
pub const NAME: &str = "idp-entra";

/// The Graph access of the adapter, a table a product embeds where its
/// configuration keeps the party binding.
///
/// ```toml
/// base_url = "https://graph.microsoft.com/v1.0"
/// timeout = "2s"
/// max_response_size = "1MiB"
/// security_enabled_only = false
///
/// [credentials]
/// issuer = "https://login.microsoftonline.com/{tenant}/v2.0"
/// client_id = "ferro-graph-reader"
/// client_secret_file = "/run/secrets/graph-client-secret"
/// scope = "https://graph.microsoft.com/.default"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GraphSection {
    /// The Microsoft Graph root every URL is built from, `https` without a
    /// query or a fragment.
    pub base_url: String,
    /// The adapter's budget for one call, the token fetch and the Graph round
    /// trip together; never zero.
    pub timeout: ferrohealth_config::units::Duration,
    /// The largest Graph answer read; never zero.
    pub max_response_size: ferrohealth_config::units::ByteSize,
    /// The `securityEnabledOnly` parameter of `getMemberObjects`: `false`
    /// reads every group, administrative unit and directory role, `true`
    /// only the security groups.
    pub security_enabled_only: bool,
    /// The client credentials grant the Graph token is obtained with, under
    /// the Graph permission the deployment grants.
    pub credentials: OauthSection,
    /// Removed: `timeout`, a duration.
    #[serde(skip_serializing)]
    pub timeout_ms: ferrohealth_config::removed::Removed,
    /// Removed: `max_response_size`, a size.
    #[serde(skip_serializing)]
    pub max_response_bytes: ferrohealth_config::removed::Removed,
}

impl Default for GraphSection {
    fn default() -> Self {
        Self {
            base_url: String::from("https://graph.microsoft.com/v1.0"),
            timeout: ferrohealth_config::units::Duration::from_secs(2),
            max_response_size: ferrohealth_config::units::ByteSize::from_mib(1),
            security_enabled_only: false,
            credentials: OauthSection::default(),
            timeout_ms: ferrohealth_config::removed::Removed::default(),
            max_response_bytes: ferrohealth_config::removed::Removed::default(),
        }
    }
}

/// A Graph access table that breaks a rule.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GraphError {
    /// `base_url` does not parse.
    #[error("graph.base_url does not parse")]
    BaseUrl {
        /// What the parser reported.
        #[source]
        source: url::ParseError,
    },
    /// `base_url` is no `https` URL without a query or a fragment.
    #[error("graph.base_url is refused")]
    Insecure {
        /// The rule it breaks.
        #[source]
        source: DiscoveryError,
    },
    /// A bound is zero.
    #[error("graph.{key} is zero")]
    Zero {
        /// The key.
        key: &'static str,
    },
    /// The `credentials` table breaks a rule.
    #[error("graph.credentials is refused")]
    Credentials {
        /// The rule it breaks.
        #[source]
        source: ConfigError,
    },
    /// The token source cannot be built.
    #[error("the Graph token source cannot be built")]
    Token {
        /// Why.
        #[source]
        source: TokenError,
    },
    /// The HTTP engine cannot be built.
    #[error("the Graph HTTP engine cannot be built")]
    Http {
        /// Why.
        #[source]
        source: DiscoveryError,
    },
}

/// Why a Graph answer does not read, the source of an
/// [`AdapterError::Unreadable`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReadError {
    /// The answer passes `max_response_bytes`.
    #[error("the Graph answer is larger than {limit} bytes")]
    TooLarge {
        /// The bound.
        limit: usize,
    },
    /// The answer is no `getMemberObjects` collection of strings, or repeats
    /// a member name (RFC 8259 §4).
    #[error("the Graph answer is no collection of strings")]
    Collection {
        /// What the reader reported.
        #[source]
        source: crate::json::JsonError,
    },
    /// The answer names a next page, so it is not the whole membership.
    #[error("the Graph answer is paged, and one page is not the whole membership")]
    Paged,
}

/// The answer of `getMemberObjects`: "String collection" in `value`.
#[derive(Deserialize)]
struct Members {
    /// The identifiers.
    value: Vec<String>,
    /// The next page, which the reference never describes for this action.
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<Value>,
}

/// The `idp-entra` adapter, registered with the party binding under
/// [`NAME`].
#[derive(Debug)]
pub struct GraphAdapter {
    /// The Graph root.
    base: Url,
    /// The client-credentials token for Graph.
    tokens: TokenSource,
    /// The engine Graph is called through.
    http: Http,
    /// The budget of one call.
    timeout: Duration,
    /// The largest answer read.
    max_response_bytes: usize,
    /// The request body.
    body: &'static [u8],
}

impl GraphSection {
    /// Returns the adapter this table describes, with its token source.
    ///
    /// Nothing is fetched until the first overage.
    ///
    /// # Errors
    ///
    /// The [`GraphError`] naming the rule broken: a `base_url` that does not
    /// parse or is not `https`, a zero bound, a `credentials` table
    /// [`OauthSection::resolve`] refuses, or an engine that cannot be built.
    pub fn adapter(&self) -> Result<GraphAdapter, GraphError> {
        let base: Url = self
            .base_url
            .parse()
            .map_err(|source| GraphError::BaseUrl { source })?;
        crate::metadata::secure(&base, "graph.base_url")
            .map_err(|source| GraphError::Insecure { source })?;
        if base.cannot_be_a_base() {
            return Err(GraphError::Insecure {
                source: DiscoveryError::Insecure {
                    what: "graph.base_url",
                    url: base.to_string(),
                },
            });
        }
        let mut removals = self.credentials.removals("graph.credentials");
        removals.replaced(
            self.timeout_ms,
            "graph.timeout_ms",
            "graph.timeout, a duration such as `2s`",
        );
        removals.replaced(
            self.max_response_bytes,
            "graph.max_response_bytes",
            "graph.max_response_size, a size such as `1MiB`",
        );
        removals
            .finish()
            .map_err(|source| GraphError::Credentials {
                source: ConfigError::RemovedKeys(source),
            })?;
        // NOTE: no specification governs this: our own design; a bound past the address
        // space bounds nothing more than the address space does, so it saturates.
        let max_response_bytes = usize::try_from(self.max_response_size).unwrap_or(usize::MAX);
        for (key, zero) in [
            ("timeout", self.timeout.is_zero()),
            ("max_response_size", max_response_bytes == 0),
        ] {
            if zero {
                return Err(GraphError::Zero { key });
            }
        }
        let grant = self
            .credentials
            .resolve()
            .map_err(|source| GraphError::Credentials { source })?;
        let tokens = TokenSource::new(grant).map_err(|source| GraphError::Token { source })?;
        let timeout = self.timeout.get();
        let http = Http::new(timeout).map_err(|source| GraphError::Http { source })?;
        Ok(GraphAdapter {
            base,
            tokens,
            http,
            timeout,
            max_response_bytes,
            body: if self.security_enabled_only {
                br#"{"securityEnabledOnly":true}"#
            } else {
                br#"{"securityEnabledOnly":false}"#
            },
        })
    }
}

impl GraphAdapter {
    /// Returns the `getMemberObjects` URL of `caller`, built from the Graph
    /// root and the token's `oid` and `idtyp`, never from `_claim_sources`.
    fn url(&self, caller: &Caller) -> Result<Url, AdapterError> {
        let claim = |claim: &str| AdapterError::Claim {
            claim: claim.to_owned(),
        };
        // NOTE: Microsoft, "Access token claims reference", `oid`: "String, a GUID", which
        // "can be used when making queries to Microsoft online services, such as the Microsoft Graph".
        let oid = caller
            .claim("oid")
            .and_then(Value::as_str)
            .filter(|oid| is_guid(oid))
            .ok_or_else(|| claim("oid"))?;
        // NOTE: Microsoft, "Optional claims reference", `idtyp`: `app` for an app-only token and
        // emitted for a user token only with `include_user_token`, so its absence is a user.
        let collection = match caller.claim("idtyp") {
            None => "users",
            Some(Value::String(kind)) if kind == "user" => "users",
            Some(Value::String(kind)) if kind == "app" => "servicePrincipals",
            Some(_) => return Err(claim("idtyp")),
        };
        let mut url = self.base.clone();
        {
            #[expect(
                clippy::expect_used,
                reason = "GraphSection::adapter refuses a base_url that cannot be a base"
            )]
            let mut segments = url
                .path_segments_mut()
                .expect("the Graph root should be a base URL");
            segments
                .pop_if_empty()
                .extend([collection, oid, "getMemberObjects"]);
        }
        Ok(url)
    }

    /// Returns the identifiers Graph answers `url` with for `caller`, under the
    /// Graph token, renewed once on a `401`.
    async fn member_objects(&self, url: Url, caller: &Caller) -> Result<Vec<String>, AdapterError> {
        let answered = self
            .tokens
            .send(&http::Method::POST, &url, |attempt| {
                let mut request = self
                    .http
                    .client()
                    .post(url.clone())
                    .header(header::AUTHORIZATION, attempt.authorization().clone())
                    .header(header::ACCEPT, "application/json")
                    .header(header::CONTENT_TYPE, "application/json");
                if let Some(proof) = attempt.proof() {
                    request = request.header(crate::client::dpop::HEADER, proof.clone());
                }
                request.body(self.body).send()
            })
            .await;
        let mut response = match answered {
            Ok(response) => response,
            Err(CallError::Token { source }) => {
                return Err(AdapterError::Unreadable { source });
            }
            Err(CallError::Renewal(renewal)) => {
                return Err(AdapterError::Unreadable {
                    source: Arc::new(renewal),
                });
            }
            Err(CallError::Call { source }) => return Err(self.transport(source)),
            Err(error @ (CallError::Proof { .. } | CallError::Unproven)) => {
                return Err(AdapterError::Unreadable {
                    source: Arc::new(error),
                });
            }
        };
        let status = response.status();
        tracing::debug!(%status, "Microsoft Graph answered getMemberObjects");
        // NOTE: Microsoft Graph v1.0, `directoryObject: getMemberObjects`: "If successful, this
        // method returns `200 OK`"; every other status is the refusal it is.
        if status != StatusCode::OK {
            let retry_after = retry_after(response.headers());
            // NOTE: no specification governs this: our own design; an error body that cannot be
            // read leaves the refusal its status, so the excerpt is absent, never the failure.
            let body = self
                .body(&mut response)
                .await
                .ok()
                .and_then(|bytes| BodyExcerpt::new(&bytes, caller));
            return Err(AdapterError::Status {
                status,
                retry_after,
                body,
            });
        }
        let bytes = self.body(&mut response).await?;
        read(&bytes)
    }

    /// Returns the body of `response`, read up to `max_response_bytes`.
    async fn body(&self, response: &mut reqwest::Response) -> Result<Vec<u8>, AdapterError> {
        let mut bytes = Vec::new();
        loop {
            let chunk = match response.chunk().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(source) => return Err(self.transport(source)),
            };
            if bytes.len().saturating_add(chunk.len()) > self.max_response_bytes {
                return Err(unreadable(ReadError::TooLarge {
                    limit: self.max_response_bytes,
                }));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    /// Returns the outcome of a transport failure: the timeout it reports,
    /// or an unreadable answer.
    fn transport(&self, source: reqwest::Error) -> AdapterError {
        if source.is_timeout() {
            AdapterError::Timeout {
                timeout: self.timeout,
            }
        } else {
            AdapterError::Unreadable {
                source: Arc::new(source),
            }
        }
    }
}

impl IdpAdapter for GraphAdapter {
    fn resolve_groups<'a>(
        &'a self,
        caller: &'a Caller,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, AdapterError>> + Send + 'a>> {
        Box::pin(async move {
            let url = self.url(caller)?;
            match tokio::time::timeout(self.timeout, self.member_objects(url, caller)).await {
                Ok(answer) => answer,
                Err(_elapsed) => Err(AdapterError::Timeout {
                    timeout: self.timeout,
                }),
            }
        })
    }
}

/// Returns the identifiers of a `getMemberObjects` answer.
fn read(bytes: &[u8]) -> Result<Vec<String>, AdapterError> {
    crate::metadata::repeats_no_name(bytes)
        .map_err(|source| unreadable(ReadError::Collection { source }))?;
    let members: Members = serde_json::from_slice(bytes).map_err(|source| {
        unreadable(ReadError::Collection {
            source: source.into(),
        })
    })?;
    // NOTE: the `getMemberObjects` reference describes no paging, so an answer naming a next
    // page is refused rather than read as the whole membership (our own design).
    if members.next_link.is_some() {
        return Err(unreadable(ReadError::Paged));
    }
    Ok(members.value)
}

/// Returns the unreadable outcome `error` causes.
fn unreadable(error: ReadError) -> AdapterError {
    AdapterError::Unreadable {
        source: Arc::new(error),
    }
}

/// Returns the delay a throttled answer names.
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    // NOTE: Microsoft, "Microsoft Graph throttling guidance": "Wait the number of seconds
    // specified in the `Retry-After` header"; a value in another form names no delay.
    let seconds = headers.get(header::RETRY_AFTER)?.to_str().ok()?;
    seconds.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// Returns whether `text` is a GUID in its 8-4-4-4-12 hexadecimal form.
fn is_guid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests {
    /// A Graph answer refusal renders no part of the answer.
    #[test]
    fn a_graph_refusal_hides_the_answer() {
        use crate::json::leak::{hidden, refused};
        hidden(&ReadError::Collection { source: refused() });
    }

    use super::*;

    #[test]
    fn a_guid_is_its_8_4_4_4_12_form_only() {
        assert!(is_guid("5ba552d6-7c3e-4a1f-9d2b-0e8f6a7b1c2d"));
        assert!(is_guid("5BA552D6-7C3E-4A1F-9D2B-0E8F6A7B1C2D"));
        for refused in [
            "",
            "5ba552d6",
            "5ba552d6-7c3e-4a1f-9d2b-0e8f6a7b1c2d0",
            "5ba552d6/7c3e-4a1f-9d2b-0e8f6a7b1c2d",
            "5ba552d6-7c3e-4a1f-9d2b-0e8f6a7b1c2g",
            "../../../me/getMemberObjects-00000000",
        ] {
            assert!(!is_guid(refused), "{refused}");
        }
    }

    // NOTE: Microsoft, "Microsoft Graph throttling guidance": the `429` sample carries
    // `Retry-After: 10`, a number of seconds.
    #[test]
    fn retry_after_reads_seconds_and_no_other_form() {
        let mut headers = HeaderMap::new();
        assert_eq!(None, retry_after(&headers));
        headers.insert(header::RETRY_AFTER, http::HeaderValue::from_static("10"));
        assert_eq!(Some(Duration::from_secs(10)), retry_after(&headers));
        headers.insert(
            header::RETRY_AFTER,
            http::HeaderValue::from_static("Wed, 21 Oct 2026 07:28:00 GMT"),
        );
        assert_eq!(None, retry_after(&headers));
    }

    // NOTE: Microsoft Graph v1.0, `directoryObject: getMemberObjects`: a "String collection"
    // in `value`, beside `@odata.context`.
    #[test]
    fn an_answer_reads_as_its_value_and_a_next_page_is_refused() {
        let answer = br#"{"@odata.context":"x","value":["a","b"]}"#;
        assert_eq!(
            vec![String::from("a"), String::from("b")],
            read(answer).expect("a collection")
        );
        for refused in [
            &br#"{"value":["a"],"@odata.nextLink":"https://graph.invalid/next"}"#[..],
            br#"{"value":["a"],"value":["b"]}"#,
            br#"{"value":[1]}"#,
            br#"{"values":["a"]}"#,
            b"not json",
        ] {
            assert!(
                matches!(read(refused), Err(AdapterError::Unreadable { .. })),
                "{}",
                String::from_utf8_lossy(refused)
            );
        }
    }
}
