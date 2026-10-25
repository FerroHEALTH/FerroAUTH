// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A remote policy decision point (feature `remote`), in the NIST SP 800-162
//! sense of a PDP the PEP consults over the network.
//!
//! Each resource type is bound to one policy of the remote point. For each
//! combination the engine posts `{server}{policy}` with a flat JSON object
//! of the attributes the binding names, read from the combination's resource
//! attributes and then from the subject's: a `200` permits, any `4xx` denies,
//! and the body of the answer is not read, so the point imposes no policy
//! language. Any other answer, a redirect included, and any failure to reach
//! the point is no decision: an [`AuthzError::Remote`] carrying the status
//! when there was one. Under a client credentials grant the call carries the
//! token of `ferrohealth-smart`, sent once more under a new token on a
//! `401`; a second `401` is no decision either. The wire contract is our
//! own design; no specification governs it.

use std::collections::BTreeMap;
use std::time::Duration;

use ferrohealth_smart::client::cache::TokenSource;
use http::StatusCode;
use url::Url;

use crate::engine::AuthzError;
use crate::engine::PolicyEngine;
use crate::request::Combination;
use crate::request::Decision;
use crate::request::Request;

/// The policy one resource type is decided by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The policy's path under the server.
    pub policy: String,
    /// The attributes the posted object carries, when they have a value.
    pub parameters: Vec<String>,
}

/// How the remote point is reached.
#[derive(Debug, Clone)]
pub struct RemoteSettings {
    /// The base URL; it ends with `/`, and every policy path joins it.
    pub server: Url,
    /// The policy of each resource type.
    pub bindings: BTreeMap<String, Binding>,
    /// How long establishing the connection may take.
    pub connect_timeout: Duration,
    /// How long one call may take.
    pub request_timeout: Duration,
}

/// Why a remote point gave no decision.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RemoteError {
    /// The settings do not hold.
    #[error("the remote policy point settings are refused: {reason}")]
    Settings {
        /// Which rule is broken.
        reason: &'static str,
    },
    /// No policy is bound to the request's resource type.
    #[error("no remote policy is bound to the resource type {resource_type}")]
    Unbound {
        /// The resource type.
        resource_type: String,
    },
    /// The call failed before an answer.
    #[error("the remote policy point could not be reached")]
    Transport(#[source] reqwest::Error),
    /// No token could be obtained for the call.
    #[error("no token for the remote policy point could be obtained")]
    Token(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The point answered a status that is no decision.
    #[error("the remote policy point answered {status}, which is no decision")]
    Status {
        /// The status.
        status: StatusCode,
    },
}

/// The remote policy decision point.
#[derive(Debug)]
pub struct RemotePdp {
    client: reqwest::Client,
    settings: RemoteSettings,
    token: Option<TokenSource>,
}

impl RemotePdp {
    /// Returns the point `settings` describe, authorized by `token` when
    /// given; without one, credentials in the server URL travel as HTTP
    /// Basic, as the HTTP client sends them.
    ///
    /// # Errors
    ///
    /// [`AuthzError::Remote`] when the server URL is not `http` or `https`
    /// or does not end with `/`, or the HTTP client cannot be built.
    pub fn new(settings: RemoteSettings, token: Option<TokenSource>) -> Result<Self, AuthzError> {
        if !matches!(settings.server.scheme(), "http" | "https") {
            return Err(remote(RemoteError::Settings {
                reason: "the server is not an http or https URL",
            }));
        }
        if !settings.server.path().ends_with('/') {
            return Err(remote(RemoteError::Settings {
                reason: "the server URL does not end with /",
            }));
        }
        let client = reqwest::Client::builder()
            .connect_timeout(settings.connect_timeout)
            .timeout(settings.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| remote(RemoteError::Transport(error)))?;
        Ok(Self {
            client,
            settings,
            token,
        })
    }

    /// Asks the point about one combination: `Ok(true)` permits.
    async fn permits(
        &self,
        binding: &Binding,
        request: &Request<'_>,
        combination: &Combination<'_>,
    ) -> Result<bool, AuthzError> {
        let url = self
            .settings
            .server
            .join(&binding.policy)
            .map_err(|_unjoinable| {
                remote(RemoteError::Settings {
                    reason: "a policy path does not join the server URL",
                })
            })?;
        let body = body(binding, request, combination);
        let send = |bearer: Option<http::HeaderValue>| {
            let mut call = self.client.post(url.clone()).json(&body);
            if let Some(bearer) = bearer {
                call = call.header(http::header::AUTHORIZATION, bearer);
            }
            call.send()
        };
        let response = match &self.token {
            None => send(None)
                .await
                .map_err(|error| remote(RemoteError::Transport(error)))?,
            Some(token) => {
                let response = token
                    .call(|bearer| send(Some(bearer)))
                    .await
                    .map_err(|error| remote(RemoteError::Token(Box::new(error))))?;
                if response.status() == StatusCode::UNAUTHORIZED {
                    return Err(remote(RemoteError::Status {
                        status: StatusCode::UNAUTHORIZED,
                    }));
                }
                response
            }
        };
        let status = response.status();
        if status == StatusCode::OK {
            Ok(true)
        } else if status.is_client_error() {
            Ok(false)
        } else {
            Err(remote(RemoteError::Status { status }))
        }
    }
}

#[async_trait::async_trait]
impl PolicyEngine for RemotePdp {
    async fn decide(&self, request: &Request<'_>) -> Result<Decision, AuthzError> {
        let binding = self
            .settings
            .bindings
            .get(request.resource_type())
            .ok_or_else(|| {
                remote(RemoteError::Unbound {
                    resource_type: request.resource_type().to_owned(),
                })
            })?;
        for combination in request.combinations() {
            if !self.permits(binding, request, &combination).await? {
                return Ok(Decision::Deny {
                    policies: vec![binding.policy.clone()],
                });
            }
        }
        Ok(Decision::Permit {
            policies: vec![binding.policy.clone()],
        })
    }
}

/// The posted object: each parameter with a value, from the combination
/// first and the subject's attributes after.
fn body(
    binding: &Binding,
    request: &Request<'_>,
    combination: &Combination<'_>,
) -> serde_json::Map<String, serde_json::Value> {
    binding
        .parameters
        .iter()
        .filter_map(|name| {
            combination
                .get(name.as_str())
                .copied()
                .or_else(|| request.subject().attributes().get(name).map(String::as_str))
                .map(|value| (name.clone(), serde_json::Value::String(value.to_owned())))
        })
        .collect()
}

/// Wraps a remote failure.
fn remote(error: RemoteError) -> AuthzError {
    AuthzError::Remote(Box::new(error))
}
