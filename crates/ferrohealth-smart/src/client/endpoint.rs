// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The two calls to the authorization server: the metadata read that finds
//! the token endpoint, and the client credentials token request.

use http::StatusCode;
use secrecy::ExposeSecret;
use serde::Deserialize;
use url::Url;

use crate::client::ClientAuth;
use crate::client::ClientCredentials;
use crate::client::OAuthError;
use crate::client::TokenError;
use crate::client::assertion::ASSERTION_TYPE;
use crate::metadata::DiscoveryError;
use crate::metadata::Http;

/// The members of an access token response the product reads (RFC 6749
/// §5.1).
#[derive(Deserialize)]
pub(super) struct TokenResponse {
    /// The access token.
    pub(super) access_token: String,
    /// The token type, compared case-insensitively.
    pub(super) token_type: String,
    /// The lifetime of the token in seconds, when the server sent one.
    pub(super) expires_in: Option<u64>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// Returns the token endpoint the metadata of `issuer` names.
pub(super) async fn discover(http: &Http, issuer: &str) -> Result<Url, TokenError> {
    let metadata = http.discover(issuer).await?;
    metadata
        .token_endpoint
        .as_deref()
        .ok_or(TokenError::NoTokenEndpoint)?
        .parse()
        .map_err(|source| TokenError::TokenEndpointUrl { source })
}

/// Returns the access token response `endpoint` answers the client
/// credentials grant of `config` with (RFC 6749 §4.4.2 and §4.4.3).
pub(super) async fn request_token(
    http: &Http,
    endpoint: &Url,
    config: &ClientCredentials,
) -> Result<TokenResponse, TokenError> {
    config.validate()?;
    let mut request = http
        .client()
        .post(endpoint.clone())
        .header(http::header::ACCEPT, "application/json");
    if config.client_auth == ClientAuth::ClientSecretBasic
        && let Some(secret) = &config.client_secret
    {
        // NOTE: RFC 6749 §2.3.1 form-encodes the id and the secret
        // (Appendix B) before they become the RFC 7617 user-pass.
        let user: String =
            url::form_urlencoded::byte_serialize(config.client_id.as_bytes()).collect();
        let password: String =
            url::form_urlencoded::byte_serialize(secret.expose_secret().as_bytes()).collect();
        request = request.basic_auth(user, Some(password));
    }
    let response = request
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(token_request_body(config, endpoint)?)
        .send()
        .await
        .map_err(|source| DiscoveryError::Transport {
            url: endpoint.clone(),
            source,
        })?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|source| DiscoveryError::Transport {
            url: endpoint.clone(),
            source,
        })?;
    if status != StatusCode::OK {
        // NOTE: RFC 6749 §5.2 makes the error body JSON with `error`; a body
        // that is not one is legitimately absent, and the raw body stays.
        let error = serde_json::from_str::<OAuthError>(&body).ok();
        return Err(TokenError::Refused {
            status,
            error,
            body,
        });
    }
    serde_json::from_str(&body).map_err(|source| TokenError::Malformed { source })
}

/// Returns the form-encoded body of the token request of `config`
/// (RFC 6749 §4.4.2): the client's id and secret under
/// `client_secret_post`, or the assertion under `private_key_jwt`
/// (RFC 7523 §2.2).
fn token_request_body(config: &ClientCredentials, endpoint: &Url) -> Result<String, TokenError> {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("grant_type", "client_credentials");
    if let Some(scope) = config.scope.as_deref() {
        form.append_pair("scope", scope);
    }
    if let Some(audience) = config.audience.as_deref() {
        form.append_pair("audience", audience);
    }
    if let Some(resource) = config.resource.as_ref() {
        form.append_pair("resource", resource.as_str());
    }
    match config.client_auth {
        ClientAuth::ClientSecretPost => {
            if let Some(secret) = &config.client_secret {
                form.append_pair("client_id", &config.client_id);
                form.append_pair("client_secret", secret.expose_secret());
            }
        }
        ClientAuth::PrivateKeyJwt => {
            if let Some(key) = &config.assertion_key {
                let assertion = key
                    .assertion(&config.client_id, endpoint.as_str())
                    .map_err(|source| TokenError::Assertion { source })?;
                form.append_pair("client_assertion_type", ASSERTION_TYPE);
                form.append_pair("client_assertion", &assertion);
            }
        }
        ClientAuth::ClientSecretBasic => {}
    }
    Ok(form.finish())
}
