// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The two calls to the authorization server: the metadata read that finds
//! the token endpoint, and the client credentials token request.

use http::StatusCode;
use secrecy::ExposeSecret;
use serde::Deserialize;
use url::Url;

use crate::client::AssertionAudience;
use crate::client::ClientAuth;
use crate::client::ClientCredentials;
use crate::client::Endpoint;
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

/// Returns the token endpoint the metadata of `issuer` names, its mutual-TLS
/// alias in preference when the client presents a certificate.
pub(super) async fn discover(
    http: &Http,
    issuer: &str,
    mutual_tls: bool,
) -> Result<Url, TokenError> {
    let metadata = http.discover(issuer).await?;
    // NOTE: RFC 8705 §5, a client intending to do mutual TLS "MUST use the alias
    // URL of the endpoint within the `mtls_endpoint_aliases`, when present".
    let alias = metadata
        .mtls_endpoint_aliases
        .as_ref()
        .and_then(|aliases| aliases.token_endpoint.as_deref())
        .filter(|_alias| mutual_tls);
    alias
        .or(metadata.token_endpoint.as_deref())
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
    // NOTE: no specification governs this: our own design; the form encoder
    // is not `Sync`, so it is finished and dropped before the request awaits.
    let (request, body) = {
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
        let request = http
            .client()
            .post(endpoint.clone())
            .header(http::header::ACCEPT, "application/json");
        let request = authenticate(request, &mut form, config, endpoint)?;
        (request, form.finish())
    };
    let response = request
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
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

/// Returns `request`, posted to `endpoint`, authenticated as the client of
/// `config`: HTTP Basic under `client_secret_basic`, or `form` extended with
/// the client's id and secret under `client_secret_post`, the assertion
/// under `private_key_jwt` (RFC 7523 §2.2), or the `client_id` under mutual
/// TLS (RFC 8705 §2). The token request and the introspection request share
/// it (RFC 7662 §2.1 and §4 admit the token endpoint's client authentication).
///
/// The assertion's `aud` is `endpoint`, or the issuer identifier when the
/// grant names one and asks for it.
pub(crate) fn authenticate(
    mut request: reqwest::RequestBuilder,
    form: &mut url::form_urlencoded::Serializer<'_, String>,
    config: &ClientCredentials,
    endpoint: &Url,
) -> Result<reqwest::RequestBuilder, TokenError> {
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
    match config.client_auth {
        ClientAuth::ClientSecretPost => {
            if let Some(secret) = &config.client_secret {
                form.append_pair("client_id", &config.client_id);
                form.append_pair("client_secret", secret.expose_secret());
            }
        }
        ClientAuth::PrivateKeyJwt => {
            if let Some(key) = &config.assertion_key {
                let audience = match (config.assertion_audience, &config.endpoint) {
                    (AssertionAudience::Issuer, Endpoint::Issuer(issuer)) => issuer.as_str(),
                    (AssertionAudience::TokenEndpoint | AssertionAudience::Issuer, _) => {
                        endpoint.as_str()
                    }
                };
                let assertion = key
                    .assertion(&config.client_id, audience)
                    .map_err(|source| TokenError::Assertion { source })?;
                form.append_pair("client_assertion_type", ASSERTION_TYPE);
                form.append_pair("client_assertion", &assertion);
            }
        }
        // NOTE: RFC 8705 §2, "the client MUST include the `client_id`
        // parameter" with mutual-TLS client authentication.
        ClientAuth::TlsClientAuth | ClientAuth::SelfSignedTlsClientAuth => {
            form.append_pair("client_id", &config.client_id);
        }
        ClientAuth::ClientSecretBasic => {}
    }
    Ok(request)
}
