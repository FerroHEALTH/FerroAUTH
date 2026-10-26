// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The OpenID Connect relying-party client against a stub provider: the code
//! exchange, a state or PKCE mismatch refused, the ID Token checks, the
//! refresh grant, revocation and the end-session URL.

use std::collections::BTreeMap;
use std::time::Duration;

use ferrohealth_secret::secret::Secret;
use ferrohealth_smart::metadata::Http;
use ferrohealth_smart::oidc::{
    Callback, OidcError, PendingSignIn, Provider, RelyingParty, TokenTypeHint, challenge,
};
use jsonwebtoken::{Algorithm, Header};
use secrecy::SecretString;
use url::Url;
use wiremock::matchers;
use wiremock::{Mock, ResponseTemplate};

use crate::support::{Issuer, JWKS_PATH, SigningKey, TOKEN_PATH, ec_key, mint_with, now};

/// The console's client id at the provider.
const CLIENT: &str = "synthetic-console";

/// The console's redirection endpoint.
const REDIRECT: &str = "https://console.example.org/auth/callback";

/// A provider with an end-session and a revocation endpoint, and the client
/// of a confidential console at it.
async fn provider(key: &SigningKey) -> (Issuer, RelyingParty) {
    let issuer = Issuer::bare().await;
    let uri = issuer.uri();
    issuer
        .mount_document(
            "/.well-known/oauth-authorization-server",
            serde_json::json!({
                "issuer": uri,
                "jwks_uri": format!("{uri}{JWKS_PATH}"),
                "authorization_endpoint": format!("{uri}/authorize?tenant=synthetic"),
                "token_endpoint": format!("{uri}{TOKEN_PATH}"),
                "end_session_endpoint": format!("{uri}/logout"),
                "revocation_endpoint": format!("{uri}/revoke"),
                "code_challenge_methods_supported": ["S256"]
            }),
        )
        .await;
    issuer.mount_keys(&[key], None).await;
    let http = Http::new(Duration::from_secs(5)).expect("the engine builds");
    let discovered = Provider::discover(&http, &uri)
        .await
        .expect("the provider is discovered");
    let client = RelyingParty::new(
        http,
        discovered,
        CLIENT,
        Url::parse(REDIRECT).expect("a URL"),
    )
    .with_client_secret(SecretString::from("synthetic-secret"))
    .with_scopes(["profile"])
    .with_post_logout_redirect_uri(Url::parse("https://console.example.org/").expect("a URL"));
    (issuer, client)
}

/// The query of `url`, by name.
fn query(url: &Url) -> BTreeMap<String, String> {
    url.query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

/// An ID Token for this client carrying `nonce`, signed by `key`.
fn id_token(issuer: &Issuer, key: &SigningKey, nonce: &str) -> String {
    let now = now();
    let mut header = Header::new(key.alg);
    header.kid = Some(key.kid.clone());
    mint_with(
        key,
        &header,
        &serde_json::json!({
            "iss": issuer.uri(),
            "aud": CLIENT,
            "azp": CLIENT,
            "sub": "synthetic-operator",
            "nonce": nonce,
            "iat": now,
            "exp": now + 300,
            "name": "  ",
            "preferred_username": "operator.one",
            "roles": ["mapping-admin"]
        }),
    )
}

/// Mounts the token endpoint answering the code exchange for `verifier`
/// with `id_token`, and `invalid_grant` for any other request.
async fn mount_exchange(issuer: &Issuer, verifier: &str, id_token: &str) {
    Mock::given(matchers::method("POST"))
        .and(matchers::path(TOKEN_PATH))
        .and(matchers::header(
            "authorization",
            "Basic c3ludGhldGljLWNvbnNvbGU6c3ludGhldGljLXNlY3JldA==",
        ))
        .and(matchers::body_string_contains(
            "grant_type=authorization_code",
        ))
        .and(matchers::body_string_contains("code=synthetic-code"))
        .and(matchers::body_string_contains(format!(
            "code_verifier={verifier}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "synthetic-access-1",
            "token_type": "Bearer",
            "expires_in": 300,
            "refresh_token": "synthetic-refresh-1",
            "id_token": id_token
        })))
        .with_priority(1)
        .mount(&issuer.server)
        .await;
    mount_invalid_grant(issuer).await;
}

/// Mounts the token endpoint's `invalid_grant` refusal (RFC 6749 §5.2).
async fn mount_invalid_grant(issuer: &Issuer) {
    Mock::given(matchers::method("POST"))
        .and(matchers::path(TOKEN_PATH))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "the grant does not verify"
        })))
        .with_priority(5)
        .mount(&issuer.server)
        .await;
}

#[tokio::test]
async fn the_authorization_request_carries_state_nonce_and_an_s256_challenge() {
    let key = ec_key("op-1", Algorithm::ES256);
    let (_issuer, client) = provider(&key).await;
    let request = client.authorization_request().expect("a sign-in is minted");
    let sent = query(&request.url);
    assert_eq!(
        Some("synthetic"),
        sent.get("tenant").map(String::as_str),
        "the endpoint's own query stays"
    );
    assert_eq!(Some("code"), sent.get("response_type").map(String::as_str));
    assert_eq!(Some(CLIENT), sent.get("client_id").map(String::as_str));
    assert_eq!(Some(REDIRECT), sent.get("redirect_uri").map(String::as_str));
    assert_eq!(
        Some("openid profile"),
        sent.get("scope").map(String::as_str)
    );
    assert_eq!(
        Some(request.pending.state()),
        sent.get("state").map(String::as_str)
    );
    assert_eq!(
        Some(request.pending.nonce()),
        sent.get("nonce").map(String::as_str)
    );
    assert_eq!(
        Some("S256"),
        sent.get("code_challenge_method").map(String::as_str)
    );
    assert_eq!(
        Some(challenge(request.pending.verifier().expose()).as_str()),
        sent.get("code_challenge").map(String::as_str)
    );
    assert!(
        !request
            .url
            .as_str()
            .contains(request.pending.verifier().expose()),
        "the verifier never travels in the browser"
    );
    assert!(!sent.contains_key("prompt"));
}

#[tokio::test]
async fn offline_access_asks_for_consent() {
    let key = ec_key("op-1", Algorithm::ES256);
    let (_issuer, client) = provider(&key).await;
    let request = client
        .with_offline_access()
        .authorization_request()
        .expect("a sign-in is minted");
    let sent = query(&request.url);
    assert_eq!(
        Some("openid profile offline_access"),
        sent.get("scope").map(String::as_str)
    );
    assert_eq!(Some("consent"), sent.get("prompt").map(String::as_str));
}

#[tokio::test]
async fn the_code_is_exchanged_and_the_id_token_checked() {
    let key = ec_key("op-1", Algorithm::ES256);
    let (issuer, client) = provider(&key).await;
    let request = client.authorization_request().expect("a sign-in is minted");
    let pending = request.pending;
    let token = id_token(&issuer, &key, pending.nonce());
    mount_exchange(&issuer, pending.verifier().expose(), &token).await;
    let signed_in = client
        .exchange(
            &pending,
            &Callback::granted("synthetic-code", pending.state()),
        )
        .await
        .expect("the sign-in completes");
    assert_eq!("synthetic-access-1", signed_in.access_token.expose());
    assert_eq!(
        Some("synthetic-refresh-1"),
        signed_in.refresh_token.as_ref().map(Secret::expose)
    );
    assert_eq!(token, signed_in.id_token.expose());
    assert_eq!(Some(Duration::from_secs(300)), signed_in.expires_in);
    assert_eq!(vec!["openid", "profile"], signed_in.scopes);
    assert_eq!("synthetic-operator", signed_in.claims.subject);
    assert_eq!(Some("operator.one"), signed_in.claims.display_name());
    assert_eq!(
        Some(&serde_json::json!(["mapping-admin"])),
        signed_in.claims.other.get("roles")
    );
    let rendered = format!("{signed_in:?}");
    for secret in ["synthetic-access-1", "synthetic-refresh-1", token.as_str()] {
        assert!(!rendered.contains(secret), "{rendered}");
    }
}

#[tokio::test]
async fn a_state_mismatch_is_refused_before_the_token_endpoint_is_called() {
    let key = ec_key("op-1", Algorithm::ES256);
    let (issuer, client) = provider(&key).await;
    let pending = client.authorization_request().expect("a sign-in").pending;
    mount_invalid_grant(&issuer).await;
    for callback in [
        Callback::granted("synthetic-code", "another-state"),
        Callback::refused("access_denied", "another-state"),
        Callback::default(),
    ] {
        let refused = client.exchange(&pending, &callback).await;
        assert!(
            matches!(refused, Err(OidcError::StateMismatch)),
            "{refused:?}"
        );
        assert!(refused.is_err_and(|error| error.refuses_the_operator()));
    }
    assert_eq!(0, issuer.reads(TOKEN_PATH).await);
}

#[tokio::test]
async fn a_pkce_mismatch_is_refused_with_the_providers_error_code() {
    let key = ec_key("op-1", Algorithm::ES256);
    let (issuer, client) = provider(&key).await;
    let pending = client.authorization_request().expect("a sign-in").pending;
    mount_exchange(&issuer, pending.verifier().expose(), "unused").await;
    let forged = PendingSignIn::from_parts(
        pending.state().to_owned(),
        pending.nonce().to_owned(),
        Secret::new("a-verifier-of-another-sign-in-0000000000000"),
    );
    let refused = client
        .exchange(
            &forged,
            &Callback::granted("synthetic-code", pending.state()),
        )
        .await
        .expect_err("the provider refuses another verifier");
    assert_eq!(Some("invalid_grant"), refused.oauth_error());
    assert_eq!(Some(http::StatusCode::BAD_REQUEST), refused.status());
    assert!(refused.is_answered_refusal());
}

#[tokio::test]
async fn a_refused_authorization_carries_the_error_code() {
    let key = ec_key("op-1", Algorithm::ES256);
    let (issuer, client) = provider(&key).await;
    let pending = client.authorization_request().expect("a sign-in").pending;
    let refused = client
        .exchange(
            &pending,
            &Callback::refused("access_denied", pending.state()),
        )
        .await
        .expect_err("the redirect carries an error");
    assert_eq!(Some("access_denied"), refused.oauth_error());
    assert_eq!(0, issuer.reads(TOKEN_PATH).await);
    let no_code = client
        .exchange(&pending, &Callback::granted("", pending.state()))
        .await;
    assert!(no_code.is_err(), "an empty code is refused by the provider");
}

#[tokio::test]
async fn an_id_token_with_another_nonce_audience_or_key_is_refused() {
    let key = ec_key("op-1", Algorithm::ES256);
    let (issuer, client) = provider(&key).await;
    let pending = client.authorization_request().expect("a sign-in").pending;
    let callback = Callback::granted("synthetic-code", pending.state());

    let replayed = id_token(&issuer, &key, "a-nonce-of-another-sign-in");
    mount_exchange(&issuer, pending.verifier().expose(), &replayed).await;
    let refused = client.exchange(&pending, &callback).await;
    assert!(matches!(refused, Err(OidcError::Nonce)), "{refused:?}");

    issuer.server.reset().await;
    issuer.mount_keys(&[&key], None).await;
    let stranger = ec_key("op-2", Algorithm::ES256);
    let unknown = id_token(&issuer, &stranger, pending.nonce());
    mount_exchange(&issuer, pending.verifier().expose(), &unknown).await;
    let refused = client.exchange(&pending, &callback).await;
    assert!(matches!(refused, Err(OidcError::Key)), "{refused:?}");

    issuer.server.reset().await;
    issuer.mount_keys(&[&key], None).await;
    let now = now();
    let mut header = Header::new(key.alg);
    header.kid = Some(key.kid.clone());
    let wide = mint_with(
        &key,
        &header,
        &serde_json::json!({
            "iss": issuer.uri(), "aud": [CLIENT, "another-client"], "sub": "synthetic-operator",
            "nonce": pending.nonce(), "iat": now, "exp": now + 300
        }),
    );
    mount_exchange(&issuer, pending.verifier().expose(), &wide).await;
    let refused = client.exchange(&pending, &callback).await;
    assert!(matches!(refused, Err(OidcError::Audience)), "{refused:?}");
}

#[tokio::test]
async fn the_refresh_grant_rotates_the_tokens_and_a_refusal_carries_its_code() {
    let key = ec_key("op-1", Algorithm::ES256);
    let (issuer, client) = provider(&key).await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path(TOKEN_PATH))
        .and(matchers::body_string_contains("grant_type=refresh_token"))
        .and(matchers::body_string_contains(
            "refresh_token=synthetic-refresh-1",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "synthetic-access-2",
            "token_type": "bearer",
            "expires_in": 600,
            "refresh_token": "synthetic-refresh-2",
            "scope": "openid profile"
        })))
        .with_priority(1)
        .mount(&issuer.server)
        .await;
    mount_invalid_grant(&issuer).await;
    let refreshed = client
        .refresh(&Secret::new("synthetic-refresh-1"))
        .await
        .expect("the refresh completes");
    assert_eq!("synthetic-access-2", refreshed.access_token.expose());
    assert_eq!(
        Some("synthetic-refresh-2"),
        refreshed.refresh_token.as_ref().map(Secret::expose)
    );
    assert_eq!(Some(Duration::from_secs(600)), refreshed.expires_in);
    assert_eq!(
        Some(vec![String::from("openid"), String::from("profile")]),
        refreshed.scopes
    );
    let refused = client
        .refresh(&Secret::new("synthetic-spent-token"))
        .await
        .expect_err("a spent refresh token is refused");
    assert_eq!(Some("invalid_grant"), refused.oauth_error());
    assert!(
        refused.is_answered_refusal(),
        "a refused refresh ends the session"
    );
    assert!(!refused.to_string().contains("synthetic-spent-token"));
}

#[tokio::test]
async fn a_provider_failing_on_its_side_is_no_answered_refusal() {
    let key = ec_key("op-1", Algorithm::ES256);
    let (issuer, client) = provider(&key).await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path(TOKEN_PATH))
        .respond_with(ResponseTemplate::new(503))
        .mount(&issuer.server)
        .await;
    let failed = client
        .refresh(&Secret::new("synthetic-refresh-1"))
        .await
        .expect_err("the provider fails");
    assert_eq!(Some(http::StatusCode::SERVICE_UNAVAILABLE), failed.status());
    assert_eq!(None, failed.oauth_error());
    assert!(
        !failed.is_answered_refusal(),
        "the session stays for a retry"
    );
}

#[tokio::test]
async fn logout_names_the_hint_and_the_redirect_and_revocation_posts_the_token() {
    let key = ec_key("op-1", Algorithm::ES256);
    let (issuer, client) = provider(&key).await;
    let hint = Secret::new("synthetic-id-token");
    let url = client
        .end_session_url(Some(&hint), Some("synthetic-logout-state"))
        .expect("the provider publishes an end-session endpoint");
    assert_eq!(
        format!("{}/logout", issuer.uri()),
        format!("{}://{}{}", url.scheme(), url.authority(), url.path())
    );
    let sent = query(&url);
    assert_eq!(
        Some("synthetic-id-token"),
        sent.get("id_token_hint").map(String::as_str)
    );
    assert_eq!(Some(CLIENT), sent.get("client_id").map(String::as_str));
    assert_eq!(
        Some("https://console.example.org/"),
        sent.get("post_logout_redirect_uri").map(String::as_str)
    );
    assert_eq!(
        Some("synthetic-logout-state"),
        sent.get("state").map(String::as_str)
    );

    Mock::given(matchers::method("POST"))
        .and(matchers::path("/revoke"))
        .and(matchers::body_string_contains("token=synthetic-refresh-1"))
        .and(matchers::body_string_contains(
            "token_type_hint=refresh_token",
        ))
        .respond_with(ResponseTemplate::new(200))
        .with_priority(1)
        .mount(&issuer.server)
        .await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/revoke"))
        .respond_with(ResponseTemplate::new(503))
        .with_priority(5)
        .mount(&issuer.server)
        .await;
    client
        .revoke(
            &Secret::new("synthetic-refresh-1"),
            TokenTypeHint::RefreshToken,
        )
        .await
        .expect("the provider revokes the token");
    let refused = client
        .revoke(
            &Secret::new("synthetic-access-1"),
            TokenTypeHint::AccessToken,
        )
        .await;
    assert!(
        matches!(refused, Err(OidcError::Revocation { status }) if status == http::StatusCode::SERVICE_UNAVAILABLE),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_provider_without_an_end_session_endpoint_has_no_logout_url() {
    let key = ec_key("op-1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let http = Http::new(Duration::from_secs(5)).expect("the engine builds");
    let discovered = Provider::discover(&http, &issuer.uri())
        .await
        .expect("the provider is discovered");
    let client = RelyingParty::new(
        http,
        discovered,
        CLIENT,
        Url::parse(REDIRECT).expect("a URL"),
    );
    assert_eq!(None, client.end_session_url(None, None));
    client
        .revoke(
            &Secret::new("synthetic-access-1"),
            TokenTypeHint::AccessToken,
        )
        .await
        .expect("no revocation endpoint is no failure");
}
