// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A confidential symmetric client at the token and revocation endpoints:
//! SMART App Launch 2.2.0, Client Authentication: Symmetric, with the
//! client secret sent by HTTP Basic or in the form (RFC 6749 §2.3.1).

use base64::Engine as _;
use ferrosmart::clients::{ClientKind, ClientSection, GrantType, resolve};
use ferrosmart::store::grant::Access;
use http::{StatusCode, header};
use serde_json::{Value, json};

use crate::introspection::{Answer, Server, VAULT_SECRET, inactive, phc};

/// Returns the `Authorization` value of `client_id` and `secret` by HTTP
/// Basic, each form-urlencoded first (RFC 6749 §2.3.1).
fn basic(client_id: &str, secret: &str) -> String {
    let encode = |value: &str| -> String {
        url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
    };
    let pair = format!("{}:{}", encode(client_id), encode(secret));
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(pair)
    )
}

/// Returns the form refreshing `token`.
fn refresh(token: &str) -> Vec<(String, String)> {
    vec![
        (String::from("grant_type"), String::from("refresh_token")),
        (String::from("refresh_token"), token.to_owned()),
    ]
}

/// Starts a server with one offline grant of `vault` and its refresh token.
async fn vault() -> (Server, String) {
    let server = Server::start().await;
    let grant = server
        .grant("vault", Some(Access::Offline), None, &json!({}))
        .await;
    let token = server.refresh(&grant, 3600).await;
    (server, token)
}

/// Returns the `error` of `answer`.
fn error(answer: &Answer) -> Value {
    answer.2.get("error").cloned().unwrap_or(Value::Null)
}

#[tokio::test]
async fn a_symmetric_client_authenticates_by_http_basic() {
    let (server, token) = vault().await;
    let answer = server
        .post_authorized(
            "/token",
            &refresh(&token),
            Some(basic("vault", VAULT_SECRET)),
        )
        .await;
    assert_eq!(StatusCode::OK, answer.0, "{:?}", answer.2);
    assert!(answer.2["access_token"].is_string());
    server.stop().await;
}

#[tokio::test]
async fn a_symmetric_client_authenticates_in_the_form() {
    let (server, token) = vault().await;
    let mut form = refresh(&token);
    form.push((String::from("client_id"), String::from("vault")));
    form.push((String::from("client_secret"), String::from(VAULT_SECRET)));
    let answer = server.post("/token", &form, None).await;
    assert_eq!(StatusCode::OK, answer.0, "{:?}", answer.2);
    server.stop().await;
}

// NOTE: RFC 6749 §5.2, invalid_client: a credential sent in the Authorization
// header answers 401 with the scheme in WWW-Authenticate.
#[tokio::test]
async fn a_wrong_secret_is_invalid_client() {
    let (server, token) = vault().await;
    for authorization in [
        basic("vault", "not the secret"),
        basic("unknown", VAULT_SECRET),
        basic("app", VAULT_SECRET),
    ] {
        let answer = server
            .post_authorized("/token", &refresh(&token), Some(authorization))
            .await;
        assert_eq!(StatusCode::UNAUTHORIZED, answer.0, "{:?}", answer.2);
        assert_eq!(json!("invalid_client"), error(&answer));
        assert_eq!(
            Some("Basic"),
            answer
                .1
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
        );
    }
    let mut form = refresh(&token);
    form.push((String::from("client_id"), String::from("vault")));
    form.push((
        String::from("client_secret"),
        String::from("not the secret"),
    ));
    let answer = server.post("/token", &form, None).await;
    assert_eq!(StatusCode::BAD_REQUEST, answer.0);
    assert_eq!(json!("invalid_client"), error(&answer));
    server.stop().await;
}

// NOTE: RFC 6749 §2.3, "The client MUST NOT use more than one authentication
// method in each request".
#[tokio::test]
async fn two_authentication_methods_at_once_are_refused() {
    let (server, token) = vault().await;
    let mut form = refresh(&token);
    form.push((String::from("client_id"), String::from("vault")));
    form.push((String::from("client_secret"), String::from(VAULT_SECRET)));
    let answer = server
        .post_authorized("/token", &form, Some(basic("vault", VAULT_SECRET)))
        .await;
    assert_eq!(json!("invalid_request"), error(&answer), "{:?}", answer.2);
    server.stop().await;
}

// NOTE: RFC 7009 §2.1, a confidential client authenticates to revoke its token.
#[tokio::test]
async fn a_symmetric_client_revokes_its_refresh_token() {
    let (server, token) = vault().await;
    let form = vec![(String::from("token"), token.clone())];
    let answer = server
        .post_authorized("/revoke", &form, Some(basic("vault", VAULT_SECRET)))
        .await;
    assert_eq!(StatusCode::OK, answer.0);
    assert_eq!(inactive(), server.introspect(&token).await);
    server.stop().await;
}

// NOTE: SMART App Launch 2.2.0, Client Authentication: Symmetric, the profile
// "SHALL NOT be used" for Backend Services.
#[test]
fn a_symmetric_client_is_refused_the_client_credentials_grant_and_a_jwk_set() {
    let dir = tempfile::tempdir().expect("a directory");
    let file = dir.path().join("secret.phc");
    std::fs::write(&file, phc(VAULT_SECRET)).expect("written");
    let section = |grants: Vec<GrantType>, jwks_uri: &str| ClientSection {
        client_id: String::from("vault"),
        kind: ClientKind::ConfidentialSymmetric,
        secret_hash_file: Some(file.clone()),
        jwks_uri: jwks_uri.to_owned(),
        redirect_uris: vec![String::from("https://vault.example.org/callback")],
        grant_types: grants,
        ..ClientSection::default()
    };
    assert!(resolve(&[section(vec![GrantType::AuthorizationCode], "")]).is_ok());
    assert!(resolve(&[section(vec![GrantType::ClientCredentials], "")]).is_err());
    assert!(
        resolve(&[section(
            vec![GrantType::AuthorizationCode],
            "https://vault.example.org/jwks"
        )])
        .is_err()
    );
    let weak = dir.path().join("weak.phc");
    std::fs::write(
        &weak,
        "$argon2id$v=19$m=1024,t=1,p=1$c3ludGhldGljLXNhbHQtMTY$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    )
    .expect("written");
    let mut below_floor = section(vec![GrantType::AuthorizationCode], "");
    below_floor.secret_hash_file = Some(weak);
    assert!(resolve(&[below_floor]).is_err(), "a hash below the floor");
    let mut public = section(vec![GrantType::AuthorizationCode], "");
    public.kind = ClientKind::Public;
    assert!(resolve(&[public]).is_err(), "a secret on a public client");
}

// NOTE: OWASP Password Storage Cheat Sheet, Argon2id at m=19456, t=2, p=1.
#[test]
fn the_hash_secret_command_makes_a_hash_at_the_floor_with_a_fresh_salt() {
    let one = phc(VAULT_SECRET);
    let other = phc(VAULT_SECRET);
    assert!(one.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{one}");
    assert_ne!(one, other, "a fresh salt each time");
}
