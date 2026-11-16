// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The revocation endpoint through the whole stack against a real
//! PostgreSQL: RFC 7009 §2, each revocation read back through the
//! introspection endpoint.

use ferrosmart::store::grant::Access;
use http::StatusCode;
use serde_json::json;

use crate::introspection::{Server, inactive, unique};
use crate::support::RESOURCE;

/// Returns the form that revokes `token`, with the `token_type_hint`
/// `hint`.
fn revoke(token: &str, hint: Option<&str>) -> Vec<(String, String)> {
    let mut form = vec![(String::from("token"), token.to_owned())];
    if let Some(hint) = hint {
        form.push((String::from("token_type_hint"), hint.to_owned()));
    }
    form
}

/// Returns `form` with the `client_id` of the public client `client`.
fn public(mut form: Vec<(String, String)>, client: &str) -> Vec<(String, String)> {
    form.push((String::from("client_id"), client.to_owned()));
    form
}

#[tokio::test]
async fn revoking_a_refresh_token_revokes_its_whole_grant() {
    let server = Server::start().await;
    let grant = server
        .grant("app", Some(Access::Offline), None, &json!({}))
        .await;
    let refresh = server.refresh(&grant, 3600).await;
    let sibling = server.refresh(&grant, 3600).await;
    let access = server.access("app", Some(&grant), 300).await;
    let other = server
        .grant("app", Some(Access::Offline), None, &json!({}))
        .await;
    let unrelated = server.refresh(&other, 3600).await;

    let (status, _, _) = server
        .post(
            "/revoke",
            &public(revoke(&refresh, Some("refresh_token")), "app"),
            None,
        )
        .await;
    assert_eq!(StatusCode::OK, status);
    // NOTE: RFC 7009 §2.1, the server SHOULD also invalidate all access tokens
    // based on the same authorization grant.
    assert_eq!(inactive(), server.introspect(&refresh).await);
    assert_eq!(inactive(), server.introspect(&sibling).await);
    assert_eq!(inactive(), server.introspect(&access).await);
    assert_eq!(
        json!(true),
        server.introspect(&unrelated).await["active"],
        "another grant is untouched"
    );
    server.stop().await;
}

#[tokio::test]
async fn revoking_an_access_token_revokes_it_alone() {
    let server = Server::start().await;
    let grant = server
        .grant("app", Some(Access::Offline), None, &json!({}))
        .await;
    let refresh = server.refresh(&grant, 3600).await;
    let access = server.access("app", Some(&grant), 300).await;
    let sibling = server.access("app", Some(&grant), 300).await;
    // NOTE: RFC 7009 §2.1, a wrong hint never stops the search.
    let (status, _, _) = server
        .post(
            "/revoke",
            &public(revoke(&access, Some("refresh_token")), "app"),
            None,
        )
        .await;
    assert_eq!(StatusCode::OK, status);
    assert_eq!(inactive(), server.introspect(&access).await);
    assert_eq!(json!(true), server.introspect(&sibling).await["active"]);
    assert_eq!(json!(true), server.introspect(&refresh).await["active"]);
    server.stop().await;
}

#[tokio::test]
async fn a_backend_service_revokes_its_own_access_token() {
    let server = Server::start().await;
    let token = server.token("export", "system/Patient.rs", RESOURCE).await;
    let mut form = server.credentials("export");
    form.extend(revoke(&token, Some("access_token")));
    let (status, headers, _) = server.post("/revoke", &form, None).await;
    assert_eq!(StatusCode::OK, status);
    assert_eq!(
        Some("no-store"),
        headers
            .get(http::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
    );
    assert_eq!(inactive(), server.introspect(&token).await);
    server.stop().await;
}

#[tokio::test]
async fn an_unknown_or_already_revoked_token_answers_200() {
    let server = Server::start().await;
    // NOTE: RFC 7009 §2.2, an invalid token answers 200.
    let (status, _, _) = server
        .post("/revoke", &public(revoke(&unique(), None), "app"), None)
        .await;
    assert_eq!(StatusCode::OK, status);
    let grant = server
        .grant("app", Some(Access::Offline), None, &json!({}))
        .await;
    let refresh = server.refresh(&grant, 3600).await;
    for _ in 0..2 {
        let (status, _, _) = server
            .post("/revoke", &public(revoke(&refresh, None), "app"), None)
            .await;
        assert_eq!(StatusCode::OK, status);
    }
    server.stop().await;
}

#[tokio::test]
async fn a_token_of_another_client_is_refused_and_stays_active() {
    let server = Server::start().await;
    let token = server.token("export", "system/Patient.rs", RESOURCE).await;
    let mut form = server.credentials("rs");
    form.extend(revoke(&token, None));
    // NOTE: RFC 7009 §2.1, the server verifies the token was issued to the client
    // making the request, and refuses it otherwise.
    let (status, _, body) = server.post("/revoke", &form, None).await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert_eq!(json!("unauthorized_client"), body["error"]);
    assert_eq!(json!(true), server.introspect(&token).await["active"]);

    let grant = server
        .grant("export", Some(Access::Offline), None, &json!({}))
        .await;
    let refresh = server.refresh(&grant, 3600).await;
    let (status, _, body) = server
        .post("/revoke", &public(revoke(&refresh, None), "app"), None)
        .await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert_eq!(json!("unauthorized_client"), body["error"]);
    assert_eq!(json!(true), server.introspect(&refresh).await["active"]);
    server.stop().await;
}

#[tokio::test]
async fn a_client_that_does_not_authenticate_is_refused() {
    let server = Server::start().await;
    let token = server.token("export", "system/Patient.rs", RESOURCE).await;
    // NOTE: RFC 7009 §2.1, a confidential client authenticates; RFC 6749 §5.2.
    for form in [
        revoke(&token, None),
        public(revoke(&token, None), "export"),
        public(revoke(&token, None), "nobody"),
    ] {
        let (status, _, body) = server.post("/revoke", &form, None).await;
        assert_eq!(StatusCode::BAD_REQUEST, status);
        assert_eq!(json!("invalid_client"), body["error"]);
    }
    assert_eq!(json!(true), server.introspect(&token).await["active"]);
    server.stop().await;
}

#[tokio::test]
async fn a_request_without_a_token_is_malformed() {
    let server = Server::start().await;
    let (status, _, body) = server
        .post("/revoke", &server.credentials("export"), None)
        .await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert_eq!(json!("invalid_request"), body["error"]);
    server.stop().await;
}
