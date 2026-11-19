// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The refresh token grant through the whole stack against a real
//! PostgreSQL: SMART App Launch 2.2.0, Refresh access token, with the
//! rotation and replay detection of RFC 9700 §4.14.2 and the OAuth 2.1
//! draft §4.3, each outcome read back through the introspection endpoint.

use ferrosmart::store::grant::Access;
use http::StatusCode;
use serde_json::{Value, json};

use crate::introspection::{Answer, Server, inactive, unique};
use crate::support::{commit, events, records, rotated_ago};

/// The scope every grant of these cases holds.
const GRANTED: &str = "openid fhirUser launch/patient patient/Observation.rs offline_access";

/// Returns the form that refreshes `token` for the public client `app`,
/// asking for `scope` when given.
fn public(token: &str, scope: Option<&str>) -> Vec<(String, String)> {
    let mut form = vec![
        (String::from("grant_type"), String::from("refresh_token")),
        (String::from("refresh_token"), token.to_owned()),
        (String::from("client_id"), String::from("app")),
    ];
    if let Some(scope) = scope {
        form.push((String::from("scope"), scope.to_owned()));
    }
    form
}

/// Returns the `error` of a refusal, asserting its status.
fn refused(answer: &Answer) -> Value {
    assert_eq!(StatusCode::BAD_REQUEST, answer.0, "{:?}", answer.2);
    answer.2.get("error").cloned().unwrap_or(Value::Null)
}

/// Starts a server with one `offline_access` grant of `app` and its refresh
/// token.
async fn offline() -> (Server, String, String) {
    let server = Server::start().await;
    let grant = server
        .grant(
            "app",
            Some(Access::Offline),
            None,
            &json!({"patient": "123"}),
        )
        .await;
    let token = server.refresh(&grant, 3600).await;
    (server, grant, token)
}

#[tokio::test]
async fn a_refresh_issues_a_new_access_token_and_rotates_the_refresh_token() {
    let (server, _, token) = offline().await;
    let (status, headers, body) = server.post("/token", &public(&token, None), None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(
        Some("no-store"),
        headers
            .get(http::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
    );
    // NOTE: SMART App Launch 2.2.0, Refresh access token, Response.
    assert_eq!(json!("bearer"), body["token_type"]);
    assert_eq!(json!(300), body["expires_in"]);
    assert_eq!(
        json!(GRANTED),
        body["scope"],
        "a missing scope is the original"
    );
    assert_eq!(json!("123"), body["patient"], "the launch context");
    let successor = body["refresh_token"].as_str().expect("a new refresh token");
    assert_ne!(token, successor);
    // NOTE: RFC 9700 §4.14.2, the previous refresh token is invalidated.
    assert_eq!(inactive(), server.introspect(&token).await);
    assert_eq!(json!(true), server.introspect(successor).await["active"]);
    let access = body["access_token"].as_str().expect("an access token");
    let answer = server.introspect(access).await;
    assert_eq!(json!(true), answer["active"]);
    assert_eq!(json!("app"), answer["client_id"]);
    assert_eq!(json!("alice"), answer["sub"]);
    assert_eq!(json!("123"), answer["patient"]);
    server.stop().await;
}

#[tokio::test]
async fn a_refresh_may_narrow_the_scope_and_never_widen_it() {
    let (server, _, token) = offline().await;
    let wider = format!("{GRANTED} patient/Patient.rs");
    // NOTE: SMART App Launch 2.2.0, Refresh access token, Request: no new
    // permissions can be obtained at refresh time.
    let answer = server
        .post("/token", &public(&token, Some(&wider)), None)
        .await;
    assert_eq!(json!("invalid_scope"), refused(&answer));
    assert_eq!(
        json!(true),
        server.introspect(&token).await["active"],
        "a refused request leaves the token unused"
    );

    let (status, _, body) = server
        .post(
            "/token",
            &public(&token, Some("patient/Observation.rs")),
            None,
        )
        .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(json!("patient/Observation.rs"), body["scope"]);
    let access = body["access_token"].as_str().expect("an access token");
    assert_eq!(
        json!("patient/Observation.rs"),
        server.introspect(access).await["scope"]
    );
    // NOTE: OAuth 2.1 draft §4.3.3, the rotated refresh token keeps the grant's scope.
    let successor = body["refresh_token"].as_str().expect("a refresh token");
    let (status, _, body) = server.post("/token", &public(successor, None), None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(json!(GRANTED), body["scope"]);
    server.stop().await;
}

#[tokio::test]
async fn a_rotated_refresh_token_presented_again_after_the_window_revokes_the_grant() {
    let (server, grant, token) = offline().await;
    let earlier = server.access("app", Some(&grant), 300).await;
    let (status, _, body) = server.post("/token", &public(&token, None), None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let successor = body["refresh_token"].as_str().expect("a refresh token");
    let access = body["access_token"].as_str().expect("an access token");
    rotated_ago(&server.database_url(), &token, 11).await;

    // NOTE: RFC 9700 §4.14.2 and OAuth 2.1 draft §4.3.1: the server revokes the
    // active refresh token as well as the grant associated with it.
    let replay = server.post("/token", &public(&token, None), None).await;
    assert_eq!(json!("invalid_grant"), refused(&replay));
    assert_eq!(inactive(), server.introspect(successor).await);
    assert_eq!(inactive(), server.introspect(access).await);
    assert_eq!(inactive(), server.introspect(&earlier).await);
    let after = server.post("/token", &public(successor, None), None).await;
    assert_eq!(json!("invalid_grant"), refused(&after));
    // NOTE: docs/architecture.md §13.2, the rotation and the reuse each commit
    // with their record.
    let happened = events(&records(&server.store).await);
    assert!(
        happened.contains(&String::from("refresh-rotated"))
            && happened.contains(&String::from("refresh-reused")),
        "{happened:?}"
    );
    server.stop().await;
}

#[tokio::test]
async fn a_retry_within_the_window_gets_the_same_successor_and_keeps_the_grant() {
    let (server, grant, token) = offline().await;
    let earlier = server.access("app", Some(&grant), 300).await;
    let (status, _, first) = server.post("/token", &public(&token, None), None).await;
    assert_eq!(StatusCode::OK, status, "{first}");
    // NOTE: docs/architecture.md §13.6 item 11: a lost response retried within
    // the window is answered again, with the successor the first answer carried.
    let (status, _, second) = server.post("/token", &public(&token, None), None).await;
    assert_eq!(StatusCode::OK, status, "{second}");
    assert_eq!(first["refresh_token"], second["refresh_token"]);
    assert_ne!(first["access_token"], second["access_token"]);
    assert_eq!(json!(GRANTED), second["scope"]);
    assert_eq!(json!("123"), second["patient"], "the launch context");
    let successor = second["refresh_token"].as_str().expect("a refresh token");
    assert_eq!(json!(true), server.introspect(successor).await["active"]);
    assert_eq!(json!(true), server.introspect(&earlier).await["active"]);
    for answer in [&first, &second] {
        let access = answer["access_token"].as_str().expect("an access token");
        assert_eq!(json!(true), server.introspect(access).await["active"]);
    }
    // NOTE: the retry narrows like any refresh, and never widens.
    let narrowed = server
        .post(
            "/token",
            &public(&token, Some("openid patient/Observation.rs")),
            None,
        )
        .await;
    assert_eq!(StatusCode::OK, narrowed.0, "{}", narrowed.2);
    assert_eq!(json!("openid patient/Observation.rs"), narrowed.2["scope"]);
    assert_eq!(first["refresh_token"], narrowed.2["refresh_token"]);
    let (status, _, next) = server.post("/token", &public(successor, None), None).await;
    assert_eq!(StatusCode::OK, status, "{next}");
    assert_eq!(inactive(), server.introspect(successor).await);
    let happened = events(&records(&server.store).await);
    assert!(
        happened.contains(&String::from("refresh-repeated"))
            && !happened.contains(&String::from("refresh-reused")),
        "{happened:?}"
    );
    server.stop().await;
}

#[tokio::test]
async fn two_refreshes_racing_with_one_token_both_get_the_same_successor() {
    let (server, _, token) = offline().await;
    let form = public(&token, None);
    let (first, second) = tokio::join!(
        server.post("/token", &form, None),
        server.post("/token", &form, None)
    );
    assert_eq!(StatusCode::OK, first.0, "{}", first.2);
    assert_eq!(StatusCode::OK, second.0, "{}", second.2);
    assert_eq!(first.2["refresh_token"], second.2["refresh_token"]);
    let successor = first.2["refresh_token"].as_str().expect("a refresh token");
    assert_eq!(json!(true), server.introspect(successor).await["active"]);
    server.stop().await;
}

#[tokio::test]
async fn two_replicas_racing_with_one_token_both_get_the_same_successor() {
    let (server, _, token) = offline().await;
    let replica = server.replica().await;
    let form = public(&token, None);
    let (first, second) = tokio::join!(
        server.post("/token", &form, None),
        replica.post("/token", &form, None)
    );
    assert_eq!(StatusCode::OK, first.0, "{}", first.2);
    assert_eq!(StatusCode::OK, second.0, "{}", second.2);
    assert_eq!(first.2["refresh_token"], second.2["refresh_token"]);
    replica.stop().await;
    server.stop().await;
}

#[tokio::test]
async fn a_repeat_once_the_successor_was_used_revokes_the_grant() {
    let (server, _, token) = offline().await;
    let (_, _, body) = server.post("/token", &public(&token, None), None).await;
    let successor = body["refresh_token"].as_str().expect("a refresh token");
    let (status, _, next) = server.post("/token", &public(successor, None), None).await;
    assert_eq!(StatusCode::OK, status, "{next}");
    let latest = next["refresh_token"].as_str().expect("a refresh token");
    // NOTE: docs/architecture.md §13.6 item 11: the chain moved on, so the first
    // token presented again is a replay even within the window.
    let replay = server.post("/token", &public(&token, None), None).await;
    assert_eq!(json!("invalid_grant"), refused(&replay));
    assert_eq!(inactive(), server.introspect(latest).await);
    server.stop().await;
}

#[tokio::test]
async fn a_repeat_by_another_client_is_refused_and_changes_nothing() {
    let (server, _, token) = offline().await;
    let (_, _, body) = server.post("/token", &public(&token, None), None).await;
    let successor = body["refresh_token"].as_str().expect("a refresh token");
    let mut form = server.credentials("portal");
    form.extend([
        (String::from("grant_type"), String::from("refresh_token")),
        (String::from("refresh_token"), token.clone()),
    ]);
    let answer = server.post("/token", &form, None).await;
    assert_eq!(json!("invalid_grant"), refused(&answer));
    assert_eq!(json!(true), server.introspect(successor).await["active"]);
    server.stop().await;
}

#[tokio::test]
async fn a_refresh_token_is_bound_to_its_client() {
    let (server, _, token) = offline().await;
    let mut form = server.credentials("portal");
    form.extend([
        (String::from("grant_type"), String::from("refresh_token")),
        (String::from("refresh_token"), token.clone()),
    ]);
    // NOTE: SMART App Launch 2.2.0, Refresh access token: a refresh token SHALL be
    // bound to the same client_id; RFC 6749 §5.2, invalid_grant.
    let answer = server.post("/token", &form, None).await;
    assert_eq!(json!("invalid_grant"), refused(&answer));
    assert_eq!(json!(true), server.introspect(&token).await["active"]);
    server.stop().await;
}

#[tokio::test]
async fn a_confidential_client_authenticates_to_refresh() {
    let server = Server::start().await;
    let grant = server
        .grant("portal", Some(Access::Offline), None, &json!({}))
        .await;
    let token = server.refresh(&grant, 3600).await;
    let named = vec![
        (String::from("grant_type"), String::from("refresh_token")),
        (String::from("refresh_token"), token.clone()),
        (String::from("client_id"), String::from("portal")),
    ];
    // NOTE: OAuth 2.1 draft §4.3.1, confidential clients MUST authenticate.
    let answer = server.post("/token", &named, None).await;
    assert_eq!(json!("invalid_client"), refused(&answer));
    let mut form = server.credentials("portal");
    form.extend([
        (String::from("grant_type"), String::from("refresh_token")),
        (String::from("refresh_token"), token),
    ]);
    let (status, _, body) = server.post("/token", &form, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(
        json!("portal"),
        server
            .introspect(body["access_token"].as_str().expect("a token"))
            .await["client_id"]
    );
    server.stop().await;
}

#[tokio::test]
async fn an_online_refresh_token_lasts_the_online_idle_time_and_the_upstream_login() {
    let server = Server::start().await;
    let session = unique();
    server
        .store
        .begin_session(&session, "https://idp.example.org", "upstream-alice", None)
        .await
        .expect("recorded");
    let grant = server
        .grant("app", Some(Access::Online), Some(&session), &json!({}))
        .await;
    let token = server.refresh(&grant, 3600).await;
    let (status, _, body) = server.post("/token", &public(&token, None), None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let successor = body["refresh_token"].as_str().expect("a refresh token");
    let now = jiff::Timestamp::now().as_second();
    let exp = server.introspect(successor).await["exp"]
        .as_i64()
        .expect("an exp");
    // NOTE: docs/architecture.md §13.10, online_idle eight hours by default.
    assert!(
        (now + 8 * 3600 - 60..=now + 8 * 3600 + 60).contains(&exp),
        "{exp}"
    );

    let mut tx = server.store.begin().await.expect("begins");
    assert!(tx.end_session(&session).await.expect("ended"));
    commit(tx).await;
    // NOTE: docs/architecture.md §13.6 item 7, online_access ends at upstream logout.
    let answer = server.post("/token", &public(successor, None), None).await;
    assert_eq!(json!("invalid_grant"), refused(&answer));
    server.stop().await;
}

#[tokio::test]
async fn an_offline_refresh_token_lasts_the_refresh_idle_time() {
    let (server, _, token) = offline().await;
    let (status, _, body) = server.post("/token", &public(&token, None), None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let successor = body["refresh_token"].as_str().expect("a refresh token");
    let now = jiff::Timestamp::now().as_second();
    let exp = server.introspect(successor).await["exp"]
        .as_i64()
        .expect("an exp");
    // NOTE: OAuth 2.1 draft §4.3.3, refresh tokens SHOULD expire when idle; 30 days.
    assert!(
        (now + 30 * 86_400 - 60..=now + 30 * 86_400 + 60).contains(&exp),
        "{exp}"
    );
    server.stop().await;
}

#[tokio::test]
async fn a_lapsed_revoked_or_unknown_refresh_token_is_refused() {
    let server = Server::start().await;
    let grant = server
        .grant("app", Some(Access::Offline), None, &json!({}))
        .await;
    let lapsed = server.refresh(&grant, -10).await;
    let revoked_grant = server
        .grant("app", Some(Access::Offline), None, &json!({}))
        .await;
    let revoked = server.refresh(&revoked_grant, 3600).await;
    let mut tx = server.store.begin().await.expect("begins");
    assert!(tx.revoke_grant(&revoked_grant).await.expect("revoked"));
    commit(tx).await;
    for token in [lapsed, revoked, unique()] {
        let answer = server.post("/token", &public(&token, None), None).await;
        assert_eq!(json!("invalid_grant"), refused(&answer));
    }
    server.stop().await;
}

#[tokio::test]
async fn a_client_without_the_grant_or_a_token_is_refused() {
    let (server, _, token) = offline().await;
    let mut form = server.credentials("export");
    form.extend([
        (String::from("grant_type"), String::from("refresh_token")),
        (String::from("refresh_token"), token.clone()),
    ]);
    let answer = server.post("/token", &form, None).await;
    assert_eq!(json!("unauthorized_client"), refused(&answer));
    let missing = vec![
        (String::from("grant_type"), String::from("refresh_token")),
        (String::from("client_id"), String::from("app")),
    ];
    let answer = server.post("/token", &missing, None).await;
    assert_eq!(json!("invalid_request"), refused(&answer));
    assert_eq!(json!(true), server.introspect(&token).await["active"]);
    server.stop().await;
}
