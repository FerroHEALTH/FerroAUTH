// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Refresh, introspection and revocation across two replicas sharing one
//! PostgreSQL database (`docs/architecture.md` §13.9): what one replica
//! issues, rotates or revokes, the other answers for at once.

use ferrosmart::store::grant::Access;
use http::StatusCode;
use serde_json::{Value, json};

use crate::introspection::{Server, inactive};

/// Returns the form that refreshes `token` for the public client `app`.
fn refresh(token: &str) -> Vec<(String, String)> {
    vec![
        (String::from("grant_type"), String::from("refresh_token")),
        (String::from("refresh_token"), token.to_owned()),
        (String::from("client_id"), String::from("app")),
    ]
}

/// Returns `name` of the JSON object `body` as a string.
fn text(body: &Value, name: &str) -> String {
    body.get(name)
        .and_then(Value::as_str)
        .expect("the member is a string")
        .to_owned()
}

#[tokio::test]
async fn a_refresh_on_one_replica_is_seen_by_the_other() {
    let first = Server::start().await;
    let second = first.replica().await;
    let grant = first
        .grant(
            "app",
            Some(Access::Offline),
            None,
            &json!({"patient": "123"}),
        )
        .await;
    let token = first.refresh(&grant, 3600).await;

    let (status, _, body) = first.post("/token", &refresh(&token), None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let access = text(&body, "access_token");
    let rotated = text(&body, "refresh_token");

    let answer = second.introspect(&access).await;
    assert_eq!(Some(&json!(true)), answer.get("active"), "{answer}");
    assert_eq!(Some(&json!("123")), answer.get("patient"), "{answer}");
    let answer = second.introspect(&rotated).await;
    assert_eq!(Some(&json!(true)), answer.get("active"), "{answer}");
    assert_eq!(inactive(), second.introspect(&token).await);

    let (status, _, body) = second.post("/token", &refresh(&rotated), None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let (status, _, body) = first.post("/token", &refresh(&rotated), None).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
    assert_eq!(Some(&json!("invalid_grant")), body.get("error"), "{body}");
    assert_eq!(
        inactive(),
        second.introspect(&access).await,
        "a replayed refresh token on one replica revokes the grant on both"
    );
    drop(second);
    first.stop().await;
}

#[tokio::test]
async fn a_revocation_on_one_replica_holds_on_the_other() {
    let first = Server::start().await;
    let second = first.replica().await;
    let grant = first
        .grant(
            "app",
            Some(Access::Offline),
            None,
            &json!({"patient": "123"}),
        )
        .await;
    let token = first.refresh(&grant, 3600).await;
    let access = first.access("app", Some(&grant), 300).await;
    let answer = second.introspect(&access).await;
    assert_eq!(Some(&json!(true)), answer.get("active"), "{answer}");

    let form = vec![
        (String::from("token"), token.clone()),
        (String::from("client_id"), String::from("app")),
    ];
    let (status, _, body) = second.post("/revoke", &form, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");

    assert_eq!(inactive(), first.introspect(&access).await);
    assert_eq!(inactive(), first.introspect(&token).await);
    let (status, _, body) = first.post("/token", &refresh(&token), None).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
    assert_eq!(Some(&json!("invalid_grant")), body.get("error"), "{body}");
    drop(second);
    first.stop().await;
}
