// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The remote decision point: `200` permits, a `4xx` denies, anything else is
//! no decision; the posted object carries the bound parameters; a token the
//! point refuses is renewed once.

use std::collections::BTreeMap;
use std::time::Duration;

use ferrohealth_authz::engine::AuthzError;
use ferrohealth_authz::engine::PolicyEngine;
use ferrohealth_authz::remote::Binding;
use ferrohealth_authz::remote::RemotePdp;
use ferrohealth_authz::remote::RemoteSettings;
use ferrohealth_authz::request::Attr;
use ferrohealth_authz::request::Decision;
use ferrohealth_authz::request::Request;
use ferrohealth_authz::request::Subject;
use ferrohealth_smart::client::ClientCredentials;
use ferrohealth_smart::client::Endpoint;
use ferrohealth_smart::client::cache::TokenSource;
use secrecy::SecretString;
use url::Url;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::body_json;
use wiremock::matchers::header;
use wiremock::matchers::method;
use wiremock::matchers::path;

fn settings(server: &MockServer) -> RemoteSettings {
    RemoteSettings {
        server: Url::parse(&format!("{}/pdp/", server.uri())).expect("a URL"),
        bindings: BTreeMap::from([(
            String::from("Composition"),
            Binding {
                policy: String::from("composition"),
                parameters: vec![String::from("organization"), String::from("patient")],
            },
        )]),
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
    }
}

fn subject() -> Subject {
    Subject::new("dr-a").with_attribute("organization", "Qz7-hospital")
}

fn request<'a>(subject: &'a Subject, patients: &[&str]) -> Request<'a> {
    Request::new(subject, "composition.read", "Composition")
        .with_attribute(
            "patient",
            Attr::Set(patients.iter().map(|p| (*p).to_owned()).collect()),
        )
        .expect("a request")
}

async fn answering(status: u16) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pdp/composition"))
        .respond_with(ResponseTemplate::new(status))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn ok_permits_and_the_object_carries_the_bound_parameters() {
    let server = MockServer::start().await;
    for patient in ["p-1", "p-2"] {
        Mock::given(method("POST"))
            .and(path("/pdp/composition"))
            .and(body_json(serde_json::json!({
                "organization": "Qz7-hospital",
                "patient": patient
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
    }
    let pdp = RemotePdp::new(settings(&server), None).expect("a point");
    let subject = subject();
    assert_eq!(
        pdp.decide(&request(&subject, &["p-1", "p-2"]))
            .await
            .expect("decides"),
        Decision::Permit {
            policies: vec![String::from("composition")]
        }
    );
}

#[tokio::test]
async fn a_client_error_denies() {
    let server = answering(403).await;
    let pdp = RemotePdp::new(settings(&server), None).expect("a point");
    let subject = subject();
    let decision = pdp
        .decide(&request(&subject, &["p-1"]))
        .await
        .expect("decides");
    assert!(!decision.is_permit());
}

#[tokio::test]
async fn a_server_error_or_a_redirect_is_no_decision() {
    for status in [500, 503, 302] {
        let server = answering(status).await;
        let pdp = RemotePdp::new(settings(&server), None).expect("a point");
        let subject = subject();
        let outcome = pdp.decide(&request(&subject, &["p-1"])).await;
        assert!(
            matches!(outcome, Err(AuthzError::Remote(_))),
            "{status}: {outcome:?}"
        );
    }
}

#[tokio::test]
async fn an_unbound_type_and_an_unreachable_point_are_no_decision() {
    let server = answering(200).await;
    let pdp = RemotePdp::new(settings(&server), None).expect("a point");
    let subject = subject();
    let query = Request::new(&subject, "query.execute", "Query");
    assert!(matches!(
        pdp.decide(&query).await,
        Err(AuthzError::Remote(_))
    ));
    let mut gone = settings(&server);
    gone.server = Url::parse("http://127.0.0.1:9/pdp/").expect("a URL");
    let pdp = RemotePdp::new(gone, None).expect("a point");
    assert!(matches!(
        pdp.decide(&request(&subject, &["p-1"])).await,
        Err(AuthzError::Remote(_))
    ));
}

#[test]
fn settings_without_a_trailing_slash_are_refused() {
    let mut refused = RemoteSettings {
        server: Url::parse("https://pdp.example.org/pdp").expect("a URL"),
        bindings: BTreeMap::new(),
        connect_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(1),
    };
    assert!(matches!(
        RemotePdp::new(refused.clone(), None),
        Err(AuthzError::Remote(_))
    ));
    refused.server = Url::parse("ftp://pdp.example.org/pdp/").expect("a URL");
    assert!(matches!(
        RemotePdp::new(refused, None),
        Err(AuthzError::Remote(_))
    ));
}

#[tokio::test]
async fn a_refused_token_is_renewed_once() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "Qz7-first", "token_type": "Bearer", "expires_in": 300
        })))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "Qz7-second", "token_type": "Bearer", "expires_in": 300
        })))
        .with_priority(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/pdp/composition"))
        .and(header("authorization", "Bearer Qz7-first"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/pdp/composition"))
        .and(header("authorization", "Bearer Qz7-second"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let grant = ClientCredentials::new(
        Endpoint::Token(Url::parse(&format!("{}/token", server.uri())).expect("a URL")),
        String::from("Qz7-pep"),
        SecretString::from("Qz7-secret"),
    );
    let pdp = RemotePdp::new(
        settings(&server),
        Some(TokenSource::new(grant).expect("a source")),
    )
    .expect("a point");
    let subject = subject();
    assert!(
        pdp.decide(&request(&subject, &["p-1"]))
            .await
            .expect("decides")
            .is_permit()
    );
}
