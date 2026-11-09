// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The outbound client built from an endpoint table: the TLS the product
//! builds reaches the integration, each credential kind authorizes the call,
//! the retry table is applied, and a refused table names its key. No
//! specification governs the seam or the retry rule: our own design (#397).

use std::time::Duration;
use std::time::Instant;

use ferrohealth_smart::client::outbound::Authorization;
use ferrohealth_smart::client::outbound::OutboundClient;
use ferrohealth_smart::client::outbound::OutboundError;
use ferrohealth_smart::client::outbound::SendError;
use ferrohealth_smart::config::endpoint::EndpointSection;
use http::Method;
use url::Url;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::header;
use wiremock::matchers::method;
use wiremock::matchers::path;

use crate::tls::Built;
use crate::tls::PemTls;

const KEY: &str = "pix.endpoint";

fn table(text: &str) -> EndpointSection {
    toml::from_str(text).expect("the table parses")
}

fn plain(url: &str, extra: &str) -> EndpointSection {
    table(&format!(
        "url = \"{url}\"\n[retry]\nmax_attempts = 3\ninitial_backoff = \"10ms\"\nmax_backoff = \"20ms\"\n{extra}"
    ))
}

async fn calls(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .expect("the server records requests")
        .len()
}

async fn get(client: &OutboundClient) -> Result<reqwest::Response, SendError> {
    let url = client.url().join("Patient").expect("a URL");
    client.send(&Method::GET, &url, |request| request).await
}

#[tokio::test]
async fn a_table_without_a_credential_sends_no_authorization() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/fhir/Patient"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let client =
        OutboundClient::build(&plain(&format!("{}/fhir/", server.uri()), ""), KEY, &PemTls)
            .expect("a client");
    assert!(client.authorization().is_none());
    assert_eq!(get(&client).await.expect("an answer").status(), 200);
    let seen = server.received_requests().await.expect("requests");
    assert!(
        seen.iter()
            .all(|request| !request.headers.contains_key("authorization")),
        "no credential was sent"
    );
}

#[tokio::test]
async fn a_basic_credential_authorizes_every_call() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/fhir/Patient"))
        // NOTE: RFC 7617 §2, base64 of "Qz7-user:Qz7-pass".
        .and(header("authorization", "Basic UXo3LXVzZXI6UXo3LXBhc3M="))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let endpoint = plain(
        &format!("{}/fhir/", server.uri()),
        "[credentials]\nuser = \"Qz7-user\"\npassword = \"Qz7-pass\"\n",
    );
    let client = OutboundClient::build(&endpoint, KEY, &PemTls).expect("a client");
    assert!(matches!(
        client.authorization(),
        Some(Authorization::Basic(_))
    ));
    assert_eq!(get(&client).await.expect("an answer").status(), 200);
}

#[tokio::test]
async fn a_client_credentials_grant_carries_its_token_and_renews_it_once_on_a_401() {
    let server = MockServer::start().await;
    for (token, priority, times) in [("Qz7-first", 1, Some(1)), ("Qz7-second", 2, None)] {
        let mock = Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": token, "token_type": "Bearer", "expires_in": 300
            })))
            .with_priority(priority);
        match times {
            Some(times) => mock.up_to_n_times(times).mount(&server).await,
            None => mock.mount(&server).await,
        }
    }
    Mock::given(method("GET"))
        .and(path("/fhir/Patient"))
        .and(header("authorization", "Bearer Qz7-first"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/fhir/Patient"))
        .and(header("authorization", "Bearer Qz7-second"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let endpoint = plain(
        &format!("{}/fhir/", server.uri()),
        &format!(
            "[credentials.oauth]\ntoken_endpoint = \"{}/token\"\nclient_id = \"Qz7-client\"\nclient_secret = \"Qz7-secret\"\n",
            server.uri()
        ),
    );
    let client = OutboundClient::build(&endpoint, KEY, &PemTls).expect("a client");
    assert!(matches!(
        client.authorization(),
        Some(Authorization::Bearer(_))
    ));
    assert_eq!(get(&client).await.expect("an answer").status(), 200);
}

#[tokio::test]
async fn a_server_error_is_tried_again_until_the_integration_answers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .with_priority(2)
        .mount(&server)
        .await;
    let client =
        OutboundClient::build(&plain(&format!("{}/fhir/", server.uri()), ""), KEY, &PemTls)
            .expect("a client");
    assert_eq!(get(&client).await.expect("an answer").status(), 200);
    assert_eq!(calls(&server).await, 3);
}

#[tokio::test]
async fn the_last_server_error_is_answered_after_max_attempts() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(502))
        .mount(&server)
        .await;
    let client =
        OutboundClient::build(&plain(&format!("{}/fhir/", server.uri()), ""), KEY, &PemTls)
            .expect("a client");
    assert_eq!(get(&client).await.expect("an answer").status(), 502);
    assert_eq!(calls(&server).await, 3);
}

#[tokio::test]
async fn a_client_error_is_answered_without_a_second_try() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let client =
        OutboundClient::build(&plain(&format!("{}/fhir/", server.uri()), ""), KEY, &PemTls)
            .expect("a client");
    assert_eq!(get(&client).await.expect("an answer").status(), 404);
    assert_eq!(calls(&server).await, 1);
}

#[tokio::test]
async fn a_timed_out_try_is_tried_again_and_redirects_are_not_followed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://elsewhere.invalid/"),
        )
        .with_priority(2)
        .mount(&server)
        .await;
    let endpoint = table(&format!(
        "url = \"{}/fhir/\"\ntimeout = \"200ms\"\n[retry]\nmax_attempts = 2\ninitial_backoff = \"10ms\"\nmax_backoff = \"10ms\"\n",
        server.uri()
    ));
    let client = OutboundClient::build(&endpoint, KEY, &PemTls).expect("a client");
    assert_eq!(get(&client).await.expect("an answer").status(), 302);
    assert_eq!(calls(&server).await, 2);
}

#[tokio::test]
async fn an_unreachable_integration_is_a_transport_error_after_every_try() {
    let endpoint = plain("http://127.0.0.1:9/fhir/", "");
    let client = OutboundClient::build(&endpoint, KEY, &PemTls).expect("a client");
    let started = Instant::now();
    assert!(matches!(get(&client).await, Err(SendError::Transport(_))));
    // The waits are 10 ms, then 20 ms.
    assert!(started.elapsed() >= Duration::from_millis(30));
}

#[test]
fn the_retry_delays_double_up_to_their_bound() {
    let endpoint = table(
        "url = \"https://x.example.org\"\n[retry]\nmax_attempts = 5\ninitial_backoff = \"100ms\"\nmax_backoff = \"300ms\"\n",
    );
    let delays: Vec<u64> = endpoint
        .retry
        .delays()
        .map(|delay| u64::try_from(delay.as_millis()).expect("milliseconds"))
        .collect();
    assert_eq!(delays, [100, 200, 300, 300]);
    let once = table("url = \"https://x.example.org\"\n[retry]\nmax_attempts = 1\n");
    assert_eq!(once.retry.delays().count(), 0);
}

#[tokio::test]
async fn the_tls_the_product_builds_reaches_the_integration() {
    let point = crate::tls::start("Qz7-unused").await;
    let identity = format!("{}{}", point.client_certificate_pem, point.client_key_pem);
    let presented =
        crate::tls::presented_identity(&point.ca_pem, &identity).expect("a configuration");
    let url = Url::parse(&point.url).expect("a URL");
    let client =
        OutboundClient::build(&plain(url.as_str(), ""), KEY, &Built(presented)).expect("a client");
    let answer = client
        .send(&Method::POST, &url, |request| request.body("{}"))
        .await
        .expect("an answer");
    assert_eq!(answer.status(), 200);
    let seen = point.seen();
    assert_eq!(seen.len(), 1);
    assert!(
        seen.iter().all(|request| request.certificate),
        "the handshake presented the product's client certificate"
    );
}

#[tokio::test]
async fn a_tls_the_integration_refuses_is_a_transport_error() {
    let point = crate::tls::start("Qz7-unused").await;
    let presented = crate::tls::presented_pem(&point.ca_pem, None).expect("a configuration");
    let url = Url::parse(&point.url).expect("a URL");
    let endpoint = table(&format!("url = \"{url}\"\n[retry]\nmax_attempts = 1\n"));
    let client = OutboundClient::build(&endpoint, KEY, &Built(presented)).expect("a client");
    assert!(matches!(
        client.send(&Method::POST, &url, |request| request).await,
        Err(SendError::Transport(_))
    ));
}

#[test]
fn a_refused_table_names_its_key() {
    for text in [
        "",
        "url = \"https://x.example.org\"\ntimeout = \"0s\"",
        "url = \"https://x.example.org\"\n[credentials]\nuser = \"a\"\n[credentials.oauth]\ntoken_endpoint = \"https://as.example.org/token\"\nclient_id = \"c\"\nclient_secret = \"s\"",
    ] {
        let refused = OutboundClient::build(&table(text), KEY, &PemTls).expect_err("refused");
        assert!(
            matches!(refused, OutboundError::Config { key: KEY, .. }),
            "{text:?}: {refused:?}"
        );
    }
}
