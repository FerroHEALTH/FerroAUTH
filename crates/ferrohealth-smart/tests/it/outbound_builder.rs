// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The outbound client's builder: a clock the product moves drives the token
//! source's expiry, and an authorization the product supplies gives every
//! try its headers, is told of every answer, renews once on a `401` and
//! carries its refusal as the source. No specification governs the seam:
//! our own design (#422, #423).

use std::error::Error as StdError;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use ferrohealth_smart::client::cache::Clock;
use ferrohealth_smart::client::outbound::Authorization;
use ferrohealth_smart::client::outbound::Authorized;
use ferrohealth_smart::client::outbound::Authorizer;
use ferrohealth_smart::client::outbound::AuthorizerError;
use ferrohealth_smart::client::outbound::OutboundClient;
use ferrohealth_smart::client::outbound::OutboundError;
use ferrohealth_smart::client::outbound::SendError;
use ferrohealth_smart::config::endpoint::EndpointSection;
use http::HeaderMap;
use http::HeaderValue;
use http::Method;
use http::StatusCode;
use url::Url;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::header;
use wiremock::matchers::method;
use wiremock::matchers::path;

use crate::tls::PemTls;

const KEY: &str = "nvi.endpoint";

fn table(url: &str, extra: &str) -> EndpointSection {
    toml::from_str(&format!(
        "url = \"{url}\"\n[retry]\nmax_attempts = 3\ninitial_backoff = \"10ms\"\nmax_backoff = \"20ms\"\n{extra}"
    ))
    .expect("the table parses")
}

async fn received(server: &MockServer, at: &str) -> usize {
    server
        .received_requests()
        .await
        .expect("the server records requests")
        .iter()
        .filter(|request| request.url.path() == at)
        .count()
}

/// A clock the test moves by hand.
#[derive(Debug)]
struct ManualClock(Mutex<Instant>);

impl ManualClock {
    fn advance(&self, by: Duration) {
        *self.0.lock().expect("the clock is not poisoned") += by;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        *self.0.lock().expect("the clock is not poisoned")
    }
}

#[tokio::test]
async fn a_moved_clock_renews_the_token_exactly_once_past_its_margin() {
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
    for token in ["Qz7-first", "Qz7-second"] {
        Mock::given(method("GET"))
            .and(path("/fhir/Patient"))
            .and(header("authorization", format!("Bearer {token}").as_str()))
            .respond_with(ResponseTemplate::new(200).insert_header("x-token", token))
            .mount(&server)
            .await;
    }
    let endpoint = table(
        &format!("{}/fhir/", server.uri()),
        &format!(
            "[credentials.oauth]\ntoken_endpoint = \"{}/token\"\nclient_id = \"Qz7-client\"\nclient_secret = \"Qz7-secret\"\nrefresh_margin = \"60s\"\n",
            server.uri()
        ),
    );
    let clock = Arc::new(ManualClock(Mutex::new(Instant::now())));
    let client = OutboundClient::builder(&endpoint, KEY, &PemTls)
        .clock(clock.clone())
        .build()
        .expect("a client");
    let url = client.url().join("Patient").expect("a URL");
    let token = async || {
        let answer = client
            .send(&Method::GET, &url, |request| request)
            .await
            .expect("an answer");
        assert_eq!(answer.status(), StatusCode::OK);
        answer
            .headers()
            .get("x-token")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .expect("the answer names the token")
    };

    assert_eq!(token().await, "Qz7-first");
    clock.advance(Duration::from_secs(239));
    assert_eq!(token().await, "Qz7-first", "within 300 - 60 seconds");
    clock.advance(Duration::from_secs(2));
    assert_eq!(token().await, "Qz7-second");
    assert_eq!(token().await, "Qz7-second");
    assert_eq!(received(&server, "/token").await, 2, "exactly one renewal");
}

/// The test's own refusal, which must reach the caller as the source.
#[derive(Debug, thiserror::Error)]
#[error("the synthetic node gave no token")]
struct NoToken;

/// An authorization in the shape of a `DPoP`-bound grant: a token of its
/// own per generation, a proof per request over the method, the URL and the
/// last nonce, the nonce kept from any answer, and the token dropped when an
/// answer refuses it without demanding a nonce.
#[derive(Debug, Default)]
struct Bound {
    refuse: bool,
    state: Mutex<BoundState>,
}

#[derive(Debug, Default)]
struct BoundState {
    generation: u32,
    nonce: Option<String>,
    asked: Vec<(Method, String)>,
    told: Vec<StatusCode>,
}

impl Bound {
    fn state(&self) -> std::sync::MutexGuard<'_, BoundState> {
        self.state.lock().expect("the state is not poisoned")
    }
}

impl Authorizer for Bound {
    fn headers<'a>(&'a self, method: &'a Method, url: &'a Url) -> Authorized<'a> {
        Box::pin(async move {
            if self.refuse {
                return Err(AuthorizerError::new(NoToken));
            }
            let mut state = self.state();
            state.asked.push((method.clone(), url.to_string()));
            let nonce = state.nonce.as_deref().unwrap_or("none");
            let mut headers = HeaderMap::new();
            let mut token = HeaderValue::try_from(format!("DPoP Qz7-token-{}", state.generation))
                .map_err(AuthorizerError::new)?;
            token.set_sensitive(true);
            headers.insert(http::header::AUTHORIZATION, token);
            headers.insert(
                "dpop",
                HeaderValue::try_from(format!("{method} {} {nonce}", url.path()))
                    .map_err(AuthorizerError::new)?,
            );
            Ok(headers)
        })
    }

    fn answered(&self, _url: &Url, status: StatusCode, headers: &HeaderMap) {
        let mut state = self.state();
        state.told.push(status);
        let nonce = headers
            .get("dpop-nonce")
            .and_then(|value| value.to_str().ok());
        if let Some(nonce) = nonce {
            state.nonce = Some(nonce.to_owned());
        } else if status == StatusCode::UNAUTHORIZED {
            state.generation += 1;
        }
    }
}

fn plain_with(server: &MockServer, authorizer: Arc<Bound>) -> OutboundClient {
    OutboundClient::builder(&table(&format!("{}/fhir/", server.uri()), ""), KEY, &PemTls)
        .authorizer(authorizer)
        .build()
        .expect("a client")
}

#[tokio::test]
async fn every_request_carries_the_headers_of_its_method_and_url() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/fhir/Patient"))
        .and(header("authorization", "DPoP Qz7-token-0"))
        .and(header("dpop", "GET /fhir/Patient none"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/fhir/Bundle"))
        .and(header("authorization", "DPoP Qz7-token-0"))
        .and(header("dpop", "POST /fhir/Bundle none"))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&server)
        .await;
    let authorizer = Arc::new(Bound::default());
    let client = plain_with(&server, authorizer.clone());
    assert!(matches!(
        client.authorization(),
        Some(Authorization::Product(_))
    ));
    let patient = client.url().join("Patient").expect("a URL");
    let bundle = client.url().join("Bundle").expect("a URL");
    let get = client
        .send(&Method::GET, &patient, |request| {
            request.header("authorization", "Basic overridden")
        })
        .await
        .expect("an answer");
    assert_eq!(get.status(), StatusCode::OK);
    let post = client
        .send(&Method::POST, &bundle, |request| request.body("{}"))
        .await
        .expect("an answer");
    assert_eq!(post.status(), StatusCode::CREATED);
    let state = authorizer.state();
    assert_eq!(
        state.asked,
        [
            (Method::GET, patient.to_string()),
            (Method::POST, bundle.to_string())
        ]
    );
    assert_eq!(state.told, [StatusCode::OK, StatusCode::CREATED]);
}

#[tokio::test]
async fn a_401_is_told_and_renewed_once_and_a_second_401_is_answered() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(header("authorization", "DPoP Qz7-token-1"))
        .respond_with(ResponseTemplate::new(200))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .expect(3)
        .with_priority(2)
        .mount(&server)
        .await;
    let authorizer = Arc::new(Bound::default());
    let client = plain_with(&server, authorizer.clone());
    let url = client.url().join("Patient").expect("a URL");
    let renewed = client
        .send(&Method::GET, &url, |request| request)
        .await
        .expect("an answer");
    assert_eq!(renewed.status(), StatusCode::OK);
    assert_eq!(
        authorizer.state().told,
        [StatusCode::UNAUTHORIZED, StatusCode::OK]
    );

    let refused = client
        .send(&Method::GET, &url, |request| request)
        .await
        .expect("an answer");
    assert_eq!(
        refused.status(),
        StatusCode::UNAUTHORIZED,
        "renewed once only"
    );
    assert_eq!(authorizer.state().asked.len(), 4);
}

#[tokio::test]
async fn a_nonce_demand_is_kept_and_the_renewal_proves_it() {
    // NOTE: RFC 9449 §9, a resource server demands a nonce with a `401`, a
    // `use_dpop_nonce` challenge and the nonce in the `DPoP-Nonce` header.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(header("dpop", "GET /fhir/Patient none"))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("www-authenticate", "DPoP error=\"use_dpop_nonce\"")
                .insert_header("dpop-nonce", "Qz7-nonce"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(header("authorization", "DPoP Qz7-token-0"))
        .and(header("dpop", "GET /fhir/Patient Qz7-nonce"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let client = plain_with(&server, Arc::new(Bound::default()));
    let url = client.url().join("Patient").expect("a URL");
    let answer = client
        .send(&Method::GET, &url, |request| request)
        .await
        .expect("an answer");
    assert_eq!(answer.status(), StatusCode::OK);
}

#[tokio::test]
async fn every_retry_asks_the_authorization_again() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(header("authorization", "DPoP Qz7-token-0"))
        .respond_with(ResponseTemplate::new(200))
        .with_priority(2)
        .mount(&server)
        .await;
    let authorizer = Arc::new(Bound::default());
    let client = plain_with(&server, authorizer.clone());
    let url = client.url().join("Patient").expect("a URL");
    let answer = client
        .send(&Method::GET, &url, |request| request)
        .await
        .expect("an answer");
    assert_eq!(answer.status(), StatusCode::OK);
    let state = authorizer.state();
    assert_eq!(state.asked.len(), 3, "one set of headers per try");
    assert_eq!(
        state.told,
        [
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::OK
        ]
    );
}

#[tokio::test]
async fn a_refusal_carries_the_products_error_and_sends_nothing() {
    let server = MockServer::start().await;
    let authorizer = Arc::new(Bound {
        refuse: true,
        ..Bound::default()
    });
    let client = plain_with(&server, authorizer);
    let url = client.url().join("Patient").expect("a URL");
    let refused = client
        .send(&Method::GET, &url, |request| request)
        .await
        .expect_err("refused");
    assert!(
        matches!(refused, SendError::Authorization(_)),
        "{refused:?}"
    );
    let mut cause: Option<&(dyn StdError + 'static)> = Some(&refused);
    let mut root = false;
    while let Some(error) = cause {
        root |= error.downcast_ref::<NoToken>().is_some();
        cause = error.source();
    }
    assert!(root, "the product's error is in the source chain");
    assert_eq!(received(&server, "/fhir/Patient").await, 0);
}

#[test]
fn a_credential_beside_the_products_authorization_is_refused() {
    let endpoint = table(
        "https://nvi.example.org/fhir/",
        "[credentials]\nuser = \"Qz7-user\"\npassword = \"Qz7-pass\"\n",
    );
    let refused = OutboundClient::builder(&endpoint, KEY, &PemTls)
        .authorizer(Arc::new(Bound::default()))
        .build()
        .expect_err("refused");
    assert!(
        matches!(
            refused,
            OutboundError::CredentialBesideAuthorizer { key: KEY }
        ),
        "{refused:?}"
    );
}
