// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The upstream credential a product obtains with the OAuth 2.0 client
//! credentials grant: discovery, the token request in the three client
//! authentication forms, the cache, the renewal after a refused token, and
//! every refusal of the authorization server as a typed error.

use std::error::Error as StdError;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use ferrohealth_smart::client::CallError;
use ferrohealth_smart::client::ClientAuth;
use ferrohealth_smart::client::ClientCredentials;
use ferrohealth_smart::client::Endpoint;
use ferrohealth_smart::client::TokenError;
use ferrohealth_smart::client::assertion::ASSERTION_TYPE;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrohealth_smart::client::assertion::jwk_set;
use ferrohealth_smart::client::assertion::thumbprint;
use ferrohealth_smart::client::cache::Clock;
use ferrohealth_smart::client::cache::Token;
use ferrohealth_smart::client::cache::TokenSource;
use ferrohealth_smart::metadata::DiscoveryError;
use http::StatusCode;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;
use jsonwebtoken::jwk::Jwk;
use secrecy::SecretString;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::Request;
use wiremock::ResponseTemplate;
use wiremock::matchers::body_string_contains;
use wiremock::matchers::header;
use wiremock::matchers::method;
use wiremock::matchers::path;

use crate::support::ec_key;
use crate::support::rsa_key;

/// The token endpoint path every stub serves.
const TOKEN_PATH: &str = "/oauth/token";

/// The upstream route the calls reach.
const UPSTREAM: &str = "/v1/ehr";

/// Returns a grant against the token endpoint of `server`.
fn grant(server: &MockServer) -> Result<ClientCredentials, Box<dyn StdError>> {
    let mut config = ClientCredentials::new(
        Endpoint::Token(format!("{}{TOKEN_PATH}", server.uri()).parse()?),
        String::from("bridge"),
        SecretString::from("synthetic-secret"),
    );
    config.timeout = Duration::from_secs(5);
    Ok(config)
}

/// Returns an access token response for `token` living `expires_in` seconds.
fn issued(token: &str, expires_in: u64) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    }))
}

/// Returns how many requests `server` received on `route`.
async fn received(server: &MockServer, route: &str) -> Result<usize, Box<dyn StdError>> {
    Ok(server
        .received_requests()
        .await
        .ok_or("the mock server is recording")?
        .iter()
        .filter(|request: &&Request| request.url.path() == route)
        .count())
}

/// Returns the header text of `token`.
fn header_of(token: &Arc<Token>) -> Result<String, Box<dyn StdError>> {
    Ok(token.header().to_str()?.to_owned())
}

/// Returns the form parameters of the `index`th request `server` received
/// on the token endpoint.
async fn token_request_form(
    server: &MockServer,
    index: usize,
) -> Result<Vec<(String, String)>, Box<dyn StdError>> {
    let requests = server.received_requests().await.ok_or("recording")?;
    let request = requests
        .iter()
        .filter(|request| request.url.path() == TOKEN_PATH)
        .nth(index)
        .ok_or("a token request")?;
    Ok(url::form_urlencoded::parse(&request.body)
        .into_owned()
        .collect())
}

/// Returns the value of `name` in `form`.
fn param(form: &[(String, String)], name: &str) -> Option<String> {
    form.iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
}

/// A clock the test moves by hand.
#[derive(Debug)]
struct ManualClock(Mutex<Instant>);

impl ManualClock {
    fn advance(&self, by: Duration) {
        let mut now = self.0.lock().expect("the clock is not poisoned");
        *now += by;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        *self.0.lock().expect("the clock is not poisoned")
    }
}

#[tokio::test]
async fn the_token_endpoint_is_discovered_from_rfc_8414_metadata() -> Result<(), Box<dyn StdError>>
{
    // NOTE: RFC 8414 §3.1 inserts the well-known suffix before the issuer's
    // path, and §3.3 requires the document's issuer to be the configured one.
    let server = MockServer::start().await;
    let issuer = format!("{}/realms/ferro", server.uri());
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server/realms/ferro"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer,
            "token_endpoint": format!("{}{TOKEN_PATH}", server.uri()),
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(issued("synthetic-token-1", 300))
        .expect(1)
        .mount(&server)
        .await;

    let config = ClientCredentials::new(
        Endpoint::Issuer(issuer),
        String::from("bridge"),
        SecretString::from("synthetic-secret"),
    );
    let source = TokenSource::new(config)?;
    let token = source.token().await.map_err(|error| error.to_string())?;
    assert_eq!("Bearer synthetic-token-1", header_of(&token)?);
    Ok(())
}

#[tokio::test]
async fn discovery_falls_back_to_the_openid_connect_location() -> Result<(), Box<dyn StdError>> {
    // NOTE: OpenID Connect Discovery 1.0 §4 appends the suffix to the issuer;
    // it is read only after the RFC 8414 location answers 404.
    let server = MockServer::start().await;
    let issuer = format!("{}/realms/ferro", server.uri());
    Mock::given(method("GET"))
        .and(path("/realms/ferro/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer,
            "token_endpoint": format!("{}{TOKEN_PATH}", server.uri()),
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(issued("synthetic-token-1", 300))
        .mount(&server)
        .await;

    let config = ClientCredentials::new(
        Endpoint::Issuer(issuer),
        String::from("bridge"),
        SecretString::from("synthetic-secret"),
    );
    assert!(TokenSource::new(config)?.token().await.is_ok());
    Ok(())
}

#[tokio::test]
async fn metadata_naming_another_issuer_or_no_token_endpoint_is_refused()
-> Result<(), Box<dyn StdError>> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server/realms/ferro"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": "https://attacker.invalid",
            "token_endpoint": format!("{}{TOKEN_PATH}", server.uri()),
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server/realms/bare"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": format!("{}/realms/bare", server.uri()),
        })))
        .mount(&server)
        .await;

    let config = ClientCredentials::new(
        Endpoint::Issuer(format!("{}/realms/ferro", server.uri())),
        String::from("bridge"),
        SecretString::from("synthetic-secret"),
    );
    let error = TokenSource::new(config)?
        .token()
        .await
        .expect_err("RFC 8414 §3.3 refuses a mismatched issuer");
    assert!(
        matches!(
            error.as_ref(),
            TokenError::Discovery(DiscoveryError::IssuerMismatch { found, .. }) if found == "https://attacker.invalid"
        ),
        "{error:?}"
    );
    assert_eq!(
        0,
        received(&server, TOKEN_PATH).await?,
        "no token was asked"
    );

    let bare = ClientCredentials::new(
        Endpoint::Issuer(format!("{}/realms/bare", server.uri())),
        String::from("bridge"),
        SecretString::from("synthetic-secret"),
    );
    let error = TokenSource::new(bare)?
        .token()
        .await
        .expect_err("no token endpoint, no token");
    assert!(
        matches!(error.as_ref(), TokenError::NoTokenEndpoint),
        "{error:?}"
    );
    Ok(())
}

#[tokio::test]
async fn client_secret_basic_form_encodes_the_id_and_the_secret() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 6749 §2.3.1, base64 of "bridge+client:s3cr3t%2Fsecret", the
    // id and the secret form-encoded first (Appendix B).
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .and(header(
            "authorization",
            "Basic YnJpZGdlK2NsaWVudDpzM2NyM3QlMkZzZWNyZXQ=",
        ))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("scope=openehr+system%2F*.crs"))
        .and(body_string_contains("audience=ferroehr"))
        .and(body_string_contains(
            "resource=https%3A%2F%2Fcdr.example.org%2Fv1",
        ))
        .respond_with(issued("synthetic-token-1", 300))
        .expect(1)
        .mount(&server)
        .await;

    let mut config = ClientCredentials::new(
        Endpoint::Token(format!("{}{TOKEN_PATH}", server.uri()).parse()?),
        String::from("bridge client"),
        SecretString::from("s3cr3t/secret"),
    );
    config.scope = Some(String::from("openehr system/*.crs"));
    config.audience = Some(String::from("ferroehr"));
    config.resource = Some("https://cdr.example.org/v1".parse()?);
    assert!(TokenSource::new(config)?.token().await.is_ok());
    let form = token_request_form(&server, 0).await?;
    assert_eq!(
        None,
        param(&form, "client_secret"),
        "the secret is not in the body"
    );
    Ok(())
}

#[tokio::test]
async fn client_secret_post_carries_the_id_and_the_secret_in_the_body()
-> Result<(), Box<dyn StdError>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("client_id=bridge"))
        .and(body_string_contains("client_secret=synthetic-secret"))
        .respond_with(issued("synthetic-token-1", 300))
        .expect(1)
        .mount(&server)
        .await;

    let mut config = grant(&server)?;
    config.client_auth = ClientAuth::ClientSecretPost;
    assert!(TokenSource::new(config)?.token().await.is_ok());
    let requests = server.received_requests().await.ok_or("recording")?;
    let request = requests.first().ok_or("one request")?;
    assert!(
        !request.headers.contains_key("authorization"),
        "client_secret_post sends no Authorization header"
    );
    Ok(())
}

#[tokio::test]
async fn private_key_jwt_sends_a_signed_assertion_per_request() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 7523 §2.2 and §3, and SMART App Launch 2.2.0 Client
    // Authentication: Asymmetric, fix the assertion's header and claims.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .and(body_string_contains("grant_type=client_credentials"))
        .respond_with(issued("synthetic-token-1", 300))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(issued("synthetic-token-2", 300))
        .mount(&server)
        .await;

    let key = ec_key("unused", Algorithm::ES384);
    let assertion_key = AssertionKey::from_pem(&key.pem, None, None)?;
    assert_eq!(
        Algorithm::ES384,
        assertion_key.algorithm(),
        "an EC key signs ES384"
    );
    let public: Jwk = serde_json::from_value(assertion_key.public_jwk())?;
    assert_eq!(
        thumbprint(&public),
        assertion_key.kid(),
        "RFC 7638 §3, the thumbprint names the key"
    );
    let set = jwk_set(&[&assertion_key]);
    assert_eq!(1, set["keys"].as_array().ok_or("keys")?.len());
    assert_eq!(serde_json::json!("sig"), set["keys"][0]["use"]);
    assert_eq!(serde_json::json!("ES384"), set["keys"][0]["alg"]);
    assert!(!format!("{assertion_key:?}").contains("PRIVATE"));

    let endpoint = format!("{}{TOKEN_PATH}", server.uri());
    let mut config = ClientCredentials::with_private_key_jwt(
        Endpoint::Token(endpoint.parse()?),
        String::from("ferrobridge"),
        assertion_key,
    );
    config.timeout = Duration::from_secs(5);
    let source = TokenSource::new(config)?;
    let token = source.token().await.map_err(|error| error.to_string())?;
    assert_eq!("Bearer synthetic-token-1", header_of(&token)?);

    let form = token_request_form(&server, 0).await?;
    assert_eq!(
        Some(String::from(ASSERTION_TYPE)),
        param(&form, "client_assertion_type")
    );
    assert_eq!(None, param(&form, "client_secret"));
    let assertion = param(&form, "client_assertion").ok_or("the assertion")?;
    let header = jsonwebtoken::decode_header(&assertion)?;
    assert_eq!(Algorithm::ES384, header.alg);
    assert_eq!(Some(String::from("JWT")), header.typ);
    assert_eq!(Some(thumbprint(&public)), header.kid);
    let mut validation = Validation::new(Algorithm::ES384);
    validation.set_audience(&[endpoint.as_str()]);
    validation.set_issuer(&["ferrobridge"]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub", "jti"]);
    let decoding = DecodingKey::from_jwk(&public)?;
    let claims = jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(
        &assertion,
        &decoding,
        &validation,
    )?
    .claims;
    assert_eq!(Some(&serde_json::json!("ferrobridge")), claims.get("sub"));
    let exp = claims
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .ok_or("exp")?;
    let iat = claims
        .get("iat")
        .and_then(serde_json::Value::as_i64)
        .ok_or("iat")?;
    assert_eq!(300, exp - iat, "no more than five minutes");
    let first_jti = claims.get("jti").cloned();

    source.invalidate(token.header());
    assert!(source.token().await.is_ok());
    let second = token_request_form(&server, 1).await?;
    let second_assertion = param(&second, "client_assertion").ok_or("the second assertion")?;
    let second_claims = jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(
        &second_assertion,
        &decoding,
        &validation,
    )?
    .claims;
    assert_ne!(
        first_jti,
        second_claims.get("jti").cloned(),
        "one assertion per request"
    );
    Ok(())
}

#[tokio::test]
async fn an_assertion_key_takes_its_configured_kid_and_algorithm() -> Result<(), Box<dyn StdError>>
{
    let rsa = rsa_key("unused", Algorithm::RS256);
    let by_type = AssertionKey::from_pem(&rsa.pem, None, None)?;
    assert_eq!(
        Algorithm::RS384,
        by_type.algorithm(),
        "an RSA key signs RS384"
    );
    let named = AssertionKey::from_pem(
        &rsa.pem,
        Some(Algorithm::PS256),
        Some(String::from("2026-10")),
    )?;
    assert_eq!(Algorithm::PS256, named.algorithm());
    assert_eq!("2026-10", named.kid());
    assert_eq!(serde_json::json!("2026-10"), named.public_jwk()["kid"]);
    assert!(
        AssertionKey::from_pem(&rsa.pem, Some(Algorithm::ES256), None).is_err(),
        "an EC algorithm cannot sign with an RSA key"
    );
    assert!(
        AssertionKey::from_pem(&rsa.pem, Some(Algorithm::HS256), None).is_err(),
        "a symmetric algorithm signs no assertion"
    );
    assert!(AssertionKey::from_pem(b"not a pem", None, None).is_err());
    Ok(())
}

#[tokio::test]
async fn a_cached_token_is_reused_and_never_rendered() -> Result<(), Box<dyn StdError>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(issued("synthetic-token-1", 300))
        .expect(1)
        .mount(&server)
        .await;

    let source = TokenSource::new(grant(&server)?)?;
    for _ in 0..3 {
        let token = source.token().await.map_err(|error| error.to_string())?;
        assert_eq!("Bearer synthetic-token-1", header_of(&token)?);
        assert!(token.header().is_sensitive());
        assert!(!format!("{token:?}").contains("synthetic-token-1"));
    }
    let rendered = format!("{source:?}");
    assert!(
        !rendered.contains("synthetic-token-1") && !rendered.contains("synthetic-secret"),
        "the Debug rendering of the cache carries neither the token nor the secret"
    );
    Ok(())
}

#[tokio::test]
async fn a_token_is_renewed_the_margin_before_it_expires() -> Result<(), Box<dyn StdError>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(issued("synthetic-token-1", 300))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(issued("synthetic-token-2", 300))
        .mount(&server)
        .await;

    let clock = Arc::new(ManualClock(Mutex::new(Instant::now())));
    let source = TokenSource::with_clock(grant(&server)?, clock.clone())?;
    let first = source.token().await.map_err(|error| error.to_string())?;
    assert_eq!("Bearer synthetic-token-1", header_of(&first)?);

    clock.advance(Duration::from_secs(269));
    let still = source.token().await.map_err(|error| error.to_string())?;
    assert_eq!(
        "Bearer synthetic-token-1",
        header_of(&still)?,
        "within 300 - 30 seconds"
    );

    clock.advance(Duration::from_secs(2));
    let renewed = source.token().await.map_err(|error| error.to_string())?;
    assert_eq!("Bearer synthetic-token-2", header_of(&renewed)?);
    assert_eq!(2, received(&server, TOKEN_PATH).await?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_callers_share_one_fetch() -> Result<(), Box<dyn StdError>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(issued("synthetic-token-1", 300).set_delay(Duration::from_millis(200)))
        .mount(&server)
        .await;

    let source = TokenSource::new(grant(&server)?)?;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let source = source.clone();
        tasks.push(tokio::spawn(async move { source.token().await }));
    }
    for task in tasks {
        let token = task.await?.map_err(|error| error.to_string())?;
        assert_eq!("Bearer synthetic-token-1", header_of(&token)?);
    }
    assert_eq!(1, received(&server, TOKEN_PATH).await?);
    Ok(())
}

#[tokio::test]
async fn a_refused_grant_is_a_typed_error_with_the_oauth_error() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 6749 §5.2, a refused client answers `invalid_client`.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_client",
            "error_description": "unknown client",
        })))
        .mount(&server)
        .await;

    let error = TokenSource::new(grant(&server)?)?
        .token()
        .await
        .expect_err("a refused grant is no token");
    match error.as_ref() {
        TokenError::Refused {
            status,
            error: Some(oauth),
            ..
        } => {
            assert_eq!(StatusCode::BAD_REQUEST, *status);
            assert_eq!("invalid_client", oauth.error);
            assert_eq!(Some("unknown client"), oauth.error_description.as_deref());
        }
        other => return Err(format!("expected the OAuth refusal, got {other:?}").into()),
    }
    assert!(!format!("{error:?}").contains("synthetic-secret"));
    Ok(())
}

#[tokio::test]
async fn a_failing_token_endpoint_keeps_its_status_and_is_not_cached()
-> Result<(), Box<dyn StdError>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(ResponseTemplate::new(503).set_body_string("restarting"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(issued("synthetic-token-1", 300))
        .mount(&server)
        .await;

    let source = TokenSource::new(grant(&server)?)?;
    let error = source.token().await.expect_err("a 503 is no token");
    assert!(
        matches!(error.as_ref(), TokenError::Refused { status, error: None, body } if *status == StatusCode::SERVICE_UNAVAILABLE && body == "restarting"),
        "{error:?}"
    );
    assert_eq!(Some(StatusCode::SERVICE_UNAVAILABLE), error.status());
    assert!(source.token().await.is_ok(), "the next call fetches again");
    Ok(())
}

#[tokio::test]
async fn a_malformed_or_non_bearer_token_response_is_a_typed_error() -> Result<(), Box<dyn StdError>>
{
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"token_type": "Bearer"})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "synthetic-token-1",
            "token_type": "DPoP",
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "not a b64token",
            "token_type": "bearer",
        })))
        .mount(&server)
        .await;

    let source = TokenSource::new(grant(&server)?)?;
    let error = source
        .token()
        .await
        .expect_err("RFC 6749 §5.1 requires access_token");
    assert!(
        matches!(error.as_ref(), TokenError::Malformed { .. }),
        "{error:?}"
    );
    let error = source
        .token()
        .await
        .expect_err("the product sends bearer tokens");
    assert!(
        matches!(error.as_ref(), TokenError::TokenType { found } if found == "DPoP"),
        "{error:?}"
    );
    let error = source.token().await.expect_err("RFC 6750 §2.1 b64token");
    assert!(matches!(error.as_ref(), TokenError::Unusable), "{error:?}");
    Ok(())
}

#[tokio::test]
async fn a_token_type_is_compared_case_insensitively() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 6749 §5.1, the `token_type` value is case insensitive.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "synthetic-token-1",
            "token_type": "bearer",
        })))
        .mount(&server)
        .await;
    assert!(TokenSource::new(grant(&server)?)?.token().await.is_ok());
    Ok(())
}

/// Mounts the token endpoint answering `first` once and `second` after.
async fn two_tokens(server: &MockServer, first: &str, second: &str) {
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(issued(first, 300))
        .up_to_n_times(1)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(issued(second, 300))
        .mount(server)
        .await;
}

/// Sends a `GET` of the upstream route under `header`.
fn call(
    server: &MockServer,
    header: http::HeaderValue,
) -> impl Future<Output = Result<reqwest::Response, reqwest::Error>> {
    let url = format!("{}{UPSTREAM}", server.uri());
    async move {
        reqwest::Client::new()
            .get(url)
            .header(http::header::AUTHORIZATION, header)
            .send()
            .await
    }
}

#[tokio::test]
async fn a_refused_token_is_renewed_and_the_call_sent_once_more() -> Result<(), Box<dyn StdError>> {
    let server = MockServer::start().await;
    two_tokens(&server, "synthetic-token-1", "synthetic-token-2").await;
    Mock::given(method("GET"))
        .and(path(UPSTREAM))
        .and(header("authorization", "Bearer synthetic-token-1"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(UPSTREAM))
        .and(header("authorization", "Bearer synthetic-token-2"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&server)
        .await;

    let source = TokenSource::new(grant(&server)?)?;
    let response = source
        .call(|header| call(&server, header))
        .await
        .map_err(|error| error.to_string())?;
    assert_eq!(StatusCode::OK, response.status());
    assert_eq!(2, received(&server, TOKEN_PATH).await?);
    let again = source
        .call(|header| call(&server, header))
        .await
        .map_err(|error| error.to_string())?;
    assert_eq!(StatusCode::OK, again.status(), "the renewed token is held");
    assert_eq!(2, received(&server, TOKEN_PATH).await?, "no third fetch");
    Ok(())
}

#[tokio::test]
async fn a_second_refusal_reaches_the_caller_and_renews_only_once() -> Result<(), Box<dyn StdError>>
{
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(issued("synthetic-token-1", 300))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(UPSTREAM))
        .respond_with(ResponseTemplate::new(401).insert_header("WWW-Authenticate", "Bearer"))
        .expect(2)
        .mount(&server)
        .await;

    let source = TokenSource::new(grant(&server)?)?;
    let response = source
        .call(|header| call(&server, header))
        .await
        .map_err(|error| error.to_string())?;
    assert_eq!(StatusCode::UNAUTHORIZED, response.status());
    assert_eq!(2, received(&server, TOKEN_PATH).await?, "one renewal");
    assert_eq!(
        2,
        received(&server, UPSTREAM).await?,
        "two attempts, never a third"
    );
    Ok(())
}

#[tokio::test]
async fn a_renewal_that_fails_after_a_refusal_carries_the_token_error()
-> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 6749 §5.2, `invalid_grant` is final for the grant, so the call
    // ends after one renewal and the token endpoint is never asked again.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(issued("synthetic-token-1", 300))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(UPSTREAM))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;

    let source = TokenSource::new(grant(&server)?)?;
    let error = source
        .call(|header| call(&server, header))
        .await
        .expect_err("no renewed token, no second send");
    let CallError::Renewal(renewal) = &error else {
        return Err(format!("expected the renewal failure, got {error:?}").into());
    };
    assert!(
        matches!(renewal.token_error(), TokenError::Refused { error: Some(oauth), .. } if oauth.error == "invalid_grant"),
        "{renewal:?}"
    );
    assert_eq!(2, received(&server, TOKEN_PATH).await?);
    assert_eq!(
        1,
        received(&server, UPSTREAM).await?,
        "the upstream is asked once"
    );
    Ok(())
}

#[tokio::test]
async fn a_call_without_a_token_never_reaches_the_upstream() -> Result<(), Box<dyn StdError>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "invalid_client",
        })))
        .mount(&server)
        .await;

    let source = TokenSource::new(grant(&server)?)?;
    let error = source
        .call(|header| call(&server, header))
        .await
        .expect_err("no token, no call");
    assert!(
        matches!(&error, CallError::Token { source } if matches!(source.as_ref(), TokenError::Refused { status, .. } if *status == StatusCode::UNAUTHORIZED)),
        "{error:?}"
    );
    assert_eq!(0, received(&server, UPSTREAM).await?);
    Ok(())
}

#[tokio::test]
async fn a_failed_call_is_the_calls_own_error() -> Result<(), Box<dyn StdError>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(issued("synthetic-token-1", 300))
        .mount(&server)
        .await;

    let source = TokenSource::new(grant(&server)?)?;
    let error = source
        .call(|_header| async { Err::<http::Response<()>, &str>("the wire broke") })
        .await
        .expect_err("the call failed");
    assert!(
        matches!(
            error,
            CallError::Call {
                source: "the wire broke"
            }
        ),
        "{error:?}"
    );
    Ok(())
}
