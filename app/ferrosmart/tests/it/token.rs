// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The token endpoint's client credentials grant, through the whole stack
//! against a real PostgreSQL: SMART App Launch 2.2.0, Backend Services,
//! with the client assertion of Client Authentication: Asymmetric, each
//! refusal its own case.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrosmart::server::{AppState, router};
use ferrosmart::store::Store;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use jsonwebtoken::Algorithm;
use jsonwebtoken::jwk::JwkSet;
use serde_json::{Value, json};
use tower::ServiceExt as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::support::{Database, Keys, RESOURCE, config, ec_key, rsa_key};

/// The issuer every case configures.
const ISSUER: &str = "https://smart.example.org";
/// The token endpoint of [`ISSUER`].
const TOKEN_URL: &str = "https://smart.example.org/token";
/// The assertion type of RFC 7523 §2.2.
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// A running server over a fresh database, with one Backend Services client.
struct Server {
    /// The application.
    app: Router,
    /// The client's signing key.
    key: AssertionKey,
    /// The client's key in PEM form.
    pem: Vec<u8>,
    /// The keys and the database, kept for the case's length.
    _keys: Keys,
    /// The database.
    database: Option<Database>,
    /// The store.
    store: Store,
}

impl Server {
    /// Starts a server whose client `export` registers its key by value
    /// (`jwks_uri` empty) or at `jwks_uri`.
    async fn start(jwks_uri: Option<&str>, algorithm: Algorithm) -> Self {
        let keys = Keys::new();
        let pem_path = if algorithm == Algorithm::ES384 {
            ec_key(keys.dir.path(), "client.pem")
        } else {
            rsa_key(keys.dir.path(), "client.pem")
        };
        let pem = std::fs::read(&pem_path).expect("the key reads");
        let key = AssertionKey::from_pem(&pem, Some(algorithm), Some(String::from("client-1")))
            .expect("a client key");
        let registration = jwks_uri.map_or_else(
            || {
                let set = keys.dir.path().join("client-jwks.json");
                std::fs::write(&set, json!({"keys": [key.public_jwk()]}).to_string())
                    .expect("written");
                format!("jwks_file = {:?}", set.display().to_string())
            },
            |uri| format!("jwks_uri = {uri:?}"),
        );
        let database = Database::create().await;
        let text = format!(
            "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.database]\nurl = {:?}\n\
             [[ferrosmart.client]]\nclient_id = \"export\"\nkind = \"confidential_asymmetric\"\n{registration}\n\
             scopes = [\"system/Patient.rs\", \"system/Observation.rs\"]\ngrant_types = [\"client_credentials\"]\n\
             [[ferrosmart.client]]\nclient_id = \"app\"\nkind = \"public\"\n\
             redirect_uris = [\"https://app.example.org/callback\"]\ngrant_types = [\"authorization_code\"]",
            secrecy::ExposeSecret::expose_secret(&database.url)
        );
        let settings = config(&text, &keys).resolve().expect("resolves");
        let store = Store::connect(&settings.database_url, 2)
            .await
            .expect("connects");
        store.migrate().await.expect("migrates");
        store.register(&settings.clients).await.expect("registered");
        let app = router(Arc::new(AppState::new(settings, store.clone())));
        Self {
            app,
            key,
            pem,
            _keys: keys,
            database: Some(database),
            store,
        }
    }

    /// Posts `form` to the token endpoint and returns the status, the
    /// headers and the JSON body.
    async fn post(&self, form: &[(&str, &str)]) -> (StatusCode, http::HeaderMap, Value) {
        let body: String = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        self.post_raw("application/x-www-form-urlencoded", body)
            .await
    }

    /// Posts `body` as `content_type` to the token endpoint.
    async fn post_raw(
        &self,
        content_type: &str,
        body: String,
    ) -> (StatusCode, http::HeaderMap, Value) {
        let request = Request::post("/token")
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(body))
            .expect("a request");
        let response = self.app.clone().oneshot(request).await.expect("an answer");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("the body")
            .to_bytes();
        (
            status,
            headers,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Returns an assertion signed by the client's key over `claims`.
    fn assertion(&self, typ: &str, claims: &Value) -> String {
        self.key.sign(typ, claims).expect("signs")
    }

    /// Drops the database.
    async fn stop(mut self) {
        if let Some(database) = self.database.take() {
            database.drop(self.store).await;
        }
    }
}

/// Returns the claims of a valid assertion of `export`.
fn valid_claims() -> Value {
    let now = jiff::Timestamp::now().as_second();
    json!({"iss": "export", "sub": "export", "aud": TOKEN_URL, "exp": now + 120, "jti": unique()})
}

/// Returns an id no other assertion of the run carries.
fn unique() -> String {
    let mut bytes = [0_u8; 12];
    aws_lc_rs::rand::fill(&mut bytes).expect("draws");
    bytes.iter().fold(String::new(), |mut id, byte| {
        use std::fmt::Write as _;
        write!(id, "{byte:02x}").expect("a String takes every write");
        id
    })
}

/// Returns the form of a client credentials request carrying `assertion`.
fn form<'a>(assertion: &'a str, scope: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("grant_type", "client_credentials"),
        ("client_assertion_type", JWT_BEARER),
        ("client_assertion", assertion),
        ("scope", scope),
    ]
}

/// Returns the `error` of a refusal, asserting the status and the headers
/// every token response carries.
fn refused(answer: &(StatusCode, http::HeaderMap, Value)) -> String {
    assert_eq!(StatusCode::BAD_REQUEST, answer.0, "{:?}", answer.2);
    assert_eq!(
        Some("no-store"),
        answer
            .1
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        "SMART App Launch 2.2.0, a token response is never cached"
    );
    assert!(
        answer
            .2
            .get("error_description")
            .is_some_and(Value::is_string),
        "SMART Backend Services, an error_description"
    );
    answer
        .2
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn a_backend_services_client_gets_an_rfc_9068_token() {
    let server = Server::start(None, Algorithm::ES384).await;
    let assertion = server.assertion("JWT", &valid_claims());
    let (status, headers, body) = server
        .post(&form(
            &assertion,
            "system/Observation.rs system/Encounter.rs",
        ))
        .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    // NOTE: SMART App Launch 2.2.0, Obtain access token, Response.
    assert_eq!(
        Some("no-store"),
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
    );
    assert_eq!(
        Some("no-cache"),
        headers.get(header::PRAGMA).and_then(|v| v.to_str().ok())
    );
    // NOTE: SMART App Launch 2.2.0, Backend Services, Issue Access Token.
    assert_eq!(json!("bearer"), body["token_type"]);
    assert_eq!(json!(300), body["expires_in"]);
    assert_eq!(
        json!("system/Observation.rs"),
        body["scope"],
        "only the ceiling's scopes"
    );
    assert_eq!(
        Value::Null,
        body["refresh_token"],
        "Refresh tokens SHOULD NOT be issued"
    );

    let token = body["access_token"].as_str().expect("a token");
    let header = jsonwebtoken::decode_header(token).expect("a JWT");
    // NOTE: RFC 9068 §2.1, typ at+jwt, signed with RS256.
    assert_eq!(Some(String::from("at+jwt")), header.typ);
    assert_eq!(Algorithm::RS256, header.alg);
    let published: JwkSet =
        serde_json::from_value(server.post_get_jwks().await).expect("a JWK Set");
    let jwk = published
        .find(header.kid.as_deref().expect("a kid"))
        .expect("published");
    let mut validation = jsonwebtoken::Validation::new(Algorithm::RS256);
    validation.set_audience(&[RESOURCE]);
    validation.set_issuer(&[ISSUER]);
    validation.set_required_spec_claims(&["iss", "exp", "aud", "sub"]);
    let claims: Value = jsonwebtoken::decode(
        token,
        &jsonwebtoken::DecodingKey::from_jwk(jwk).expect("a key"),
        &validation,
    )
    .expect("verifies")
    .claims;
    // NOTE: RFC 9068 §2.2, the required claims; sub is the client (§2.2, §5).
    assert_eq!(json!("export"), claims["sub"]);
    assert_eq!(json!("export"), claims["client_id"]);
    assert_eq!(json!("system/Observation.rs"), claims["scope"]);
    assert!(claims["iat"].is_i64() && claims["jti"].is_string());
    server.stop().await;
}

impl Server {
    /// Returns the published JWK Set.
    async fn post_get_jwks(&self) -> Value {
        let request = Request::get("/jwks")
            .body(Body::empty())
            .expect("a request");
        let response = self.app.clone().oneshot(request).await.expect("an answer");
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("the body")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("JSON")
    }
}

#[tokio::test]
async fn an_rs384_assertion_typed_by_rfc_10070_naming_the_issuer_is_admitted() {
    let server = Server::start(None, Algorithm::RS384).await;
    let mut claims = valid_claims();
    claims["aud"] = json!(ISSUER);
    let assertion = server.assertion("client-authentication+jwt", &claims);
    let (status, _, body) = server.post(&form(&assertion, "system/Patient.rs")).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    server.stop().await;
}

#[tokio::test]
async fn the_assertion_s_audience_is_one_string_naming_this_server() {
    let server = Server::start(None, Algorithm::ES384).await;
    // NOTE: docs/architecture.md §13.6 item 1, RFC 10070 §4 "sole value".
    for aud in [
        json!([TOKEN_URL]),
        json!([TOKEN_URL, ISSUER]),
        json!("https://other.example.org/token"),
        json!(format!("{ISSUER}/")),
    ] {
        let mut claims = valid_claims();
        claims["aud"] = aud.clone();
        let assertion = server.assertion("JWT", &claims);
        assert_eq!(
            "invalid_client",
            refused(&server.post(&form(&assertion, "system/Patient.rs")).await),
            "{aud}"
        );
    }
    server.stop().await;
}

#[tokio::test]
async fn a_replayed_or_long_lived_or_unsigned_assertion_is_refused() {
    let server = Server::start(None, Algorithm::ES384).await;
    let claims = valid_claims();
    let assertion = server.assertion("JWT", &claims);
    assert_eq!(
        StatusCode::OK,
        server.post(&form(&assertion, "system/Patient.rs")).await.0
    );
    // NOTE: SMART App Launch 2.2.0, Signature Verification, the jti check.
    assert_eq!(
        "invalid_client",
        refused(&server.post(&form(&assertion, "system/Patient.rs")).await)
    );

    let mut long = valid_claims();
    long["exp"] = json!(jiff::Timestamp::now().as_second() + 3600);
    let assertion = server.assertion("JWT", &long);
    assert_eq!(
        "invalid_client",
        refused(&server.post(&form(&assertion, "system/Patient.rs")).await)
    );

    let mut expired = valid_claims();
    expired["exp"] = json!(jiff::Timestamp::now().as_second() - 3600);
    let assertion = server.assertion("JWT", &expired);
    assert_eq!(
        "invalid_client",
        refused(&server.post(&form(&assertion, "system/Patient.rs")).await)
    );

    let valid = server.assertion("JWT", &valid_claims());
    let mut tampered: Vec<&str> = valid.split('.').collect();
    let foreign = server.assertion("JWT", &valid_claims());
    let foreign_signature = foreign.rsplit('.').next().expect("a signature");
    tampered[2] = foreign_signature;
    let tampered = tampered.join(".");
    assert_eq!(
        "invalid_client",
        refused(&server.post(&form(&tampered, "system/Patient.rs")).await)
    );
    server.stop().await;
}

#[tokio::test]
async fn an_assertion_breaking_the_profile_is_refused() {
    let server = Server::start(None, Algorithm::ES384).await;
    let other = valid_claims();
    let mut unknown = valid_claims();
    unknown["iss"] = json!("nobody");
    unknown["sub"] = json!("nobody");
    let mut public = valid_claims();
    public["iss"] = json!("app");
    public["sub"] = json!("app");
    let mut split = valid_claims();
    split["sub"] = json!("someone-else");
    for (typ, claims, case) in [
        ("JOSE", &other, "a typ outside the two"),
        ("JWT", &unknown, "an unregistered client"),
        ("JWT", &public, "a public client"),
        ("JWT", &split, "a sub that is not the iss"),
    ] {
        let assertion = server.assertion(typ, claims);
        assert_eq!(
            "invalid_client",
            refused(&server.post(&form(&assertion, "system/Patient.rs")).await),
            "{case}"
        );
    }
    let assertion = server.assertion("JWT", &valid_claims());
    let mut wrong_type = form(&assertion, "system/Patient.rs");
    wrong_type[1] = ("client_assertion_type", "not_an_assertion_type");
    assert_eq!("invalid_client", refused(&server.post(&wrong_type).await));
    let mut no_assertion = form(&assertion, "system/Patient.rs");
    no_assertion.remove(2);
    assert_eq!("invalid_client", refused(&server.post(&no_assertion).await));
    server.stop().await;
}

#[tokio::test]
async fn a_request_outside_the_grant_is_refused_with_its_own_error() {
    let server = Server::start(None, Algorithm::ES384).await;
    let assertion = server.assertion("JWT", &valid_claims());
    let mut grant = form(&assertion, "system/Patient.rs");
    grant[0] = ("grant_type", "password");
    assert_eq!(
        "unsupported_grant_type",
        refused(&server.post(&grant).await)
    );
    let mut none = form(&assertion, "system/Patient.rs");
    none.remove(0);
    assert_eq!("invalid_request", refused(&server.post(&none).await));
    let mut twice = form(&assertion, "system/Patient.rs");
    twice.push(("scope", "system/Observation.rs"));
    assert_eq!(
        "invalid_request",
        refused(&server.post(&twice).await),
        "RFC 6749 §3.2"
    );
    assert_eq!(
        "invalid_request",
        refused(
            &server
                .post_raw("application/json", String::from("{}"))
                .await
        )
    );

    let assertion = server.assertion("JWT", &valid_claims());
    assert_eq!(
        "invalid_scope",
        refused(&server.post(&form(&assertion, "system/Encounter.rs")).await)
    );
    let assertion = server.assertion("JWT", &valid_claims());
    let mut target = form(&assertion, "system/Patient.rs");
    target.push(("resource", "https://other.example.org/fhir"));
    assert_eq!(
        "invalid_target",
        refused(&server.post(&target).await),
        "RFC 8707 §2"
    );
    let assertion = server.assertion("JWT", &valid_claims());
    let mut named = form(&assertion, "system/Patient.rs");
    named.push(("resource", RESOURCE));
    assert_eq!(StatusCode::OK, server.post(&named).await.0);
    server.stop().await;
}

#[tokio::test]
async fn a_jwk_set_url_is_read_and_cached_as_the_client_allows() {
    let jwks = MockServer::start().await;
    let server_url = format!("{}/jwks.json", jwks.uri());
    let server = Server::start(Some(&server_url), Algorithm::ES384).await;
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("cache-control", "max-age=600")
                .set_body_json(json!({"keys": [server.key.public_jwk()]})),
        )
        .expect(1)
        .mount(&jwks)
        .await;
    for _ in 0..2 {
        let assertion = server.assertion("JWT", &valid_claims());
        assert_eq!(
            StatusCode::OK,
            server.post(&form(&assertion, "system/Patient.rs")).await.0
        );
    }
    // NOTE: SMART App Launch 2.2.0, Signature Verification, step 1: a jku is
    // the registered URL, or the verification fails.
    let encoding = jsonwebtoken::EncodingKey::from_ec_pem(&server.pem).expect("the key reads");
    for (jku, admitted) in [
        (server_url.as_str(), true),
        ("https://attacker.example.org/jwks.json", false),
    ] {
        let mut header = jsonwebtoken::Header::new(Algorithm::ES384);
        header.kid = Some(String::from("client-1"));
        header.typ = Some(String::from("JWT"));
        header.jku = Some(jku.to_owned());
        let assertion = jsonwebtoken::encode(&header, &valid_claims(), &encoding).expect("signs");
        let answer = server.post(&form(&assertion, "system/Patient.rs")).await;
        if admitted {
            assert_eq!(StatusCode::OK, answer.0, "{}", answer.2);
        } else {
            assert_eq!("invalid_client", refused(&answer));
        }
    }
    server.stop().await;
    jwks.verify().await;
}
