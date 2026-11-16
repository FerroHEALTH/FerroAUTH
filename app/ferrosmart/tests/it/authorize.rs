// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The authorization code flow through the whole stack against a real
//! PostgreSQL and a stub upstream OpenID Provider: SMART App Launch 2.2.0,
//! standalone launch, with the consent page between the login and the code.

use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use axum::Router;
use axum::body::Body;
use ferrosmart::authorize::{COOKIE, offer};
use ferrosmart::clients::{ClientKind, ClientSection, GrantType, resolve};
use ferrosmart::server::{AppState, router};
use ferrosmart::store::Store;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use url::Url;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

use crate::support::{Database, Keys, RESOURCE, config};

/// FerroSMART's issuer in every case.
const ISSUER: &str = "https://smart.example.org";
/// The app's redirect URI.
const REDIRECT: &str = "https://app.example.org/callback";
/// FerroSMART's client id at the provider.
const UPSTREAM_CLIENT: &str = "ferrosmart";
/// The deployment's SMART style document.
const STYLE: &str = "https://smart.example.org/smart-style.json";
/// The app's PKCE verifier and its S256 challenge (RFC 7636 Appendix B).
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// The challenge of [`VERIFIER`].
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// The stub upstream provider and its signing key.
struct Provider {
    /// The server.
    server: MockServer,
    /// The key its ID Tokens are signed with.
    encoding: EncodingKey,
}

impl Provider {
    /// Starts a provider serving its metadata and its key set.
    async fn start() -> Self {
        let server = MockServer::start().await;
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .expect("a key pair");
        let encoding = EncodingKey::from_ec_der(pkcs8.as_ref());
        let mut jwk = serde_json::to_value(
            Jwk::from_encoding_key(&encoding, Algorithm::ES256).expect("a JWK"),
        )
        .expect("serializes");
        if let Some(members) = jwk.as_object_mut() {
            members.insert(String::from("kid"), json!("op-1"));
            members.insert(String::from("use"), json!("sig"));
        }
        let uri = server.uri();
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/.well-known/oauth-authorization-server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": uri,
                "authorization_endpoint": format!("{uri}/authorize"),
                "token_endpoint": format!("{uri}/token"),
                "jwks_uri": format!("{uri}/jwks"),
                "code_challenge_methods_supported": ["S256"]
            })))
            .mount(&server)
            .await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
            .mount(&server)
            .await;
        Self { server, encoding }
    }

    /// Mounts the code exchange answering an ID Token with `nonce` for a
    /// person holding `roles`.
    async fn answer(&self, nonce: &str, roles: &[&str]) {
        let now = jiff::Timestamp::now().as_second();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(String::from("op-1"));
        let id_token = jsonwebtoken::encode(
            &header,
            &json!({
                "iss": self.server.uri(), "aud": UPSTREAM_CLIENT, "sub": "synthetic-person",
                "nonce": nonce, "iat": now, "exp": now + 300, "name": "Synthetic Clinician",
                "roles": roles, "fhir_user": "Practitioner/synthetic-1"
            }),
            &self.encoding,
        )
        .expect("signs");
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "synthetic-upstream-token", "token_type": "Bearer",
                "expires_in": 300, "id_token": id_token
            })))
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }
}

/// FerroSMART with a login upstream, over a fresh database.
struct Smart {
    /// The application.
    app: Router,
    /// The provider.
    provider: Provider,
    /// The store.
    store: Store,
    /// The database.
    database: Database,
    /// The keys, kept for the case's length.
    _keys: Keys,
}

impl Smart {
    /// Starts FerroSMART with the public app `app` and the clinician role.
    async fn start() -> Self {
        Self::start_with(
            "[\"authorization_code\"]",
            "[\"openid\", \"fhirUser\", \"user/Observation.rs\", \"user/Patient.rs\"]",
            "[\"user/Observation.rs\"]",
        )
        .await
    }

    /// Starts FerroSMART with the public app `app` registering the grant
    /// types `grants` and the ceiling `ceiling`, and the clinician role
    /// granting `role`, each a TOML array.
    async fn start_with(grants: &str, ceiling: &str, role: &str) -> Self {
        let provider = Provider::start().await;
        let keys = Keys::new();
        let database = Database::create().await;
        let text = format!(
            "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.database]\nurl = {:?}\n\
             [ferrosmart.upstream]\nissuer = {:?}\nclient_id = {UPSTREAM_CLIENT:?}\nfhir_user_claim = \"fhir_user\"\n\
             [ferrosmart.branding]\nsmart_style_url = {STYLE:?}\n\
             [[ferrosmart.role]]\nname = \"clinician\"\nscopes = {role}\n\
             [[ferrosmart.client]]\nclient_id = \"app\"\nname = \"Synthetic App\"\nkind = \"public\"\n\
             redirect_uris = [{REDIRECT:?}]\ngrant_types = {grants}\nscopes = {ceiling}",
            secrecy::ExposeSecret::expose_secret(&database.url),
            provider.server.uri()
        );
        let settings = config(&text, &keys).resolve().expect("resolves");
        let store = Store::connect(&settings.database_url, 2)
            .await
            .expect("connects");
        store.migrate().await.expect("migrates");
        store.register(&settings.clients).await.expect("registered");
        let callback =
            Url::parse(&settings.endpoint(ferrosmart::authorize::CALLBACK_ROUTE)).expect("a URL");
        let party = settings
            .upstream
            .as_ref()
            .expect("an upstream")
            .relying_party(callback)
            .await
            .expect("the provider is discovered");
        let state = AppState::new(settings, store.clone()).with_login(party);
        Self {
            app: router(Arc::new(state)),
            provider,
            store,
            database,
            _keys: keys,
        }
    }

    /// Sends `request` and returns the status, the headers and the body.
    async fn send(&self, request: Request<Body>) -> (StatusCode, http::HeaderMap, String) {
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
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    /// Gets `path` with the request cookie `cookie`, if any.
    async fn get(&self, path: &str, cookie: Option<&str>) -> (StatusCode, http::HeaderMap, String) {
        let mut request = Request::get(path);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, format!("{COOKIE}={cookie}"));
        }
        self.send(request.body(Body::empty()).expect("a request"))
            .await
    }

    /// Posts the form `pairs` to `path` with the cookie, if any.
    async fn post(
        &self,
        path: &str,
        pairs: &[(&str, &str)],
        cookie: Option<&str>,
    ) -> (StatusCode, http::HeaderMap, String) {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        let mut request =
            Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, format!("{COOKIE}={cookie}"));
        }
        self.send(request.body(Body::from(body)).expect("a request"))
            .await
    }

    /// Drops the database.
    async fn stop(self) {
        self.database.drop(self.store).await;
    }
}

/// Returns the authorization request with `overrides` over the defaults.
fn authorize_path(overrides: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", "app"),
        ("redirect_uri", REDIRECT),
        (
            "scope",
            "openid fhirUser user/Observation.rs user/Patient.rs launch/patient",
        ),
        ("state", "synthetic-state"),
        ("aud", RESOURCE),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("nonce", "synthetic-nonce"),
    ];
    for (name, value) in overrides {
        pairs.retain(|(kept, _)| kept != name);
        if !value.is_empty() {
            pairs.push((name, value));
        }
    }
    format!(
        "/authorize?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish()
    )
}

/// Returns the location of a `303`, parsed.
fn location(headers: &http::HeaderMap) -> Url {
    let location = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("a location");
    Url::parse(location).unwrap_or_else(|_relative| {
        Url::parse(ISSUER)
            .expect("a URL")
            .join(location)
            .expect("a URL")
    })
}

/// Returns the query parameter `name` of `url`.
fn param(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// Returns the cookie value a response set.
fn set_cookie(headers: &http::HeaderMap) -> String {
    let cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("a cookie");
    cookie
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value.to_owned())
        .expect("a value")
}

/// Runs the flow to the consent page and returns the cookie and the form
/// token it drew.
async fn to_consent(smart: &Smart, roles: &[&str]) -> (String, String) {
    to_consent_with(smart, roles, &[]).await
}

/// Runs the flow with the authorization request `overrides` to the consent
/// page and returns the cookie and the form token it drew.
async fn to_consent_with(
    smart: &Smart,
    roles: &[&str],
    overrides: &[(&str, &str)],
) -> (String, String) {
    let (status, headers, _) = smart.get(&authorize_path(overrides), None).await;
    assert_eq!(
        StatusCode::SEE_OTHER,
        status,
        "the authorization endpoint sends the browser on"
    );
    let upstream = location(&headers);
    assert!(
        upstream.as_str().starts_with(&smart.provider.server.uri()),
        "the browser goes to the provider"
    );
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer(&param(&upstream, "nonce").expect("a nonce"), roles)
        .await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(
        StatusCode::SEE_OTHER,
        status,
        "the callback sends the browser on"
    );
    assert_eq!("/consent", location(&headers).path(), "to the consent page");
    let (status, headers, page) = smart.get("/consent", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    let policy = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .expect("a policy");
    assert!(
        policy.contains("script-src 'self'")
            && policy.contains("form-action 'self' https://app.example.org"),
        "{policy}"
    );
    let token = page
        .split("name=\"form_token\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a form token")
        .to_owned();
    (cookie, token)
}

#[tokio::test]
async fn a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens() {
    let smart = Smart::start().await;
    let (cookie, token) = to_consent(&smart, &["clinician"]).await;
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    assert!(page.contains("Synthetic App") && page.contains("Synthetic Clinician"));
    assert_eq!(
        1,
        page.matches("<h1").count(),
        "the page card titles the page: {page}"
    );
    assert!(
        page.contains("<h1 class=\"fui-page-card-title\">Allow"),
        "{page}"
    );
    assert!(page.contains("user/Observation.rs"), "the role grants it");
    assert!(
        !page.contains("value=\"user/Patient.rs\""),
        "no role grants it"
    );
    assert!(
        !page.contains("value=\"launch/patient\""),
        "the picker arrives with #516"
    );

    let (status, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", &token),
                ("decision", "approve"),
                ("scope", "openid"),
                ("scope", "fhirUser"),
                ("scope", "user/Observation.rs"),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let back = location(&headers);
    assert!(back.as_str().starts_with(REDIRECT));
    // NOTE: RFC 6749 §4.1.2, the state; RFC 9207 §2, the iss.
    assert_eq!(Some(String::from("synthetic-state")), param(&back, "state"));
    assert_eq!(Some(String::from(ISSUER)), param(&back, "iss"));
    let code = param(&back, "code").expect("a code");

    let exchange = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_id", "app"),
    ];
    let (status, headers, body) = smart.post("/token", &exchange, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(
        Some("no-store"),
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
    );
    let body: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(json!("Bearer"), body["token_type"]);
    assert_eq!(json!("openid fhirUser user/Observation.rs"), body["scope"]);
    // NOTE: SMART App Launch 2.2.0, App Launch, the launch context parameters.
    assert_eq!(json!(STYLE), body["smart_style_url"]);
    let id_token = body["id_token"].as_str().expect("an ID Token");
    let claims: Value = jsonwebtoken::dangerous::insecure_decode_claims(id_token).expect("claims");
    // NOTE: OpenID Connect Core 1.0 §2; SMART App Launch 2.2.0, fhirUser.
    assert_eq!(json!(ISSUER), claims["iss"]);
    assert_eq!(json!("app"), claims["aud"]);
    assert_eq!(json!("synthetic-nonce"), claims["nonce"]);
    assert_eq!(json!("Practitioner/synthetic-1"), claims["fhirUser"]);
    assert_ne!(
        json!("synthetic-person"),
        claims["sub"],
        "the upstream sub never leaves"
    );
    let access: Value = jsonwebtoken::dangerous::insecure_decode_claims(
        body["access_token"].as_str().expect("a token"),
    )
    .expect("claims");
    assert_eq!(json!(RESOURCE), access["aud"]);
    assert_eq!(claims["sub"], access["sub"]);
    assert_eq!(
        Value::Null,
        body["refresh_token"],
        "no offline_access or online_access, no refresh token"
    );

    // NOTE: OAuth 2.1 draft §4.1.3, a second use is refused and revokes.
    let (status, _, body) = smart.post("/token", &exchange, None).await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert!(body.contains("invalid_grant"));
    let jti = access["jti"].as_str().expect("a jti");
    assert!(
        smart.store.revoked(jti).await.expect("read"),
        "the first token is revoked"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_declined_consent_sends_access_denied_back() {
    let smart = Smart::start().await;
    let (cookie, token) = to_consent(&smart, &["clinician"]).await;
    let (status, headers, _) = smart
        .post(
            "/consent",
            &[("form_token", &token), ("decision", "deny")],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let back = location(&headers);
    assert_eq!(Some(String::from("access_denied")), param(&back, "error"));
    assert_eq!(Some(String::from("synthetic-state")), param(&back, "state"));
    let (status, _, _) = smart.get("/consent", Some(&cookie)).await;
    assert_eq!(StatusCode::NOT_FOUND, status, "decided once");
    smart.stop().await;
}

#[tokio::test]
async fn a_consent_post_without_its_page_s_token_or_cookie_is_refused() {
    let smart = Smart::start().await;
    let (cookie, _token) = to_consent(&smart, &["clinician"]).await;
    let (status, _, _) = smart
        .post(
            "/consent",
            &[("form_token", "forged"), ("decision", "approve")],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "RFC 6749 §10.12");
    let (status, _, _) = smart.get("/consent", Some("another-browser")).await;
    assert_eq!(StatusCode::NOT_FOUND, status);
    smart.stop().await;
}

#[tokio::test]
async fn a_request_the_endpoint_cannot_trust_is_shown_never_redirected() {
    let smart = Smart::start().await;
    for overrides in [
        &[("client_id", "unknown")][..],
        &[("redirect_uri", "https://evil.example.org/cb")][..],
        &[("redirect_uri", "")][..],
    ] {
        let (status, headers, page) = smart.get(&authorize_path(overrides), None).await;
        assert_eq!(StatusCode::BAD_REQUEST, status, "{overrides:?}");
        assert!(headers.get(header::LOCATION).is_none(), "RFC 6749 §4.1.2.1");
        assert!(
            page.contains("Bad request · 400") && page.contains("<h1>"),
            "the error page of a 400: {page}"
        );
    }
    smart.stop().await;
}

#[tokio::test]
async fn a_request_that_breaks_the_profile_is_sent_back_with_its_error() {
    let smart = Smart::start().await;
    for (overrides, error) in [
        (&[("code_challenge_method", "plain")][..], "invalid_request"),
        (&[("code_challenge", "")][..], "invalid_request"),
        (
            &[("aud", "https://other.example.org/fhir")][..],
            "invalid_request",
        ),
        (&[("state", "")][..], "invalid_request"),
        (
            &[("response_type", "token")][..],
            "unsupported_response_type",
        ),
        (
            &[("launch", "synthetic-launch"), ("scope", "openid launch")][..],
            "invalid_request",
        ),
        (&[("launch", "synthetic-launch")][..], "invalid_scope"),
        (&[("scope", "")][..], "invalid_scope"),
    ] {
        let (status, headers, _) = smart.get(&authorize_path(overrides), None).await;
        assert_eq!(StatusCode::SEE_OTHER, status, "{overrides:?}");
        let back = location(&headers);
        assert!(back.as_str().starts_with(REDIRECT), "{overrides:?}");
        assert_eq!(
            Some(String::from(error)),
            param(&back, "error"),
            "{overrides:?}"
        );
        assert_eq!(Some(String::from(ISSUER)), param(&back, "iss"));
    }
    smart.stop().await;
}

#[tokio::test]
async fn a_callback_from_another_browser_is_refused() {
    let smart = Smart::start().await;
    let (_, headers, _) = smart.get(&authorize_path(&[]), None).await;
    let upstream = location(&headers);
    let callback = format!(
        "/callback?code=x&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, _, _) = smart.get(&callback, Some("another-browser")).await;
    assert_eq!(StatusCode::FORBIDDEN, status, "RFC 9700 §4.7");
    smart.stop().await;
}

#[tokio::test]
async fn a_code_exchange_that_does_not_hold_is_refused_and_burns_nothing() {
    let smart = Smart::start().await;
    let (cookie, token) = to_consent(&smart, &["clinician"]).await;
    let (_, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", &token),
                ("decision", "approve"),
                ("scope", "user/Observation.rs"),
            ],
            Some(&cookie),
        )
        .await;
    let code = param(&location(&headers), "code").expect("a code");
    for (name, value, error) in [
        (
            "code_verifier",
            "wrong-verifier-wrong-verifier-wrong-verifier-xx",
            "invalid_grant",
        ),
        (
            "redirect_uri",
            "https://app.example.org/other",
            "invalid_grant",
        ),
        ("client_id", "unknown", "invalid_client"),
    ] {
        let mut exchange = vec![
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
            ("client_id", "app"),
        ];
        exchange.retain(|(kept, _)| *kept != name);
        exchange.push((name, value));
        let (status, _, body) = smart.post("/token", &exchange, None).await;
        assert_eq!(StatusCode::BAD_REQUEST, status);
        assert!(body.contains(error), "{name}: {body}");
    }
    // NOTE: OAuth 2.1 draft §7.5.3, a request with invalid parameters burns nothing.
    let exchange = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_id", "app"),
    ];
    let (status, _, body) = smart.post("/token", &exchange, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let body: Value = serde_json::from_str(&body).expect("JSON");
    assert!(body.get("id_token").is_none(), "no openid, no ID Token");
    smart.stop().await;
}

#[tokio::test]
async fn the_documents_describe_the_login_once_it_is_configured() {
    let smart = Smart::start().await;
    let (_, _, body) = smart.get("/.well-known/smart-configuration", None).await;
    let smart_doc: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(
        json!(format!("{ISSUER}/authorize")),
        smart_doc["authorization_endpoint"]
    );
    let capabilities = smart_doc["capabilities"].as_array().expect("capabilities");
    for capability in [
        "launch-standalone",
        "client-public",
        "client-confidential-asymmetric",
        "sso-openid-connect",
        "permission-user",
        "permission-v2",
    ] {
        assert!(capabilities.contains(&json!(capability)), "{capability}");
    }
    assert_eq!(
        json!(ISSUER),
        smart_doc["issuer"],
        "with sso-openid-connect"
    );
    let (status, _, body) = smart.get("/.well-known/openid-configuration", None).await;
    assert_eq!(StatusCode::OK, status);
    let openid: Value = serde_json::from_str(&body).expect("JSON");
    // NOTE: OpenID Connect Discovery 1.0 §3, the members it requires.
    assert_eq!(json!(["code"]), openid["response_types_supported"]);
    assert_eq!(json!(["pairwise"]), openid["subject_types_supported"]);
    assert_eq!(
        json!(["RS256"]),
        openid["id_token_signing_alg_values_supported"]
    );
    smart.stop().await;
}

#[test]
fn the_consent_page_offers_what_the_ceiling_and_the_roles_allow() {
    let client = resolve(&[ClientSection {
        client_id: String::from("app"),
        kind: ClientKind::Public,
        redirect_uris: vec![String::from(REDIRECT)],
        grant_types: vec![GrantType::AuthorizationCode],
        scopes: [
            "openid",
            "fhirUser",
            "user/Observation.rs",
            "user/Patient.rs",
            "offline_access",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        ..ClientSection::default()
    }])
    .expect("admitted")
    .remove(0);
    let roles = [(
        String::from("clinician"),
        vec![String::from("user/Observation.rs")],
    )]
    .into_iter()
    .collect();
    let held = vec![String::from("clinician")];
    let requested = "openid fhirUser user/Observation.rs user/Patient.rs system/Patient.rs offline_access user/Observation.rs";
    assert_eq!(
        vec!["openid", "fhirUser", "user/Observation.rs"],
        offer(requested, &client, &held, &roles, true, None)
    );
    assert_eq!(
        vec!["openid", "user/Observation.rs"],
        offer(requested, &client, &held, &roles, false, None),
        "no fhirUser to give"
    );
    assert_eq!(
        vec!["user/Observation.rs"],
        offer(
            "fhirUser user/Observation.rs",
            &client,
            &held,
            &roles,
            true,
            None
        ),
        "fhirUser rides on openid"
    );
    assert!(
        offer(requested, &client, &[], &roles, true, None)
            .iter()
            .all(|scope| !scope.starts_with("user/")),
        "no role, no user scope"
    );
}

#[tokio::test]
async fn a_remembered_consent_answers_again_until_it_is_withdrawn() {
    let smart = Smart::start().await;
    let (cookie, token) = to_consent(&smart, &["clinician"]).await;
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    assert!(
        page.contains("name=\"remember\""),
        "the person may choose to remember"
    );
    let granted = [
        ("form_token", token.as_str()),
        ("decision", "approve"),
        ("scope", "openid"),
        ("scope", "fhirUser"),
        ("scope", "user/Observation.rs"),
        ("remember", "yes"),
    ];
    let (status, _, _) = smart.post("/consent", &granted, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status);

    // NOTE: docs/architecture.md §13.6 item 6, the remembered consent covers
    // the same request, so the browser goes back with a code at once.
    let (_, headers, _) = smart.get(&authorize_path(&[]), None).await;
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer(&param(&upstream, "nonce").expect("a nonce"), &["clinician"])
        .await;
    let callback = format!(
        "/callback?code=c&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let back = location(&headers);
    assert!(back.as_str().starts_with(REDIRECT), "{back}");
    assert!(param(&back, "code").is_some(), "no consent page this time");

    // NOTE: SMART App Launch 2.2.0, Conformance, management_endpoint.
    let (status, headers, _) = smart.get("/manage", None).await;
    assert_eq!(
        StatusCode::SEE_OTHER,
        status,
        "the visit begins with a login"
    );
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer(&param(&upstream, "nonce").expect("a nonce"), &["clinician"])
        .await;
    let callback = format!(
        "/callback?code=m&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert_eq!("/manage", location(&headers).path());
    let (status, _, page) = smart.get("/manage", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(page.contains("Synthetic App"));
    assert!(
        page.contains("<h1 class=\"fui-page-card-title\">Apps you allowed</h1>"),
        "{page}"
    );
    let form_token = page
        .split("name=\"form_token\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a form token")
        .to_owned();
    let (status, _, _) = smart
        .post(
            "/manage",
            &[("form_token", &form_token), ("client_id", "app")],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let (_, _, page) = smart.get("/manage", Some(&cookie)).await;
    assert!(!page.contains("Synthetic App"), "withdrawn");

    // The next request asks again.
    let (_, headers, _) = smart.get(&authorize_path(&[]), None).await;
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer(&param(&upstream, "nonce").expect("a nonce"), &["clinician"])
        .await;
    let callback = format!(
        "/callback?code=d&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (_, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!("/consent", location(&headers).path(), "asked again");
    smart.stop().await;
}

/// Starts FerroSMART whose app may refresh, and runs a launch asking for
/// `access` (`offline_access` or `online_access`) to its token response.
async fn launch_with(access: &str) -> (Smart, Value) {
    let smart = Smart::start_with(
        "[\"authorization_code\", \"refresh_token\"]",
        "[\"openid\", \"fhirUser\", \"user/Observation.rs\", \"offline_access\", \"online_access\"]",
        "[\"user/Observation.rs\"]",
    )
    .await;
    let scope = format!("openid fhirUser user/Observation.rs {access}");
    let (cookie, token) = to_consent_with(&smart, &["clinician"], &[("scope", &scope)]).await;
    let (status, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", &token),
                ("decision", "approve"),
                ("scope", "openid"),
                ("scope", "fhirUser"),
                ("scope", "user/Observation.rs"),
                ("scope", access),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(
        StatusCode::SEE_OTHER,
        status,
        "the consent sends the browser back"
    );
    let code = param(&location(&headers), "code").expect("a code");
    let exchange = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_id", "app"),
    ];
    let (status, _, body) = smart.post("/token", &exchange, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    (smart, serde_json::from_str(&body).expect("JSON"))
}

/// Refreshes with `token` as the public app and returns the status and
/// the JSON body.
async fn refresh(smart: &Smart, token: &str) -> (StatusCode, Value) {
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", token),
        ("client_id", "app"),
    ];
    let (status, _, body) = smart.post("/token", &form, None).await;
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn an_offline_access_launch_issues_a_refresh_token_that_rotates() {
    let (smart, body) = launch_with("offline_access").await;
    // NOTE: SMART App Launch 2.2.0, Obtain access token, Response: refresh_token.
    let first = body["refresh_token"].as_str().expect("a refresh token");
    assert_eq!(
        json!("openid fhirUser user/Observation.rs offline_access"),
        body["scope"]
    );
    let (status, renewed) = refresh(&smart, first).await;
    assert_eq!(StatusCode::OK, status, "{renewed}");
    assert_eq!(json!("bearer"), renewed["token_type"]);
    assert_eq!(body["scope"], renewed["scope"]);
    assert_eq!(
        json!(STYLE),
        renewed["smart_style_url"],
        "the launch context"
    );
    assert!(renewed["id_token"].is_null());
    let access: Value = jsonwebtoken::dangerous::insecure_decode_claims(
        renewed["access_token"].as_str().expect("a token"),
    )
    .expect("claims");
    // NOTE: docs/architecture.md §13.6 item 2, fhirUser rides in the access token.
    assert_eq!(json!("Practitioner/synthetic-1"), access["fhirUser"]);
    let second = renewed["refresh_token"].as_str().expect("rotated");
    assert_ne!(first, second);
    // NOTE: RFC 9700 §4.14.2, the rotated token presented again revokes the grant.
    let (status, replay) = refresh(&smart, first).await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert_eq!(json!("invalid_grant"), replay["error"]);
    let (status, _) = refresh(&smart, second).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "the grant is revoked");
    let jti = access["jti"].as_str().expect("a jti");
    assert!(smart.store.revoked(jti).await.expect("read"));
    smart.stop().await;
}

#[tokio::test]
async fn an_online_access_launch_ends_with_its_upstream_login() {
    let (smart, body) = launch_with("online_access").await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    let (status, renewed) = refresh(&smart, token).await;
    assert_eq!(StatusCode::OK, status, "{renewed}");
    let session: String = {
        use sqlx::Connection as _;
        let mut connection =
            sqlx::PgConnection::connect(secrecy::ExposeSecret::expose_secret(&smart.database.url))
                .await
                .expect("connects");
        sqlx::query_scalar("SELECT upstream_session FROM authorization_grant")
            .fetch_one(&mut connection)
            .await
            .expect("the grant names its session")
    };
    assert!(smart.store.end_session(&session).await.expect("ended"));
    // NOTE: docs/architecture.md §13.6 item 7, online_access ends with the upstream login.
    let next = renewed["refresh_token"].as_str().expect("rotated");
    let (status, refused) = refresh(&smart, next).await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert_eq!(json!("invalid_grant"), refused["error"]);
    smart.stop().await;
}

#[tokio::test]
async fn withdrawing_a_consent_revokes_the_grants_it_covered() {
    let (smart, body) = launch_with("offline_access").await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    let access: Value = jsonwebtoken::dangerous::insecure_decode_claims(
        body["access_token"].as_str().expect("a token"),
    )
    .expect("claims");
    let subject = access["sub"].as_str().expect("a sub");
    smart
        .store
        .revoke_consent(subject, "app")
        .await
        .expect("withdrawn");
    // NOTE: docs/architecture.md §13.6 item 6, revoking a consent revokes its grants.
    let (status, refused) = refresh(&smart, token).await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert_eq!(json!("invalid_grant"), refused["error"]);
    smart.stop().await;
}

#[test]
fn offline_and_online_access_are_offered_to_a_client_that_refreshes() {
    let client = resolve(&[ClientSection {
        client_id: String::from("app"),
        kind: ClientKind::Public,
        redirect_uris: vec![String::from(REDIRECT)],
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        scopes: ["openid", "offline_access", "online_access"]
            .into_iter()
            .map(String::from)
            .collect(),
        ..ClientSection::default()
    }])
    .expect("admitted")
    .remove(0);
    let roles = std::collections::BTreeMap::new();
    assert_eq!(
        vec!["openid", "offline_access", "online_access"],
        offer(
            "openid offline_access online_access",
            &client,
            &[],
            &roles,
            false,
            None,
        )
    );
}
