// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The introspection check (RFC 7662): an active response admits its
//! caller and is held until its `exp`, and every response that does not
//! hold, or an endpoint that cannot answer, refuses the token. Every
//! endpoint is a `wiremock` stub and every token a synthetic string.

use std::error::Error as StdError;
use std::time::Duration;

use ferrohealth_smart::client::ClientAuth;
use ferrohealth_smart::client::ClientCredentials;
use ferrohealth_smart::client::Endpoint;
use ferrohealth_smart::client::cache::TokenSource;
use ferrohealth_smart::config::AuthMode;
use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::IntrospectionSection;
use ferrohealth_smart::config::IssuerKey;
use ferrohealth_smart::config::OauthSection;
use ferrohealth_smart::refusal::Reason;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::resource::introspection::IntrospectionAuth;
use ferrohealth_smart::resource::introspection::IntrospectionError;
use ferrohealth_smart::resource::introspection::IntrospectionSettings;
use ferrohealth_smart::resource::introspection::Introspector;
use http::StatusCode;
use secrecy::SecretString;
use wiremock::Mock;
use wiremock::ResponseTemplate;
use wiremock::matchers::body_string_contains;
use wiremock::matchers::header;
use wiremock::matchers::method;
use wiremock::matchers::path;

use crate::support::AUDIENCE;
use crate::support::Issuer;
use crate::support::now;

const OAUTH: &str = "/.well-known/oauth-authorization-server";
const INTROSPECT: &str = "/introspect";
const TOKEN: &str = "synthetic-opaque-token";

/// Returns an issuer whose metadata names its introspection endpoint.
async fn issuer() -> Issuer {
    let issuer = Issuer::bare().await;
    issuer.mount_metadata(OAUTH).await;
    issuer
}

/// Returns the client authentication of the resource server at `issuer`.
fn client(issuer: &Issuer) -> IntrospectionAuth {
    IntrospectionAuth::Client(Box::new(ClientCredentials::new(
        Endpoint::Issuer(issuer.uri()),
        String::from("ferro-rs"),
        SecretString::from("synthetic-secret"),
    )))
}

/// Returns introspection settings for `issuer` under client authentication.
fn settings(issuer: &Issuer) -> IntrospectionSettings {
    IntrospectionSettings::new(issuer.uri(), AUDIENCE, client(issuer))
}

/// Returns an active response for `issuer`, expiring in `seconds`.
fn active(issuer: &Issuer, seconds: i64) -> serde_json::Value {
    serde_json::json!({
        "active": true,
        "scope": "system/Observation.rs",
        "client_id": "synthetic-client",
        "sub": "synthetic-sub",
        "patient": "synthetic-patient",
        "aud": AUDIENCE,
        "iss": issuer.uri(),
        "token_type": "Bearer",
        "exp": now() + seconds,
        "iat": now(),
    })
}

/// Mounts `response` as the introspection answer, expecting `times` calls.
async fn answer(issuer: &Issuer, response: ResponseTemplate, times: u64) {
    Mock::given(method("POST"))
        .and(path(INTROSPECT))
        .respond_with(response)
        .expect(times)
        .mount(&issuer.server)
        .await;
}

/// Changes one member of a response.
type Change = fn(&mut serde_json::Value);

fn json(body: &serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(body)
}

#[tokio::test]
async fn an_active_token_admits_its_caller_under_client_authentication()
-> Result<(), Box<dyn StdError>> {
    let issuer = issuer().await;
    Mock::given(method("POST"))
        .and(path(INTROSPECT))
        // NOTE: RFC 6749 §2.3.1, the id and secret travel as HTTP Basic.
        .and(header(
            "authorization",
            "Basic ZmVycm8tcnM6c3ludGhldGljLXNlY3JldA==",
        ))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains(format!("token={TOKEN}")))
        .and(body_string_contains("token_type_hint=access_token"))
        .respond_with(json(&active(&issuer, 300)))
        .expect(1)
        .mount(&issuer.server)
        .await;
    let introspector = Introspector::discover(settings(&issuer)).await?;
    assert_eq!(
        format!("{}{INTROSPECT}", issuer.uri()),
        introspector.endpoint().as_str()
    );
    let caller = introspector.authenticate(TOKEN).await?;
    assert_eq!("synthetic-sub", caller.subject());
    assert_eq!(Some("synthetic-client"), caller.client_id());
    assert_eq!(Some("synthetic-patient"), caller.patient());
    assert_eq!(Some(issuer.uri().as_str()), caller.issuer());
    assert_eq!(&[String::from("system/Observation.rs")], caller.scope());
    assert!(!caller.cached(), "the first answer comes from the endpoint");
    Ok(())
}

#[tokio::test]
async fn an_active_response_is_held_and_read_from_the_cache() -> Result<(), Box<dyn StdError>> {
    let issuer = issuer().await;
    answer(&issuer, json(&active(&issuer, 300)), 1).await;
    let introspector = Introspector::discover(settings(&issuer)).await?;
    introspector.authenticate(TOKEN).await?;
    let again = introspector.authenticate(TOKEN).await?;
    assert!(again.cached(), "the second answer is the held one");
    assert_eq!("synthetic-sub", again.subject());
    Ok(())
}

#[tokio::test]
async fn the_cache_never_holds_a_response_past_its_exp() -> Result<(), Box<dyn StdError>> {
    let issuer = issuer().await;
    answer(&issuer, json(&active(&issuer, 1)), 2).await;
    let introspector = Introspector::discover(settings(&issuer)).await?;
    introspector.authenticate(TOKEN).await?;
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let again = introspector.authenticate(TOKEN).await?;
    assert!(!again.cached(), "RFC 7662 §4: not cached beyond exp");
    Ok(())
}

#[tokio::test]
async fn a_zero_cache_age_asks_the_endpoint_every_time() -> Result<(), Box<dyn StdError>> {
    let issuer = issuer().await;
    answer(&issuer, json(&active(&issuer, 300)), 2).await;
    let mut settings = settings(&issuer);
    settings.cache_max_age = Duration::ZERO;
    let introspector = Introspector::discover(settings).await?;
    introspector.authenticate(TOKEN).await?;
    assert!(!introspector.authenticate(TOKEN).await?.cached());
    Ok(())
}

#[tokio::test]
async fn an_inactive_token_is_refused_and_never_held() -> Result<(), Box<dyn StdError>> {
    let issuer = issuer().await;
    answer(&issuer, json(&serde_json::json!({ "active": false })), 2).await;
    let introspector = Introspector::discover(settings(&issuer)).await?;
    for _ in 0..2 {
        assert!(matches!(
            introspector.authenticate(TOKEN).await,
            Err(Rejection::Invalid {
                reason: Reason::Inactive
            })
        ));
    }
    Ok(())
}

#[tokio::test]
async fn a_response_that_does_not_hold_refuses_the_token() -> Result<(), Box<dyn StdError>> {
    let cases: [(&str, Change, Reason); 9] = [
        (
            "no scope",
            |r| drop(r.as_object_mut().map(|o| o.remove("scope"))),
            Reason::MissingClaim,
        ),
        (
            "no client_id",
            |r| drop(r.as_object_mut().map(|o| o.remove("client_id"))),
            Reason::MissingClaim,
        ),
        (
            "no exp",
            |r| drop(r.as_object_mut().map(|o| o.remove("exp"))),
            Reason::MissingClaim,
        ),
        (
            "expired",
            |r| r["exp"] = serde_json::json!(now() - 3_600),
            Reason::Expired,
        ),
        (
            "not yet valid",
            |r| r["nbf"] = serde_json::json!(now() + 3_600),
            Reason::NotYetValid,
        ),
        (
            "another issuer",
            |r| r["iss"] = serde_json::json!("https://attacker.invalid"),
            Reason::Issuer,
        ),
        (
            "another audience",
            |r| r["aud"] = serde_json::json!(["https://other.invalid"]),
            Reason::Audience,
        ),
        (
            "a DPoP token",
            |r| r["token_type"] = serde_json::json!("DPoP"),
            Reason::Type,
        ),
        (
            "a blank sub",
            |r| r["sub"] = serde_json::json!(" "),
            Reason::BlankSubject,
        ),
    ];
    for (name, change, reason) in cases {
        let issuer = issuer().await;
        let mut response = active(&issuer, 300);
        change(&mut response);
        answer(&issuer, json(&response), 1).await;
        let introspector = Introspector::discover(settings(&issuer)).await?;
        let outcome = introspector.authenticate(TOKEN).await;
        assert!(
            matches!(outcome, Err(Rejection::Invalid { reason: found }) if found == reason),
            "{name}: {outcome:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_response_without_aud_iss_or_sub_is_the_clients() -> Result<(), Box<dyn StdError>> {
    let issuer = issuer().await;
    let mut response = active(&issuer, 300);
    for member in ["aud", "iss", "sub", "token_type"] {
        response.as_object_mut().ok_or("an object")?.remove(member);
    }
    answer(&issuer, json(&response), 1).await;
    let introspector = Introspector::discover(settings(&issuer)).await?;
    let caller = introspector.authenticate(TOKEN).await?;
    assert_eq!("synthetic-client", caller.subject(), "RFC 9068 §2.2");
    Ok(())
}

#[tokio::test]
async fn an_endpoint_that_cannot_answer_is_an_upstream_failure() -> Result<(), Box<dyn StdError>> {
    let bodies: [(&str, ResponseTemplate, Option<StatusCode>); 5] = [
        (
            "401",
            ResponseTemplate::new(401).set_body_string(r#"{"error":"invalid_client"}"#),
            Some(StatusCode::UNAUTHORIZED),
        ),
        (
            "500",
            ResponseTemplate::new(500),
            Some(StatusCode::INTERNAL_SERVER_ERROR),
        ),
        (
            "no JSON",
            ResponseTemplate::new(200).set_body_string("{\"active\": "),
            None,
        ),
        (
            "no active",
            json(&serde_json::json!({ "scope": "x" })),
            None,
        ),
        (
            "a repeated name",
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{"active": false, "active": true}"#),
            None,
        ),
    ];
    for (name, response, status) in bodies {
        let issuer = issuer().await;
        answer(&issuer, response, 1).await;
        let introspector = Introspector::discover(settings(&issuer)).await?;
        let outcome = introspector.authenticate(TOKEN).await;
        let Err(Rejection::Upstream { source, .. }) = outcome else {
            panic!("{name}: an upstream failure, got {outcome:?}");
        };
        let error = source
            .downcast_ref::<IntrospectionError>()
            .ok_or("an introspection error")?;
        assert_eq!(status, error.status(), "{name}: {error:?}");
        if name == "a repeated name" {
            assert!(
                matches!(error, IntrospectionError::RepeatedName { .. }),
                "RFC 8259 §4"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_bearer_token_from_the_grant_authorizes_the_call() -> Result<(), Box<dyn StdError>> {
    let issuer = issuer().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(json(&serde_json::json!({
            "access_token": "synthetic-introspection-bearer",
            "token_type": "Bearer",
            "expires_in": 300,
        })))
        .expect(1)
        .mount(&issuer.server)
        .await;
    Mock::given(method("POST"))
        .and(path(INTROSPECT))
        .and(header(
            "authorization",
            "Bearer synthetic-introspection-bearer",
        ))
        .and(body_string_contains(format!("token={TOKEN}")))
        .respond_with(json(&active(&issuer, 300)))
        .expect(1)
        .mount(&issuer.server)
        .await;
    let grant = ClientCredentials::new(
        Endpoint::Issuer(issuer.uri()),
        String::from("ferro-rs"),
        SecretString::from("synthetic-secret"),
    );
    let auth = IntrospectionAuth::Bearer(TokenSource::new(grant)?);
    let introspector =
        Introspector::discover(IntrospectionSettings::new(issuer.uri(), AUDIENCE, auth)).await?;
    assert_eq!(
        "synthetic-sub",
        introspector.authenticate(TOKEN).await?.subject()
    );
    Ok(())
}

#[tokio::test]
async fn client_secret_post_sends_the_id_and_secret_in_the_body() -> Result<(), Box<dyn StdError>> {
    let issuer = issuer().await;
    Mock::given(method("POST"))
        .and(path(INTROSPECT))
        .and(body_string_contains("client_id=ferro-rs"))
        .and(body_string_contains("client_secret=synthetic-secret"))
        .and(body_string_contains(format!("token={TOKEN}")))
        .respond_with(json(&active(&issuer, 300)))
        .expect(1)
        .mount(&issuer.server)
        .await;
    let mut credentials = ClientCredentials::new(
        Endpoint::Issuer(issuer.uri()),
        String::from("ferro-rs"),
        SecretString::from("synthetic-secret"),
    );
    credentials.client_auth = ClientAuth::ClientSecretPost;
    let settings = IntrospectionSettings::new(
        issuer.uri(),
        AUDIENCE,
        IntrospectionAuth::Client(Box::new(credentials)),
    );
    Introspector::discover(settings)
        .await?
        .authenticate(TOKEN)
        .await?;
    Ok(())
}

#[tokio::test]
async fn metadata_without_an_introspection_endpoint_refuses_the_start()
-> Result<(), Box<dyn StdError>> {
    let issuer = Issuer::bare().await;
    let mut metadata = issuer.metadata();
    metadata
        .as_object_mut()
        .ok_or("an object")?
        .remove("introspection_endpoint");
    issuer.mount_document(OAUTH, metadata).await;
    assert!(matches!(
        Introspector::discover(settings(&issuer)).await,
        Err(IntrospectionError::NoEndpoint)
    ));
    let mut configured = settings(&issuer);
    configured.endpoint = Some("http://as.example.org/introspect".parse()?);
    assert!(matches!(
        Introspector::discover(configured).await,
        Err(IntrospectionError::Discovery(_))
    ));
    let mut no_audience = settings(&issuer);
    no_audience.audience = Vec::new();
    assert!(matches!(
        no_audience.validate(),
        Err(IntrospectionError::NoAudience)
    ));
    Ok(())
}

/// Returns an `[auth]` section in introspection mode for `issuer`.
fn section(issuer: &str) -> AuthSection {
    AuthSection {
        issuer: IssuerKey::Flat(issuer.to_owned()),
        audience: vec![String::from(AUDIENCE)],
        mode: AuthMode::Introspection,
        introspection: Some(IntrospectionSection {
            client: Some(OauthSection {
                client_id: String::from("ferro-rs"),
                client_secret: Some(SecretString::from("synthetic-secret")),
                ..OauthSection::default()
            }),
            ..IntrospectionSection::default()
        }),
        ..AuthSection::default()
    }
}

#[test]
fn the_auth_section_resolves_introspection_mode() -> Result<(), Box<dyn StdError>> {
    let resolved = section("https://as.example.org").resolve()?;
    assert!(resolved.issuers.is_empty(), "no key set issuer is read");
    let settings = resolved.introspection.ok_or("the introspection settings")?;
    assert_eq!("https://as.example.org", settings.issuer);
    assert_eq!(vec![String::from(AUDIENCE)], settings.audience);
    assert_eq!(Duration::from_secs(60), settings.cache_max_age);
    let IntrospectionAuth::Client(credentials) = settings.auth else {
        panic!("client authentication");
    };
    assert_eq!(
        Endpoint::Issuer(String::from("https://as.example.org")),
        credentials.endpoint
    );
    Ok(())
}

#[test]
fn the_auth_section_refuses_an_introspection_mode_that_breaks_a_rule() {
    let mut no_table = section("https://as.example.org");
    no_table.introspection = None;
    assert!(matches!(
        no_table.resolve(),
        Err(ConfigError::Missing {
            key: "auth.introspection"
        })
    ));
    let mut both = section("https://as.example.org");
    if let Some(table) = both.introspection.as_mut() {
        table.bearer = table.client.clone();
    }
    assert!(matches!(both.resolve(), Err(ConfigError::Exclusive { .. })));
    let mut jwt = section("https://as.example.org");
    jwt.mode = AuthMode::Jwt;
    assert!(matches!(jwt.resolve(), Err(ConfigError::Exclusive { .. })));
    let mut list = section("https://as.example.org");
    list.issuer = IssuerKey::List(Vec::new());
    assert!(matches!(list.resolve(), Err(ConfigError::Exclusive { .. })));
    let mut keyed = section("https://as.example.org");
    keyed.jwks_file = String::from("/keys.json");
    assert!(matches!(
        keyed.resolve(),
        Err(ConfigError::Exclusive { .. })
    ));
    let mut no_audience = section("https://as.example.org");
    no_audience.audience = Vec::new();
    assert!(matches!(
        no_audience.resolve(),
        Err(ConfigError::Introspection { .. })
    ));
    let mut no_secret = section("https://as.example.org");
    if let Some(client) = no_secret
        .introspection
        .as_mut()
        .and_then(|table| table.client.as_mut())
    {
        client.client_secret = None;
    }
    assert!(matches!(
        no_secret.resolve(),
        Err(ConfigError::Secret { .. })
    ));
}

#[test]
fn the_introspection_table_reads_from_toml() -> Result<(), Box<dyn StdError>> {
    let section: AuthSection = toml::from_str(
        r#"
        issuer = "https://as.example.org"
        audience = ["http://ferro.invalid/fhir"]
        mode = "introspection"

        [introspection]
        endpoint = "https://as.example.org/oauth2/introspect"
        cache_max_age_seconds = 30

        [introspection.client]
        client_id = "ferro-rs"
        client_secret = "synthetic-secret"
        "#,
    )?;
    let settings = section
        .resolve()?
        .introspection
        .ok_or("the introspection settings")?;
    assert_eq!(
        Some("https://as.example.org/oauth2/introspect"),
        settings.endpoint.as_ref().map(url::Url::as_str)
    );
    assert_eq!(Duration::from_secs(30), settings.cache_max_age);
    Ok(())
}
