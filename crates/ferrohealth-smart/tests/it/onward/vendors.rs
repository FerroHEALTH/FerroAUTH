// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The vendored examples of the two vendor presets: Microsoft's
//! "On-behalf-of flow" (MicrosoftDocs/entra-docs 219d8d57) "Second case"
//! certificate request, "Success response example" and "Error response
//! example", and Keycloak 26.8.2 `token-exchange.adoc`, its "Example token
//! exchange request" and Examples 1 to 3.

use ferrohealth_smart::client::TokenError;
use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::client::onward::Rejected;
use ferrohealth_smart::client::onward::Target;
use http::StatusCode;
use serde_json::json;
use wiremock::ResponseTemplate;

use super::figure_form;
use super::harness::ENTRA_CLIENT;
use super::harness::ENTRA_TARGET;
use super::harness::Flavor;
use super::harness::Harness;
use super::harness::ROUTE;
use super::param;
use super::received;
use super::sign;
use super::sorted;

/// The "Second case" body without `client_assertion` and `assertion`, which
/// the case signs, and without `offline_access`, which the client never
/// asks for.
const SECOND_CASE: &str = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&client_id=11112222-bbbb-3333-cccc-4444dddd5555&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&requested_token_use=on_behalf_of&scope=https://graph.microsoft.com/user.read";

/// The "Error response example" body, as published.
const ERROR_RESPONSE: &str = r#"{
    "error":"interaction_required",
    "error_description":"AADSTS50079: Due to a configuration change made by your administrator, or because you moved to a new location, you must enroll in multifactor authentication to access 'aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb'.\r\nTrace ID: 0000aaaa-11bb-cccc-dd22-eeeeee333333\r\nCorrelation ID: aaaa0000-bb11-2222-33cc-444444dddddd\r\nTimestamp: 2017-05-01 22:43:20Z",
    "error_codes":[50079],
    "timestamp":"2017-05-01 22:43:20Z",
    "trace_id":"0000aaaa-11bb-cccc-dd22-eeeeee333333",
    "correlation_id":"aaaa0000-bb11-2222-33cc-444444dddddd",
    "claims":"{\"access_token\":{\"polids\":{\"essential\":true,\"values\":[\"00aa00aa-bb11-cc22-dd33-44ee44ee44ee\"]}}}"
}"#;

/// The challenge of the "Error response example".
const CHALLENGE: &str = r#"{"access_token":{"polids":{"essential":true,"values":["00aa00aa-bb11-cc22-dd33-44ee44ee44ee"]}}}"#;

/// Returns the Graph target of the "Second case" example.
fn graph() -> Target {
    Target::new(["https://graph.microsoft.com"]).with_scope("https://graph.microsoft.com/user.read")
}

#[tokio::test]
async fn entra_second_case_with_offline_access_is_refused_before_sending() {
    // NOTE: Microsoft, "On-behalf-of flow", "Second case": the example scope
    // names `offline_access`, for which the refresh token is issued.
    let harness = Harness::start(Flavor::Entra).await;
    let (subject, _) = harness.person();
    let target = Target::new(["https://graph.microsoft.com"])
        .with_scope("https://graph.microsoft.com/user.read offline_access");
    let error = harness
        .onward
        .token(&subject, None, &target)
        .await
        .expect_err("refused");
    assert!(matches!(error, OnwardError::OfflineAccess), "{error:?}");
    assert_eq!(0, harness.calls().await);
}

#[tokio::test]
async fn entra_second_case_is_reproduced_parameter_for_parameter() {
    // NOTE: Microsoft, "On-behalf-of flow", "Second case: Access token request
    // with a certificate", every parameter but `offline_access`.
    let harness = Harness::start(Flavor::Entra).await;
    let (subject, claims) = harness.person();
    let mut issued = Flavor::Entra.issued_claims(&claims, harness.now());
    issued["aud"] = json!("https://graph.microsoft.com");
    harness
        .answer(
            ResponseTemplate::new(200)
                .set_body_json(Flavor::Entra.response(&sign(&harness.key, &issued))),
        )
        .await;
    harness
        .onward
        .token(&subject, None, &graph())
        .await
        .expect("accepted");
    let sent = received(&harness.server).await;
    let form = sent.first().expect("one request");
    assert_eq!(
        sorted(&figure_form(SECOND_CASE), &[]),
        sorted(form, &["client_assertion", "assertion"]),
        "the Second case parameter for parameter"
    );
    harness.client.verify(
        form,
        ENTRA_CLIENT,
        &format!("{}{ROUTE}", harness.server.uri()),
    );
    assert!(param(form, "assertion").is_some(), "the incoming token");
}

#[tokio::test]
async fn entra_success_response_with_its_refresh_token_is_refused() {
    // NOTE: Microsoft, "On-behalf-of flow", "Success response example", which
    // carries a refresh token because the request asked `offline_access`.
    let harness = Harness::start(Flavor::Entra).await;
    let (subject, _) = harness.person();
    harness
        .answer(ResponseTemplate::new(200).set_body_json(json!({
            "token_type": "Bearer",
            "scope": "https://graph.microsoft.com/user.read",
            "expires_in": 3269,
            "ext_expires_in": 0,
            "access_token": "eyJhbGciO...",
            "refresh_token": "OAQABAAAAAABnfiG-mA6NTae7CdWW7QfdAALzDWjw6qSn4GUDfxWzJDZ6lk9qRw4An{a lot of characters here}"
        })))
        .await;
    let error = harness
        .onward
        .token(&subject, None, &graph())
        .await
        .expect_err("refused");
    assert!(matches!(error, OnwardError::RefreshToken), "{error:?}");
}

#[tokio::test]
async fn entra_success_response_without_a_refresh_token_is_read() {
    // NOTE: Microsoft, "On-behalf-of flow", "Success response example", its
    // `access_token` signed now with the v2.0 claims the `entra` preset reads.
    let harness = Harness::start(Flavor::Entra).await;
    let (subject, claims) = harness.person();
    let now = harness.now();
    let mut issued = Flavor::Entra.issued_claims(&claims, now);
    issued["aud"] = json!("https://graph.microsoft.com");
    issued["exp"] = json!(now + 3269);
    issued["scp"] = json!("User.Read");
    let token = sign(&harness.key, &issued);
    harness
        .answer(ResponseTemplate::new(200).set_body_json(json!({
            "token_type": "Bearer",
            "scope": "https://graph.microsoft.com/user.read",
            "expires_in": 3269,
            "ext_expires_in": 0,
            "access_token": token
        })))
        .await;
    let onward = harness
        .onward
        .token(&subject, None, &graph())
        .await
        .expect("accepted");
    assert_eq!(
        Some(format!("Bearer {token}").as_str()),
        onward.header().to_str().ok()
    );
    assert_eq!(
        claims["exp"].as_i64(),
        Some(onward.expires_at()),
        "used only until the subject token's exp"
    );
}

#[tokio::test]
async fn entra_error_response_is_interaction_required_with_its_challenge() {
    // NOTE: Microsoft, "On-behalf-of flow", "Error response example": the
    // middle tier surfaces it to its client with the claims challenge.
    let harness = Harness::start(Flavor::Entra).await;
    let (subject, _) = harness.person();
    harness
        .answer(ResponseTemplate::new(400).set_body_raw(ERROR_RESPONSE, "application/json"))
        .await;
    let error = harness
        .onward
        .token(&subject, None, &graph())
        .await
        .expect_err("refused");
    assert_eq!(Some(StatusCode::BAD_REQUEST), error.status());
    match error {
        OnwardError::InteractionRequired {
            status,
            error,
            challenge,
        } => {
            assert_eq!(StatusCode::BAD_REQUEST, status);
            assert_eq!("interaction_required", error.error);
            assert_eq!(Some(CHALLENGE), challenge.as_deref());
        }
        other => panic!("not interaction_required: {other:?}"),
    }
}

#[tokio::test]
async fn interaction_required_without_a_challenge_carries_none() {
    for flavor in [Flavor::Generic, Flavor::Keycloak] {
        let harness = Harness::start(flavor).await;
        let (subject, _) = harness.person();
        harness
            .answer(ResponseTemplate::new(400).set_body_json(json!({
                "error": "interaction_required"
            })))
            .await;
        let error = harness.token(&subject, None).await.expect_err("refused");
        assert!(
            matches!(
                error,
                OnwardError::InteractionRequired {
                    challenge: None,
                    ..
                }
            ),
            "{flavor:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn keycloak_example_request_is_reproduced_byte_for_byte() {
    // NOTE: Keycloak 26.8.2 token-exchange.adoc, "Example token exchange
    // request" of `requester-client` with Basic `requester-client:password`.
    let harness = Harness::start(Flavor::Keycloak).await;
    let (subject, claims) = harness.person();
    let issued = Flavor::Keycloak.issued_claims(&claims, harness.now());
    let token = sign(&harness.key, &issued);
    harness
        .answer(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": token,
            "expires_in": 300,
            "token_type": "Bearer",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "session_state": "287f3c57-32b8-4c0f-8b00-8c7db231d701",
            "scope": "default-scope1",
            "refresh_expires_in": 0,
            "not-before-policy": 0
        })))
        .await;
    let target = Target::new(["target-client2"]);
    harness
        .onward
        .token(&subject, None, &target)
        .await
        .expect("accepted");
    let requests = harness.server.received_requests().await.unwrap_or_default();
    let request = requests.first().expect("one request");
    let subject_token = param(&super::form(request), "subject_token")
        .expect("the subject token")
        .to_owned();
    let expected = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token={subject_token}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
    );
    assert_eq!(expected.as_bytes(), request.body.as_slice());
    assert_eq!(
        Some("Basic cmVxdWVzdGVyLWNsaWVudDpwYXNzd29yZA=="),
        request
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
    );
}

/// Returns the outcome of Keycloak Examples 1 to 3: a request naming
/// `audiences`, answered with a token whose `aud` is `issued_aud`, checked
/// against `allowed`.
async fn keycloak_example(
    audiences: &[&str],
    issued_aud: &[&str],
    allowed: &[&str],
) -> (Result<(), OnwardError>, Vec<(String, String)>) {
    let harness = Harness::start(Flavor::Keycloak).await;
    let (subject, claims) = harness.person();
    let mut issued = super::object(&Flavor::Keycloak.issued_claims(&claims, harness.now()));
    issued.insert(String::from("aud"), json!(issued_aud));
    let scope = if audiences.is_empty() {
        "default-scope1 optional-scope2"
    } else {
        "optional-scope2"
    };
    issued.insert(String::from("scope"), json!(scope));
    let issued = serde_json::Value::Object(issued);
    harness.issue(&issued, None).await;
    let mut target = Target::new(allowed.iter().copied()).with_scope("optional-scope2");
    for audience in audiences {
        target = target.with_indicator(*audience);
    }
    let outcome = harness
        .onward
        .token(&subject, None, &target)
        .await
        .map(drop);
    let form = received(&harness.server)
        .await
        .into_iter()
        .next()
        .unwrap_or_default();
    (outcome, form)
}

#[tokio::test]
async fn keycloak_example_1_without_audience_is_accepted_for_both_audiences() {
    // NOTE: Keycloak 26.8.2 token-exchange.adoc, Example 1: no `audience`, so
    // no filtering, and `aud` names target-client1 and target-client2.
    let both = ["target-client1", "target-client2"];
    let (outcome, form) = keycloak_example(&[], &both, &both).await;
    assert!(outcome.is_ok(), "{outcome:?}");
    assert_eq!(Some("optional-scope2"), param(&form, "scope"));
    assert_eq!(None, param(&form, "audience"));
}

#[tokio::test]
async fn keycloak_example_1_is_refused_for_a_target_that_admits_one_audience() {
    // NOTE: Keycloak 26.8.2 token-exchange.adoc, Example 1's token also names
    // target-client1, which a target-client2 target never receives.
    let (outcome, _) = keycloak_example(
        &[],
        &["target-client1", "target-client2"],
        &["target-client2"],
    )
    .await;
    assert!(
        matches!(outcome, Err(OnwardError::Rejected(Rejected::Audience))),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn keycloak_example_2_with_audience_is_accepted() {
    // NOTE: Keycloak 26.8.2 token-exchange.adoc, Example 2: `audience`
    // target-client2 filters `aud` to that client.
    let (outcome, form) = keycloak_example(
        &["target-client2"],
        &["target-client2"],
        &["target-client2"],
    )
    .await;
    assert!(outcome.is_ok(), "{outcome:?}");
    assert_eq!(Some("target-client2"), param(&form, "audience"));
    assert_eq!(None, param(&form, "resource"), "Keycloak reads no resource");
}

#[tokio::test]
async fn keycloak_example_3_rejected_by_the_server_is_a_typed_error() {
    // NOTE: Keycloak 26.8.2 token-exchange.adoc, Example 3 "will be rejected";
    // the error code is RFC 8693 §2.2.2's `invalid_target`, which the guide
    // does not name.
    let harness = Harness::start(Flavor::Keycloak).await;
    let (subject, _) = harness.person();
    harness
        .answer(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_target"
        })))
        .await;
    let target = Target::new(["target-client2", "target-client3"])
        .with_indicator("target-client2")
        .with_indicator("target-client3")
        .with_scope("optional-scope2");
    let error = harness
        .onward
        .token(&subject, None, &target)
        .await
        .expect_err("refused");
    assert!(
        matches!(&error, OnwardError::Token(TokenError::Refused { status, error: Some(oauth), .. }) if *status == StatusCode::BAD_REQUEST && oauth.error == "invalid_target"),
        "{error:?}"
    );
    let form = received(&harness.server).await;
    let audiences: Vec<&str> = form
        .first()
        .map(|form| {
            form.iter()
                .filter(|(name, _)| name == "audience")
                .map(|(_, value)| value.as_str())
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(vec!["target-client2", "target-client3"], audiences);
}

#[tokio::test]
async fn entra_downstream_target_is_named_by_its_default_scope() {
    // NOTE: Microsoft, "On-behalf-of flow", ".default and combined consent": a
    // resource is asked for as `<resource>/.default`.
    let harness = Harness::start(Flavor::Entra).await;
    let (subject, claims) = harness.person();
    harness
        .issue(&Flavor::Entra.issued_claims(&claims, harness.now()), None)
        .await;
    harness.token(&subject, None).await.expect("accepted");
    let sent = received(&harness.server).await;
    let form = sent.first().expect("one request");
    assert_eq!(
        Some(format!("api://{ENTRA_TARGET}/.default").as_str()),
        param(form, "scope")
    );
    assert_eq!(Some("on_behalf_of"), param(form, "requested_token_use"));
}
