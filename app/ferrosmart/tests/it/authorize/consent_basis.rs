// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A remembered consent answers only for the client and the resource
//! server it was given for, and every code's record names the basis it was
//! issued on (`docs/architecture.md` §13.6 item 6, §13.2; no specification
//! governs either: our own design).

use super::*;

/// The second resource server of the case.
const SECOND: &str = "https://second.example.org/fhir";

/// The scope every request of the case asks for.
const SCOPE: &str = "openid fhirUser user/Observation.rs";

/// Runs a request to `aud` past the login and returns where the callback
/// sends the browser, with the cookie.
async fn login_at(smart: &Smart, aud: &str) -> (String, Url) {
    let (_, headers, _) = smart
        .get(&authorize_path(&[("aud", aud), ("scope", SCOPE)]), None)
        .await;
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer(&param(&upstream, "nonce").expect("a nonce"), &["clinician"])
        .await;
    let callback = format!(
        "/callback?code=b&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "the login returns");
    (cookie, location(&headers))
}

#[tokio::test]
async fn a_remembered_consent_answers_only_at_the_resource_server_it_was_given_for() {
    let smart = Smart::start_over(
        "[\"authorization_code\"]",
        "[\"openid\", \"fhirUser\", \"user/Observation.rs\"]",
        "[\"user/Observation.rs\"]",
        &format!(
            "[[ferrosmart.resource]]\nbase = {RESOURCE:?}\n\
             [[ferrosmart.resource]]\nbase = {SECOND:?}\n"
        ),
    )
    .await;
    let (cookie, back) = login_at(&smart, RESOURCE).await;
    assert_eq!("/consent", back.path(), "nothing remembered yet");
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    let decision = [
        ("form_token", form_token(&page)),
        ("decision", String::from("approve")),
        ("scope", String::from("user/Observation.rs")),
        ("remember", String::from("yes")),
    ];
    let pairs: Vec<(&str, &str)> = decision
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    let (status, _, _) = smart.post("/consent", &pairs, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status);

    let (_, back) = login_at(&smart, RESOURCE).await;
    assert!(
        back.as_str().starts_with(REDIRECT),
        "the same client at the same server: {back}"
    );
    let (_, back) = login_at(&smart, SECOND).await;
    assert_eq!(
        "/consent",
        back.path(),
        "a consent given at one server never answers at another"
    );
    // NOTE: docs/architecture.md §13.2, each code's record names its basis.
    assert_eq!(
        vec![String::from("page"), String::from("remembered")],
        bases(&records(&smart.store).await)
    );
    smart.stop().await;
}
