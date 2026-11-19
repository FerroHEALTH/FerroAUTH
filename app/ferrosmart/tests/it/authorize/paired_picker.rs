// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The patient picker at an openEHR resource server paired with the
//! platform's FHIR server: the patient picked at the FHIR server and their
//! EHR looked up at the openEHR server, both as the signed-in person, with
//! `patient` and `ehrId` in the launch context (SMART on openEHR draft,
//! Context Selection and Service Discovery).

use super::ehr_picker::{EHR_ID, NAMESPACE, OpenEhr, lookups};
use super::*;

/// The scope the app asks for at the openEHR server.
const SCOPE: &str = "openid fhirUser launch/patient patient/composition-*.r";
/// The system of the identifier that names an EHR's subject.
const SYSTEM: &str = "urn:example:mrn";
/// The identifier of the FHIR stub's one patient in [`SYSTEM`].
const RECORD: &str = "MRN-1";

/// A platform: its FHIR server, its openEHR server, and the claims each
/// was shown.
struct Platform {
    /// FerroSMART over both.
    smart: Smart,
    /// The FHIR base.
    fhir_base: String,
    /// The openEHR base, the audience of the launch.
    openehr_base: String,
    /// The claims of the tokens the FHIR server was shown.
    fhir_seen: Arc<std::sync::Mutex<Vec<Value>>>,
    /// The claims of the tokens the openEHR server was shown.
    openehr_seen: Arc<std::sync::Mutex<Vec<Value>>>,
    /// The FHIR server, kept for the case's length.
    _fhir: MockServer,
    /// The openEHR server, kept for the case's length.
    _openehr: MockServer,
}

/// Starts a platform whose FHIR patient `p-1` carries [`RECORD`] in
/// [`SYSTEM`], whose openEHR server answers as `openehr`, and whose openEHR
/// base reads a patient's subject from `system`.
async fn platform(openehr: impl wiremock::Respond + 'static, system: &str) -> Platform {
    let fhir_server = MockServer::start().await;
    let fhir_seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(matchers::method("GET"))
        .respond_with(Fhir {
            seen: Arc::clone(&fhir_seen),
        })
        .mount(&fhir_server)
        .await;
    let openehr_server = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/openehr/v1/ehr"))
        .respond_with(openehr)
        .mount(&openehr_server)
        .await;
    let fhir_base = format!("{}/fhir", fhir_server.uri());
    let openehr_base = format!("{}/openehr/v1", openehr_server.uri());
    let smart = Smart::start_over(
        "[\"authorization_code\"]",
        "[\"openid\", \"fhirUser\", \"launch/patient\", \"patient/composition-*.r\"]",
        "[\"patient/composition-*.r\"]",
        &format!(
            "[[ferrosmart.resource]]\nbase = {fhir_base:?}\n\
             [[ferrosmart.resource]]\nbase = {openehr_base:?}\nkind = \"openehr\"\n\
             subject_namespace = {NAMESPACE:?}\nfhir_base = {fhir_base:?}\n\
             subject_system = {system:?}\n"
        ),
    )
    .await;
    Platform {
        smart,
        fhir_base,
        openehr_base,
        fhir_seen,
        openehr_seen: Arc::new(std::sync::Mutex::new(Vec::new())),
        _fhir: fhir_server,
        _openehr: openehr_server,
    }
}

/// Starts a platform whose openEHR server holds the EHR of `subject`.
async fn platform_holding(subject: &'static str, system: &str) -> Platform {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut platform = platform(
        OpenEhr {
            subject,
            seen: Arc::clone(&seen),
        },
        system,
    )
    .await;
    platform.openehr_seen = seen;
    platform
}

/// Runs the launch to the picker as the clinician, searches, and posts the
/// choice of patient `p-1`; returns the cookie and the answer.
async fn choose(platform: &Platform) -> (String, StatusCode, http::HeaderMap, String) {
    let smart = &platform.smart;
    let cookie = to_picker_asking(
        smart,
        &platform.openehr_base,
        SCOPE,
        "synthetic-person",
        "Practitioner/synthetic-1",
    )
    .await;
    let (status, _, page) = smart.get("/picker", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(
        page.contains("name=\"name\"") && !page.contains("name=\"subject_id\""),
        "the FHIR search form: {page}"
    );
    let (status, _, page) = smart.get("/picker?name=Synthetic", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(page.contains("value=\"p-1\""), "{page}");
    let token = form_token(&page);
    let (status, headers, page) = smart
        .post(
            "/picker",
            &[("form_token", token.as_str()), ("patient", "p-1")],
            Some(&cookie),
        )
        .await;
    (cookie, status, headers, page)
}

#[tokio::test]
async fn a_standalone_launch_at_a_paired_openehr_base_picks_the_patient_and_their_ehr() {
    let platform = platform_holding(RECORD, SYSTEM).await;
    let smart = &platform.smart;
    let (cookie, status, headers, page) = choose(&platform).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    assert_eq!("/consent", location(&headers).path());
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    let token = form_token(&page);
    let (_, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", token.as_str()),
                ("decision", "approve"),
                ("scope", "openid"),
                ("scope", "launch/patient"),
                ("scope", "patient/composition-*.r"),
            ],
            Some(&cookie),
        )
        .await;
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
    let body: Value = serde_json::from_str(&body).expect("JSON");
    // NOTE: SMART on openEHR draft, Context Selection, `launch/patient` asks for
    // "both FHIR Patient resource and corresponding openEHR EHR instance".
    assert_eq!(json!("p-1"), body["patient"]);
    assert_eq!(json!(EHR_ID), body["ehrId"]);
    let access: Value = jsonwebtoken::dangerous::insecure_decode_claims(
        body["access_token"].as_str().expect("a token"),
    )
    .expect("claims");
    assert_eq!(json!("p-1"), access["patient"], "the token carries it too");
    assert_eq!(json!(EHR_ID), access["ehrId"], "the token carries it too");
    assert_eq!(json!(platform.openehr_base), access["aud"]);

    // Each server was asked as the person, with a token for that server and
    // that request alone, revoked once it was answered.
    let fhir = platform.fhir_seen.lock().expect("held").clone();
    let openehr = platform.openehr_seen.lock().expect("held").clone();
    assert_eq!(2, fhir.len(), "the search and the read again");
    assert_eq!(1, openehr.len(), "the EHR lookup");
    let asked = fhir
        .iter()
        .map(|claims| (claims, &platform.fhir_base, "user/Patient.rs"))
        .chain(
            openehr
                .iter()
                .map(|claims| (claims, &platform.openehr_base, "user/composition-*.r")),
        );
    for (claims, base, scope) in asked {
        assert_eq!(access["sub"], claims["sub"], "the person, never a system");
        assert_eq!(json!(base), claims["aud"], "a token for the one server");
        assert_eq!(json!(scope), claims["scope"]);
        let lifetime = claims["exp"].as_i64().expect("exp") - claims["iat"].as_i64().expect("iat");
        assert!(lifetime <= 30, "a minimal lifetime: {lifetime}");
        let jti = claims["jti"].as_str().expect("a jti");
        assert!(
            smart.store.revoked(jti).await.expect("read"),
            "revoked after use"
        );
    }
    // NOTE: Regulation (EU) 2025/327 Annex II 3.2, every search, read and lookup
    // is an access record that names the server it reached.
    let stored = records(&smart.store).await;
    let found = lookups(&stored);
    assert_eq!(1, found.len(), "{stored:?}");
    let text = serde_json::to_string(&found).expect("JSON");
    assert!(text.contains(EHR_ID), "the EHR reached: {text}");
    assert!(text.contains(RECORD), "the patient named: {text}");
    let text = serde_json::to_string(&stored).expect("JSON");
    assert!(
        text.contains(&platform.fhir_base),
        "the FHIR server reached: {text}"
    );
    platform.smart.stop().await;
}

#[tokio::test]
async fn a_patient_without_an_ehr_is_told_so_and_enters_no_context() {
    // The openEHR server holds no EHR of the patient's identifier.
    let platform = platform_holding("another-subject", SYSTEM).await;
    let (cookie, status, _, page) = choose(&platform).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(
        page.contains("This patient has no health record you may see."),
        "{page}"
    );
    assert!(page.contains("name=\"name\""), "the person searches again");
    let pending = platform
        .smart
        .store
        .pending(&cookie)
        .await
        .expect("read")
        .expect("pending");
    assert!(pending.launch_context.is_none(), "no context entered");
    let stored = records(&platform.smart.store).await;
    assert_eq!(1, lookups(&stored).len(), "the lookup is recorded");
    platform.smart.stop().await;
}

#[tokio::test]
async fn a_patient_without_the_subject_identifier_has_no_ehr_to_look_up() {
    let platform = platform_holding(RECORD, "urn:example:national-id").await;
    let (cookie, status, _, page) = choose(&platform).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(
        page.contains("This patient has no health record you may see."),
        "{page}"
    );
    assert!(
        platform.openehr_seen.lock().expect("held").is_empty(),
        "no subject to look up"
    );
    let pending = platform
        .smart
        .store
        .pending(&cookie)
        .await
        .expect("read")
        .expect("pending");
    assert!(pending.launch_context.is_none(), "no context entered");
    platform.smart.stop().await;
}

#[tokio::test]
async fn a_failed_ehr_lookup_at_a_paired_base_is_an_error_page_and_an_access_record() {
    let platform = platform(ResponseTemplate::new(500), SYSTEM).await;
    let (cookie, status, _, page) = choose(&platform).await;
    assert_eq!(StatusCode::INTERNAL_SERVER_ERROR, status, "{page}");
    assert!(
        !page.contains("no health record"),
        "a failure is no empty result"
    );
    let pending = platform
        .smart
        .store
        .pending(&cookie)
        .await
        .expect("read")
        .expect("pending");
    assert!(pending.launch_context.is_none(), "no context entered");
    let stored = records(&platform.smart.store).await;
    assert_eq!(1, lookups(&stored).len(), "the failed lookup is recorded");
    platform.smart.stop().await;
}

#[tokio::test]
async fn a_patient_the_person_may_not_see_is_never_looked_up() {
    let platform = platform_holding(RECORD, SYSTEM).await;
    let smart = &platform.smart;
    let cookie = to_picker_asking(
        smart,
        &platform.openehr_base,
        SCOPE,
        "other-person",
        "Practitioner/synthetic-2",
    )
    .await;
    let token = smart
        .store
        .pending(&cookie)
        .await
        .expect("read")
        .expect("pending")
        .form_token;
    let (status, _, _) = smart
        .post(
            "/picker",
            &[("form_token", token.as_str()), ("patient", "p-1")],
            Some(&cookie),
        )
        .await;
    assert_eq!(
        StatusCode::BAD_REQUEST,
        status,
        "a forged choice is refused"
    );
    assert!(
        platform.openehr_seen.lock().expect("held").is_empty(),
        "no EHR is looked up for a patient the person may not read"
    );
    platform.smart.stop().await;
}
