// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A patient's own token exchanged at a `patients` issuer, by token
//! exchange (RFC 8693 §2.1) and by Microsoft Entra ID's on-behalf-of flow
//! (the JWT bearer grant of RFC 7523 §2.1): the issued token must read as a
//! patient token of that issuer and keep the patient context.

use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::client::onward::Rejected;
use ferrohealth_smart::client::onward::SubjectToken;
use ferrohealth_smart::config::credentials::CredentialsSection;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::kind::Unclassified;
use ferrohealth_smart::profile::onward::OnwardGrant;
use ferrohealth_smart::resource::PatientClaim;
use secrecy::SecretString;
use serde_json::Value;
use serde_json::json;

use super::caller;
use super::harness::Flavor;
use super::harness::Harness;
use super::param;
use super::received;
use super::sign;
use crate::support::temp_file;

/// The two forms of the exchange: RFC 8693 token exchange and Entra ID's
/// on-behalf-of flow.
const FORMS: [Flavor; 2] = [Flavor::Generic, Flavor::Entra];

/// The patient the cases' tokens name.
const PATIENT: &str = "synthetic-patient-1";

/// Returns the scope claim the flavor's profile reads.
const fn scope_claim(flavor: Flavor) -> &'static str {
    match flavor {
        Flavor::Entra => "scp",
        Flavor::Generic | Flavor::GenericJwtBearer | Flavor::Keycloak => "scope",
    }
}

/// Starts the harness of `flavor` over a `patients` issuer.
async fn start(flavor: Flavor) -> Harness {
    let mut settings = flavor.settings(3600);
    settings.kind = IssuerKind::Patients;
    Harness::with_settings(flavor, settings).await
}

/// Returns `claims` with `claim` set to `value`.
fn with(mut claims: Value, claim: &str, value: Value) -> Value {
    if let Some(object) = claims.as_object_mut() {
        object.insert(claim.to_owned(), value);
    }
    claims
}

/// Returns the claims of a patient's token under `flavor`, naming the
/// patient in its `patient` launch context.
fn patient_claims(flavor: Flavor, now: i64) -> Value {
    let claims = with(
        flavor.subject_claims(now),
        scope_claim(flavor),
        json!("patient/*.rs"),
    );
    with(claims, "patient", json!(PATIENT))
}

/// Returns the claims of the patient token an exchange of `subject` issues.
fn issued_claims(flavor: Flavor, subject: &Value, now: i64) -> Value {
    let issued = with(
        flavor.issued_claims(subject, now),
        scope_claim(flavor),
        json!("patient/Observation.rs"),
    );
    let issued = with(issued, "patient", json!(PATIENT));
    // NOTE: the `entra` preset reads `acct` as a user claim, so a patient token of
    // that issuer carries it as the subject token does.
    match subject.get("acct") {
        Some(acct) => with(issued, "acct", acct.clone()),
        None => issued,
    }
}

/// Returns the patient's subject token and its claims.
fn patient(harness: &Harness) -> (SubjectToken, Value) {
    let claims = patient_claims(harness.flavor, harness.now());
    (harness.subject(&claims, CallerKind::Patient), claims)
}

/// Returns the refusal of an exchange whose issued token `change` alters,
/// and the requests the token endpoint received.
async fn refused(flavor: Flavor, change: impl Fn(&mut Value)) -> (OnwardError, usize) {
    let harness = start(flavor).await;
    let (subject, claims) = patient(&harness);
    let mut issued = issued_claims(flavor, &claims, harness.now());
    change(&mut issued);
    harness.issue(&issued, None).await;
    let error = harness
        .token(&subject, None)
        .await
        .expect_err("the issued token is refused");
    (error, harness.calls().await)
}

#[tokio::test]
async fn a_patients_token_is_exchanged_in_both_forms_and_keeps_the_patient() {
    for flavor in FORMS {
        let harness = start(flavor).await;
        let (subject, claims) = patient(&harness);
        let issued = issued_claims(flavor, &claims, harness.now());
        let token = harness.issue(&issued, None).await;
        let onward = harness
            .token(&subject, None)
            .await
            .expect("the patient's exchange succeeds");
        assert_eq!(
            Some(format!("Bearer {token}").as_str()),
            onward.header().to_str().ok(),
            "{flavor:?}"
        );
        let sent = received(&harness.server).await;
        let form = sent.first().expect("one request");
        assert_eq!(
            Some(flavor.grant().grant_type()),
            param(form, "grant_type"),
            "{flavor:?}"
        );
        match flavor.grant() {
            // NOTE: RFC 8693 §2.1, the patient's token is the `subject_token`.
            OnwardGrant::TokenExchange => assert!(param(form, "subject_token").is_some()),
            // NOTE: Microsoft, "On-behalf-of flow": the patient's token is the
            // `assertion`, with `requested_token_use=on_behalf_of`.
            OnwardGrant::JwtBearer => {
                assert!(param(form, "assertion").is_some());
                assert_eq!(
                    Some("on_behalf_of"),
                    param(form, "requested_token_use"),
                    "{flavor:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn an_issued_token_for_another_patient_is_refused() {
    for flavor in FORMS {
        let (error, _) = refused(flavor, |issued| {
            issued["patient"] = json!("synthetic-patient-2");
        })
        .await;
        assert!(
            matches!(&error, OnwardError::Rejected(Rejected::PatientContext { claim }) if claim == "patient"),
            "{flavor:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn an_issued_token_without_the_patient_is_refused() {
    for flavor in FORMS {
        let (error, _) = refused(flavor, |issued| {
            if let Some(claims) = issued.as_object_mut() {
                claims.remove("patient");
            }
        })
        .await;
        assert!(
            matches!(&error, OnwardError::Rejected(Rejected::PatientContext { claim }) if claim == "patient"),
            "{flavor:?}: {error:?}"
        );
    }
}

// NOTE: SMART on openEHR `master08-scopes`: a patients token names the record
// subject alone, so a `user/` grant beside the `patient/` one is no patient token.
#[tokio::test]
async fn an_issued_token_that_is_no_patient_token_is_refused() {
    for flavor in FORMS {
        let (error, _) = refused(flavor, |issued| {
            issued[scope_claim(flavor)] = json!("patient/Observation.rs user/Observation.rs");
        })
        .await;
        assert!(
            matches!(
                &error,
                OnwardError::Rejected(Rejected::Patient(Unclassified::NotPatientContext))
            ),
            "{flavor:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn a_patients_issuer_refuses_a_persons_token_before_sending() {
    for flavor in FORMS {
        let harness = start(flavor).await;
        let (subject, _) = harness.person();
        let error = harness
            .token(&subject, None)
            .await
            .expect_err("a person is refused");
        assert!(
            matches!(error, OnwardError::PatientRequired),
            "{flavor:?}: {error:?}"
        );
        assert_eq!(0, harness.calls().await, "{flavor:?}: nothing is sent");
    }
}

#[tokio::test]
async fn a_patient_token_without_a_patient_context_is_refused_before_sending() {
    for flavor in FORMS {
        let harness = start(flavor).await;
        let mut claims = patient_claims(flavor, harness.now());
        if let Some(object) = claims.as_object_mut() {
            object.remove("patient");
        }
        let subject = harness.subject(&claims, CallerKind::Patient);
        let error = harness
            .token(&subject, None)
            .await
            .expect_err("no patient context");
        assert!(
            matches!(error, OnwardError::NoPatientContext),
            "{flavor:?}: {error:?}"
        );
        assert_eq!(0, harness.calls().await, "{flavor:?}: nothing is sent");
    }
}

#[tokio::test]
async fn the_deployments_patient_claim_is_kept_too() {
    for flavor in FORMS {
        let harness = start(flavor).await;
        let mut claims = patient_claims(flavor, harness.now());
        claims["person"] = json!({ "patient_id": "nhs-0001" });
        let admitted = caller(&claims, CallerKind::Patient)
            .with_extension(PatientClaim::new("person.patient_id").expect("a claim path"));
        let subject =
            SubjectToken::from_caller(&admitted, SecretString::from(sign(&harness.key, &claims)))
                .expect("the caller holds a verified token");
        let mut issued = issued_claims(flavor, &claims, harness.now());
        issued["person"] = json!({ "patient_id": "nhs-0002" });
        harness.issue(&issued, None).await;
        let error = harness
            .token(&subject, None)
            .await
            .expect_err("another patient id");
        assert!(
            matches!(&error, OnwardError::Rejected(Rejected::PatientContext { claim }) if claim == "person.patient_id"),
            "{flavor:?}: {error:?}"
        );
    }
}

#[test]
fn a_lane_table_accepts_a_patients_issuer() {
    let secret = temp_file("patients-onward-secret", b"password\n");
    let section: CredentialsSection = toml::from_str(&format!(
        "[oauth]\nissuer = \"https://as.example.org\"\nclient_id = \"bridge\"\nclient_secret_file = \"{}\"\n\
         [onward]\nissuer = \"https://patients.example.org\"\nkind = \"patients\"\n\
         token_endpoint = \"https://patients.example.org/token\"\n\
         audiences = [\"https://ehr.example.org\"]\nindicators = [\"https://ehr.example.org/api\"]\n\
         [onward.keys]\nmax_onward_lifetime = 3600",
        secret.display()
    ))
    .expect("the lane parses");
    let lane = section.onward().expect("the lane loads");
    assert!(lane.is_some());
}
