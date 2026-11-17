// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The encounter step of the picker at a FHIR server: after the patient,
//! one of that patient's encounters the person may see, read again as them
//! before it enters the launch context (SMART App Launch 2.2.0, Scopes and
//! Launch Context, Standalone apps, `context-standalone-encounter`).

use super::*;

/// The scope the app asks for.
const SCOPE: &str = "openid fhirUser launch/patient launch/encounter patient/Observation.rs";
/// The person who may see the patient and the encounter.
const ALLOWED: &str = "Practitioner/synthetic-1";

/// A FHIR server that holds the patient `p-1` with the encounters `e-1` and
/// `e-2`, and `e-9` of another patient, all of which only [`ALLOWED`] may
/// see; it keeps the claims of every token it was shown.
struct Fhir {
    /// The claims of the tokens it was shown.
    seen: Arc<std::sync::Mutex<Vec<Value>>>,
}

impl wiremock::Respond for Fhir {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let token = request
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default();
        let Ok(claims) = jsonwebtoken::dangerous::insecure_decode_claims::<Value>(token) else {
            return ResponseTemplate::new(401);
        };
        let person = claims.get("fhirUser") == Some(&json!(ALLOWED));
        let scope = claims
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        self.seen.lock().expect("held").push(claims);
        let path = request.url.path();
        let encounter = |id: &str, patient: &str, start: &str| {
            json!({
                "resourceType": "Encounter", "id": id, "status": "finished",
                "class": {"system": "http://terminology.hl7.org/CodeSystem/v3-ActCode", "code": "AMB"},
                "type": [{"text": format!("Visit {id}")}],
                "subject": {"reference": format!("Patient/{patient}")},
                "period": {"start": start}
            })
        };
        let encounters = [
            encounter("e-1", "p-1", "2026-01-02T09:00:00Z"),
            encounter("e-2", "p-1", "2026-03-04T09:00:00Z"),
            encounter("e-9", "p-9", "2026-05-06T09:00:00Z"),
        ];
        if path.contains("/Patient") {
            if !(person && scope == "user/Patient.rs") {
                return ResponseTemplate::new(403);
            }
            let patient = json!({
                "resourceType": "Patient", "id": "p-1",
                "name": [{"given": ["Synthetic"], "family": "Patient"}]
            });
            if path.ends_with("/Patient/p-1") {
                return ResponseTemplate::new(200).set_body_json(patient);
            }
            return ResponseTemplate::new(200).set_body_json(json!({
                "resourceType": "Bundle", "type": "searchset", "entry": [{"resource": patient}]
            }));
        }
        if !(person && scope == "user/Encounter.rs") {
            return ResponseTemplate::new(403);
        }
        if let Some(id) = path
            .rsplit('/')
            .next()
            .filter(|_| !path.ends_with("/Encounter"))
        {
            return encounters
                .iter()
                .find(|resource| resource["id"] == json!(id))
                .map_or_else(
                    || ResponseTemplate::new(404),
                    |resource| ResponseTemplate::new(200).set_body_json(resource),
                );
        }
        // NOTE: the server answers the search with the other patient's
        // encounter too, which the picker leaves out.
        let entry: Vec<Value> = encounters
            .iter()
            .map(|resource| json!({ "resource": resource }))
            .collect();
        ResponseTemplate::new(200)
            .set_body_json(json!({ "resourceType": "Bundle", "type": "searchset", "entry": entry }))
    }
}

/// Starts FerroSMART over a FHIR server for a standalone launch with
/// `launch/patient` and `launch/encounter`, runs it to the picker as the
/// person with `fhir_user`, and returns them with the cookie and the claims
/// the server sees.
async fn to_encounter_picker(
    fhir_user: &str,
) -> (Smart, MockServer, String, Arc<std::sync::Mutex<Vec<Value>>>) {
    let fhir = MockServer::start().await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(matchers::method("GET"))
        .respond_with(Fhir {
            seen: Arc::clone(&seen),
        })
        .mount(&fhir)
        .await;
    let base = format!("{}/fhir", fhir.uri());
    let smart = Smart::start_on(
        "[\"authorization_code\"]",
        "[\"openid\", \"fhirUser\", \"launch/patient\", \"launch/encounter\", \"patient/Observation.rs\"]",
        "[\"patient/Observation.rs\"]",
        Some(&base),
    )
    .await;
    let cookie = to_picker_asking(&smart, &base, SCOPE, "synthetic-person", fhir_user).await;
    (smart, fhir, cookie, seen)
}

/// Chooses the patient `p-1` on the picker of `cookie` and returns where the
/// browser is sent.
async fn choose_patient(smart: &Smart, cookie: &str) -> Url {
    let (_, _, page) = smart.get("/picker?name=Synthetic", Some(cookie)).await;
    let token = form_token(&page);
    let (status, headers, _) = smart
        .post(
            "/picker",
            &[("form_token", &token), ("patient", "p-1")],
            Some(cookie),
        )
        .await;
    assert_eq!(
        StatusCode::SEE_OTHER,
        status,
        "the choice sends the browser on"
    );
    location(&headers)
}

/// Approves every scope offered on the consent page of `cookie`, redeems
/// the code and returns the token response.
async fn approve_all(smart: &Smart, cookie: &str) -> Value {
    let (_, _, page) = smart.get("/consent", Some(cookie)).await;
    let token = form_token(&page);
    let offered: Vec<String> = page
        .split("name=\"scope\" value=\"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .map(str::to_owned)
        .collect();
    let mut form = vec![("form_token", token.as_str()), ("decision", "approve")];
    form.extend(offered.iter().map(|scope| ("scope", scope.as_str())));
    let (_, headers, _) = smart.post("/consent", &form, Some(cookie)).await;
    let code = param(&location(&headers), "code").expect("a code");
    let (status, _, body) = smart
        .post(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", REDIRECT),
                ("code_verifier", VERIFIER),
                ("client_id", "app"),
            ],
            None,
        )
        .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    serde_json::from_str(&body).expect("JSON")
}

#[tokio::test]
async fn a_standalone_launch_picks_an_encounter_of_the_chosen_patient() {
    let (smart, _fhir, cookie, seen) = to_encounter_picker(ALLOWED).await;
    let next = choose_patient(&smart, &cookie).await;
    assert_eq!("/picker", next.path());
    assert_eq!(Some(String::from("p-1")), param(&next, "patient"));
    let (status, _, page) = smart
        .get(
            &format!("{}?{}", next.path(), next.query().unwrap_or_default()),
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(page.contains("<h1 class=\"fui-page-card-title\">Choose an encounter</h1>"));
    let latest = page.find("value=\"e-2\"").expect("e-2 is offered");
    let earlier = page.find("value=\"e-1\"").expect("e-1 is offered");
    assert!(latest < earlier, "the latest encounter first");
    assert!(
        !page.contains("e-9"),
        "another patient's encounter never shows"
    );
    let token = form_token(&page);
    let (status, headers, _) = smart
        .post(
            "/picker",
            &[
                ("form_token", token.as_str()),
                ("step", "encounter"),
                ("patient", "p-1"),
                ("encounter", "e-2"),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert_eq!("/consent", location(&headers).path());
    let (_, _, consent) = smart.get("/consent", Some(&cookie)).await;
    assert!(consent.contains("value=\"launch/encounter\""), "{consent}");
    let body = approve_all(&smart, &cookie).await;
    // NOTE: SMART App Launch 2.2.0, Launch context arrives with your access_token.
    assert_eq!(json!("p-1"), body["patient"]);
    assert_eq!(json!("e-2"), body["encounter"]);
    let access: Value = jsonwebtoken::dangerous::insecure_decode_claims(
        body["access_token"].as_str().expect("a token"),
    )
    .expect("claims");
    assert_eq!(
        json!("e-2"),
        access["encounter"],
        "the token carries it too"
    );
    assert!(
        body["scope"]
            .as_str()
            .is_some_and(|scope| scope.split(' ').any(|scope| scope == "launch/encounter")),
        "{body}"
    );
    // The patient search and read, the encounter search, and the encounter
    // step's patient and encounter reads, each as the person.
    let shown = seen.lock().expect("held").clone();
    let scopes: Vec<&str> = shown
        .iter()
        .filter_map(|claims| claims["scope"].as_str())
        .collect();
    assert_eq!(
        vec![
            "user/Patient.rs",
            "user/Patient.rs",
            "user/Encounter.rs",
            "user/Patient.rs",
            "user/Encounter.rs"
        ],
        scopes
    );
    for claims in &shown {
        assert_eq!(access["sub"], claims["sub"], "the person, never a system");
        let jti = claims["jti"].as_str().expect("a jti");
        assert!(smart.store.revoked(jti).await.expect("read"), "revoked");
    }
    smart.stop().await;
}

#[tokio::test]
async fn a_person_may_go_on_without_an_encounter() {
    let (smart, _fhir, cookie, _seen) = to_encounter_picker(ALLOWED).await;
    let next = choose_patient(&smart, &cookie).await;
    let (_, _, page) = smart
        .get(
            &format!("{}?{}", next.path(), next.query().unwrap_or_default()),
            Some(&cookie),
        )
        .await;
    let token = form_token(&page);
    let (status, headers, _) = smart
        .post(
            "/picker",
            &[
                ("form_token", token.as_str()),
                ("step", "encounter"),
                ("patient", "p-1"),
                ("without", "yes"),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert_eq!("/consent", location(&headers).path());
    let (_, _, consent) = smart.get("/consent", Some(&cookie)).await;
    assert!(
        !consent.contains("value=\"launch/encounter\""),
        "no encounter, no launch/encounter: {consent}"
    );
    let body = approve_all(&smart, &cookie).await;
    assert_eq!(json!("p-1"), body["patient"]);
    assert!(body.get("encounter").is_none(), "{body}");
    smart.stop().await;
}

#[tokio::test]
async fn an_encounter_of_another_patient_or_unseen_is_refused() {
    let (smart, _fhir, cookie, _seen) = to_encounter_picker(ALLOWED).await;
    choose_patient(&smart, &cookie).await;
    let token = smart
        .store
        .pending(&cookie)
        .await
        .expect("read")
        .expect("pending")
        .form_token;
    for encounter in ["e-9", "e-404"] {
        let (status, _, _) = smart
            .post(
                "/picker",
                &[
                    ("form_token", token.as_str()),
                    ("step", "encounter"),
                    ("patient", "p-1"),
                    ("encounter", encounter),
                ],
                Some(&cookie),
            )
            .await;
        assert_eq!(StatusCode::BAD_REQUEST, status, "{encounter}");
    }
    let (_, headers, _) = smart.get("/consent", Some(&cookie)).await;
    assert_eq!(
        "/picker",
        location(&headers).path(),
        "nothing entered the context"
    );
    smart.stop().await;
}

#[tokio::test]
async fn the_encounter_step_is_refused_where_no_encounter_was_asked_for() {
    let (smart, fhir, _seen) = picker_launch().await;
    let base = format!("{}/fhir", fhir.uri());
    let cookie = to_picker(&smart, &base, "synthetic-person", ALLOWED).await;
    let (status, _, _) = smart.get("/picker?patient=p-1", Some(&cookie)).await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    smart.stop().await;
}
