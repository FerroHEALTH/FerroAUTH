// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The roles and the purpose of use of a professional's patient picker
//! lookup at an openEHR resource server (`docs/architecture.md` §13.6 item
//! 4, #716): the token carries the person's `roles`, the lookup and the
//! look-up-again declare the purpose the person chose in the server's
//! header, and a patient's own lookup declares none. No specification
//! governs a picker's purpose: our own design.

use super::ehr_picker::{EHR_ID, NAMESPACE, OpenEhr, lookups};
use super::*;

/// The scope the app asks for at the openEHR server.
const SCOPE: &str = "openid fhirUser launch/patient patient/composition-*.r";
/// The subject id of the EHR the openEHR server holds.
const SUBJECT: &str = "ins01";
/// The code system of the purposes.
const SYSTEM: &str = "http://terminology.hl7.org/CodeSystem/v3-ActReason";

/// An openEHR server that answers as [`OpenEhr`] and keeps the value of
/// the purpose header of every request.
struct Declaring {
    /// The server behind.
    inner: OpenEhr,
    /// The header read.
    header: &'static str,
    /// The values it carried, `None` where it was absent.
    purposes: Arc<std::sync::Mutex<Vec<Option<String>>>>,
}

impl wiremock::Respond for Declaring {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let purpose = request
            .headers
            .get(self.header)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        self.purposes.lock().expect("held").push(purpose);
        self.inner.respond(request)
    }
}

/// FerroSMART over an openEHR server that lists purposes, with what the
/// server saw.
struct Listing {
    /// FerroSMART.
    smart: Smart,
    /// The openEHR base.
    base: String,
    /// The claims of the tokens the server was shown.
    seen: Arc<std::sync::Mutex<Vec<Value>>>,
    /// The purpose header of each request.
    purposes: Arc<std::sync::Mutex<Vec<Option<String>>>>,
    /// The server, kept for the case's length.
    _openehr: MockServer,
}

/// Returns the `[[ferrosmart.resource.purpose]]` tables of `codes`.
fn tables(codes: &[(&str, &str)]) -> String {
    codes
        .iter()
        .map(|(code, display)| {
            format!(
                "[[ferrosmart.resource.purpose]]\ncode = {code:?}\nsystem = {SYSTEM:?}\n\
                 display = {display:?}\n"
            )
        })
        .collect::<Vec<_>>()
        .concat()
}

/// Starts an openEHR server holding the EHR of `subject`, and FerroSMART
/// over it with the resource tables `resource` makes of its base, whose
/// purposes go in `header`.
async fn listing(
    (subject, header): (&'static str, &'static str),
    resource: impl Fn(&str) -> String,
) -> Listing {
    let openehr = MockServer::start().await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let purposes = Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/openehr/v1/ehr"))
        .respond_with(Declaring {
            inner: OpenEhr {
                subject,
                seen: Arc::clone(&seen),
            },
            header,
            purposes: Arc::clone(&purposes),
        })
        .mount(&openehr)
        .await;
    let base = format!("{}/openehr/v1", openehr.uri());
    let smart = Smart::start_over(
        "[\"authorization_code\"]",
        "[\"openid\", \"fhirUser\", \"launch/patient\", \"patient/composition-*.r\"]",
        "[\"patient/composition-*.r\"]",
        &resource(&base),
    )
    .await;
    Listing {
        smart,
        base,
        seen,
        purposes,
        _openehr: openehr,
    }
}

/// Starts FerroSMART over an openEHR base that lists `codes` in the
/// default header.
async fn listing_codes(codes: &[(&str, &str)]) -> Listing {
    let purposes = tables(codes);
    listing((SUBJECT, "x-purpose-of-use"), move |base| {
        format!(
            "[[ferrosmart.resource]]\nbase = {base:?}\nkind = \"openehr\"\n\
             subject_namespace = {NAMESPACE:?}\n{purposes}"
        )
    })
    .await
}

/// The two purposes of most cases.
const TWO: [(&str, &str); 2] = [("TREAT", "Treatment"), ("ETREAT", "Emergency treatment")];

/// Runs the launch to the picker as the clinician and returns the cookie.
async fn at_picker(listing: &Listing) -> String {
    to_picker_asking(
        &listing.smart,
        &listing.base,
        SCOPE,
        "synthetic-person",
        "Practitioner/synthetic-1",
    )
    .await
}

/// Returns the purpose codes the access records of the EHR lookups in
/// `stored` name in `purposeOfEvent`, with their systems.
fn purposes_of_event(stored: &[Value]) -> Vec<Vec<(String, String)>> {
    lookups(stored)
        .into_iter()
        .map(|record| {
            record
                .get("purposeOfEvent")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|concept| concept.get("coding").and_then(Value::as_array))
                .flatten()
                .map(|coding| {
                    let text = |name: &str| {
                        coding
                            .get(name)
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()
                    };
                    (text("system"), text("code"))
                })
                .collect()
        })
        .collect()
}

#[tokio::test]
async fn a_professionals_lookup_carries_their_roles_and_the_purpose_they_chose() {
    let listing = listing_codes(&TWO).await;
    let smart = &listing.smart;
    let cookie = at_picker(&listing).await;
    let (status, _, page) = smart.get("/picker", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    for code in ["TREAT", "ETREAT"] {
        assert!(
            page.contains(&format!(
                "name=\"purpose_of_use\" value=\"{code}\" required>"
            )),
            "{code} offered, none chosen for the person: {page}"
        );
    }
    assert!(page.contains("Emergency treatment"), "{page}");
    let (status, _, page) = smart
        .get(
            &format!("/picker?purpose_of_use=TREAT&subject_id={SUBJECT}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(page.contains(&format!("value=\"{EHR_ID}\"")), "{page}");
    assert!(
        page.contains("value=\"TREAT\" required checked>") && !page.contains("value=\"ETREAT\""),
        "the purpose is kept and shown: {page}"
    );
    let pending = smart
        .store
        .pending(&cookie)
        .await
        .expect("read")
        .expect("pending");
    assert_eq!(Some("TREAT"), pending.purpose_of_use.as_deref());
    let token = form_token(&page);
    let (status, headers, page) = smart
        .post(
            "/picker",
            &[
                ("form_token", token.as_str()),
                ("subject_id", SUBJECT),
                ("ehr_id", EHR_ID),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    assert_eq!("/consent", location(&headers).path());

    assert_eq!(
        vec![Some(String::from("TREAT")); 2],
        *listing.purposes.lock().expect("held"),
        "the lookup and the look-up-again declare the chosen purpose"
    );
    let shown = listing.seen.lock().expect("held").clone();
    assert_eq!(2, shown.len());
    for claims in &shown {
        assert_eq!(json!(["clinician"]), claims["roles"], "{claims}");
        assert!(claims.get("purpose_of_use").is_none(), "no claim: {claims}");
    }
    // NOTE: Regulation (EU) 2025/327 Annex II 3.2 and BALP purposeOfEvent, each
    // lookup's access record names the purpose with its system.
    let stored = records(&smart.store).await;
    assert_eq!(
        vec![vec![(String::from(SYSTEM), String::from("TREAT"))]; 2],
        purposes_of_event(&stored),
        "{stored:?}"
    );
    listing.smart.stop().await;
}

#[tokio::test]
async fn the_purpose_cannot_change_between_the_lookup_and_the_look_up_again() {
    let listing = listing_codes(&TWO).await;
    let smart = &listing.smart;
    let cookie = at_picker(&listing).await;
    let (status, _, page) = smart
        .get(
            &format!("/picker?purpose_of_use=TREAT&subject_id={SUBJECT}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::OK, status, "{page}");
    let token = form_token(&page);
    let (status, _, _) = smart
        .post(
            "/picker",
            &[
                ("form_token", token.as_str()),
                ("purpose_of_use", "ETREAT"),
                ("subject_id", SUBJECT),
                ("ehr_id", EHR_ID),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(
        StatusCode::BAD_REQUEST,
        status,
        "another purpose is refused"
    );
    let (status, _, _) = smart
        .get(
            &format!("/picker?purpose_of_use=ETREAT&subject_id={SUBJECT}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(
        StatusCode::BAD_REQUEST,
        status,
        "and so is a search under it"
    );
    assert_eq!(
        vec![Some(String::from("TREAT"))],
        *listing.purposes.lock().expect("held"),
        "nothing was asked under another purpose"
    );
    let pending = smart
        .store
        .pending(&cookie)
        .await
        .expect("read")
        .expect("pending");
    assert_eq!(Some("TREAT"), pending.purpose_of_use.as_deref());
    assert!(pending.launch_context.is_none(), "no EHR entered");
    listing.smart.stop().await;
}

#[tokio::test]
async fn a_lookup_without_a_listed_purpose_is_refused_when_several_are_listed() {
    let listing = listing_codes(&TWO).await;
    let smart = &listing.smart;
    let cookie = at_picker(&listing).await;
    for query in [
        format!("subject_id={SUBJECT}"),
        format!("purpose_of_use=&subject_id={SUBJECT}"),
        format!("purpose_of_use=HMARKT&subject_id={SUBJECT}"),
    ] {
        let (status, _, page) = smart.get(&format!("/picker?{query}"), Some(&cookie)).await;
        assert_eq!(StatusCode::BAD_REQUEST, status, "{query}: {page}");
    }
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
            &[
                ("form_token", token.as_str()),
                ("subject_id", SUBJECT),
                ("ehr_id", EHR_ID),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "a choice with no purpose");
    assert!(
        listing.purposes.lock().expect("held").is_empty(),
        "nothing was asked"
    );
    let pending = smart
        .store
        .pending(&cookie)
        .await
        .expect("read")
        .expect("pending");
    assert_eq!(None, pending.purpose_of_use, "nothing kept");
    listing.smart.stop().await;
}

#[tokio::test]
async fn one_listed_purpose_is_chosen_for_the_person_in_the_header_the_base_names() {
    let purposes = tables(&[("TREAT", "Treatment")]);
    let listing = listing((SUBJECT, "x-pou"), move |base| {
        format!(
            "[[ferrosmart.resource]]\nbase = {base:?}\nkind = \"openehr\"\n\
             subject_namespace = {NAMESPACE:?}\npurpose_header = \"X-PoU\"\n{purposes}"
        )
    })
    .await;
    let smart = &listing.smart;
    let cookie = at_picker(&listing).await;
    let (_, _, page) = smart.get("/picker", Some(&cookie)).await;
    assert!(
        page.contains("name=\"purpose_of_use\" value=\"TREAT\" required checked>"),
        "preselected: {page}"
    );
    let (status, _, page) = smart
        .get(&format!("/picker?subject_id={SUBJECT}"), Some(&cookie))
        .await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert_eq!(
        vec![Some(String::from("TREAT"))],
        *listing.purposes.lock().expect("held")
    );
    listing.smart.stop().await;
}

#[tokio::test]
async fn a_base_without_purposes_declares_none() {
    let listing = listing_codes(&[]).await;
    let smart = &listing.smart;
    let cookie = at_picker(&listing).await;
    let (_, _, page) = smart.get("/picker", Some(&cookie)).await;
    assert!(!page.contains("purpose_of_use"), "{page}");
    let (status, _, page) = smart
        .get(
            &format!("/picker?purpose_of_use=TREAT&subject_id={SUBJECT}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert_eq!(vec![None], *listing.purposes.lock().expect("held"));
    let stored = records(&smart.store).await;
    assert_eq!(
        vec![Vec::<(String, String)>::new()],
        purposes_of_event(&stored)
    );
    listing.smart.stop().await;
}

/// Starts a platform whose openEHR base, paired with its FHIR server, lists
/// [`TWO`]; returns it with the FHIR server.
async fn paired_listing() -> (Listing, MockServer) {
    let fhir = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .respond_with(Fhir {
            seen: Arc::new(std::sync::Mutex::new(Vec::new())),
        })
        .mount(&fhir)
        .await;
    let fhir_base = format!("{}/fhir", fhir.uri());
    let purposes = tables(&TWO);
    let listing = listing(("MRN-1", "x-purpose-of-use"), move |base| {
        format!(
            "[[ferrosmart.resource]]\nbase = {fhir_base:?}\n\
             [[ferrosmart.resource]]\nbase = {base:?}\nkind = \"openehr\"\n\
             subject_namespace = {NAMESPACE:?}\nfhir_base = {fhir_base:?}\n\
             subject_system = \"urn:example:mrn\"\n{purposes}"
        )
    })
    .await;
    (listing, fhir)
}

#[tokio::test]
async fn at_a_paired_base_the_professional_chooses_the_purpose_with_the_patient() {
    let (listing, _fhir) = paired_listing().await;
    let smart = &listing.smart;
    let cookie = at_picker(&listing).await;
    let (status, _, page) = smart.get("/picker?name=Synthetic", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(page.contains("value=\"ETREAT\""), "{page}");
    let token = form_token(&page);
    let (status, _, _) = smart
        .post(
            "/picker",
            &[("form_token", token.as_str()), ("patient", "p-1")],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "no purpose chosen");
    let (status, headers, page) = smart
        .post(
            "/picker",
            &[
                ("form_token", token.as_str()),
                ("purpose_of_use", "ETREAT"),
                ("patient", "p-1"),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    assert_eq!("/consent", location(&headers).path());
    assert_eq!(
        vec![Some(String::from("ETREAT"))],
        *listing.purposes.lock().expect("held"),
        "the lookup declares it"
    );
    listing.smart.stop().await;
}

// NOTE: docs/architecture.md §13.6 item 4 (#673, #716), a patient's lookup of their
// own record is no professional's, so it declares no purpose.
#[tokio::test]
async fn a_patients_own_lookup_declares_no_purpose() {
    let (listing, _fhir) = paired_listing().await;
    let smart = &listing.smart;
    let (cookie, (status, headers, body)) =
        as_patient(smart, &listing.base, SCOPE, "Patient/p-1").await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{body}");
    assert_eq!("/consent", location(&headers).path(), "no picker");
    assert_eq!(
        vec![None],
        *listing.purposes.lock().expect("held"),
        "the own lookup declares none"
    );
    let pending = smart
        .store
        .pending(&cookie)
        .await
        .expect("read")
        .expect("pending");
    assert_eq!(None, pending.purpose_of_use);
    let stored = records(&smart.store).await;
    assert_eq!(
        vec![Vec::<(String, String)>::new()],
        purposes_of_event(&stored)
    );
    listing.smart.stop().await;
}
