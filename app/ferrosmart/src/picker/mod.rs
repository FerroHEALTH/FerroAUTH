// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The patient picker of a standalone launch (`docs/architecture.md` §13.6
//! item 4).
//!
//! For a standalone launch that asks for `launch/patient`, "the EHR's
//! 'authorize' endpoint will take care of acquiring the context it needs
//! ... the EHR may provide the end-user with a patient selection widget"
//! (SMART App Launch 2.2.0, Obtain authorization code). FerroSMART draws
//! that widget itself, between the login and the consent: a FHIR R4 search
//! of `Patient` at the request's resource server, by name or identifier.
//!
//! The search runs with the signed-in person's own access: FerroSMART issues
//! itself a token whose `sub` is the person's pairwise subject and whose
//! `fhirUser` is theirs, for the one resource server, with the one scope
//! `user/Patient.rs`, living [`TOKEN_SECONDS`], and revoked once the
//! request is answered. The resource server applies that person's rules,
//! so the picker offers only the patients they may see, and a patient they
//! cannot read is never chosen. The issue and the revocation each commit
//! with their record, and every search and read writes the access record
//! of Regulation (EU) 2025/327 Annex II 3.2 through `ehds-logging`. The
//! search parameters, the token and the page are our own design.
//!
//! At a FHIR resource server the picker also offers the chosen patient's
//! encounters when the app asks for `launch/encounter` (Standalone apps,
//! `context-standalone-encounter`), in [`encounter`]. At an openEHR resource
//! server paired with the platform's FHIR server, the person picks the
//! patient there and the `paired` module looks their EHR up, so the context
//! carries both `patient` and `ehrId`.

use std::net::IpAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::response::Response;
use ehds_logging::classify::Evidence;
use ehds_logging::label::LabelPolicy;
use ehds_logging::map::CategoryMap;
use ehds_logging::record::{
    AccessRecord, Accessor, Action, DataSubject, Origin, Outcome, PatientIdentifier, Professional,
    Request,
};
use ehds_logging::retention::RetentionPolicy;
use http::HeaderMap;
use ihe_atna::balp::NetworkAddress;
use secrecy::SecretString;
use serde::Serialize;
use serde_json::Value;
use url::Url;

use crate::audit::{self, Connected, Event, Happening};
use crate::authorize::callback::{Asked, onward};
use crate::authorize::{Back, logged_in, see_other};
use crate::form::Params;
use crate::launch::context::Context;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::{IssuedToken, Pending};

pub mod encounter;
pub mod openehr;
mod paired;

/// The route of the picker under the issuer.
pub const PICKER_ROUTE: &str = "/picker";

/// The one scope the picker's token carries (SMART App Launch 2.2.0, Scopes
/// for requesting clinical data).
pub const PICKER_SCOPE: &str = "user/Patient.rs";

/// How long the picker's token lives, in seconds: one search and its read.
/// No specification governs the value: our own design.
pub const TOKEN_SECONDS: i64 = 30;

/// The most patients one search shows.
pub const MAX_RESULTS: usize = 20;

/// How long one search or read may take.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Returns whether the picker can choose a patient at `audience`: a FHIR
/// resource server the configuration names, or an openEHR one with a
/// subject namespace to look an EHR up in.
#[must_use]
pub fn searchable(state: &AppState, audience: &str) -> bool {
    let settings = state.settings();
    if settings
        .openehr_resources
        .iter()
        .any(|base| base == audience)
    {
        return settings.subject_namespaces.contains_key(audience);
    }
    settings.resources.iter().any(|base| base == audience)
}

/// What the picker can put in context at a resource server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Nothing: the picker cannot search the server.
    Nothing,
    /// A patient: an openEHR server with a subject namespace.
    Patient,
    /// A patient and one of their encounters: a FHIR server.
    Encounter,
}

/// Returns what the picker can put in context at `audience`.
#[must_use]
pub fn reach(state: &AppState, audience: &str) -> Reach {
    if !searchable(state, audience) {
        Reach::Nothing
    } else if openehr_namespace(state, audience).is_some() {
        Reach::Patient
    } else {
        Reach::Encounter
    }
}

/// Returns the subject namespace of `audience` when it is an openEHR
/// resource server the picker looks EHRs up at.
fn openehr_namespace<'a>(state: &'a AppState, audience: &str) -> Option<&'a str> {
    let settings = state.settings();
    settings
        .openehr_resources
        .iter()
        .any(|base| base == audience)
        .then(|| {
            settings
                .subject_namespaces
                .get(audience)
                .map(String::as_str)
        })
        .flatten()
}

/// A patient the search returned, as the page shows them: the id and the
/// display fields alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The resource id.
    pub id: String,
    /// The name, as written or joined from its parts.
    pub name: String,
    /// The birth date.
    pub birth_date: Option<String>,
    /// The administrative gender.
    pub gender: Option<String>,
    /// The first identifier's value.
    pub identifier: Option<String>,
}

/// Why the picker could not answer.
#[derive(Debug, thiserror::Error)]
pub enum PickerError {
    /// The token could not be issued, revoked or recorded.
    #[error("the picker's token could not be issued or recorded")]
    Record(#[source] audit::RecordFailure),
    /// The token could not be signed.
    #[error("the picker's token could not be signed")]
    Sign(#[source] ferrohealth_smart::client::assertion::AssertionError),
    /// The resource server could not be reached or answered badly.
    #[error("the resource server could not be searched")]
    Fetch(#[source] reqwest::Error),
    /// The resource server refused the search or the read.
    #[error("the resource server answered {0}")]
    Refused(http::StatusCode),
    /// The answer was no Bundle, Patient or EHR.
    #[error("the resource server's answer is not the resource asked for")]
    Unreadable,
    /// The resource server's URL could not be built from its base.
    #[error("the resource server's URL could not be built")]
    Url(#[source] url::ParseError),
    /// The patient carries more than one current identifier of the system
    /// their EHR's subject is named by.
    #[error("the patient has more than one identifier of the subject system")]
    Ambiguous,
    /// No id could be drawn.
    #[error("no token id could be drawn")]
    Random(#[source] aws_lc_rs::error::Unspecified),
}

/// `GET {issuer}/picker?name=&identifier=`: the picker page, with the
/// patients a search found when it names one.
pub async fn picker_get(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let pending = match picking(&state, &headers).await {
        Ok(pending) => pending,
        Err(response) => return *response,
    };
    let Ok(params) = Params::parse(query.unwrap_or_default().as_bytes(), &[]) else {
        return pages::fault(&state, Fault::BadRequest);
    };
    let pairing = state.settings().pairings.get(&pending.audience);
    if let (None, Some(namespace)) = (pairing, openehr_namespace(&state, &pending.audience)) {
        return openehr::look_up(&state, &headers, &pending, from, namespace, &params).await;
    }
    // NOTE: SMART on openEHR draft, Context Selection, `launch/patient` asks for the
    // FHIR Patient and its EHR, so a paired base searches the platform's FHIR server.
    let base = pairing.map_or(pending.audience.as_str(), |pairing| &pairing.fhir_base);
    let name = params
        .get("name")
        .map(str::trim)
        .filter(|text| !text.is_empty());
    let identifier = params
        .get("identifier")
        .map(str::trim)
        .filter(|text| !text.is_empty());
    if let (None, Some(patient)) = (pairing, params.get("patient")) {
        return encounter::list(&state, &headers, &pending, from, patient).await;
    }
    if name.is_none() && identifier.is_none() {
        return pages::picker(&state, &headers, &pending, None, None, None);
    }
    let mut url = match patient_url(base, None) {
        Ok(url) => url,
        Err(error) => return pages::server_error(&state, &error),
    };
    {
        let mut pairs = url.query_pairs_mut();
        if let Some(name) = name {
            pairs.append_pair("name", name);
        }
        if let Some(identifier) = identifier {
            pairs.append_pair("identifier", identifier);
        }
        pairs.append_pair("_count", &MAX_RESULTS.to_string());
    }
    match as_person(&state, &pending, from, &fhir_ask(&url, base, Action::Query)).await {
        Ok(Value::Object(bundle)) if bundle.get("resourceType") == Some(&Value::from("Bundle")) => {
            let found = patients(&Value::Object(bundle));
            pages::picker(
                &state,
                &headers,
                &pending,
                Some((name, identifier)),
                Some(&found),
                None,
            )
        }
        Ok(_) => pages::server_error(&state, &PickerError::Unreadable),
        Err(error) => pages::server_error(&state, &error),
    }
}

/// `POST {issuer}/picker`: the person's choice, read again as them before it
/// enters the launch context.
pub async fn picker_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Connected(from): Connected,
    body: Bytes,
) -> Response {
    let pending = match picking(&state, &headers).await {
        Ok(pending) => pending,
        Err(response) => return *response,
    };
    let Ok(form) = Params::parse(&body, &[]) else {
        return pages::fault(&state, Fault::BadRequest);
    };
    let sent = form.get("form_token").unwrap_or_default();
    if !crate::authorize::constant_eq(sent.as_bytes(), pending.form_token.as_bytes()) {
        return pages::fault(&state, Fault::BadRequest);
    }
    if let Some(pairing) = state.settings().pairings.get(&pending.audience) {
        return paired::choose(&state, &headers, &pending, from, pairing, &form).await;
    }
    if let Some(namespace) = openehr_namespace(&state, &pending.audience) {
        let context = match openehr::choose(&state, &pending, from, namespace, &form).await {
            Ok(context) => context,
            Err(response) => return *response,
        };
        return enter(&state, &pending, &context, from).await;
    }
    if form.get("step") == Some(encounter::STEP) {
        return encounter::choose(&state, &pending, from, &form).await;
    }
    let Some(id) = form.get("patient").filter(|id| is_fhir_id(id)) else {
        return pages::fault(&state, Fault::BadRequest);
    };
    if let Err(response) = read_patient(&state, &pending, from, &pending.audience, id).await {
        return *response;
    }
    if encounter::wanted(&state, &pending) {
        return see_other(&format!(
            "{}?patient={id}",
            state.settings().endpoint(PICKER_ROUTE)
        ));
    }
    let context = Context {
        patient: Some(id.to_owned()),
        ..Context::default()
    };
    enter(&state, &pending, &context, from).await
}

/// Reads the patient `id` at the FHIR base `base` as the signed-in person
/// of `pending`, or returns the page that says why it could not.
async fn read_patient(
    state: &AppState,
    pending: &Pending,
    from: IpAddr,
    base: &str,
    id: &str,
) -> Result<Value, Box<Response>> {
    let url = patient_url(base, Some(id))
        .map_err(|error| Box::new(pages::server_error(state, &error)))?;
    // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, `patient` is the
    // id of a patient the person may see, so the choice is read again as them.
    match as_person(state, pending, from, &fhir_ask(&url, base, Action::Read)).await {
        Ok(resource) if resource.get("id").and_then(Value::as_str) == Some(id) => Ok(resource),
        Ok(_) => Err(Box::new(pages::server_error(
            state,
            &PickerError::Unreadable,
        ))),
        Err(PickerError::Refused(_)) => Err(Box::new(pages::fault(state, Fault::BadRequest))),
        Err(error) => Err(Box::new(pages::server_error(state, &error))),
    }
}

/// Puts the chosen `context` into the launch of `pending` and sends the
/// browser on to the consent.
async fn enter(state: &AppState, pending: &Pending, context: &Context, from: IpAddr) -> Response {
    if let Err(error) = state.store().set_launch_context(&pending.id, context).await {
        return pages::server_error(state, &error);
    }
    let offered = pending.offered_scope.clone().unwrap_or_default();
    go_on(state, pending, &offered, from).await
}

/// Sends the browser of `pending` on to the consent, offering `offered`.
async fn go_on(state: &AppState, pending: &Pending, offered: &str, from: IpAddr) -> Response {
    let (Some(subject), Some(client_id)) = (&pending.subject, &pending.client_id) else {
        return pages::fault(state, Fault::Lapsed);
    };
    let offered: Vec<&str> = offered
        .split(' ')
        .filter(|scope| !scope.is_empty())
        .collect();
    let client = match state.store().client(client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return pages::fault(state, Fault::Lapsed),
        Err(error) => return pages::server_error(state, &error),
    };
    let back = Back::of(state, pending);
    let asked = Asked {
        id: &pending.id,
        subject,
        fhir_user: pending.fhir_user.as_deref(),
        requested: &pending.scope,
        client: &client,
        offered: &offered,
        consent: pending.asking.prompt.consent,
    };
    onward(state, &asked, &back, from).await
}

/// Returns whether `pending` waits for the picker: a standalone launch
/// offered `launch/patient` whose patient is not chosen yet.
#[must_use]
pub fn waits(state: &AppState, pending: &Pending) -> bool {
    let offered = pending.offered_scope.as_deref().unwrap_or_default();
    pending.launch_context.is_none()
        && offered.split(' ').any(|scope| scope == "launch/patient")
        && searchable(state, &pending.audience)
}

/// Returns the browser's request when it waits for its patient, or the page
/// that says why it does not.
async fn picking(state: &AppState, headers: &HeaderMap) -> Result<Pending, Box<Response>> {
    let pending = logged_in(state, headers).await?;
    if !waits(state, &pending) {
        return Err(Box::new(see_other(
            &state.settings().endpoint(crate::authorize::CONSENT_ROUTE),
        )));
    }
    Ok(pending)
}

/// Returns `[base]/Patient`, or `[base]/Patient/[id]` when `id` names one.
fn patient_url(base: &str, id: Option<&str>) -> Result<Url, url::ParseError> {
    let base = base.trim_end_matches('/');
    match id {
        Some(id) => Url::parse(&format!("{base}/Patient/{id}")),
        None => Url::parse(&format!("{base}/Patient")),
    }
}

/// Whether `id` is a FHIR R4 `id`: 1 to 64 of `A-Z`, `a-z`, `0-9`, `-` and
/// `.` (FHIR R4 datatypes, id).
fn is_fhir_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
}

/// The claims of the picker's token (RFC 9068 §2.2).
#[derive(Debug, Serialize)]
struct PickerClaims<'a> {
    /// FerroSMART.
    iss: &'a str,
    /// The signed-in person.
    sub: &'a str,
    /// The resource server.
    aud: &'a str,
    /// The expiry.
    exp: i64,
    /// The issue time.
    iat: i64,
    /// The token id.
    jti: &'a str,
    /// FerroSMART itself, the client the token is issued to.
    client_id: &'a str,
    /// [`PICKER_SCOPE`], or [`openehr::EHR_SCOPE`] at an openEHR server.
    scope: &'a str,
    /// The person's `fhirUser`.
    #[serde(rename = "fhirUser", skip_serializing_if = "Option::is_none")]
    fhir_user: Option<&'a str>,
}

/// One request the picker sends as the signed-in person: where, with
/// which scope, what it accepts, and how its access is recorded.
struct Ask<'a> {
    /// The URL asked.
    url: &'a Url,
    /// The base of the resource server asked, the token's audience.
    audience: &'a str,
    /// The one scope the token carries.
    scope: &'static str,
    /// The media type asked for.
    accept: &'static str,
    /// The access the answer makes, for its record.
    describe: Describe<'a>,
}

/// How an [`Ask`] describes the access its answer made.
type Describe<'a> = Box<dyn Fn(&Result<Value, PickerError>) -> Access + Send + Sync + 'a>;

/// What an access record says of one request beyond who asked: the action,
/// what it delivered, whose data and the request itself (Regulation (EU)
/// 2025/327 Annex II 3.2).
struct Access {
    /// The action.
    action: Action,
    /// The resources delivered, when the request was answered.
    delivered: Option<usize>,
    /// Whose data it was.
    subject: DataSubject,
    /// The request.
    request: Request,
}

/// Returns the FHIR search or read of `url` at the base `audience`.
fn fhir_ask<'a>(url: &'a Url, audience: &'a str, action: Action) -> Ask<'a> {
    Ask {
        url,
        audience,
        scope: PICKER_SCOPE,
        accept: "application/fhir+json",
        describe: Box::new(move |fetched| {
            let delivered = match fetched {
                Ok(Value::Object(bundle)) if action == Action::Query => {
                    Some(patients(&Value::Object(bundle.clone())).len())
                }
                Ok(_) => Some(1),
                Err(_) => None,
            };
            let patient = (action == Action::Read)
                .then(|| {
                    url.path_segments()
                        .and_then(|mut segments| segments.next_back())
                })
                .flatten()
                .map(|id| PatientIdentifier {
                    namespace: Some(audience.to_owned()),
                    value: SecretString::from(id.to_owned()),
                });
            Access {
                action,
                delivered,
                subject: DataSubject {
                    patient,
                    ..DataSubject::default()
                },
                request: fhir_request(url, action, "Patient"),
            }
        }),
    }
}

/// Returns the access record's request of the FHIR read or type search
/// `url` of `resource` (FHIR R4, `RESTful` interactions).
fn fhir_request(url: &Url, action: Action, resource: &str) -> Request {
    Request {
        id: None,
        operation: String::from(if action == Action::Read {
            "read"
        } else {
            "search-type"
        }),
        operation_system: Some(String::from("http://hl7.org/fhir/restful-interaction")),
        resource: Some(resource.to_owned()),
        query: Some(ihe_atna::balp::request_text(url)),
        stored_query: None,
        client_address: None,
        correlation: None,
    }
}

/// Returns the resources of type `kind` in the entries of the search
/// Bundle `bundle`.
fn entries<'a>(bundle: &'a Value, kind: &'a str) -> impl Iterator<Item = &'a Value> + 'a {
    bundle
        .get("entry")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("resource"))
        .filter(move |resource| resource.get("resourceType").and_then(Value::as_str) == Some(kind))
}

/// Sends `ask` as the signed-in person of `pending` with a token issued for
/// this request alone, records the access, revokes the token and returns
/// the answer.
async fn as_person(
    state: &AppState,
    pending: &Pending,
    from: IpAddr,
    ask: &Ask<'_>,
) -> Result<Value, PickerError> {
    let Some(subject) = pending.subject.as_deref() else {
        return Err(PickerError::Unreadable);
    };
    let settings = state.settings();
    let jti = crate::authorize::random().map_err(PickerError::Random)?;
    let issued_at = jiff::Timestamp::now().as_second();
    let expires_at = issued_at.saturating_add(TOKEN_SECONDS);
    let claims = PickerClaims {
        iss: &settings.issuer,
        sub: subject,
        aud: ask.audience,
        exp: expires_at,
        iat: issued_at,
        jti: &jti,
        client_id: &settings.issuer,
        scope: ask.scope,
        fhir_user: pending.fhir_user.as_deref(),
    };
    // NOTE: RFC 9068 §2.1, typ at+jwt.
    let token = settings
        .keys
        .current()
        .sign("at+jwt", &claims)
        .map_err(PickerError::Sign)?;
    let endpoint = settings.endpoint_url(PICKER_ROUTE);
    let happening = |event, details| Happening {
        event,
        issuer: &settings.issuer,
        client_id: pending.client_id.as_deref(),
        subject: Some(subject),
        from,
        endpoint: &endpoint,
        details,
    };
    let mut tx = state
        .store()
        .begin()
        .await
        .map_err(|error| PickerError::Record(audit::RecordFailure::Store(error)))?;
    tx.insert_token(&IssuedToken {
        jti: &jti,
        client_id: &settings.issuer,
        subject,
        audience: ask.audience,
        scope: ask.scope,
        issued_at,
        expires_at,
        grant_id: None,
        code_hash: None,
    })
    .await
    .map_err(|error| PickerError::Record(audit::RecordFailure::Store(error)))?;
    state
        .audit()
        .commit_happening(
            tx,
            &happening(Event::PickerToken, vec![("jti", jti.clone())]),
        )
        .await
        .map_err(PickerError::Record)?;
    let fetched = fetch(state, ask, &token).await;
    let asker = Asker {
        pending,
        subject,
        from,
        audience: ask.audience,
    };
    let recorded = record_access(state, &asker, (ask.describe)(&fetched)).await;
    let revoked = revoke(
        state,
        &jti,
        happening(Event::TokenRevoked, vec![("jti", jti.clone())]),
    )
    .await;
    recorded?;
    revoked?;
    fetched
}

/// Sends `ask` with the bearer `token`.
async fn fetch(state: &AppState, ask: &Ask<'_>, token: &str) -> Result<Value, PickerError> {
    let answer = state
        .fhir()
        .get(ask.url.clone())
        .bearer_auth(token)
        .header(http::header::ACCEPT, ask.accept)
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await
        .map_err(PickerError::Fetch)?;
    let status = answer.status();
    if !status.is_success() {
        return Err(PickerError::Refused(status));
    }
    answer.json::<Value>().await.map_err(PickerError::Fetch)
}

/// Revokes the picker's token `jti` with the record `happening`.
async fn revoke(state: &AppState, jti: &str, happening: Happening<'_>) -> Result<(), PickerError> {
    let mut tx = state
        .store()
        .begin()
        .await
        .map_err(|error| PickerError::Record(audit::RecordFailure::Store(error)))?;
    tx.revoke_access_token(jti)
        .await
        .map_err(|error| PickerError::Record(audit::RecordFailure::Store(error)))?;
    state
        .audit()
        .commit_happening(tx, &happening)
        .await
        .map_err(PickerError::Record)
}

/// Who sent one request of the picker, from where and to which server.
struct Asker<'a> {
    /// The browser's request.
    pending: &'a Pending,
    /// The signed-in person.
    subject: &'a str,
    /// The browser's address.
    from: IpAddr,
    /// The base of the resource server asked.
    audience: &'a str,
}

/// Stores the access record of one request `asker` sent, as `access`
/// describes it (Regulation (EU) 2025/327 Annex II 3.2).
async fn record_access(
    state: &AppState,
    asker: &Asker<'_>,
    access: Access,
) -> Result<(), PickerError> {
    let Asker {
        pending,
        subject,
        from,
        audience,
    } = *asker;
    let settings = state.settings();
    let recorded = jiff::Timestamp::now();
    // NOTE: Regulation (EU) 2025/327 Art 14(1), a Patient's demographics and an
    // EHR's id are none of the priority categories, so the access has no category.
    let categories = CategoryMap::default().classify(&Evidence::no_category());
    let origins = vec![Origin {
        endpoint: Some(audience.to_owned()),
        node: None,
        system_id: None,
        status: None,
        rows: None,
        version: None,
        created_ehr: None,
        categories: None,
    }];
    let keys = || origins.iter().filter_map(Origin::key);
    let retention = RetentionPolicy::default().retain(recorded, &categories, keys());
    let labels = LabelPolicy::default().label(&categories, keys());
    let outcome = if access.delivered.is_some() {
        Outcome::Success
    } else {
        Outcome::MinorFailure
    };
    let record = AccessRecord {
        action: access.action,
        recorded,
        outcome,
        outcome_description: None,
        accessor: accessor(&settings.issuer, asker),
        subject: access.subject,
        categories,
        delivered: access.delivered,
        origins,
        origin_count: None,
        request: Request {
            client_address: Some(from),
            ..access.request
        },
        retention,
        labels,
        emergency: None,
        inserted: None,
        transformations: Vec::new(),
    };
    let endpoint = NetworkAddress::uri(&settings.endpoint_url(PICKER_ROUTE));
    let exchange = ehds_logging::balp::exchange(&record, &endpoint);
    let row = state
        .audit()
        .row(
            &exchange,
            "access",
            Some(subject),
            pending.client_id.as_deref(),
        )
        .map_err(PickerError::Record)?;
    state
        .audit()
        .record(state.store(), &row)
        .await
        .map_err(PickerError::Record)
}

/// Returns the person of `asker` under FerroSMART's `issuer`, as the
/// access record names the accessor.
fn accessor(issuer: &str, asker: &Asker<'_>) -> Accessor {
    let pending = asker.pending;
    Accessor {
        issuer: Some(issuer.to_owned()),
        subject: asker.subject.to_owned(),
        client_id: pending.client_id.clone(),
        audience: Some(asker.audience.to_owned()),
        provider: None,
        acting: None,
        roles: Vec::new(),
        token_id: None,
        assurance: None,
        professional: Professional {
            name: pending.display_name.clone(),
            ..Professional::default()
        },
        alt_id: None,
        purposes: Vec::new(),
        policies: Vec::new(),
        relayed: None,
        binding: None,
        actors: Vec::new(),
        represents: None,
        acts_for: None,
        facilities: Vec::new(),
    }
}

/// Returns the patients of the search Bundle `bundle`, at most
/// [`MAX_RESULTS`], with their display fields.
fn patients(bundle: &Value) -> Vec<Found> {
    entries(bundle, "Patient")
        .filter_map(|resource| {
            let id = resource.get("id").and_then(Value::as_str)?;
            is_fhir_id(id).then(|| Found {
                id: id.to_owned(),
                name: name_of(resource),
                birth_date: text(resource, "birthDate"),
                gender: text(resource, "gender"),
                identifier: resource
                    .pointer("/identifier/0/value")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            })
        })
        .take(MAX_RESULTS)
        .collect()
}

/// Returns the member `name` of `resource` as text.
fn text(resource: &Value, name: &str) -> Option<String> {
    resource
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Returns the first name of `resource`: its `text`, or its given names and
/// family joined.
fn name_of(resource: &Value) -> String {
    let Some(name) = resource.pointer("/name/0") else {
        return String::new();
    };
    if let Some(text) = name.get("text").and_then(Value::as_str) {
        return text.to_owned();
    }
    let given = name
        .get("given")
        .and_then(Value::as_array)
        .map(|given| {
            given
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let family = name
        .get("family")
        .and_then(Value::as_str)
        .unwrap_or_default();
    format!("{given} {family}").trim().to_owned()
}
