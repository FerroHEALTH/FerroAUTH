// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The upstream provider's redirect back: the login completed, the person's
//! scopes offered, and on to the consent page or the app.

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{RawQuery, State};
use axum::response::Response;
use ferrohealth_secret::secret::Secret;
use ferrohealth_smart::oidc::{Callback, PendingSignIn};
use http::HeaderMap;
use url::Url;

use crate::audit::Connected;
use crate::audit::exchanges::{Person, login};
use crate::clients::{Approval, Client};
use crate::form::Params;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::{Asking, Login, Pending, Purpose};

use super::consent::{Basis, FhirUser, approve, offer};
use super::{
    Back, CONSENT_ROUTE, COOKIE, Denial, MANAGE_ROUTE, cookie, forget, found, now, random,
    registered, see_other, set_cookie,
};

/// `GET {issuer}/callback`, where the upstream provider sends the browser
/// back.
pub async fn callback(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let query = query.unwrap_or_default();
    let Ok(answer) = read_callback(&query) else {
        return pages::fault(&state, Fault::BadRequest);
    };
    let Some(upstream_state) = answer.state.as_deref() else {
        return pages::fault(&state, Fault::Lapsed);
    };
    let pending = match found(
        &state,
        state.store().pending_by_upstream(upstream_state).await,
    ) {
        Ok(pending) => pending,
        Err(response) => return *response,
    };
    // NOTE: RFC 9700 §4.7, the login completes in the browser that began it.
    if cookie(&headers, COOKIE).as_deref() != Some(pending.id.as_str()) {
        return pages::fault(&state, Fault::OtherBrowser);
    }
    let Some(party) = state.relying_party() else {
        return pages::fault(&state, Fault::BadRequest);
    };
    let back = Back::of(&state, &pending);
    let sign_in = PendingSignIn::from_parts(
        pending.upstream_state.clone(),
        pending.upstream_nonce.clone(),
        Secret::new(pending.upstream_verifier.clone()),
    );
    let signed_in = match party.exchange(&sign_in, &answer).await {
        Ok(signed_in) => signed_in,
        Err(error) => {
            forget(&state, &pending).await;
            tracing::warn!(error = %ferrohealth_server::run::chain(&error), "the upstream login failed");
            let reason = if answer.error.is_some() {
                "the person declined at the provider"
            } else {
                "the login could not be completed"
            };
            if let Err(response) = record_login(&state, Err(reason)).await {
                return *response;
            }
            if pending.purpose == Purpose::Manage {
                return pages::fault(&state, Fault::Lapsed);
            }
            // NOTE: RFC 6749 §4.1.2.1, a person who declined at the provider is
            // access_denied; any other failure is the server's.
            if answer.error.is_some() {
                return back.deny(Denial {
                    error: "access_denied",
                    description: "the login was declined",
                });
            }
            return back.deny(Denial {
                error: "server_error",
                description: "the login could not be completed",
            });
        }
    };
    let upstream_at = signed_in
        .claims
        .other
        .get("auth_time")
        .and_then(serde_json::Value::as_i64);
    let auth_time = match freshness(&pending.asking, upstream_at, now()) {
        Fresh::At(auth_time) => auth_time,
        Fresh::Again => return again(&state, &pending, party).await,
        Fresh::Stale => {
            forget(&state, &pending).await;
            if let Err(response) =
                record_login(&state, Err("the login is older than max_age")).await
            {
                return *response;
            }
            // NOTE: OpenID Connect Core 1.0 §3.1.2.6: the person could not be
            // authenticated within max_age, so the request needs a login.
            return back.deny(Denial {
                error: "login_required",
                description: "the login is older than max_age",
            });
        }
    };
    proceed(&state, &pending, &back, &signed_in.claims, auth_time, from).await
}

/// When the person last authenticated, as the request's `max_age` judges
/// the upstream login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fresh {
    /// They authenticated at this time, in seconds since the epoch.
    At(i64),
    /// The upstream login is older than `max_age`, or does not say when it
    /// authenticated: it is begun again with `prompt=login`.
    Again,
    /// The upstream login begun again is still older than `max_age`.
    Stale,
}

/// Judges the upstream login's `auth_time`, `upstream`, against what
/// `asking` asked, at `now`. Without `max_age` the time is the upstream
/// login's, or the callback's when its ID Token names none.
fn freshness(asking: &Asking, upstream: Option<i64>, now: i64) -> Fresh {
    let Some(max_age) = asking.max_age else {
        return Fresh::At(upstream.map_or(now, |at| at.min(now)));
    };
    // NOTE: OpenID Connect Core 1.0 §3.1.2.1: past max_age the OP MUST attempt to
    // actively re-authenticate, so the upstream login is begun again with prompt=login.
    match upstream {
        Some(at) if now.saturating_sub(at) <= max_age => Fresh::At(at.min(now)),
        _ if !asking.reauthenticated => Fresh::Again,
        Some(_) => Fresh::Stale,
        // NOTE: the upstream login was told prompt=login, so it authenticated just now.
        None => Fresh::At(now),
    }
}

/// Begins the upstream login of `pending` again with `prompt=login`, as
/// its authentication was older than the request's `max_age`.
async fn again(
    state: &AppState,
    pending: &Pending,
    party: &ferrohealth_smart::oidc::RelyingParty,
) -> Response {
    let Ok(upstream) = party.authorization_request() else {
        return pages::fault(state, Fault::Server);
    };
    let mut asking = pending.asking.clone();
    asking.prompt.login = true;
    if let Err(error) = state
        .store()
        .reauthenticate(
            &pending.id,
            upstream.pending.state(),
            upstream.pending.nonce(),
            upstream.pending.verifier().expose(),
        )
        .await
    {
        return pages::server_error(state, &error);
    }
    see_other(super::oidc::upstream(upstream.url, &asking).as_str())
}

/// Goes on once the person logged in as `claims` for `pending`: to the
/// management page, to the consent page, or straight back to the app with
/// a code when a remembered consent covers what is offered.
async fn proceed(
    state: &AppState,
    pending: &Pending,
    back: &Back,
    claims: &ferrohealth_smart::oidc::IdTokenClaims,
    auth_time: i64,
    from: IpAddr,
) -> Response {
    let Some(upstream) = &state.settings().upstream else {
        return pages::fault(state, Fault::BadRequest);
    };
    let fhir_user = upstream
        .fhir_user_claim
        .as_deref()
        .and_then(|claim| ferrohealth_smart::roles::claim_text(&claims.other, claim))
        .map(str::to_owned);
    let held = ferrohealth_smart::roles::from_claims(&claims.other, &upstream.role_claims);
    let subject = crate::upstream::pairwise(&claims.issuer, &claims.subject);
    let upstream_session = match pending.purpose {
        Purpose::Authorize => match begin_session(state, claims).await {
            Ok(session) => Some(session),
            Err(response) => return *response,
        },
        Purpose::Manage => None,
    };
    let fhir_user = match fhir_user {
        Some(claimed) => Some(claimed),
        None if pending.purpose == Purpose::Authorize => {
            looked_up(state, pending, &subject, claims, from).await
        }
        None => None,
    };
    let mut login = Login {
        subject,
        fhir_user,
        display_name: claims.display_name().map(str::to_owned),
        offered_scope: String::new(),
        auth_time,
        upstream_session,
        roles: mapped(&held, &state.settings().roles),
        person_claims: crate::store::PersonClaims::from_claims(claims),
    };
    let person = Person {
        issuer: &state.settings().issuer,
        subject: &login.subject,
        name: login.display_name.as_deref(),
        client_id: pending.client_id.as_deref(),
    };
    if let Err(response) = record_login(state, Ok(person)).await {
        return *response;
    }
    if pending.purpose == Purpose::Manage {
        if let Err(error) = state.store().logged_in(&pending.id, &login).await {
            return pages::server_error(state, &error);
        }
        return see_other(&state.settings().endpoint(MANAGE_ROUTE));
    }
    let client = match registered(state, pending).await {
        Ok(client) => client,
        Err(response) => return *response,
    };
    let own = crate::picker::own_patient(state, &pending.audience, login.fhir_user.as_deref())
        .map(str::to_owned);
    let fhir_user = match (&login.fhir_user, &own) {
        (None, _) => FhirUser::Absent,
        (Some(_), None) => FhirUser::Present,
        (Some(_), Some(_)) => FhirUser::ThePatient,
    };
    let offered = offer(
        &pending.scope,
        &client,
        &held,
        &state.settings().roles,
        fhir_user,
        pending.launch_context.as_ref(),
        crate::picker::reach(state, &pending.audience),
    );
    if offered.is_empty() {
        forget(state, pending).await;
        return no_scope(state, &client, &pending.scope, back);
    }
    login.offered_scope = offered.join(" ");
    if let Err(error) = state.store().logged_in(&pending.id, &login).await {
        return pages::server_error(state, &error);
    }
    let offered: Vec<&str> = offered.iter().map(String::as_str).collect();
    // NOTE: SMART App Launch 2.2.0, Obtain authorization code, the patient is
    // chosen within the authorization flow, before the consent.
    if pending.launch_context.is_none() && offered.contains(&"launch/patient") {
        // NOTE: docs/architecture.md §13.6 item 4 (owner, 2026-11-19, #673): a patient's
        // own record is the context, read again as them, with no picker.
        if let Some(id) = &own {
            return match state.store().pending(&pending.id).await {
                Ok(Some(signed_in)) => crate::picker::own_record(state, &signed_in, from, id).await,
                Ok(None) => pages::fault(state, Fault::Lapsed),
                Err(error) => pages::server_error(state, &error),
            };
        }
        return see_other(&state.settings().endpoint(crate::picker::PICKER_ROUTE));
    }
    let asked = Asked {
        id: &pending.id,
        subject: &login.subject,
        fhir_user: login.fhir_user.as_deref(),
        requested: &pending.scope,
        client: &client,
        offered: &offered,
        consent: pending.asking.prompt.consent,
    };
    onward(state, &asked, back, from).await
}

/// Returns the `fhirUser` the lookups configured for the request's server
/// find for the person `subject` with the upstream `claims`, and writes the
/// outcome as an audit line, never a value (`docs/architecture.md` §13.6
/// item 9).
async fn looked_up(
    state: &AppState,
    pending: &Pending,
    subject: &str,
    claims: &ferrohealth_smart::oidc::IdTokenClaims,
    from: IpAddr,
) -> Option<String> {
    let asking = Pending {
        subject: Some(subject.to_owned()),
        ..pending.clone()
    };
    let resolved =
        crate::picker::fhir_user::resolve(state, &asking, from, &pending.audience, &claims.other)
            .await?;
    tracing::info!(
        target: "ferrosmart::audit",
        event = "fhir_user.lookup",
        client_id = ?pending.client_id,
        outcome = resolved.as_str(),
        "the person's fhirUser was looked up"
    );
    match resolved {
        crate::picker::fhir_user::Resolved::Found(fhir_user) => Some(fhir_user),
        _ => None,
    }
}

/// Answers a request of which no scope can be granted to the person: a page
/// naming the roles that would grant one, whose way on sends the browser
/// back with `access_denied` (RFC 6749 §4.1.2.1; the page first is our own
/// design, `docs/architecture.md` §13.6 item 5).
fn no_scope(state: &AppState, client: &Client, requested: &str, back: &Back) -> Response {
    let roles = granting_roles(client, requested, &state.settings().roles);
    tracing::info!(
        target: "ferrosmart::audit",
        event = "authorization.refused",
        client_id = %client.client_id,
        reason = "no requested scope can be granted to this person",
        "no scope could be granted"
    );
    let Some(url) = back.denial_url(Denial {
        error: "access_denied",
        description: "no requested scope can be granted to this person",
    }) else {
        return pages::fault(state, Fault::UnknownRedirect);
    };
    pages::no_scope(state, client, &roles, url.as_str())
}

/// Returns the configured roles, in name order, that grant at least one
/// scope of `requested` the client's ceiling admits.
fn granting_roles<'a>(
    client: &Client,
    requested: &str,
    roles: &'a std::collections::BTreeMap<String, Vec<String>>,
) -> Vec<&'a str> {
    let wanted: Vec<&str> = requested
        .split(' ')
        .filter(|scope| !scope.is_empty() && crate::scopes::admits(&client.scopes, scope))
        .collect();
    roles
        .iter()
        .filter(|(_, scopes)| {
            wanted
                .iter()
                .any(|scope| crate::scopes::admits(scopes, scope))
        })
        .map(|(name, _)| name.as_str())
        .collect()
}

/// What a person, logged in with the launch context complete, was asked
/// to authorize.
pub(crate) struct Asked<'a> {
    /// The pending authorization's id.
    pub(crate) id: &'a str,
    /// The person's pairwise subject.
    pub(crate) subject: &'a str,
    /// The person's `fhirUser`, when the provider carries one.
    pub(crate) fhir_user: Option<&'a str>,
    /// The scope the app requested.
    pub(crate) requested: &'a str,
    /// The client.
    pub(crate) client: &'a Client,
    /// The scopes policy offers (`docs/architecture.md` §13.6 item 5).
    pub(crate) offered: &'a [&'a str],
    /// Whether the app asked for the consent page with `prompt=consent`
    /// (OpenID Connect Core 1.0 §3.1.2.1).
    pub(crate) consent: bool,
}

/// Returns the organisation approval of the client that `asked` falls
/// under: the approval covers every scope offered and, unless the app is
/// the organisation's own (first party), the person is a professional and
/// the request names no `patient/` scope (`docs/architecture.md` §13.6
/// item 6).
fn approved<'a>(asked: &Asked<'a>) -> Option<&'a Approval> {
    let approval = asked.client.approval.as_ref()?;
    if approval.first_party {
        return approval.covers(asked.offered).then_some(approval);
    }
    // NOTE: SMART App Launch 2.2.0, Scopes for requesting identity data, a
    // fhirUser of these types is the patient or speaks for one: they decide.
    let own_data = asked.fhir_user.is_some_and(|reference| {
        ["Patient/", "RelatedPerson/", "Person/"]
            .iter()
            .any(|kind| reference.starts_with(kind))
    });
    let patient_scope = asked
        .requested
        .split(' ')
        .any(|scope| scope.starts_with("patient/"));
    (!own_data && !patient_scope && approval.covers(asked.offered)).then_some(approval)
}

/// Goes on once the person logged in and the context is complete: straight
/// back to the app with a code when a remembered consent covers `offered`,
/// to the consent page otherwise.
pub(crate) async fn onward(
    state: &AppState,
    asked: &Asked<'_>,
    back: &Back,
    from: IpAddr,
) -> Response {
    // NOTE: OpenID Connect Core 1.0 §3.1.2.1: prompt=consent asks the person for
    // consent, so neither an approval nor a remembered consent answers for them.
    if asked.consent {
        return see_other(&state.settings().endpoint(CONSENT_ROUTE));
    }
    let basis = if let Some(approval) = approved(asked) {
        Basis::Organisation(approval)
    } else {
        // NOTE: docs/architecture.md §13.6 item 6, a consent the person chose to
        // remember answers again while it covers every scope offered.
        let remembered = match state
            .store()
            .remembered(asked.subject, &asked.client.client_id)
            .await
        {
            Ok(remembered) => remembered,
            Err(error) => return pages::server_error(state, &error),
        };
        let covered = remembered.is_some_and(|scope| {
            asked
                .offered
                .iter()
                .all(|wanted| scope.split(' ').any(|given| given == *wanted))
        });
        if !covered {
            return see_other(&state.settings().endpoint(CONSENT_ROUTE));
        }
        Basis::Remembered
    };
    let pending = match found(state, state.store().finish(asked.id).await) {
        Ok(pending) => pending,
        Err(response) => return *response,
    };
    let mut response = approve(state, &pending, asked.offered, basis, back, from).await;
    set_cookie(state, &mut response, COOKIE, "", 0);
    response
}

/// Returns the roles of `held` that a `[[ferrosmart.role]]` of `roles`
/// names, sorted and once each: the roles FerroSMART maps, which the access
/// token carries (RFC 9068 §2.2.3.1; `docs/architecture.md` §13.6 item 5).
/// A role no table names is the provider's alone and stays there.
fn mapped(held: &[String], roles: &std::collections::BTreeMap<String, Vec<String>>) -> Vec<String> {
    held.iter()
        .filter(|role| roles.contains_key(role.as_str()))
        .cloned()
        .collect::<std::collections::BTreeSet<String>>()
        .into_iter()
        .collect()
}

/// Records the upstream login `claims` describe as a session, with the
/// provider's `sid` when its ID Token carries one, and returns its id: the
/// session an `online_access` grant lives in (`docs/architecture.md` §13.6
/// item 7), which the provider's back-channel logout ends.
async fn begin_session(
    state: &AppState,
    claims: &ferrohealth_smart::oidc::IdTokenClaims,
) -> Result<String, Box<Response>> {
    let session = random().map_err(|error| Box::new(pages::server_error(state, &error)))?;
    let sid = claims.other.get("sid").and_then(serde_json::Value::as_str);
    state
        .store()
        .begin_session(&session, &claims.issuer, &claims.subject, sid)
        .await
        .map_err(|error| Box::new(pages::server_error(state, &error)))?;
    Ok(session)
}

/// Reads the provider's answer from the callback's query (RFC 6749 §4.1.2,
/// §4.1.2.1).
fn read_callback(query: &str) -> Result<Callback, crate::form::Repeated> {
    let params = Params::parse(query.as_bytes(), &[])?;
    let mut answer = Callback::default();
    answer.code = params.get("code").map(Secret::new);
    answer.state = params.get("state").map(str::to_owned);
    answer.error = params.get("error").map(str::to_owned);
    answer.error_description = params.get("error_description").map(str::to_owned);
    answer.error_uri = params.get("error_uri").map(str::to_owned);
    Ok(answer)
}

/// Records the login `answer` at the upstream provider, or returns the page
/// of a login that could not be recorded: a login whose record is not
/// stored does not go on (no specification governs this: our own design).
async fn record_login(
    state: &AppState,
    answer: Result<Person<'_>, &str>,
) -> Result<(), Box<Response>> {
    let Some(upstream) = &state.settings().upstream else {
        return Err(Box::new(pages::fault(state, Fault::BadRequest)));
    };
    let provider = Url::parse(&upstream.issuer)
        .map_err(|error| Box::new(pages::server_error(state, &error)))?;
    let (subject, client_id) = answer.ok().map_or((None, None), |person| {
        (Some(person.subject), person.client_id)
    });
    let recorded = state
        .audit()
        .row(&login(&provider, answer), "login", subject, client_id)
        .map_err(|error| Box::new(pages::server_error(state, &error)))?;
    state
        .audit()
        .record(state.store(), &recorded)
        .await
        .map_err(|error| Box::new(pages::server_error(state, &error)))
}
