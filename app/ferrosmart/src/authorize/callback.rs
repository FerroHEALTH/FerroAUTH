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
use crate::form::Params;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::{Login, Pending, Purpose};

use super::consent::{approve, offer};
use super::{
    Back, CONSENT_ROUTE, Denial, MANAGE_ROUTE, cookie, forget, found, now, random, registered,
    see_other, set_cookie,
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
    if cookie(&headers).as_deref() != Some(pending.id.as_str()) {
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
    proceed(&state, &pending, &back, &signed_in.claims, from).await
}

/// Goes on once the person logged in as `claims` for `pending`: to the
/// management page, to the consent page, or straight back to the app with
/// a code when a remembered consent covers what is offered.
async fn proceed(
    state: &AppState,
    pending: &Pending,
    back: &Back,
    claims: &ferrohealth_smart::oidc::IdTokenClaims,
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
    let mut login = Login {
        subject,
        fhir_user,
        display_name: claims.display_name().map(str::to_owned),
        offered_scope: String::new(),
        auth_time: now(),
        upstream_session,
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
    let offered = offer(
        &pending.scope,
        &client,
        &held,
        &state.settings().roles,
        login.fhir_user.is_some(),
        pending.launch_context.as_ref(),
        crate::picker::searchable(state, &pending.audience),
    );
    if offered.is_empty() {
        forget(state, pending).await;
        return back.deny(Denial {
            error: "invalid_scope",
            description: "no requested scope can be granted to this person",
        });
    }
    login.offered_scope = offered.join(" ");
    if let Err(error) = state.store().logged_in(&pending.id, &login).await {
        return pages::server_error(state, &error);
    }
    let offered: Vec<&str> = offered.iter().map(String::as_str).collect();
    // NOTE: SMART App Launch 2.2.0, Obtain authorization code, the patient is
    // chosen within the authorization flow, before the consent.
    if pending.launch_context.is_none() && offered.contains(&"launch/patient") {
        return see_other(&state.settings().endpoint(crate::picker::PICKER_ROUTE));
    }
    onward(
        state,
        &pending.id,
        &login.subject,
        &client.client_id,
        &offered,
        back,
        from,
    )
    .await
}

/// Goes on once the person logged in and the context is complete: straight
/// back to the app with a code when a remembered consent covers `offered`,
/// to the consent page otherwise.
pub(crate) async fn onward(
    state: &AppState,
    id: &str,
    subject: &str,
    client_id: &str,
    offered: &[&str],
    back: &Back,
    from: IpAddr,
) -> Response {
    // NOTE: docs/architecture.md §13.6 item 6, a consent the person chose to
    // remember answers again while it covers every scope offered.
    let remembered = match state.store().remembered(subject, client_id).await {
        Ok(remembered) => remembered,
        Err(error) => return pages::server_error(state, &error),
    };
    let covered = remembered.is_some_and(|scope| {
        offered
            .iter()
            .all(|wanted| scope.split(' ').any(|given| given == *wanted))
    });
    if covered {
        let pending = match found(state, state.store().finish(id).await) {
            Ok(pending) => pending,
            Err(response) => return *response,
        };
        let mut response = approve(state, &pending, offered, false, back, from).await;
        set_cookie(state, &mut response, "", 0);
        return response;
    }
    see_other(&state.settings().endpoint(CONSENT_ROUTE))
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
