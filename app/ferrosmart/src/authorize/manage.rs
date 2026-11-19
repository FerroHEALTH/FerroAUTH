// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The management page of remembered consents, the `management_endpoint`
//! (SMART App Launch 2.2.0, Conformance, Metadata).

use std::net::IpAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::response::Response;
use http::HeaderMap;

use crate::audit::{self, Connected};
use crate::form::Params;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::grant::Access;
use crate::store::{Asking, Pending, Purpose};

use super::{
    MANAGE_ROUTE, REQUEST_SECONDS, Stop, constant_eq, cookie, fail, now, random, see_other,
    set_cookie,
};

/// `GET {issuer}/manage`: the person's remembered consents, once they
/// logged in at the provider for it; the visit begins that login.
pub async fn manage_get(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(id) = cookie(&headers) {
        match state.store().pending(&id).await {
            Ok(Some(pending))
                if pending.purpose == Purpose::Manage && pending.subject.is_some() =>
            {
                return manage_page(&state, &headers, &pending).await;
            }
            Ok(_) => {}
            Err(error) => return pages::server_error(&state, &error),
        }
    }
    let Some(party) = state.relying_party() else {
        return pages::fault(&state, Fault::BadRequest);
    };
    let begun = (|| {
        let upstream = party.authorization_request().map_err(fail)?;
        Ok::<_, Stop>((upstream, random().map_err(fail)?, random().map_err(fail)?))
    })();
    let Ok((upstream, id, form_token)) = begun else {
        return pages::fault(&state, Fault::Server);
    };
    let pending = Pending {
        id: id.clone(),
        client_id: None,
        redirect_uri: String::new(),
        scope: String::new(),
        state: String::new(),
        nonce: None,
        code_challenge: String::new(),
        audience: String::new(),
        upstream_state: upstream.pending.state().to_owned(),
        upstream_nonce: upstream.pending.nonce().to_owned(),
        upstream_verifier: upstream.pending.verifier().expose().to_owned(),
        form_token,
        subject: None,
        fhir_user: None,
        display_name: None,
        offered_scope: None,
        auth_time: None,
        expires_at: now().saturating_add(REQUEST_SECONDS),
        purpose: Purpose::Manage,
        launch_context: None,
        upstream_session: None,
        roles: Vec::new(),
        asking: Asking::default(),
    };
    if let Err(error) = state.store().begin_authorization(&pending).await {
        return pages::server_error(&state, &error);
    }
    let mut response = see_other(upstream.url.as_str());
    set_cookie(&state, &mut response, &id, REQUEST_SECONDS);
    response
}

/// `POST {issuer}/manage`: forgets the consent the form names and revokes
/// the client's tokens about the person.
pub async fn manage_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Connected(from): Connected,
    body: Bytes,
) -> Response {
    let Ok(form) = Params::parse(&body, &[]) else {
        return pages::fault(&state, Fault::BadRequest);
    };
    let pending = match cookie(&headers) {
        Some(id) => match state.store().pending(&id).await {
            Ok(Some(pending)) if pending.purpose == Purpose::Manage => pending,
            Ok(_) => return pages::fault(&state, Fault::Lapsed),
            Err(error) => return pages::server_error(&state, &error),
        },
        None => return pages::fault(&state, Fault::Lapsed),
    };
    let sent = form.get("form_token").unwrap_or_default();
    let (Some(subject), Some(client_id)) = (&pending.subject, form.get("client_id")) else {
        return pages::fault(&state, Fault::BadRequest);
    };
    if !constant_eq(sent.as_bytes(), pending.form_token.as_bytes()) {
        return pages::fault(&state, Fault::BadRequest);
    }
    match withdraw(&state, subject, client_id, from).await {
        Ok(()) => see_other(&state.settings().endpoint(MANAGE_ROUTE)),
        Err(error) => pages::server_error(&state, &error),
    }
}

/// Forgets the consent `subject` gave `client_id`, revoking what it
/// covered, with its record in one transaction.
async fn withdraw(
    state: &AppState,
    subject: &str,
    client_id: &str,
    from: IpAddr,
) -> Result<(), audit::RecordFailure> {
    let mut tx = state
        .store()
        .begin()
        .await
        .map_err(audit::RecordFailure::Store)?;
    let forgotten = tx
        .revoke_consent(subject, client_id)
        .await
        .map_err(audit::RecordFailure::Store)?;
    let endpoint = state.settings().endpoint_url(MANAGE_ROUTE);
    state
        .audit()
        .commit_happening(
            tx,
            &audit::Happening {
                event: audit::Event::ConsentWithdrawn,
                issuer: &state.settings().issuer,
                client_id: Some(client_id),
                subject: Some(subject),
                from,
                endpoint: &endpoint,
                details: vec![("remembered", forgotten.to_string())],
            },
        )
        .await
}

/// Draws the management page of `pending`'s person.
async fn manage_page(state: &AppState, headers: &HeaderMap, pending: &Pending) -> Response {
    let Some(subject) = &pending.subject else {
        return pages::fault(state, Fault::Lapsed);
    };
    let consents = match state.store().consents(subject).await {
        Ok(consents) => consents,
        Err(error) => return pages::server_error(state, &error),
    };
    // NOTE: SMART App Launch 2.2.0, Best Practices, remind users which apps have
    // offline access: every app with a live refresh grant is listed, remembered or not.
    let held = match state.store().refresh_access(subject).await {
        Ok(held) => held,
        Err(error) => return pages::server_error(state, &error),
    };
    // NOTE: docs/architecture.md §13.6 item 6, an app the organisation approved is
    // listed as such, and only an administrator withdraws it.
    let approved = match state.store().approved_apps(subject).await {
        Ok(approved) => approved,
        Err(error) => return pages::server_error(state, &error),
    };
    let mut apps: std::collections::BTreeMap<String, (String, Option<Access>, bool)> = consents
        .into_iter()
        .map(|(client_id, scope)| (client_id, (scope, None, false)))
        .collect();
    for (client_id, scope) in approved {
        apps.entry(client_id)
            .and_modify(|(_, _, organisation)| *organisation = true)
            .or_insert((scope, None, true));
    }
    for (client_id, scope, access) in held {
        apps.entry(client_id)
            .and_modify(|(_, held, _)| *held = Some(access))
            .or_insert((scope, Some(access), false));
    }
    let mut named = Vec::with_capacity(apps.len());
    for (client_id, (scope, access, organisation)) in apps {
        let name = match state.store().client(&client_id).await {
            Ok(Some(client)) => client.name,
            Ok(None) => client_id.clone(),
            Err(error) => return pages::server_error(state, &error),
        };
        named.push(pages::Remembered {
            client_id,
            name,
            scope,
            access,
            organisation,
        });
    }
    pages::manage(state, headers, pending, &named)
}
