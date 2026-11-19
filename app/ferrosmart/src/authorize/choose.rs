// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Which upstream provider a person logs in at, and the start of that
//! login.
//!
//! A client names the providers its people may log in at (every provider
//! when it names none). With one, the browser goes straight to it; with
//! several, `GET {issuer}/login` draws the chooser and its post sends the
//! browser on. The pending request records the provider, so the callback
//! completes the login with that provider's settings alone. Nothing in
//! SMART App Launch 2.2.0 limits a server to one provider; the chooser is
//! our own design (#678).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::response::Response;
use http::HeaderMap;
use url::Url;

use crate::form::Params;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::{Asking, Pending, Purpose};
use crate::upstream::LoginProvider;

use super::{COOKIE, Stop, constant_eq, cookie, fail, random, see_other};

/// The chooser's route under the issuer.
pub const LOGIN_ROUTE: &str = "/login";

/// Where a new request's browser goes first, and what the request records
/// of it.
#[derive(Debug)]
pub(super) struct Start {
    /// The provider's login, or the chooser.
    pub(super) location: Url,
    /// The provider chosen, when only one was allowed.
    pub(super) provider: Option<String>,
    /// The upstream `state`, `nonce` and PKCE verifier; drawn at random
    /// until a provider is chosen, so no callback can match them.
    pub(super) sign_in: [String; 3],
}

/// Returns how a new request whose client allows `allowed` starts: at the
/// one provider, or at the chooser.
pub(super) fn start(
    state: &AppState,
    allowed: &[&LoginProvider],
    asking: &Asking,
) -> Result<Start, Stop> {
    match allowed {
        [] => Err(Stop::Deny(super::Denial::request("no login is configured"))),
        [only] => {
            let (location, sign_in) = sign_in_at(only, asking)?;
            Ok(Start {
                location,
                provider: Some(only.name().to_owned()),
                sign_in,
            })
        }
        _ => Ok(Start {
            location: state.settings().endpoint_url(LOGIN_ROUTE),
            provider: None,
            sign_in: [
                random().map_err(fail)?,
                random().map_err(fail)?,
                random().map_err(fail)?,
            ],
        }),
    }
}

/// Returns the login request at `provider`, carrying what `asking` passes
/// on, with its `state`, `nonce` and PKCE verifier.
pub(super) fn sign_in_at(
    provider: &LoginProvider,
    asking: &Asking,
) -> Result<(Url, [String; 3]), Stop> {
    let party = provider
        .oidc()
        .ok_or(Stop::Deny(super::Denial::request("no login is configured")))?;
    let upstream = party.authorization_request().map_err(fail)?;
    let location = super::oidc::upstream(upstream.url.clone(), asking);
    Ok((
        location,
        [
            upstream.pending.state().to_owned(),
            upstream.pending.nonce().to_owned(),
            upstream.pending.verifier().expose().to_owned(),
        ],
    ))
}

/// Returns the providers the person of `pending` may choose from: those its
/// client allows, or every provider for the management page.
async fn allowed<'a>(
    state: &'a AppState,
    pending: &Pending,
) -> Result<Vec<&'a LoginProvider>, Box<Response>> {
    if pending.purpose == Purpose::Manage {
        return Ok(state.providers().iter().collect());
    }
    let client = super::registered(state, pending).await?;
    Ok(state.providers().allowed(&client.upstreams))
}

/// Returns the browser's request that waits for a provider, or the page
/// that says why there is none.
async fn choosing(state: &AppState, headers: &HeaderMap) -> Result<Pending, Box<Response>> {
    let Some(id) = cookie(headers, COOKIE) else {
        return Err(Box::new(pages::fault(state, Fault::Lapsed)));
    };
    let pending = super::found(state, state.store().pending(&id).await)?;
    if pending.upstream_provider.is_some() {
        return Err(Box::new(pages::fault(state, Fault::Lapsed)));
    }
    Ok(pending)
}

/// `GET {issuer}/login`: the chooser.
pub async fn choose_get(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let pending = match choosing(&state, &headers).await {
        Ok(pending) => pending,
        Err(page) => return *page,
    };
    match allowed(&state, &pending).await {
        Ok(providers) => pages::chooser(&state, &headers, &pending, &providers),
        Err(page) => *page,
    }
}

/// `POST {issuer}/login`: the person's choice, which sends the browser on to
/// that provider.
pub async fn choose_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (pending, provider) = match chosen(&state, &headers, &body).await {
        Ok(chosen) => chosen,
        Err(page) => return *page,
    };
    let Ok((location, [upstream_state, nonce, verifier])) = sign_in_at(provider, &pending.asking)
    else {
        return pages::fault(&state, Fault::Server);
    };
    match state
        .store()
        .choose_upstream(
            &pending.id,
            provider.name(),
            [&upstream_state, &nonce, &verifier],
        )
        .await
    {
        Ok(true) => see_other(location.as_str()),
        Ok(false) => pages::fault(&state, Fault::Lapsed),
        Err(error) => pages::server_error(&state, &error),
    }
}

/// Reads the chooser's form against the request the cookie names: the
/// request and the provider chosen among those it allows, or the page that
/// refuses the form.
async fn chosen<'a>(
    state: &'a AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(Pending, &'a LoginProvider), Box<Response>> {
    let refuse = |fault| Box::new(pages::fault(state, fault));
    let form = Params::parse(body, &[]).map_err(|_repeated| refuse(Fault::BadRequest))?;
    let pending = choosing(state, headers).await?;
    let sent = form.get("form_token").unwrap_or_default();
    if !constant_eq(sent.as_bytes(), pending.form_token.as_bytes()) {
        return Err(refuse(Fault::BadRequest));
    }
    let provider = allowed(state, &pending)
        .await?
        .into_iter()
        .find(|provider| form.get("provider") == Some(provider.name()))
        .ok_or_else(|| refuse(Fault::BadRequest))?;
    Ok((pending, provider))
}
