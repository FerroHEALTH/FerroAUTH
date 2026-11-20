// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The end-session endpoint (OpenID Connect RP-Initiated Logout 1.0).
//!
//! An app sends the person here to log out. FerroSMART checks the ID Token
//! hint it issued and the `post_logout_redirect_uri` the client registered,
//! asks the person to confirm (§2: SHOULD always, MUST without a hint),
//! ends the person's `online_access` grants, and sends the browser on to
//! the upstream provider's own end-session endpoint when it has one, whose
//! redirect back brings the browser to [`END_SESSION_RETURN_ROUTE`] and
//! from there to the app (§3).
//!
//! The person the logout is for is the `sub` of the hint: FerroSMART keeps
//! no browser session of its own (`docs/architecture.md` §13.6 item 7).
//! Without a hint nothing of FerroSMART's ends, and the upstream logout,
//! whose back-channel or front-channel notice comes back here, ends the
//! person's sessions.

use std::net::IpAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::response::Response;
use http::HeaderMap;
use serde_json::Value;
use url::Url;

use crate::audit::{Connected, Event, Happening, RecordFailure};
use crate::authorize::{REQUEST_SECONDS, constant_eq, cookie, now, random, see_other, set_cookie};
use crate::form::Params;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::logout::PendingLogout;

/// The end-session endpoint's route under the issuer.
pub const END_SESSION_ROUTE: &str = "/logout";

/// The route the confirmation form posts to.
pub const END_SESSION_CONFIRM_ROUTE: &str = "/logout/confirm";

/// The route the upstream provider's end-session endpoint sends the browser
/// back to, which the provider's registration of FerroSMART lists as a
/// post-logout redirect URI.
pub const END_SESSION_RETURN_ROUTE: &str = "/logout/return";

/// The cookie that carries a pending logout's id.
pub const LOGOUT_COOKIE: &str = "ferrosmart_logout";

/// Why a logout request is refused with a page and no redirect (§2, §3:
/// the OP "MUST NOT perform post-logout redirection" to an unregistered
/// URI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The `id_token_hint` is no ID Token FerroSMART issued.
    Hint,
    /// The `client_id` is unknown, or is not the hint's audience.
    Client,
    /// The `post_logout_redirect_uri` is not one the client registered.
    Redirect,
}

impl Refused {
    /// The reason the audit line names.
    const fn reason(self) -> &'static str {
        match self {
            Self::Hint => "the id_token_hint was not issued by this server",
            Self::Client => "the client_id is unknown or not the hint's audience",
            Self::Redirect => "the post_logout_redirect_uri is not registered",
        }
    }
}

/// `GET {issuer}/logout`, the request in the query (§2).
pub async fn end_session_get(
    State(state): State<Arc<AppState>>,
    RawQuery(query): RawQuery,
) -> Response {
    end_session(&state, query.unwrap_or_default().as_bytes()).await
}

/// `POST {issuer}/logout`, the request as a form ("OpenID Providers MUST
/// support the use of the HTTP GET and POST methods", §2).
pub async fn end_session_post(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    end_session(&state, &body).await
}

/// Checks the request, records it and draws the confirmation page.
async fn end_session(state: &AppState, encoded: &[u8]) -> Response {
    let Ok(params) = Params::parse(encoded, &[]) else {
        return pages::fault(state, Fault::BadRequest);
    };
    if state.providers().is_empty() {
        return pages::fault(state, Fault::BadRequest);
    }
    let checked = match checked(state, &params).await {
        Ok(checked) => checked,
        Err(Ok(refused)) => {
            tracing::info!(
                target: "ferrosmart::audit",
                event = "logout.refused",
                channel = "end_session",
                error = refused.reason(),
                "a logout request was refused"
            );
            return pages::logout::refused(state, refused);
        }
        Err(Err(error)) => return pages::server_error(state, &error),
    };
    let drawn = (|| Ok::<_, aws_lc_rs::error::Unspecified>((random()?, random()?, random()?)))();
    let Ok((id, form_token, upstream_state)) = drawn else {
        return pages::fault(state, Fault::Server);
    };
    let upstream_provider = match followed_by(state, checked.subject.as_deref()).await {
        Ok(provider) => provider,
        Err(error) => return pages::server_error(state, &error),
    };
    let pending = PendingLogout {
        upstream_provider,
        id,
        client_id: checked.client_id,
        subject: checked.subject,
        redirect_uri: checked.redirect,
        state: checked.state,
        form_token,
        upstream_state,
        expires_at: now().saturating_add(REQUEST_SECONDS),
    };
    if let Err(error) = state.store().begin_logout(&pending).await {
        return pages::server_error(state, &error);
    }
    let mut response = pages::logout::confirm(state, &pending, &forms_reach(state, &pending));
    set_cookie(
        state,
        &mut response,
        LOGOUT_COOKIE,
        &pending.id,
        REQUEST_SECONDS,
    );
    response
}

/// Returns the provider whose own logout follows the person `subject`'s:
/// the one they last logged in at, or the one provider configured.
async fn followed_by(
    state: &AppState,
    subject: Option<&str>,
) -> Result<Option<String>, crate::store::StoreError> {
    let issuer = match subject {
        Some(subject) => state.store().person_issuer(subject).await?,
        None => None,
    };
    let mut providers = state.providers().iter();
    let provider = match issuer {
        Some(issuer) => state.providers().by_issuer(&issuer),
        None => match (providers.next(), providers.next()) {
            (Some(only), None) => Some(only),
            _ => None,
        },
    };
    Ok(provider.map(|provider| provider.name().to_owned()))
}

/// Returns the login provider `pending`'s logout is followed by, if any.
fn provider_of<'a>(
    state: &'a AppState,
    pending: &PendingLogout,
) -> Option<&'a crate::upstream::LoginProvider> {
    pending
        .upstream_provider
        .as_deref()
        .and_then(|name| state.providers().named(name))
}

/// What a checked request asks.
#[derive(Debug, Default)]
struct Checked {
    /// The client, named or the hint's audience.
    client_id: Option<String>,
    /// The person the hint names.
    subject: Option<String>,
    /// The registered redirect, kept only with a hint (§3).
    redirect: Option<String>,
    /// The client's `state`, kept with the redirect.
    state: Option<String>,
}

/// Checks `params` against the ID Token hint and the client's registration.
async fn checked(
    state: &AppState,
    params: &Params,
) -> Result<Checked, Result<Refused, crate::store::StoreError>> {
    let hint = match params.get("id_token_hint").filter(|hint| !hint.is_empty()) {
        // NOTE: RP-Initiated Logout 1.0 §2, the OP MUST validate it issued the hint
        // and SHOULD accept it past its exp.
        Some(hint) => {
            Some(crate::token::own_jwt(state.settings(), hint, "JWT").ok_or(Ok(Refused::Hint))?)
        }
        None => None,
    };
    let audience = hint
        .as_ref()
        .and_then(|claims| claims.get("aud"))
        .and_then(Value::as_str);
    let subject = hint
        .as_ref()
        .and_then(|claims| claims.get("sub"))
        .and_then(Value::as_str);
    if hint.is_some() && (audience.is_none() || subject.is_none()) {
        return Err(Ok(Refused::Hint));
    }
    let named = params.get("client_id").filter(|id| !id.is_empty());
    // NOTE: RP-Initiated Logout 1.0 §2, with both the OP MUST verify the client_id is
    // the one the ID Token was issued to.
    if let (Some(named), Some(audience)) = (named, audience)
        && named != audience
    {
        return Err(Ok(Refused::Client));
    }
    let client_id = named.or(audience);
    let client = match client_id {
        Some(client_id) => Some(
            state
                .store()
                .client(client_id)
                .await
                .map_err(Err)?
                .ok_or(Ok(Refused::Client))?,
        ),
        None => None,
    };
    let mut checked = Checked {
        client_id: client_id.map(str::to_owned),
        subject: subject.map(str::to_owned),
        ..Checked::default()
    };
    if let Some(redirect) = params
        .get("post_logout_redirect_uri")
        .filter(|uri| !uri.is_empty())
    {
        // NOTE: RP-Initiated Logout 1.0 §3, an exact match of a registered URI.
        let registered = client.as_ref().is_some_and(|client| {
            client
                .post_logout_redirect_uris
                .iter()
                .any(|uri| uri == redirect)
        });
        if !registered {
            return Err(Ok(Refused::Redirect));
        }
        // NOTE: RP-Initiated Logout 1.0 §3, without an id_token_hint the OP MUST NOT
        // redirect, so the logout goes on and ends on FerroSMART's own page.
        if hint.is_some() {
            checked.redirect = Some(redirect.to_owned());
            checked.state = params
                .get("state")
                .filter(|state| !state.is_empty())
                .map(str::to_owned);
        }
    }
    Ok(checked)
}

/// Returns the origins the confirmation form's answer may go on to: the
/// upstream provider's end-session endpoint and the app's redirect, which
/// a page's `form-action` must admit.
fn forms_reach(state: &AppState, pending: &PendingLogout) -> Vec<String> {
    let upstream = provider_of(state, pending)
        .and_then(crate::upstream::LoginProvider::oidc)
        .and_then(|party| party.provider().end_session_endpoint().cloned());
    let app = pending
        .redirect_uri
        .as_deref()
        .and_then(|uri| Url::parse(uri).ok());
    crate::upstream::origins_of(upstream.iter().chain(app.iter()))
}

/// `POST {issuer}/logout/confirm`: the person's answer.
pub async fn end_session_confirm(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (decision, pending) = match answer(&state, &headers, &body).await {
        Ok(answered) => answered,
        Err(page) => return *page,
    };
    if !decision {
        return match state
            .store()
            .take_logout(&pending.id, &pending.upstream_state)
            .await
        {
            Ok(_) => pages::logout::stayed(&state),
            Err(error) => pages::server_error(&state, &error),
        };
    }
    let upstream = provider_of(&state, &pending)
        .and_then(crate::upstream::LoginProvider::oidc)
        .and_then(|party| party.end_session_url(None, Some(pending.upstream_state.as_str())));
    match logged_out(&state, &pending, upstream.is_none(), from).await {
        // NOTE: RP-Initiated Logout 1.0 §2, the OP that is itself an RP forwards the
        // person to its OP's logout, whose redirect brings them back.
        Ok(()) => match upstream {
            Some(upstream) => see_other(upstream.as_str()),
            None => finished(&state, &pending),
        },
        Err(error) => pages::server_error(&state, &error),
    }
}

/// Reads the confirmation form against the pending logout the cookie names:
/// whether the person chose to log out, and the logout, or the page that
/// refuses the form.
async fn answer(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(bool, PendingLogout), Box<Response>> {
    let refuse = |fault| Box::new(pages::fault(state, fault));
    let form = Params::parse(body, &[]).map_err(|_repeated| refuse(Fault::BadRequest))?;
    let id = cookie(headers, LOGOUT_COOKIE).ok_or_else(|| refuse(Fault::Lapsed))?;
    let pending = state
        .store()
        .pending_logout(&id)
        .await
        .map_err(|error| Box::new(pages::server_error(state, &error)))?
        .ok_or_else(|| refuse(Fault::Lapsed))?;
    let sent = form.get("form_token").unwrap_or_default();
    if !constant_eq(sent.as_bytes(), pending.form_token.as_bytes()) {
        return Err(refuse(Fault::BadRequest));
    }
    Ok((form.get("decision") == Some("logout"), pending))
}

/// Ends the person's online grants and records the logout, in one
/// transaction that takes the pending logout when `last` says nothing
/// follows.
async fn logged_out(
    state: &AppState,
    pending: &PendingLogout,
    last: bool,
    from: IpAddr,
) -> Result<(), RecordFailure> {
    let mut tx = state.store().begin().await.map_err(RecordFailure::Store)?;
    let ended = match &pending.subject {
        Some(subject) => tx
            .log_out_person(subject)
            .await
            .map_err(RecordFailure::Store)?,
        None => Vec::new(),
    };
    if last {
        tx.take_pending_logout(&pending.id)
            .await
            .map_err(RecordFailure::Store)?;
    }
    let endpoint = state.settings().endpoint_url(END_SESSION_ROUTE);
    let happening = Happening {
        event: Event::LoggedOut,
        issuer: &state.settings().issuer,
        client_id: pending.client_id.as_deref(),
        subject: pending.subject.as_deref(),
        from,
        endpoint: &endpoint,
        details: vec![("grants", ended.len().to_string())],
    };
    state.audit().commit_happening(tx, &happening).await
}

/// `GET {issuer}/logout/return`: the upstream provider's redirect back,
/// with the `state` FerroSMART sent it.
pub async fn end_session_return(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let Ok(params) = Params::parse(query.unwrap_or_default().as_bytes(), &[]) else {
        return pages::fault(&state, Fault::BadRequest);
    };
    let (Some(id), Some(upstream_state)) = (cookie(&headers, LOGOUT_COOKIE), params.get("state"))
    else {
        return pages::fault(&state, Fault::Lapsed);
    };
    match state.store().take_logout(&id, upstream_state).await {
        Ok(Some(pending)) => finished(&state, &pending),
        Ok(None) => pages::fault(&state, Fault::Lapsed),
        Err(error) => pages::server_error(&state, &error),
    }
}

/// Sends the browser to the app's registered redirect with its `state`
/// (§3), or draws FerroSMART's own logged-out page, and clears the cookie.
fn finished(state: &AppState, pending: &PendingLogout) -> Response {
    let redirect = pending
        .redirect_uri
        .as_deref()
        .and_then(|uri| Url::parse(uri).ok());
    let mut response = match redirect {
        Some(mut redirect) => {
            if let Some(app_state) = &pending.state {
                redirect.query_pairs_mut().append_pair("state", app_state);
            }
            see_other(redirect.as_str())
        }
        None => pages::logout::logged_out(state),
    };
    set_cookie(state, &mut response, LOGOUT_COOKIE, "", 0);
    response
}
