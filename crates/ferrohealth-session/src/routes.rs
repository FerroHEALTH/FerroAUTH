// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The four sign-in routes as an axum router, and the middleware every page
//! sits behind.
//!
//! - `GET /login` mints the `state`, the `nonce` and the PKCE verifier
//!   through the relying party, keeps them as a pending sign-in with the page
//!   `?return=` names, and redirects to the provider (RFC 6749 §4.1.1,
//!   RFC 7636 §4.3, OpenID Connect Core 1.0 §3.1.2.1).
//! - `GET /auth/callback` takes the pending sign-in once; the relying party
//!   holds the returned `state` to it (RFC 6749 §10.12), trades the code and
//!   checks the ID Token, and only then is a session begun.
//! - `POST /logout` ends the session, revokes its token at the provider when
//!   it has a revocation endpoint (RFC 7009 §2.1), and sends the operator to
//!   its end-session endpoint (OpenID Connect RP-Initiated Logout 1.0 §2).
//!   With no provider configured, or one with no end-session endpoint, it
//!   ends the session, removes its cookie and redirects to
//!   [`Pages::signed_out`]; a sign-out never answers `503`.
//! - `GET /session` reads what the session has left and never counts as
//!   activity, `POST /session` extends the idle lifetime, and both answer
//!   `401` once the session is gone, with an RFC 9457 problem whose `detail`
//!   the console words ([`Pages::session_gone`]): the wire of FerroUI's
//!   session watch.
//!
//! A `POST` is taken only from the console's own pages, which the console's
//! stack holds (`ferrohealth_server::same_origin`). Every answer is
//! `Cache-Control: no-store`. The console draws every stopped sign-in through
//! its [`Pages`], in its own locale.

use std::future::Future;

use axum::Router;
use axum::extract::{Query, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response};
use axum::routing::{get, post};
use ferrohealth_smart::oidc::{Callback, OidcError, RelyingParty};
use http::header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION, SET_COOKIE};
use http::request::Parts;
use http::{HeaderValue, Method, StatusCode};
use serde::Deserialize;

use crate::paths::{CALLBACK, LOGIN, LOGOUT, SESSION, is_own};
use crate::record::SignedIn;
use crate::refresh::Freshness;
use crate::return_path::ReturnPath;
use crate::sessions::{SessionError, Sessions};

/// Why a sign-in stopped, which the console's [`Pages`] draws.
#[derive(Debug)]
#[non_exhaustive]
pub enum Stopped {
    /// The console has no OpenID Provider configured (`503`).
    NotConfigured,
    /// The callback names no pending sign-in, or one expired (`400`).
    NoSignInPending,
    /// The redirect's `state` is not the pending sign-in's (`400`,
    /// RFC 6749 §10.12).
    StateMismatch,
    /// The redirect carries no authorization code (`400`).
    NoCode,
    /// The provider refused the sign-in, or its ID Token does not verify
    /// (`401`).
    Rejected(OidcError),
    /// The sign-in could not be completed at the provider (`502`).
    NotCompleted(OidcError),
    /// The memory store holds as many sessions as it may (`503`).
    Full,
    /// The session store failed (`500`).
    Store(SessionError),
}

impl Stopped {
    /// The status the answer carries.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::NotConfigured | Self::Full => StatusCode::SERVICE_UNAVAILABLE,
            Self::NoSignInPending | Self::StateMismatch | Self::NoCode => StatusCode::BAD_REQUEST,
            Self::Rejected(_) => StatusCode::UNAUTHORIZED,
            Self::NotCompleted(_) => StatusCode::BAD_GATEWAY,
            Self::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Whether trying the sign-in again may help.
    #[must_use]
    pub const fn retry(&self) -> bool {
        matches!(self, Self::NotCompleted(_) | Self::NoSignInPending)
    }
}

/// The pages a console draws around its sign-in, in its own locale.
pub trait Pages: Clone + Send + Sync + 'static {
    /// The answer to a sign-in that stopped for `why`, for the request
    /// `parts`, with the status [`Stopped::status`] names.
    fn stopped(&self, parts: Parts, why: Stopped) -> impl Future<Output = Response> + Send;

    /// The path of the console's own sign-in page, which is never a return
    /// path.
    fn sign_in_page(&self) -> &str;

    /// Where a sign-out lands when the provider has no end-session
    /// endpoint, or the console has no provider: the session is ended and
    /// its cookie removed all the same, and the sign-out never answers
    /// `503`.
    fn signed_out(&self) -> &str;

    /// Where a completed sign-in lands with no return path, such as `/`.
    fn home(&self) -> &str;

    /// The `detail` of the problem the session watch answers once the
    /// session of the request `parts` is gone, in the console's locale; the
    /// default is English.
    fn session_gone(&self, _parts: &Parts) -> String {
        String::from("The session has ended. Sign in again to go on.")
    }
}

/// What the routes and the middleware share.
#[derive(Debug, Clone)]
pub struct SignIn<P> {
    sessions: Sessions,
    party: Option<RelyingParty>,
    pages: P,
}

impl<P: Pages> SignIn<P> {
    /// The sign-in of a console with `sessions`, its relying party when an
    /// OpenID Provider is configured, and its `pages`.
    #[must_use]
    pub const fn new(sessions: Sessions, party: Option<RelyingParty>, pages: P) -> Self {
        Self {
            sessions,
            party,
            pages,
        }
    }

    /// The session store.
    #[must_use]
    pub const fn sessions(&self) -> &Sessions {
        &self.sessions
    }

    /// The relying party, when a provider is configured.
    #[must_use]
    pub const fn party(&self) -> Option<&RelyingParty> {
        self.party.as_ref()
    }

    async fn stop(&self, parts: Parts, why: Stopped, cookies: Vec<HeaderValue>) -> Response {
        let mut response = self.pages.stopped(parts, why).await;
        append(&mut response, cookies);
        response
    }
}

/// The four routes, for a router of any state.
pub fn router<P: Pages, S: Clone + Send + Sync + 'static>(sign_in: SignIn<P>) -> Router<S> {
    Router::new()
        .route(LOGIN, get(login::<P>))
        .route(CALLBACK, get(callback::<P>))
        .route(LOGOUT, post(logout::<P>))
        .route(SESSION, get(watch::<P>).post(watch::<P>))
        .with_state(sign_in)
}

/// The middleware every page sits behind.
///
/// Mounted with `axum::middleware::from_fn_with_state`, it renews an access
/// token that is due, counts the request as activity, puts the request's
/// [`crate::record::Held`] into its extensions, and sets the cookies the
/// store answered.
pub async fn keep_session<P: Pages>(
    State(sign_in): State<SignIn<P>>,
    request: Request,
    next: Next,
) -> Response {
    if is_own(request.uri().path()) {
        return next.run(request).await;
    }
    if let Some(party) = sign_in.party() {
        match sign_in.sessions.keep_fresh(party, request.headers()).await {
            Ok(Freshness::Ended(error)) => {
                tracing::warn!(%error, "the OpenID Provider refused a refresh, so the session is ended");
            }
            Ok(Freshness::Unreached(error)) => {
                tracing::warn!(%error, "an access token could not be refreshed at the OpenID Provider");
            }
            Ok(_) => {}
            Err(error) => return store_failed(&sign_in, request, error).await,
        }
    }
    match sign_in.sessions.held(request.headers()) {
        Ok(held) => {
            let mut request = request;
            request.extensions_mut().insert(held.value);
            let mut response = next.run(request).await;
            append(&mut response, held.cookies);
            response
        }
        Err(error) => store_failed(&sign_in, request, error).await,
    }
}

async fn store_failed<P: Pages>(
    sign_in: &SignIn<P>,
    request: Request,
    error: SessionError,
) -> Response {
    tracing::error!(%error, "the session store could not be read");
    let (parts, _body) = request.into_parts();
    sign_in.stop(parts, Stopped::Store(error), Vec::new()).await
}

/// The query of `GET /login`.
#[derive(Debug, Default, Deserialize)]
struct LoginQuery {
    #[serde(rename = "return")]
    back: Option<String>,
}

async fn login<P: Pages>(State(sign_in): State<SignIn<P>>, request: Request) -> Response {
    let (parts, _body) = request.into_parts();
    let Some(relying_party) = sign_in.party() else {
        return sign_in
            .stop(parts, Stopped::NotConfigured, Vec::new())
            .await;
    };
    // NOTE: no specification governs this: our own design; a return address that is not one
    // of the console's pages leads home, so the sign-in still begins.
    let back = Query::<LoginQuery>::try_from_uri(&parts.uri)
        .ok()
        .and_then(|Query(query)| query.back)
        .and_then(|back| ReturnPath::parse(&back, sign_in.pages.sign_in_page()));
    let authorization = match relying_party.authorization_request() {
        Ok(authorization) => authorization,
        Err(error) => {
            tracing::error!(%error, "a sign-in could not be minted");
            return sign_in
                .stop(parts, Stopped::Store(SessionError::Random), Vec::new())
                .await;
        }
    };
    match sign_in.sessions.begin(authorization.pending, back) {
        Ok(cookie) => redirect(authorization.url.as_str(), vec![cookie]),
        Err(error) => sign_in.stop(parts, Stopped::Store(error), Vec::new()).await,
    }
}

async fn callback<P: Pages>(State(sign_in): State<SignIn<P>>, request: Request) -> Response {
    let (parts, _body) = request.into_parts();
    let taken = match sign_in.sessions.take_pending(&parts.headers) {
        Ok(taken) => taken,
        Err(error) => return sign_in.stop(parts, Stopped::Store(error), Vec::new()).await,
    };
    let removal = taken.cookies;
    let Some(pending) = taken.value else {
        return sign_in.stop(parts, Stopped::NoSignInPending, removal).await;
    };
    let Some(relying_party) = sign_in.party() else {
        return sign_in.stop(parts, Stopped::NotConfigured, removal).await;
    };
    // NOTE: RFC 6749 §10.12: a redirect whose query does not read carries no state, which the
    // exchange refuses as a mismatch before anything else it says is read.
    let query = Query::<Callback>::try_from_uri(&parts.uri)
        .map(|Query(query)| query)
        .unwrap_or_default();
    let signed_in = match relying_party.exchange(&pending.sign_in, &query).await {
        Ok(signed_in) => signed_in,
        Err(error) => return sign_in.stop(parts, refused(error), removal).await,
    };
    match sign_in
        .sessions
        .establish(&parts.headers, SignedIn::from_oidc(signed_in))
    {
        Ok(cookie) => {
            let landing = pending
                .back
                .as_ref()
                .map_or_else(|| sign_in.pages.home(), ReturnPath::as_str);
            let mut cookies = removal;
            cookies.push(cookie);
            redirect(landing, cookies)
        }
        Err(SessionError::Full) => sign_in.stop(parts, Stopped::Full, removal).await,
        Err(error) => sign_in.stop(parts, Stopped::Store(error), removal).await,
    }
}

/// The stop a failed exchange is.
fn refused(error: OidcError) -> Stopped {
    match error {
        OidcError::StateMismatch => Stopped::StateMismatch,
        OidcError::NoCode => Stopped::NoCode,
        error
            if matches!(error, OidcError::Authorization { .. }) || error.refuses_the_operator() =>
        {
            tracing::warn!(%error, "a sign-in was refused");
            Stopped::Rejected(error)
        }
        error => {
            tracing::error!(%error, "a sign-in could not be completed at the OpenID Provider");
            Stopped::NotCompleted(error)
        }
    }
}

async fn logout<P: Pages>(State(sign_in): State<SignIn<P>>, request: Request) -> Response {
    let (parts, _body) = request.into_parts();
    let ended = match sign_in.sessions.end(&parts.headers) {
        Ok(ended) => ended,
        Err(error) => return sign_in.stop(parts, Stopped::Store(error), Vec::new()).await,
    };
    let mut location = None;
    if let Some(party) = sign_in.party() {
        let held = ended.value.as_ref();
        if let Some((token, kind)) = held.and_then(|ended| ended.revocable.as_ref())
            && let Err(error) = party.revoke(token, *kind).await
        {
            // NOTE: RFC 7009 §2.2: the console's session is already gone; a token the provider
            // did not revoke expires on its own, and the log says so.
            tracing::warn!(%error, "the OpenID Provider did not revoke an operator's token");
        }
        let hint = held.and_then(|ended| ended.id_token.as_ref());
        location = party.end_session_url(hint, None).map(String::from);
    }
    let location = location.unwrap_or_else(|| sign_in.pages.signed_out().to_owned());
    redirect(&location, ended.cookies)
}

async fn watch<P: Pages>(
    State(sign_in): State<SignIn<P>>,
    method: Method,
    request: Request,
) -> Response {
    let extend = method == Method::POST;
    let (parts, _body) = request.into_parts();
    match sign_in.sessions.left(&parts.headers, extend) {
        Ok(left) => {
            let mut response = match left.value {
                Some(left) => axum::Json(left).into_response(),
                None => gone(&sign_in.pages.session_gone(&parts)),
            };
            no_store(&mut response);
            append(&mut response, left.cookies);
            response
        }
        Err(error) => {
            tracing::error!(%error, "the session store could not be read");
            let mut response = StatusCode::INTERNAL_SERVER_ERROR.into_response();
            no_store(&mut response);
            response
        }
    }
}

/// The `401` of a session that is gone: an `about:blank` problem
/// (RFC 9457 §3, §4.2.1) whose `detail` is `detail`.
fn gone(detail: &str) -> Response {
    let problem = serde_json::json!({
        "type": "about:blank",
        "title": "Unauthorized",
        "status": StatusCode::UNAUTHORIZED.as_u16(),
        "detail": detail,
    });
    (
        StatusCode::UNAUTHORIZED,
        [(CONTENT_TYPE, HeaderValue::from_static(PROBLEM_JSON))],
        problem.to_string(),
    )
        .into_response()
}

/// The media type of a problem document (RFC 9457 §3).
const PROBLEM_JSON: &str = "application/problem+json";

/// A `303` to `location` that sets `cookies`.
fn redirect(location: &str, cookies: Vec<HeaderValue>) -> Response {
    let Ok(location) = HeaderValue::from_str(location) else {
        tracing::error!("a sign-in redirect could not be written as a header");
        let mut response = StatusCode::INTERNAL_SERVER_ERROR.into_response();
        no_store(&mut response);
        return response;
    };
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(LOCATION, location);
    no_store(&mut response);
    append(&mut response, cookies);
    response
}

fn no_store(response: &mut Response) {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

fn append(response: &mut Response, cookies: Vec<HeaderValue>) {
    for cookie in cookies {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
}
