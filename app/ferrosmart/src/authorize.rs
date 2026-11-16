// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The authorization endpoint, the upstream login and the consent page:
//! SMART App Launch 2.2.0's authorization code flow, standalone launch
//! (`docs/architecture.md` §13.6).
//!
//! `GET` or `POST {issuer}/authorize` checks the request and sends the
//! browser to the upstream provider; `GET {issuer}/callback` completes the
//! login there and offers the person the scopes policy allows them; the
//! consent page's post issues the code and sends the browser back to the
//! app. A cookie of FerroSMART's own binds the three to one browser.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use ferrohealth_secret::secret::Secret;
use ferrohealth_smart::oidc::{Callback, PendingSignIn};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use url::Url;

use crate::clients::{Client, GrantType};
use crate::form::Params;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::{Code, Login, Pending, Purpose, StoreError};

/// The cookie that binds an authorization request to the browser that
/// began it. No specification governs it: our own design.
pub const COOKIE: &str = "ferrosmart_authorization";

/// How long an authorization request may take, login and consent
/// included. No specification governs the value: our own design.
pub const REQUEST_SECONDS: i64 = 600;

/// How long an authorization code lives: "short-lived, usually expiring
/// within around one minute" (SMART App Launch 2.2.0, Obtain authorization
/// code, Response).
pub const CODE_SECONDS: i64 = 60;

/// The authorization endpoint's route under the issuer.
pub const AUTHORIZE_ROUTE: &str = "/authorize";
/// The upstream provider's redirection endpoint under the issuer.
pub const CALLBACK_ROUTE: &str = "/callback";
/// The consent page's route under the issuer.
pub const CONSENT_ROUTE: &str = "/consent";
/// The management page's route under the issuer, the `management_endpoint`
/// (SMART App Launch 2.2.0, Conformance, Metadata).
pub const MANAGE_ROUTE: &str = "/manage";

/// An error the authorization endpoint sends back to the app (RFC 6749
/// §4.1.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Denial {
    /// The `error` code.
    error: &'static str,
    /// The `error_description`.
    description: &'static str,
}

impl Denial {
    /// The `invalid_request` denial.
    const fn request(description: &'static str) -> Self {
        Self {
            error: "invalid_request",
            description,
        }
    }
}

/// `GET {issuer}/authorize`, the request in the query.
pub async fn authorize_get(
    State(state): State<Arc<AppState>>,
    RawQuery(query): RawQuery,
) -> Response {
    authorize(&state, query.unwrap_or_default().as_bytes()).await
}

/// `POST {issuer}/authorize`, the request as a form.
///
/// "Authorization Servers SHALL support the use of the HTTP GET and POST methods at the
/// Authorization Endpoint", SMART App Launch 2.2.0, Obtain authorization
/// code).
pub async fn authorize_post(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    authorize(&state, &body).await
}

/// Checks the authorization request `encoded` and sends the browser to the
/// upstream provider.
async fn authorize(state: &AppState, encoded: &[u8]) -> Response {
    let Ok(params) = Params::parse(encoded, &[]) else {
        return pages::fault(state, Fault::BadRequest);
    };
    // NOTE: RFC 6749 §4.1.2.1, an unknown client or a redirect URI that is not
    // registered is told to the person, never redirected to.
    let client = match params.get("client_id") {
        Some(client_id) => match state.store().client(client_id).await {
            Ok(Some(client)) if client.grant_types.contains(&GrantType::AuthorizationCode) => {
                client
            }
            Ok(_) => return pages::fault(state, Fault::UnknownClient),
            Err(error) => return pages::server_error(state, &error),
        },
        None => return pages::fault(state, Fault::UnknownClient),
    };
    // NOTE: RFC 9700 §2.1, the redirect URI matches a registered one exactly.
    let Some(redirect_uri) = params.get("redirect_uri").filter(|uri| {
        client
            .redirect_uris
            .iter()
            .any(|registered| registered == uri)
    }) else {
        return pages::fault(state, Fault::UnknownRedirect);
    };
    let back = Back {
        redirect_uri: redirect_uri.to_owned(),
        state: params.get("state").map(str::to_owned),
        issuer: state.settings().issuer.clone(),
    };
    match begin(state, &client, &params, redirect_uri).await {
        Ok(response) => response,
        Err(Stop::Deny(denial)) => back.deny(denial),
        Err(Stop::Fail(error)) => {
            tracing::error!(error = %ferrohealth_server::run::chain(&*error), "the authorization request failed");
            back.deny(Denial {
                error: "server_error",
                description: "the authorization server failed",
            })
        }
    }
}

/// Why the authorization request stopped before the upstream login.
#[derive(Debug)]
enum Stop {
    /// The request is refused, and the app is told why.
    Deny(Denial),
    /// The server failed.
    Fail(Box<dyn std::error::Error + Send + Sync>),
}

/// Returns `error` as the server's failure.
fn fail(error: impl std::error::Error + Send + Sync + 'static) -> Stop {
    Stop::Fail(Box::new(error))
}

/// Checks the rest of the request and begins the upstream login.
async fn begin(
    state: &AppState,
    client: &Client,
    params: &Params,
    redirect_uri: &str,
) -> Result<Response, Stop> {
    if params.get("response_type") != Some("code") {
        return Err(Stop::Deny(Denial {
            error: "unsupported_response_type",
            description: "the response_type is not code",
        }));
    }
    // NOTE: SMART App Launch 2.2.0, Obtain authorization code, `state` is required.
    let client_state = params
        .get("state")
        .ok_or(Stop::Deny(Denial::request("the request carries no state")))?;
    // NOTE: SMART App Launch 2.2.0, Considerations for PKCE Support: S256, never plain.
    let challenge = params
        .get("code_challenge")
        .filter(|_| params.get("code_challenge_method") == Some("S256"))
        .ok_or(Stop::Deny(Denial::request(
            "the request carries no S256 code_challenge",
        )))?;
    // NOTE: SMART App Launch 2.2.0, `aud` is required and `resource` MAY be its
    // synonym; it names a resource server this issuer serves.
    let audience = params
        .get("aud")
        .or_else(|| params.get("resource"))
        .filter(|aud| state.settings().resources.iter().any(|base| base == aud))
        .ok_or(Stop::Deny(Denial::request(
            "the aud is not a server this issuer serves",
        )))?;
    if params.get("launch").is_some() {
        return Err(Stop::Deny(Denial::request(
            "an EHR launch is not supported",
        )));
    }
    let scope = params.get("scope").ok_or(Stop::Deny(Denial {
        error: "invalid_scope",
        description: "the request names no scope",
    }))?;
    let party = state
        .relying_party()
        .ok_or(Stop::Deny(Denial::request("no login is configured")))?;
    let upstream = party.authorization_request().map_err(fail)?;
    let id = random().map_err(fail)?;
    let pending = Pending {
        id: id.clone(),
        client_id: Some(client.client_id.clone()),
        redirect_uri: redirect_uri.to_owned(),
        scope: scope.to_owned(),
        state: client_state.to_owned(),
        nonce: params.get("nonce").map(str::to_owned),
        code_challenge: challenge.to_owned(),
        audience: audience.to_owned(),
        upstream_state: upstream.pending.state().to_owned(),
        upstream_nonce: upstream.pending.nonce().to_owned(),
        upstream_verifier: upstream.pending.verifier().expose().to_owned(),
        form_token: random().map_err(fail)?,
        subject: None,
        fhir_user: None,
        display_name: None,
        offered_scope: None,
        auth_time: None,
        expires_at: now().saturating_add(REQUEST_SECONDS),
        purpose: Purpose::Authorize,
        upstream_session: None,
    };
    state
        .store()
        .begin_authorization(&pending)
        .await
        .map_err(fail)?;
    let mut response = see_other(upstream.url.as_str());
    set_cookie(state, &mut response, &id, REQUEST_SECONDS);
    Ok(response)
}

/// `GET {issuer}/callback`, where the upstream provider sends the browser
/// back.
pub async fn callback(
    State(state): State<Arc<AppState>>,
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
        Err(error) if pending.purpose == Purpose::Manage => {
            forget(&state, &pending).await;
            tracing::warn!(error = %ferrohealth_server::run::chain(&error), "the upstream login failed");
            return pages::fault(&state, Fault::Lapsed);
        }
        Err(error) => {
            forget(&state, &pending).await;
            // NOTE: RFC 6749 §4.1.2.1, a person who declined at the provider is
            // access_denied; any other failure is the server's.
            if answer.error.is_some() {
                return back.deny(Denial {
                    error: "access_denied",
                    description: "the login was declined",
                });
            }
            tracing::warn!(error = %ferrohealth_server::run::chain(&error), "the upstream login failed");
            return back.deny(Denial {
                error: "server_error",
                description: "the login could not be completed",
            });
        }
    };
    proceed(&state, &pending, &back, &signed_in.claims).await
}

/// Goes on once the person logged in as `claims` for `pending`: to the
/// management page, to the consent page, or straight back to the app with
/// a code when a remembered consent covers what is offered.
async fn proceed(
    state: &AppState,
    pending: &Pending,
    back: &Back,
    claims: &ferrohealth_smart::oidc::IdTokenClaims,
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
    tracing::info!(
        target: "ferrosmart::audit",
        event = "login",
        subject = %login.subject,
        client_id = ?pending.client_id,
        manage = pending.purpose == Purpose::Manage,
        "a person logged in at the upstream provider"
    );
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
    );
    if offered.is_empty() {
        forget(state, pending).await;
        return back.deny(Denial {
            error: "invalid_scope",
            description: "no requested scope can be granted to this person",
        });
    }
    login.offered_scope = offered.join(" ");
    // NOTE: docs/architecture.md §13.6 item 6, a consent the person chose to
    // remember answers again while it covers every scope offered.
    let remembered = match state
        .store()
        .remembered(&login.subject, &client.client_id)
        .await
    {
        Ok(remembered) => remembered,
        Err(error) => return pages::server_error(state, &error),
    };
    let covered = remembered.is_some_and(|scope| {
        offered
            .iter()
            .all(|wanted| scope.split(' ').any(|given| given == wanted))
    });
    if let Err(error) = state.store().logged_in(&pending.id, &login).await {
        return pages::server_error(state, &error);
    }
    if covered {
        let pending = match found(state, state.store().finish(&pending.id).await) {
            Ok(pending) => pending,
            Err(response) => return *response,
        };
        let offered: Vec<&str> = offered.iter().map(String::as_str).collect();
        let mut response = approve(state, &pending, &offered, false, back).await;
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

/// Returns the client of `pending`, or the page that says it is gone.
async fn registered(state: &AppState, pending: &Pending) -> Result<Client, Box<Response>> {
    let found = match &pending.client_id {
        Some(client_id) => state.store().client(client_id).await,
        None => Ok(None),
    };
    match found {
        Ok(Some(client)) => Ok(client),
        Ok(None) => Err(Box::new(pages::fault(state, Fault::UnknownClient))),
        Err(error) => Err(Box::new(pages::server_error(state, &error))),
    }
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

/// Returns the scopes the consent page offers the person.
///
/// Of the requested scopes it offers `openid` and `fhirUser` when the client may ask for them (and the
/// provider carries the person's `fhirUser`, without which "it cannot
/// support the `fhirUser` scope", SMART App Launch 2.2.0, Scopes for
/// requesting identity data), and each `user/` scope the client may ask
/// for and one of the person's roles grants (13.6 item 5). Scopes that need
/// a patient in context, a refresh token or an EHR launch join with the
/// steps that bring them (#516, #517, #518). Matching a scope as written
/// is our own design.
#[must_use]
pub fn offer(
    requested: &str,
    client: &Client,
    held: &[String],
    roles: &std::collections::BTreeMap<String, Vec<String>>,
    has_fhir_user: bool,
) -> Vec<String> {
    let ceiling = |scope: &str| client.scopes.iter().any(|allowed| allowed == scope);
    let granted_by_role = |scope: &str| {
        held.iter()
            .filter_map(|role| roles.get(role))
            .any(|scopes| scopes.iter().any(|allowed| allowed == scope))
    };
    let mut offered: Vec<String> = Vec::new();
    for scope in requested.split(' ').filter(|scope| !scope.is_empty()) {
        let admitted = match scope {
            "openid" => ceiling(scope),
            "fhirUser" => ceiling(scope) && has_fhir_user,
            user if user.starts_with("user/") => ceiling(user) && granted_by_role(user),
            // NOTE: SMART App Launch 2.2.0, Refresh access token, the server decides
            // which clients get a refresh token: those whose ceiling and grants name it.
            "offline_access" | "online_access" => {
                ceiling(scope) && client.grant_types.contains(&GrantType::RefreshToken)
            }
            _ => false,
        };
        if admitted && !offered.iter().any(|kept| kept == scope) {
            offered.push(scope.to_owned());
        }
    }
    // NOTE: OpenID Connect Core 1.0 §3.1.2.1, `fhirUser` arrives in an ID Token,
    // which only `openid` asks for.
    if !offered.iter().any(|scope| scope == "openid") {
        offered.retain(|scope| scope != "fhirUser");
    }
    offered
}

/// `GET {issuer}/consent`: the consent page of the browser's request.
pub async fn consent_get(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let pending = match logged_in(&state, &headers).await {
        Ok(pending) => pending,
        Err(response) => return *response,
    };
    let client = match registered(&state, &pending).await {
        Ok(client) => client,
        Err(response) => return *response,
    };
    pages::consent(&state, &headers, &client, &pending)
}

/// `POST {issuer}/consent`: the person's decision.
pub async fn consent_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(form) = Params::parse(&body, &["scope"]) else {
        return pages::fault(&state, Fault::BadRequest);
    };
    let pending = match logged_in(&state, &headers).await {
        Ok(pending) => pending,
        Err(response) => return *response,
    };
    // NOTE: RFC 6749 §10.12, the decision carries the token its page drew.
    let sent = form.get("form_token").unwrap_or_default();
    if !constant_eq(sent.as_bytes(), pending.form_token.as_bytes()) {
        return pages::fault(&state, Fault::BadRequest);
    }
    let pending = match found(&state, state.store().finish(&pending.id).await) {
        Ok(pending) => pending,
        Err(response) => return *response,
    };
    let back = Back::of(&state, &pending);
    let mut response = if form.get("decision") == Some("approve") {
        let remember = form.get("remember") == Some("yes");
        approve(&state, &pending, &form.all("scope"), remember, &back).await
    } else {
        tracing::info!(
            target: "ferrosmart::audit",
            event = "authorization.declined",
            client_id = ?pending.client_id,
            "the person declined"
        );
        back.deny(Denial {
            error: "access_denied",
            description: "the person declined",
        })
    };
    set_cookie(&state, &mut response, "", 0);
    response
}

/// Issues the code for the scopes the person kept of those offered, and
/// sends the browser back to the app with it.
async fn approve(
    state: &AppState,
    pending: &Pending,
    selected: &[&str],
    remember: bool,
    back: &Back,
) -> Response {
    let offered = pending.offered_scope.as_deref().unwrap_or_default();
    let mut granted: Vec<&str> = offered
        .split(' ')
        .filter(|scope| selected.contains(scope))
        .collect();
    if !granted.contains(&"openid") {
        granted.retain(|scope| *scope != "fhirUser");
    }
    if granted.is_empty() {
        return back.deny(Denial {
            error: "access_denied",
            description: "the person granted no scope",
        });
    }
    let (Some(subject), Some(auth_time), Some(client_id)) =
        (&pending.subject, pending.auth_time, &pending.client_id)
    else {
        return pages::fault(state, Fault::Lapsed);
    };
    let issued = random().map(|code| (sha256(&code), code));
    let Ok((hash, code)) = issued else {
        return back.deny(Denial {
            error: "server_error",
            description: "no code could be drawn",
        });
    };
    let grant = Code {
        client_id: client_id.clone(),
        redirect_uri: pending.redirect_uri.clone(),
        code_challenge: pending.code_challenge.clone(),
        audience: pending.audience.clone(),
        subject: subject.clone(),
        fhir_user: pending.fhir_user.clone(),
        scope: granted.join(" "),
        nonce: pending.nonce.clone(),
        auth_time,
        expires_at: now().saturating_add(CODE_SECONDS),
        upstream_session: pending.upstream_session.clone(),
    };
    if let Err(error) = state.store().issue_code(&hash, &grant).await {
        tracing::error!(error = %ferrohealth_server::run::chain(&error), "the code could not be stored");
        return back.deny(Denial {
            error: "server_error",
            description: "the code could not be stored",
        });
    }
    if remember
        && let Err(error) = state
            .store()
            .remember(subject, client_id, &grant.scope)
            .await
    {
        tracing::error!(error = %ferrohealth_server::run::chain(&error), "the consent could not be remembered");
    }
    tracing::info!(
        target: "ferrosmart::audit",
        event = "authorization.granted",
        client_id = %client_id,
        scope = %grant.scope,
        "an authorization code was issued"
    );
    back.grant(&code)
}

/// Returns the request a store lookup `looked` found, or the page that says
/// it lapsed or that the store failed.
fn found(
    state: &AppState,
    looked: Result<Option<Pending>, StoreError>,
) -> Result<Pending, Box<Response>> {
    match looked {
        Ok(Some(pending)) => Ok(pending),
        Ok(None) => Err(Box::new(pages::fault(state, Fault::Lapsed))),
        Err(error) => Err(Box::new(pages::server_error(state, &error))),
    }
}

/// Returns the browser's request once its person logged in, or the page
/// that says why there is none.
async fn logged_in(state: &AppState, headers: &HeaderMap) -> Result<Pending, Box<Response>> {
    let Some(id) = cookie(headers) else {
        return Err(Box::new(pages::fault(state, Fault::Lapsed)));
    };
    let pending = found(state, state.store().pending(&id).await)?;
    if pending.subject.is_some() && pending.purpose == Purpose::Authorize {
        Ok(pending)
    } else {
        Err(Box::new(pages::fault(state, Fault::Lapsed)))
    }
}

/// Where and how the browser goes back to the app.
#[derive(Debug, Clone)]
struct Back {
    /// The app's redirect URI.
    redirect_uri: String,
    /// The app's `state`.
    state: Option<String>,
    /// FerroSMART's issuer, sent as `iss` (RFC 9207 §2).
    issuer: String,
}

impl Back {
    /// Returns the way back for `pending`.
    fn of(state: &AppState, pending: &Pending) -> Self {
        Self {
            redirect_uri: pending.redirect_uri.clone(),
            state: Some(pending.state.clone()),
            issuer: state.settings().issuer.clone(),
        }
    }

    /// Sends the browser back with `denial` (RFC 6749 §4.1.2.1).
    fn deny(&self, denial: Denial) -> Response {
        self.send(&[
            ("error", denial.error),
            ("error_description", denial.description),
        ])
    }

    /// Sends the browser back with `code` (RFC 6749 §4.1.2).
    fn grant(&self, code: &str) -> Response {
        self.send(&[("code", code)])
    }

    /// Sends the browser back with `pairs`, the `state` and the `iss`.
    fn send(&self, pairs: &[(&str, &str)]) -> Response {
        let Ok(mut url) = Url::parse(&self.redirect_uri) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        {
            let mut query = url.query_pairs_mut();
            query.extend_pairs(pairs);
            if let Some(state) = &self.state {
                query.append_pair("state", state);
            }
            query.append_pair("iss", &self.issuer);
        }
        see_other(url.as_str())
    }
}

/// Ends `pending` before the browser is sent back, logging a failure: the
/// request lapses on its own then.
async fn forget(state: &AppState, pending: &Pending) {
    if let Err(error) = state.store().finish(&pending.id).await {
        tracing::warn!(error = %ferrohealth_server::run::chain(&error), "a pending authorization was not ended");
    }
}

/// Returns a `303 See Other` to `location`.
fn see_other(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    no_store(response)
}

/// Returns `response` uncacheable: an authorization response carries a code
/// (RFC 6749 §10.3; RFC 9700 §4.2).
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// Sets the request cookie to `value` for `max_age` seconds, scoped to the
/// issuer's path: `HttpOnly`, `Secure` and `SameSite=Lax`, which the
/// provider's redirect back still carries.
fn set_cookie(state: &AppState, response: &mut Response, value: &str, max_age: i64) {
    let path = state.settings().issuer_url.path();
    let cookie =
        format!("{COOKIE}={value}; Path={path}; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax");
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// Returns the request cookie's value.
fn cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .map(|(_, value)| value.to_owned())
        .filter(|value| !value.is_empty())
}

/// Returns whether `a` and `b` are equal, in time that depends only on
/// their lengths.
fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Returns 256 random bits, base64url: a code, a request id, a grant id or
/// a refresh token, each beyond guessing (RFC 6749 §10.10).
pub(crate) fn random() -> Result<String, aws_lc_rs::error::Unspecified> {
    let mut bytes = [0_u8; 32];
    aws_lc_rs::rand::fill(&mut bytes)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Returns the SHA-256 of `value`, base64url: how the store keeps a code.
#[must_use]
pub fn sha256(value: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        value.as_bytes(),
    ))
}

/// Returns the time now in seconds since the epoch.
fn now() -> i64 {
    jiff::Timestamp::now().as_second()
}

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
        upstream_session: None,
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
    match state.store().revoke_consent(subject, client_id).await {
        Ok(_) => {
            tracing::info!(target: "ferrosmart::audit", event = "consent.revoked", client_id = %client_id, "a remembered consent was revoked");
            see_other(&state.settings().endpoint(MANAGE_ROUTE))
        }
        Err(error) => pages::server_error(&state, &error),
    }
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
    let mut named = Vec::with_capacity(consents.len());
    for (client_id, scope) in consents {
        let name = match state.store().client(&client_id).await {
            Ok(Some(client)) => client.name,
            Ok(None) => client_id.clone(),
            Err(error) => return pages::server_error(state, &error),
        };
        named.push(pages::Remembered {
            client_id,
            name,
            scope,
        });
    }
    pages::manage(state, headers, pending, &named)
}
