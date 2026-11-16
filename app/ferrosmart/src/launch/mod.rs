// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The EHR launch API (`docs/architecture.md` §13.6 item 3).
//!
//! In an EHR launch the EHR hands the app "an opaque handle to the EHR
//! context", which the app passes back as `launch` at the authorization
//! endpoint, and "The server will provide the application with EHR context
//! based on this handle" (SMART App Launch 2.2.0, SMART authorization & FHIR
//! access: overview). SMART defines no way for the EHR to give the
//! authorization server that context, so the API is our own design, in two
//! forms that both bind a launch to the EHR, the app and the resource
//! server, and both last at most five minutes and redeem once:
//!
//! - `POST {issuer}/launch`, shaped as RFC 9126's pushed authorization
//!   request: a form the EHR client authenticates with its `private_key_jwt`
//!   assertion, as at the token endpoint, answered `201` with the opaque
//!   `launch` value and its `expires_in`. The value is 256 random bits,
//!   stored as its SHA-256.
//! - A launch JWT ([`signed`]) the EHR signs and hands the app as the
//!   `launch` value, which needs no call to FerroSMART first.

pub mod context;
pub mod signed;

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, StatusCode, header};
use serde::Serialize;
use serde_json::Value;

use crate::authorize::{random, sha256};
use crate::clients::{Client, GrantType};
use crate::form::Params;
use crate::launch::context::Context;
use crate::server::AppState;
use crate::store::StoreError;
use crate::store::launch::NewLaunch;
use crate::token::{Refusal, authenticate, no_store, server_error};

/// The route of the launch API under the issuer.
pub const LAUNCH_ROUTE: &str = "/launch";

/// The scope a client's ceiling lists to register or sign launches.
///
/// It is a SMART v2 `system/` scope with the `c` permission over the launch, our own name
/// (SMART App Launch 2.2.0, Scopes and Launch Context, Extensibility).
pub const LAUNCH_SCOPE: &str = "system/launch.c";

/// How long a launch lives: five minutes.
///
/// It is the bound SMART App Launch 2.2.0
/// sets a client assertion (Client Authentication: Asymmetric, Request). No
/// specification governs a launch's lifetime: our own design.
pub const MAX_LAUNCH_SECONDS: u64 = 300;

/// The parameters of a launch registration: the client authentication of
/// RFC 7521 §4.2, the app (`app_client_id`), the resource server (`resource`,
/// RFC 8707 §2) and the context parameters.
const PARAMETERS: [&str; 11] = [
    "client_assertion_type",
    "client_assertion",
    "app_client_id",
    "resource",
    "patient",
    "encounter",
    "fhirContext",
    "intent",
    "need_patient_banner",
    "tenant",
    "ehrId",
];

/// Why a launch value was not resolved.
#[derive(Debug, thiserror::Error)]
pub enum Unresolved {
    /// The request carries a `launch` and not the `launch` scope.
    #[error("a launch needs the launch scope")]
    NoLaunchScope,
    /// The value names no launch the request may redeem; the description
    /// quotes no value.
    #[error("{0}")]
    Refused(&'static str),
    /// The store failed.
    #[error("the launch store failed")]
    Store(#[from] StoreError),
}

/// A launch resolved at the authorization endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The EHR client that launched.
    pub ehr_client_id: String,
    /// The launch context.
    pub context: Context,
}

/// Redeems the `launch` an app `client_id` passed to the authorization
/// endpoint for `audience` with the requested `scope`, and returns its
/// context.
///
/// "If an app receives the URL parameter `launch=abc123`, then it requests
/// the scope `launch` and provides an additional URL parameter of
/// `launch=abc123`" (SMART App Launch 2.2.0, Scopes and Launch Context,
/// Apps that launch from the EHR), so a `launch` without the `launch` scope
/// is refused before the launch is touched.
///
/// # Errors
/// Returns [`Unresolved::NoLaunchScope`] without the `launch` scope, and
/// the errors of [`resolve`].
pub async fn redeem(
    state: &AppState,
    client_id: &str,
    launch: &str,
    audience: &str,
    scope: &str,
) -> Result<Context, Unresolved> {
    if !scope.split(' ').any(|requested| requested == "launch") {
        return Err(Unresolved::NoLaunchScope);
    }
    let resolved = resolve(state, launch, client_id, audience).await?;
    tracing::info!(
        target: "ferrosmart::audit",
        event = "launch.redeemed",
        client_id = %client_id,
        ehr = %resolved.ehr_client_id,
        "an app redeemed an EHR launch"
    );
    Ok(resolved.context)
}

/// Resolves and redeems the `launch` value an app passed to the authorization endpoint.
///
/// The launch is redeemed for `client_id` at the resource server
/// `audience`. A compact JWS is read as a launch JWT and its `jti` recorded, anything
/// else is looked up as a registered launch. A launch for another app or
/// server is refused and stays unredeemed.
///
/// # Errors
/// Returns [`Unresolved::Refused`] when the value is unknown, used, lapsed,
/// forged or bound to another app or server, and [`Unresolved::Store`]
/// when the store fails.
pub async fn resolve(
    state: &AppState,
    launch: &str,
    client_id: &str,
    audience: &str,
) -> Result<Resolved, Unresolved> {
    if launch.split('.').count() == 3 {
        let signed = signed::read(state, launch).await?;
        if signed.client_id != client_id || signed.audience != audience {
            return Err(Unresolved::Refused(
                "the launch is for another app or resource server",
            ));
        }
        let fresh = state
            .store()
            .first_use(&signed.ehr_client_id, &signed.jti, signed.expires_at)
            .await?;
        if !fresh {
            return Err(Unresolved::Refused("the launch was used before"));
        }
        return Ok(Resolved {
            ehr_client_id: signed.ehr_client_id,
            context: signed.context,
        });
    }
    let redeemed = state
        .store()
        .redeem_launch(&sha256(launch), client_id, audience)
        .await?
        .ok_or(Unresolved::Refused(
            "the launch is unknown, used, lapsed or for another app or resource server",
        ))?;
    Ok(Resolved {
        ehr_client_id: redeemed.ehr_client_id,
        context: redeemed.context,
    })
}

/// Returns the registered client `client_id` when it may launch
/// ([`signed::may_launch`]).
///
/// # Errors
/// Returns [`Unresolved::Store`] when the registry cannot be read.
pub async fn launching_ehr(
    state: &AppState,
    client_id: &str,
) -> Result<Option<Client>, Unresolved> {
    Ok(state
        .store()
        .client(client_id)
        .await?
        .filter(signed::may_launch))
}

/// The answer to a launch registration.
#[derive(Debug, Serialize)]
struct Registered {
    /// The opaque `launch` value.
    launch: String,
    /// Its lifetime in seconds.
    expires_in: u64,
}

/// `POST {issuer}/launch`.
pub async fn launch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match register(&state, &headers, &body).await {
        Ok((ehr, app, registered)) => {
            tracing::info!(
                target: "ferrosmart::audit",
                event = "launch.registered",
                client_id = %ehr,
                app = %app,
                "an EHR registered a launch"
            );
            // NOTE: RFC 9126 §2.2, the pushed request this API is shaped as is
            // answered 201 Created with its handle and lifetime.
            no_store((StatusCode::CREATED, Json(registered)).into_response())
        }
        Err(refusal) => {
            tracing::info!(
                target: "ferrosmart::audit",
                event = "launch.refused",
                error = refusal.error,
                "a launch registration was refused"
            );
            refusal.into_response()
        }
    }
}

/// Registers the launch `body` states, returning the EHR, the app and the
/// answer.
async fn register(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(String, String, Registered), Refusal> {
    let media = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    // NOTE: RFC 9126 §2.1, the request is application/x-www-form-urlencoded.
    if !media.is_some_and(|media| media.eq_ignore_ascii_case("application/x-www-form-urlencoded")) {
        return Err(refusal(
            "invalid_request",
            "the request is not form-encoded",
        ));
    }
    let form = Params::parse(body, &[])
        .map_err(|_repeated| refusal("invalid_request", "a parameter is repeated"))?;
    if url::form_urlencoded::parse(body).any(|(name, _)| !PARAMETERS.contains(&name.as_ref())) {
        return Err(refusal(
            "invalid_request",
            "a parameter is not a launch parameter",
        ));
    }
    let ehr = authenticate(state, &form).await?;
    if !signed::may_launch(&ehr) {
        return Err(refusal(
            "unauthorized_client",
            "the client may not register a launch",
        ));
    }
    let app = app(state, form.get("app_client_id")).await?;
    let audience = form
        .get("resource")
        .filter(|base| {
            state
                .settings()
                .resources
                .iter()
                .any(|served| served == base)
        })
        .ok_or(refusal(
            "invalid_target",
            "the resource is not served by this issuer",
        ))?;
    let context = form_context(&form)?;
    context
        .check(
            state
                .settings()
                .openehr_resources
                .iter()
                .any(|base| base == audience),
        )
        .map_err(|rule| refusal("invalid_request", rule))?;
    let value = random().map_err(|error| server_error("no launch value could be drawn", &error))?;
    let expires_at = jiff::Timestamp::now()
        .as_second()
        .saturating_add_unsigned(MAX_LAUNCH_SECONDS);
    state
        .store()
        .record_launch(&NewLaunch {
            launch_hash: &sha256(&value),
            ehr_client_id: &ehr.client_id,
            client_id: &app.client_id,
            audience,
            context: &context,
            expires_at,
        })
        .await
        .map_err(|error| server_error("the launch could not be recorded", &error))?;
    Ok((
        ehr.client_id,
        app.client_id,
        Registered {
            launch: value,
            expires_in: MAX_LAUNCH_SECONDS,
        },
    ))
}

/// Returns the registered app `client_id` names: a client of the
/// authorization code grant, the one an EHR launch continues in.
async fn app(state: &AppState, client_id: Option<&str>) -> Result<Client, Refusal> {
    let client_id = client_id.ok_or(refusal(
        "invalid_request",
        "the request names no app_client_id",
    ))?;
    state
        .store()
        .client(client_id)
        .await
        .map_err(|error| server_error("the client registry cannot be read", &error))?
        .filter(|app| app.grant_types.contains(&GrantType::AuthorizationCode))
        .ok_or(refusal(
            "invalid_request",
            "the app_client_id names no app of the authorization code grant",
        ))
}

/// Returns the context the form `form` states: `fhirContext` as the JSON
/// array the token response carries (the form RFC 9396 §3 gives a JSON
/// parameter), `need_patient_banner` as `true` or `false`.
fn form_context(form: &Params) -> Result<Context, Refusal> {
    let text = |name: &str| form.get(name).map(str::to_owned);
    let fhir_context = form
        .get("fhirContext")
        .map(serde_json::from_str::<Vec<Value>>)
        .transpose()
        .map_err(|_unread| refusal("invalid_request", "the fhirContext is no JSON array"))?
        .unwrap_or_default();
    let need_patient_banner = match form.get("need_patient_banner") {
        None => None,
        Some("true") => Some(true),
        Some("false") => Some(false),
        Some(_) => {
            return Err(refusal(
                "invalid_request",
                "the need_patient_banner is not true or false",
            ));
        }
    };
    Ok(Context {
        patient: text("patient"),
        encounter: text("encounter"),
        fhir_context,
        intent: text("intent"),
        need_patient_banner,
        tenant: text("tenant"),
        ehr_id: text("ehrId"),
    })
}

/// Returns the refusal `error` described by `description`.
const fn refusal(error: &'static str, description: &'static str) -> Refusal {
    Refusal { error, description }
}
