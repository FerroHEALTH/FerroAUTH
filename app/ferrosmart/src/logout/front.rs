// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The front-channel logout URI FerroSMART registers at its upstream
//! provider (OpenID Connect Front-Channel Logout 1.0 §2).
//!
//! The provider renders the URI in an iframe when a person's login there
//! ends, with its `iss` and the login's `sid` as query parameters. A
//! provider such as Microsoft Entra ID offers this channel alone. FerroSMART
//! keeps no browser session of its own, so the `sid` is what names the
//! login: the provider registers the URI with
//! `frontchannel_logout_session_required`, and a request without both
//! parameters, or from another issuer, ends nothing. The sessions the `sid`
//! names end as a back-channel logout ends them, with their
//! `online_access` grants.

use std::net::IpAddr;
use std::sync::Arc;

use crate::upstream::LoginProvider;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use serde::Deserialize;

use crate::audit::Connected;
use crate::server::AppState;

/// The front-channel logout URI's route under the issuer.
pub const FRONTCHANNEL_LOGOUT_ROUTE: &str = "/frontchannel-logout";

/// The query the provider renders the URI with (Front-Channel Logout 1.0
/// §2: "if either is included, both MUST be").
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct FrontChannel {
    /// The provider's issuer identifier.
    iss: Option<String>,
    /// The provider's session id of the login.
    sid: Option<String>,
}

/// `GET {issuer}/frontchannel-logout`.
pub async fn frontchannel_logout(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    Query(query): Query<FrontChannel>,
) -> Response {
    let status = match logged_out(&state, &query, from).await {
        Ok(()) => StatusCode::OK,
        Err(refused) => {
            tracing::info!(
                target: "ferrosmart::audit",
                event = "logout.refused",
                channel = "front",
                error = refused,
                "a front-channel logout was refused"
            );
            StatusCode::BAD_REQUEST
        }
    };
    let provider = query
        .iss
        .as_deref()
        .and_then(|issuer| state.providers().by_issuer(issuer));
    framed(provider, status)
}

/// Ends the sessions the request names, or says why not.
async fn logged_out(
    state: &AppState,
    query: &FrontChannel,
    from: IpAddr,
) -> Result<(), &'static str> {
    let (Some(issuer), Some(sid)) = (query.iss.as_deref(), query.sid.as_deref()) else {
        return Err("the request does not carry both iss and sid");
    };
    // NOTE: Front-Channel Logout 1.0 §2, the RP MAY check iss and sid; a logout
    // from an issuer no provider has is ignored.
    if state.providers().by_issuer(issuer).is_none() || sid.is_empty() {
        return Err("the request names no configured issuer or no session");
    }
    super::end_sessions(
        state,
        super::Ended {
            issuer,
            subject: None,
            sid: Some(sid),
            route: FRONTCHANNEL_LOGOUT_ROUTE,
            channel: "front",
        },
        from,
    )
    .await
}

/// Returns the empty document the provider's iframe renders: never cached
/// (Front-Channel Logout 1.0 §2, `Cache-Control: no-store`) and framed by
/// the provider's own origins alone, where every other page refuses any
/// frame (RFC 9700 §4.16).
fn framed(provider: Option<&LoginProvider>, status: StatusCode) -> Response {
    let ancestors = provider.map(LoginProvider::origins).unwrap_or_default();
    let ancestors = if ancestors.is_empty() {
        String::from("'none'")
    } else {
        ancestors.join(" ")
    };
    let mut response = (
        status,
        axum::response::Html("<!doctype html><html lang=\"en\"><title>Logout</title></html>"),
    )
        .into_response();
    let policy = format!("default-src 'none'; frame-ancestors {ancestors}; base-uri 'none'");
    crate::pages::page_headers(response.headers_mut(), &policy);
    response
}
