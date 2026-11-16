// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The back-channel logout URI FerroSMART registers at its upstream
//! provider (OpenID Connect Back-Channel Logout 1.0 §2.5).
//!
//! The provider posts a Logout Token when a person's login there ends. Once
//! the token checks (§2.6, through `ferrohealth_smart::oidc`), the sessions
//! it names end, and with them the `online_access` grants they carry
//! ("Refresh tokens issued without the `offline_access` property to a session
//! being logged out SHOULD be revoked", §2.7; `docs/architecture.md` §13.6
//! item 7). An `offline_access` grant outlives the login (§2.7, "SHOULD NOT
//! be revoked"). Logging out twice ends nothing more, so a token posted
//! again is answered as the first was: the optional `jti` check of §2.6 is
//! not made.

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, StatusCode};
use serde_json::json;

use crate::server::AppState;
use crate::token::{no_store, read_form};

/// The back-channel logout URI's route under the issuer.
pub const BACKCHANNEL_LOGOUT_ROUTE: &str = "/backchannel-logout";

/// `POST {issuer}/backchannel-logout`.
pub async fn backchannel_logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match logged_out(&state, &headers, &body).await {
        Ok(()) => no_store(StatusCode::OK.into_response()),
        Err(refused) => {
            tracing::info!(
                target: "ferrosmart::audit",
                event = "logout.refused",
                error = refused,
                "a back-channel logout was refused"
            );
            // NOTE: Back-Channel Logout 1.0 §2.8, a 400 with an OAuth 2.0 error body.
            let body = json!({ "error": "invalid_request", "error_description": refused });
            no_store((StatusCode::BAD_REQUEST, Json(body)).into_response())
        }
    }
}

/// Ends the sessions the request's Logout Token names, or says why not.
async fn logged_out(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), &'static str> {
    let form = read_form(headers, body).map_err(|refusal| refusal.description)?;
    let token = form
        .get("logout_token")
        .ok_or("the request carries no logout_token")?;
    let party = state
        .relying_party()
        .ok_or("no upstream provider is configured")?;
    let claims = party.logout_token(token).await.map_err(|error| {
        tracing::info!(error = %ferrohealth_server::run::chain(&error), "a Logout Token was refused");
        "the logout_token does not verify"
    })?;
    let ended = state
        .store()
        .log_out(
            &claims.issuer,
            claims.subject.as_deref(),
            claims.session.as_deref(),
        )
        .await
        .map_err(|error| {
            tracing::error!(error = %ferrohealth_server::run::chain(&error), "the logout could not be recorded");
            "the logout could not be recorded"
        })?;
    tracing::info!(
        target: "ferrosmart::audit",
        event = "logout",
        issuer = %claims.issuer,
        sessions = ended,
        "the upstream provider ended a login"
    );
    Ok(())
}
