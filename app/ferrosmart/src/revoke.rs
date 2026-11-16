// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The revocation endpoint (RFC 7009 §2).
//!
//! A confidential client authenticates by its `private_key_jwt` assertion,
//! a public client names itself by `client_id` (RFC 7009 §2.1, RFC 6749
//! §2.3); the token must have been issued to it. Revoking a refresh token
//! revokes its whole grant, every refresh and access token issued under it
//! ("the authorization server SHOULD also invalidate all access tokens
//! based on the same authorization grant", RFC 7009 §2.1); revoking an
//! access token revokes that token alone. An unknown, expired or already
//! revoked token answers `200` (RFC 7009 §2.2).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, StatusCode};

use crate::clients::{Client, ClientKind};
use crate::introspect::{Found, find};
use crate::server::AppState;
use crate::token::{Form, Refusal, authenticate, no_store, read_form, server_error};

/// `POST {issuer}/revoke`.
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match revoked(&state, &headers, &body).await {
        Ok(()) => no_store(StatusCode::OK.into_response()),
        Err(refusal) => {
            tracing::info!(
                target: "ferrosmart::audit",
                event = "revocation.refused",
                error = refusal.error,
                "a revocation request was refused"
            );
            refusal.into_response()
        }
    }
}

/// Revokes the token the request names, once its client is known and the
/// token is its own.
async fn revoked(state: &AppState, headers: &HeaderMap, body: &[u8]) -> Result<(), Refusal> {
    let form = read_form(headers, body)?;
    let client = client(state, &form).await?;
    let token = form
        .get("token")
        .ok_or(Refusal::request("the request carries no token"))?;
    // NOTE: RFC 7009 §2.1, a server MAY ignore token_type_hint; the value itself
    // tells an access token from a refresh token.
    let not_its_own = Refusal {
        error: "unauthorized_client",
        description: "the token was not issued to this client",
    };
    match find(state, token).await? {
        Some(Found::Access { jti, record }) => {
            if record.client_id != client.client_id {
                return Err(not_its_own);
            }
            let revoked = state
                .store()
                .revoke_access_token(&jti)
                .await
                .map_err(|error| server_error("the token cannot be revoked", &error))?;
            tracing::info!(
                target: "ferrosmart::audit",
                event = "token.revoked",
                client_id = %client.client_id,
                jti = %jti,
                revoked,
                "an access token was revoked"
            );
        }
        Some(Found::Refresh { record }) => {
            if record.grant.client_id != client.client_id {
                return Err(not_its_own);
            }
            let revoked = state
                .store()
                .revoke_grant(&record.grant.id)
                .await
                .map_err(|error| server_error("the grant cannot be revoked", &error))?;
            tracing::info!(
                target: "ferrosmart::audit",
                event = "grant.revoked",
                client_id = %client.client_id,
                grant = %record.grant.id,
                revoked,
                "a refresh token's grant was revoked"
            );
        }
        None => {}
    }
    Ok(())
}

/// Returns the client of the request: authenticated by its assertion, or a
/// registered public client named by `client_id`.
async fn client(state: &AppState, form: &Form) -> Result<Client, Refusal> {
    if form.get("client_assertion").is_some() || form.get("client_assertion_type").is_some() {
        return authenticate(state, form).await;
    }
    let client_id = form
        .get("client_id")
        .ok_or(Refusal::client("the request names no client"))?;
    match state.store().client(client_id).await {
        Ok(Some(client)) if client.kind == ClientKind::Public => Ok(client),
        Ok(_) => Err(Refusal::client(
            "the client is not a registered public client",
        )),
        Err(error) => Err(server_error("the client registry cannot be read", &error)),
    }
}
