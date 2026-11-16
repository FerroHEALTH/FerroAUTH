// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The refresh token grant (RFC 6749 §6; SMART App Launch 2.2.0, Refresh
//! access token).
//!
//! Every refresh rotates the token: the one presented is used up and a new
//! one issued under the same grant, with the grant's whole scope (OAuth 2.1
//! draft §4.3.3). A token presented again after its rotation revokes the
//! grant with every token under it, which is the replay detection RFC 9700
//! §4.14.2 requires for public clients and FerroSMART applies to every
//! client. A refresh token lapses after its idle time, `refresh_idle` for
//! `offline_access` and `online_access`'s shorter `online_idle`, and an
//! `online_access` one with the person's upstream login
//! (`docs/architecture.md` §13.6 item 7).

use serde_json::Value;

use crate::clients::GrantType;
use crate::introspect::sha256;
use crate::server::AppState;
use crate::store::grant::{IdleUntil, Rotation};
use crate::token::{Form, Issued, Refusal, identify, mint, server_error};

/// The `invalid_grant` refusal: "The provided authorization grant ... or
/// refresh token is invalid, expired, revoked, ... or was issued to another
/// client" (RFC 6749 §5.2).
const fn invalid(description: &'static str) -> Refusal {
    Refusal {
        error: "invalid_grant",
        description,
    }
}

/// Answers a refresh token request.
pub(crate) async fn refresh(state: &AppState, form: &Form) -> Result<Issued, Refusal> {
    let client = identify(state, form).await?;
    if !client.grant_types.contains(&GrantType::RefreshToken) {
        return Err(Refusal {
            error: "unauthorized_client",
            description: "the client may not use this grant",
        });
    }
    let presented = form
        .get("refresh_token")
        .ok_or(Refusal::request("the request carries no refresh_token"))?;
    let hash = sha256(presented);
    // NOTE: SMART App Launch 2.2.0, Refresh access token, Request: a scope names no
    // permission the grant lacks; it is checked before the token is used up.
    let granted = state
        .store()
        .refresh_token(&hash)
        .await
        .map_err(|error| server_error("the refresh token cannot be read", &error))?
        .filter(|record| record.grant.client_id == client.client_id)
        .map(|record| record.grant.scope);
    let scope = match (&granted, form.get("scope")) {
        (Some(granted), Some(requested)) => narrowed(granted, requested)?,
        (Some(granted), None) => granted.clone(),
        (None, _) => String::new(),
    };
    let successor =
        random_secret().map_err(|error| server_error("no refresh token could be drawn", &error))?;
    let settings = state.settings();
    let now = jiff::Timestamp::now().as_second();
    let idle = IdleUntil {
        offline: now.saturating_add_unsigned(settings.refresh_idle.as_secs()),
        online: now.saturating_add_unsigned(settings.online_idle.as_secs()),
    };
    let rotation = state
        .store()
        .rotate(&hash, &client.client_id, &sha256(&successor), idle)
        .await
        .map_err(|error| server_error("the refresh token cannot be redeemed", &error))?;
    let grant = match rotation {
        Rotation::Rotated(grant) => grant,
        Rotation::Reused { grant_id } => {
            tracing::warn!(
                target: "ferrosmart::audit",
                event = "refresh.reused",
                client_id = %client.client_id,
                grant = %grant_id,
                "a rotated refresh token was presented again; its grant is revoked"
            );
            return Err(invalid("the refresh token was used before"));
        }
        Rotation::OtherClient | Rotation::Invalid => {
            return Err(invalid("the refresh token is not valid"));
        }
    };
    let mut issued = mint(
        state,
        &client,
        &grant.subject,
        &grant.audience,
        &scope,
        Some(&grant.id),
    )
    .await?;
    tracing::info!(
        target: "ferrosmart::audit",
        event = "refresh.rotated",
        client_id = %client.client_id,
        grant = %grant.id,
        "a refresh token was rotated"
    );
    issued.response.refresh_token = Some(successor);
    // NOTE: SMART App Launch 2.2.0, Refresh access token, Response: the launch
    // context MAY be included, and is, as the original response carried it.
    if let Value::Object(context) = grant.context {
        issued.response.context = context;
    }
    Ok(issued)
}

/// Returns the scopes of `requested` the grant's `granted` scope holds, in
/// the grant's order, refusing a request that names any other ("no new
/// permissions can be obtained at refresh time", SMART App Launch 2.2.0,
/// Refresh access token, Request; "MUST NOT include any scope not
/// originally granted", OAuth 2.1 draft §4.3.1).
fn narrowed(granted: &str, requested: &str) -> Result<String, Refusal> {
    let requested: Vec<&str> = requested.split(' ').filter(|s| !s.is_empty()).collect();
    let held: Vec<&str> = granted.split(' ').filter(|s| !s.is_empty()).collect();
    if requested.is_empty() || requested.iter().any(|scope| !held.contains(scope)) {
        return Err(Refusal {
            error: "invalid_scope",
            description: "the scope names a permission the grant does not hold",
        });
    }
    Ok(held
        .into_iter()
        .filter(|scope| requested.contains(scope))
        .collect::<Vec<_>>()
        .join(" "))
}

/// Returns the value of a new refresh token: 256 random bits, base64url.
///
/// RFC 6749 §10.10 has the chance of guessing it at most 2^(-128) and
/// "SHOULD be less than or equal to 2^(-160)".
///
/// # Errors
/// Returns the random source's error when it draws nothing.
pub fn random_secret() -> Result<String, aws_lc_rs::error::Unspecified> {
    use base64::Engine as _;
    let mut bytes = [0_u8; 32];
    aws_lc_rs::rand::fill(&mut bytes)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}
