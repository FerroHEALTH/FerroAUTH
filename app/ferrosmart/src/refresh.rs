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

use serde_json::{Map, Value};

use crate::authorize::{random, sha256};
use crate::clients::{Client, GrantType};
use crate::form::Params;
use crate::server::AppState;
use crate::store::Code;
use crate::store::grant::{Access, IdleUntil, NewGrant, Rotation};
use crate::token::{Grant, Issued, Refusal, identify, mint, server_error};

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
pub(crate) async fn refresh(state: &AppState, form: &Params) -> Result<Issued, Refusal> {
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
        random().map_err(|error| server_error("no refresh token could be drawn", &error))?;
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
    let context = match &grant.context {
        Value::Object(members) => members.clone(),
        _ => Map::new(),
    };
    let fhir_user = grant
        .fhir_user
        .as_deref()
        .filter(|_| holds(&scope, "fhirUser"));
    let mut issued = mint(
        state,
        &client,
        Grant {
            subject: &grant.subject,
            audience: &grant.audience,
            scope: &scope,
            fhir_user,
            code_hash: None,
            token_type: "bearer",
            identity: None,
            under: Some(&grant.id),
            context: &context,
        },
    )
    .await?;
    tracing::info!(
        target: "ferrosmart::audit",
        event = "refresh.rotated",
        client_id = %client.client_id,
        grant = %grant.id,
        "a refresh token was rotated"
    );
    // NOTE: SMART App Launch 2.2.0, Refresh access token, Response: the launch
    // context MAY be included, and is, as the original response carried it.
    issued.response.refresh_token = Some(successor);
    Ok(issued)
}

/// What redeeming a code opens: the grant every token of the launch is
/// issued under, the launch context the responses carry, and the first
/// refresh token when the grant has one.
#[derive(Debug)]
pub(crate) struct Opened {
    /// The grant's id.
    pub(crate) grant_id: String,
    /// The launch context parameters.
    pub(crate) context: Map<String, Value>,
    /// The first refresh token.
    pub(crate) refresh_token: Option<String>,
}

/// Records the grant the code `code` opens for `client`, with its first
/// refresh token when the person granted `offline_access` or
/// `online_access` and the client registered the `refresh_token` grant.
///
/// `offline_access` wins over `online_access` when both are granted; an
/// `online_access` grant needs the upstream session the person logged in
/// under, and gets no refresh token without one (`docs/architecture.md`
/// §13.6 item 7).
pub(crate) async fn open(
    state: &AppState,
    client: &Client,
    code: &Code,
) -> Result<Opened, Refusal> {
    let settings = state.settings();
    let mut context = Map::new();
    if !settings.branding.smart_style_url.is_empty() {
        context.insert(
            String::from("smart_style_url"),
            Value::String(settings.branding.smart_style_url.clone()),
        );
    }
    let refreshes = client.grant_types.contains(&GrantType::RefreshToken);
    let access = if !refreshes {
        None
    } else if holds(&code.scope, "offline_access") {
        Some(Access::Offline)
    } else if holds(&code.scope, "online_access") && code.upstream_session.is_some() {
        Some(Access::Online)
    } else {
        None
    };
    let grant_id = random().map_err(|error| server_error("no grant id could be drawn", &error))?;
    let context_value = Value::Object(context.clone());
    state
        .store()
        .create_grant(&NewGrant {
            id: &grant_id,
            client_id: &client.client_id,
            subject: &code.subject,
            fhir_user: code
                .fhir_user
                .as_deref()
                .filter(|_| holds(&code.scope, "fhirUser")),
            audience: &code.audience,
            scope: &code.scope,
            context: &context_value,
            auth_time: Some(code.auth_time),
            access,
            upstream_session: code
                .upstream_session
                .as_deref()
                .filter(|_| access == Some(Access::Online)),
        })
        .await
        .map_err(|error| server_error("the grant could not be recorded", &error))?;
    let refresh_token = match access {
        Some(access) => {
            let value = random()
                .map_err(|error| server_error("no refresh token could be drawn", &error))?;
            let idle = match access {
                Access::Offline => settings.refresh_idle,
                Access::Online => settings.online_idle,
            };
            let expires = jiff::Timestamp::now()
                .as_second()
                .saturating_add_unsigned(idle.as_secs());
            state
                .store()
                .issue_refresh(&sha256(&value), &grant_id, expires)
                .await
                .map_err(|error| server_error("the refresh token could not be recorded", &error))?;
            Some(value)
        }
        None => None,
    };
    tracing::info!(
        target: "ferrosmart::audit",
        event = "grant.opened",
        client_id = %client.client_id,
        grant = %grant_id,
        access = access.map_or("none", Access::as_str),
        "a grant was opened"
    );
    Ok(Opened {
        grant_id,
        context,
        refresh_token,
    })
}

/// Returns whether the space-separated `scope` holds `wanted`.
fn holds(scope: &str, wanted: &str) -> bool {
    scope.split(' ').any(|held| held == wanted)
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
