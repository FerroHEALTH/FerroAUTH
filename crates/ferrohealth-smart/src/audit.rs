// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The one audit line of a request.
//!
//! It names who called (the principal, the client, the scheme and the
//! issuer), what was asked (the method, the matched route, what was
//! addressed and the interaction) and how it ended (the status and the duration). It
//! never carries the token, a claim beyond those three, a scope, a query
//! string, a header or a body. No specification governs the line: our own
//! design, shaped so it can serve as the access record the products keep
//! under Regulation (EU) 2025/327 Annex II 3.2(b). It is written through
//! `tracing` under [`AUDIT_TARGET`], so a deployment routes it apart from
//! the application log, and its field set is fixed, so every product's
//! record reads the same.

use std::time::Duration;

use http::Method;
use http::StatusCode;

use crate::resource::Access;
use crate::resource::Via;

/// The audit line's `tracing` target.
///
/// No field of the line is named `target`, `level` or after any other key a
/// `tracing` formatter writes from the event's metadata, so a JSON log that
/// flattens the fields keeps every one of them.
pub const AUDIT_TARGET: &str = "ferrohealth_smart::audit";

/// The longest the logged `addressed` value may be.
pub const MAX_ADDRESSED_LENGTH: usize = 64;

/// Who a line records as the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor<'a> {
    /// The surface is open: no credential was asked.
    Open,
    /// The request carried no valid credential.
    Unauthenticated,
    /// A caller with a valid credential.
    Caller {
        /// The principal: the token's `sub` or the Basic user-id.
        principal: &'a str,
        /// The client, when the credential names one.
        client: Option<&'a str>,
        /// The scheme the credential arrived with.
        via: Via,
        /// The issuer that signed the token, when one did.
        issuer: Option<&'a str>,
    },
}

impl<'a> Actor<'a> {
    /// Returns the actor `access` records, `Unauthenticated` for `None`.
    #[must_use]
    pub fn of(access: Option<&'a Access>) -> Self {
        match access {
            None => Self::Unauthenticated,
            Some(Access::Open) => Self::Open,
            Some(Access::Caller(caller)) => Self::Caller {
                principal: caller.subject(),
                client: caller.client_id(),
                via: caller.via(),
                issuer: caller.issuer(),
            },
        }
    }
}

/// Everything one audit line records.
#[derive(Debug, Clone)]
pub struct AuditLine<'a> {
    /// When the request arrived.
    at: jiff::Timestamp,
    /// How long it took.
    duration: Duration,
    /// Who called.
    actor: Actor<'a>,
    /// The method.
    method: &'a Method,
    /// The matched route template, never the raw path.
    route: Option<&'a str>,
    /// The product's name for what was addressed.
    addressed: Option<&'a str>,
    /// The interaction, by the name the product records (the FHIR R4
    /// restful interaction codes on a FHIR surface, an ITS-REST operation id
    /// on an openEHR surface).
    interaction: &'a str,
    /// The status answered.
    status: StatusCode,
    /// The request id.
    request_id: Option<&'a str>,
    /// The position of the batch entry the line records, `None` for a
    /// request.
    entry: Option<usize>,
}

impl<'a> AuditLine<'a> {
    /// Returns a line for `method` answered `status`, as `interaction`.
    #[must_use]
    pub fn new(method: &'a Method, interaction: &'a str, status: StatusCode) -> Self {
        Self {
            at: jiff::Timestamp::now(),
            duration: Duration::ZERO,
            actor: Actor::Unauthenticated,
            method,
            route: None,
            addressed: None,
            interaction,
            status,
            request_id: None,
            entry: None,
        }
    }

    /// Returns this line arrived `at`, lasting `duration`.
    #[must_use]
    pub const fn timed(mut self, at: jiff::Timestamp, duration: Duration) -> Self {
        self.at = at;
        self.duration = duration;
        self
    }

    /// Returns this line recording `actor`.
    #[must_use]
    pub const fn by(mut self, actor: Actor<'a>) -> Self {
        self.actor = actor;
        self
    }

    /// Returns this line naming the matched `route` template and what was
    /// `addressed`.
    #[must_use]
    pub const fn on(mut self, route: Option<&'a str>, addressed: Option<&'a str>) -> Self {
        self.route = route;
        self.addressed = addressed;
        self
    }

    /// Returns this line under `request_id`.
    #[must_use]
    pub const fn request(mut self, request_id: Option<&'a str>) -> Self {
        self.request_id = request_id;
        self
    }

    /// Returns this line as the record of the batch entry at `position`.
    #[must_use]
    pub const fn entry(mut self, position: usize) -> Self {
        self.entry = Some(position);
        self
    }

    /// Writes the line under [`AUDIT_TARGET`].
    pub fn write(&self) {
        let (principal, client, via, issuer) = match self.actor {
            Actor::Caller {
                principal,
                client,
                via,
                issuer,
            } => (
                principal,
                client.unwrap_or("-"),
                via.name(),
                issuer.unwrap_or("-"),
            ),
            Actor::Open => ("-", "-", "open", "-"),
            Actor::Unauthenticated => ("unauthenticated", "-", "none", "-"),
        };
        let addressed: String = self
            .addressed
            .unwrap_or("-")
            .chars()
            .take(MAX_ADDRESSED_LENGTH)
            .collect();
        let at = self.at.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let duration_ms = self.duration.as_secs_f64() * 1000.0;
        if let Some(position) = self.entry {
            tracing::info!(
                target: AUDIT_TARGET,
                at,
                request_id = self.request_id.unwrap_or("-"),
                principal,
                client,
                via,
                issuer,
                method = self.method.as_str(),
                route = self.route.unwrap_or("-"),
                addressed,
                interaction = self.interaction,
                status = self.status.as_u16(),
                duration_ms,
                entry = position,
                "audit"
            );
            return;
        }
        tracing::info!(
            target: AUDIT_TARGET,
            at,
            request_id = self.request_id.unwrap_or("-"),
            principal,
            client,
            via,
            issuer,
            method = self.method.as_str(),
            route = self.route.unwrap_or("-"),
            addressed,
            interaction = self.interaction,
            status = self.status.as_u16(),
            duration_ms,
            "audit"
        );
    }
}
