// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The refresh of a session's access token before it expires (RFC 6749 §6).
//!
//! A session of the memory store that holds a refresh token outlives its
//! access token; a request that finds the token within [`MARGIN`] of its
//! expiry renews it first. One refresh per session runs at a time, so a
//! refresh token the provider rotates is never spent twice. No specification
//! governs when to refresh: our own design.

use std::fmt;
use std::time::Duration;

use ferrohealth_smart::oidc::{OidcError, RelyingParty};
use http::HeaderMap;

use crate::lifetime::seconds;
use crate::record::Record;
use crate::sessions::{SessionError, Sessions};

/// How long before its expiry an access token is renewed, at most half its
/// lifetime.
pub const MARGIN: Duration = Duration::from_secs(60);

/// What [`Sessions::keep_fresh`] did.
#[non_exhaustive]
pub enum Freshness {
    /// Nothing was due: no session, no refresh token, or a token not near
    /// its expiry.
    Current,
    /// The access token was renewed.
    Refreshed,
    /// The provider refused the refresh, so the session is ended.
    Ended(OidcError),
    /// The provider could not be reached or answered no token; the session
    /// keeps its access token until it expires, and the next request tries
    /// again.
    Unreached(OidcError),
}

impl fmt::Debug for Freshness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Current => f.write_str("Current"),
            Self::Refreshed => f.write_str("Refreshed"),
            Self::Ended(error) => f.debug_tuple("Ended").field(error).finish(),
            Self::Unreached(error) => f.debug_tuple("Unreached").field(error).finish(),
        }
    }
}

/// Whether `record`'s access token is due for renewal at `now`.
fn due(record: &Record, now: i64) -> bool {
    let margin = record.lifetime.map_or(seconds(MARGIN), |lifetime| {
        seconds(MARGIN).min(i64::try_from(lifetime.div_euclid(2)).unwrap_or(i64::MAX))
    });
    record.refresh_token.is_some()
        && record
            .expires
            .is_some_and(|expires| expires.saturating_sub(now) <= margin)
}

impl Sessions {
    /// Renews the access token of the request's session at `party` when it
    /// is due.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Poisoned`] for an unusable memory store. A
    /// provider's refusal or failure is a [`Freshness`], never an error.
    pub async fn keep_fresh(
        &self,
        party: &RelyingParty,
        headers: &HeaderMap,
    ) -> Result<Freshness, SessionError> {
        let (Some(memory), Some(id)) = (self.memory(), self.session_id(headers)) else {
            return Ok(Freshness::Current);
        };
        let now = self.now();
        let gate = memory.with(
            &id,
            |record| self.live_at(record),
            |entry| due(&entry.record, now).then(|| std::sync::Arc::clone(&entry.gate)),
        )?;
        let Some(gate) = gate.flatten() else {
            return Ok(Freshness::Current);
        };
        let _refreshing = gate.lock().await;
        let now = self.now();
        let grant = memory.with(
            &id,
            |record| self.live_at(record),
            |entry| {
                due(&entry.record, now)
                    .then(|| entry.record.refresh_token.clone())
                    .flatten()
            },
        )?;
        let Some(refresh_token) = grant.flatten() else {
            return Ok(Freshness::Current);
        };
        match party.refresh(&refresh_token).await {
            Ok(refreshed) => {
                let now = self.now();
                memory.with(
                    &id,
                    |record| self.live_at(record),
                    |entry| {
                        let record = &mut entry.record;
                        record.credential =
                            crate::record::Credential::Bearer(refreshed.access_token);
                        record.expires = refreshed
                            .expires_in
                            .map(|lifetime| now.saturating_add(seconds(lifetime)));
                        record.lifetime = refreshed.expires_in.map(|lifetime| lifetime.as_secs());
                        if let Some(rotated) = refreshed.refresh_token {
                            record.refresh_token = Some(rotated);
                        }
                        if let Some(scopes) = refreshed.scopes {
                            record.scopes = scopes;
                        }
                    },
                )?;
                Ok(Freshness::Refreshed)
            }
            Err(error) if error.is_answered_refusal() => {
                memory.end(&id)?;
                Ok(Freshness::Ended(error))
            }
            Err(error) => Ok(Freshness::Unreached(error)),
        }
    }
}
