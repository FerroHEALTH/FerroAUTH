// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The session store every request of a console shares.
//!
//! [`Sessions`] keeps the pending sign-ins between `GET /login` and the
//! provider's redirect back, and the sessions once a sign-in completes, in
//! the store `[session] store` names. Every method reads the request's
//! cookies and answers the `Set-Cookie` values its response must carry, so a
//! console handles both stores alike.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use ferrohealth_secret::secret::Secret;
use ferrohealth_smart::oidc::PendingSignIn;
use ferrohealth_ui::view::session::Left;
use http::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};

use crate::clock::Clock;
use crate::config::{SessionSettings, Storage};
use crate::cookies::{CookieNames, Jar, header};
use crate::lifetime::seconds;
use crate::record::{Ended, Held, Record, Sealed, SignedIn};
use crate::return_path::ReturnPath;
use crate::store::{COOKIE_LIMIT, Id, Memory, open, seal};

/// Why a sign-in or a session could not be begun, read or ended.
///
/// No variant carries a token, a key or an id.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    /// The system random source failed.
    #[error("the system random source failed")]
    Random,
    /// The memory store holds as many sessions as it may.
    #[error("the session pool is full")]
    Full,
    /// A thread panicked while it held the memory store.
    #[error("the session store is unusable after a panic")]
    Poisoned,
    /// A sealed payload could not be written.
    #[error("the session could not be sealed")]
    Seal(#[source] serde_json::Error),
    /// The private jar sealed nothing.
    #[error("the session cookie was not sealed")]
    Unsealed,
    /// A sealed cookie is larger than a browser keeps (RFC 6265 §6.1).
    #[error(
        "the sealed session cookie takes {found} bytes, more than the {COOKIE_LIMIT} a browser keeps"
    )]
    TooLarge {
        /// Its size in bytes.
        found: usize,
    },
    /// A cookie could not be written as a header value.
    #[error("a cookie could not be written as a header")]
    Header,
}

/// A pending sign-in: what the callback checks the provider's redirect
/// against, and the page to come back to.
pub struct Pending {
    /// The `state`, the `nonce` and the PKCE verifier.
    pub sign_in: PendingSignIn,
    /// The page the operator comes back to; `None` leads to the console's
    /// home.
    pub back: Option<ReturnPath>,
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field("back", &self.back)
            .finish_non_exhaustive()
    }
}

/// How many entries each pool of a memory store holds, expired ones not
/// yet dropped included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Occupancy {
    /// Pending sign-ins.
    pub sign_ins: usize,
    /// Sessions.
    pub sessions: usize,
}

/// An answer with the `Set-Cookie` values its response must carry.
#[derive(Debug)]
pub struct WithCookies<T> {
    /// The answer.
    pub value: T,
    /// The `Set-Cookie` values, in order.
    pub cookies: Vec<HeaderValue>,
}

impl<T> WithCookies<T> {
    fn new(value: T, cookies: Vec<HeaderValue>) -> Self {
        Self { value, cookies }
    }
}

/// A pending sign-in as a sealed cookie carries it.
#[derive(Serialize, Deserialize)]
struct SealedPending {
    state: String,
    nonce: String,
    verifier: String,
    back: Option<String>,
    created: i64,
}

/// Where the sessions are kept.
#[derive(Clone)]
enum Backend {
    Memory(Memory),
    Sealed(cookie::Key),
}

/// The store and what it is configured with.
struct Inner {
    settings: SessionSettings,
    jar: Jar,
    clock: Clock,
    backend: Backend,
}

/// The session store, shared by every request; cloning it shares it.
#[derive(Clone)]
pub struct Sessions {
    inner: Arc<Inner>,
}

impl fmt::Debug for Sessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sessions")
            .field("settings", &self.inner.settings)
            .field("names", &self.inner.jar.names)
            .finish_non_exhaustive()
    }
}

impl Sessions {
    /// An empty store under `settings`, with the cookie names `names`.
    #[must_use]
    pub fn new(settings: SessionSettings, names: CookieNames) -> Self {
        Self::with_clock(settings, names, Clock::System)
    }

    pub(crate) fn with_clock(settings: SessionSettings, names: CookieNames, clock: Clock) -> Self {
        let backend = match &settings.storage {
            Storage::Memory {
                max_sign_ins,
                max_sessions,
            } => Backend::Memory(Memory::new(*max_sign_ins, *max_sessions)),
            Storage::Sealed(key) => Backend::Sealed(key.clone()),
        };
        let jar = Jar {
            names,
            secure: settings.secure_cookie,
        };
        Self {
            inner: Arc::new(Inner {
                settings,
                jar,
                clock,
                backend,
            }),
        }
    }

    /// The checked `[session]` the store runs under.
    #[must_use]
    pub fn settings(&self) -> &SessionSettings {
        &self.inner.settings
    }

    fn now(&self) -> i64 {
        self.inner.clock.now()
    }

    fn timeout(&self) -> i64 {
        seconds(self.inner.settings.sign_in_timeout)
    }

    fn jar(&self) -> &Jar {
        &self.inner.jar
    }

    fn live(&self, record: &Record, now: i64) -> bool {
        self.inner
            .settings
            .lifetimes
            .left(record.times(), now)
            .is_some()
    }

    /// Keeps `sign_in`, begun now, and answers the cookie that names it,
    /// which expires with the sign-in.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Random`] when no id could be minted,
    /// [`SessionError::Poisoned`] for an unusable memory store, and the
    /// sealing errors of a sealed store.
    pub fn begin(
        &self,
        sign_in: PendingSignIn,
        back: Option<ReturnPath>,
    ) -> Result<HeaderValue, SessionError> {
        let now = self.now();
        let name = self.jar().names.sign_in();
        let value = match &self.inner.backend {
            Backend::Memory(memory) => {
                let id = memory.begin(Pending { sign_in, back }, now, self.timeout())?;
                id.as_str().to_owned()
            }
            Backend::Sealed(key) => {
                let pending = SealedPending {
                    state: sign_in.state().to_owned(),
                    nonce: sign_in.nonce().to_owned(),
                    verifier: sign_in.verifier().expose().to_owned(),
                    back: back.map(|back| back.as_str().to_owned()),
                    created: now,
                };
                seal(key, &self.jar().name(&name), &pending)?
            }
        };
        self.set(&name, value, Some(self.timeout()))
    }

    /// Takes the pending sign-in the request's cookie names, once, and
    /// answers the removal of that cookie beside it; `None` for no cookie,
    /// or a sign-in unknown, dropped or expired.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Poisoned`] for an unusable memory store and
    /// [`SessionError::Header`] when the removal cannot be written.
    pub fn take_pending(
        &self,
        headers: &HeaderMap,
    ) -> Result<WithCookies<Option<Pending>>, SessionError> {
        let now = self.now();
        let name = self.jar().names.sign_in();
        let removal = header(&self.jar().removal(&name))?;
        let Some(value) = self.jar().read(headers, &name) else {
            return Ok(WithCookies::new(None, Vec::new()));
        };
        let pending = match &self.inner.backend {
            Backend::Memory(memory) => memory.take(&Id::from_cookie(value), now, self.timeout())?,
            Backend::Sealed(key) => open::<SealedPending>(key, &self.jar().name(&name), value)
                .filter(|pending| now.saturating_sub(pending.created) < self.timeout())
                .map(|pending| Pending {
                    sign_in: PendingSignIn::from_parts(
                        pending.state,
                        pending.nonce,
                        Secret::new(pending.verifier),
                    ),
                    back: pending.back.map(ReturnPath::sealed),
                }),
        };
        Ok(WithCookies::new(pending, vec![removal]))
    }

    /// Begins the session of a completed sign-in and answers its cookie; the
    /// session the request held before is ended first, so signing in again
    /// never fills the store.
    ///
    /// A sealed store keeps no refresh token, so its session ends when the
    /// access token expires.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Full`] when the memory store is at its bound,
    /// [`SessionError::Random`] and [`SessionError::Poisoned`] as for
    /// [`Self::begin`], and the sealing errors of a sealed store.
    pub fn establish(
        &self,
        headers: &HeaderMap,
        signed_in: SignedIn,
    ) -> Result<HeaderValue, SessionError> {
        let now = self.now();
        let mut record = Record::begin(signed_in, now);
        let name = self.jar().names.session();
        match &self.inner.backend {
            Backend::Memory(memory) => {
                if let Some(held) = self.jar().read(headers, &name) {
                    memory.end(&Id::from_cookie(held))?;
                }
                let id = memory.establish(record, |record| self.live(record, now))?;
                self.set(&name, id.as_str().to_owned(), None)
            }
            Backend::Sealed(key) => {
                record.refresh_token = None;
                self.reseal(key, &record, now)
            }
        }
    }

    /// What the request carries, its activity counted: a live session's idle
    /// lifetime starts again and a sealed cookie is sealed again; a cookie
    /// that names no live session is answered with its removal.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Poisoned`] for an unusable memory store, and
    /// the sealing errors of a sealed store.
    pub fn held(&self, headers: &HeaderMap) -> Result<WithCookies<Held>, SessionError> {
        let now = self.now();
        let name = self.jar().names.session();
        let Some(value) = self.jar().read(headers, &name) else {
            return Ok(WithCookies::new(Held::Absent, Vec::new()));
        };
        let lifetimes = self.inner.settings.lifetimes;
        match &self.inner.backend {
            Backend::Memory(memory) => {
                let held = memory.with(
                    &Id::from_cookie(value),
                    |record| self.live(record, now),
                    |entry| {
                        entry.record.touched = now;
                        match lifetimes.left(entry.record.times(), now) {
                            Some(left) if entry.record.token_valid(now) => {
                                Held::SignedIn(entry.record.session(left))
                            }
                            _ => Held::TokenExpired,
                        }
                    },
                )?;
                match held {
                    Some(held) => Ok(WithCookies::new(held, Vec::new())),
                    None => self.ended(&name),
                }
            }
            Backend::Sealed(key) => {
                let opened = self.open_session(key, &name, value, now);
                let Some(mut record) = opened else {
                    return self.ended(&name);
                };
                record.touched = now;
                let Some(left) = lifetimes.left(record.times(), now) else {
                    return self.ended(&name);
                };
                let cookie = self.reseal(key, &record, now)?;
                Ok(WithCookies::new(
                    Held::SignedIn(record.session(left)),
                    vec![cookie],
                ))
            }
        }
    }

    /// What the request's session has left, for the session watch: with
    /// `extend` the request counts as activity and starts the idle lifetime
    /// again, which never reaches past the absolute one; without it nothing
    /// moves. `None` for no live session, with the cookie's removal.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::held`].
    pub fn left(
        &self,
        headers: &HeaderMap,
        extend: bool,
    ) -> Result<WithCookies<Option<Left>>, SessionError> {
        let now = self.now();
        let name = self.jar().names.session();
        let Some(value) = self.jar().read(headers, &name) else {
            return Ok(WithCookies::new(None, Vec::new()));
        };
        let lifetimes = self.inner.settings.lifetimes;
        let gone = |this: &Self| -> Result<WithCookies<Option<Left>>, SessionError> {
            let removal = header(&this.jar().removal(&name))?;
            Ok(WithCookies::new(None, vec![removal]))
        };
        match &self.inner.backend {
            Backend::Memory(memory) => {
                let left = memory.with(
                    &Id::from_cookie(value),
                    |record| self.live(record, now),
                    |entry| {
                        if extend {
                            entry.record.touched = now;
                        }
                        lifetimes.left(entry.record.times(), now)
                    },
                )?;
                match left.flatten() {
                    Some(left) => Ok(WithCookies::new(Some(left), Vec::new())),
                    None => gone(self),
                }
            }
            Backend::Sealed(key) => {
                let Some(mut record) = self.open_session(key, &name, value, now) else {
                    return gone(self);
                };
                if !extend {
                    return Ok(WithCookies::new(
                        lifetimes.left(record.times(), now),
                        Vec::new(),
                    ));
                }
                record.touched = now;
                let left = lifetimes.left(record.times(), now);
                let cookie = self.reseal(key, &record, now)?;
                Ok(WithCookies::new(left, vec![cookie]))
            }
        }
    }

    /// Ends the request's session and answers what the provider is told,
    /// beside the removal of its cookie; `None` when the request held none.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Poisoned`] for an unusable memory store and
    /// [`SessionError::Header`] when the removal cannot be written.
    pub fn end(&self, headers: &HeaderMap) -> Result<WithCookies<Option<Ended>>, SessionError> {
        let now = self.now();
        let name = self.jar().names.session();
        let removal = header(&self.jar().removal(&name))?;
        let Some(value) = self.jar().read(headers, &name) else {
            return Ok(WithCookies::new(None, vec![removal]));
        };
        let record = match &self.inner.backend {
            Backend::Memory(memory) => memory.end(&Id::from_cookie(value))?,
            Backend::Sealed(key) => self.open_session(key, &name, value, now),
        };
        Ok(WithCookies::new(record.map(Record::ended), vec![removal]))
    }

    /// How many entries each pool of a memory store holds; `None` for a
    /// sealed store, which holds none.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Poisoned`] for an unusable memory store.
    pub fn occupancy(&self) -> Result<Option<Occupancy>, SessionError> {
        match &self.inner.backend {
            Backend::Memory(memory) => memory.occupancy().map(Some),
            Backend::Sealed(_) => Ok(None),
        }
    }

    /// The `Set-Cookie` value that keeps the operator's preference `name` at
    /// `value` for `max_age`, with the attributes of every other cookie.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Header`] when the cookie cannot be written.
    pub fn preference(
        &self,
        name: &str,
        value: &str,
        max_age: Duration,
    ) -> Result<HeaderValue, SessionError> {
        self.set(
            &self.jar().names.preference(name),
            value.to_owned(),
            Some(seconds(max_age)),
        )
    }

    /// The `Set-Cookie` value that clears the operator's preference `name`.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Header`] when the cookie cannot be written.
    pub fn preference_removal(&self, name: &str) -> Result<HeaderValue, SessionError> {
        header(&self.jar().removal(&self.jar().names.preference(name)))
    }

    /// The operator's preference `name` the request carries.
    #[must_use]
    pub fn preference_in(&self, headers: &HeaderMap, name: &str) -> Option<String> {
        self.jar().read(headers, &self.jar().names.preference(name))
    }

    pub(crate) fn memory(&self) -> Option<&Memory> {
        match &self.inner.backend {
            Backend::Memory(memory) => Some(memory),
            Backend::Sealed(_) => None,
        }
    }

    pub(crate) fn session_id(&self, headers: &HeaderMap) -> Option<Id> {
        self.jar()
            .read(headers, &self.jar().names.session())
            .map(Id::from_cookie)
    }

    pub(crate) fn live_at(&self, record: &Record) -> bool {
        self.live(record, self.now())
    }

    pub(crate) fn clock_now(&self) -> i64 {
        self.now()
    }

    /// The live record a sealed session cookie carries.
    fn open_session(
        &self,
        key: &cookie::Key,
        name: &str,
        value: String,
        now: i64,
    ) -> Option<Record> {
        open::<Sealed>(key, &self.jar().name(name), value)
            .and_then(Sealed::record)
            .filter(|record| self.live(record, now))
    }

    /// `record` sealed into its cookie, living until the first lifetime ends.
    fn reseal(
        &self,
        key: &cookie::Key,
        record: &Record,
        now: i64,
    ) -> Result<HeaderValue, SessionError> {
        let name = self.jar().names.session();
        let value = seal(key, &self.jar().name(&name), &Sealed::from(record))?;
        let max_age = self
            .inner
            .settings
            .lifetimes
            .left(record.times(), now)
            .map_or(0, |left| i64::from(left.idle));
        let cookie = self.set(&name, value, Some(max_age))?;
        if cookie.len() > COOKIE_LIMIT {
            return Err(SessionError::TooLarge {
                found: cookie.len(),
            });
        }
        Ok(cookie)
    }

    fn ended(&self, name: &str) -> Result<WithCookies<Held>, SessionError> {
        Ok(WithCookies::new(
            Held::Ended,
            vec![header(&self.jar().removal(name))?],
        ))
    }

    fn set(
        &self,
        base: &str,
        value: String,
        max_age: Option<i64>,
    ) -> Result<HeaderValue, SessionError> {
        header(&self.jar().cookie(base, value, max_age))
    }
}

#[cfg(test)]
mod tests;
