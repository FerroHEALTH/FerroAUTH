// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The token cache, one token shared by every upstream call.
//!
//! It is fetched on first use, reused until a margin before it expires,
//! refreshed by one fetch that concurrent callers share, and renewed once
//! when the upstream refuses it. A `DPoP`-bound token is sent through
//! [`TokenSource::send`], which proves each attempt and answers a resource's
//! nonce demand once (RFC 9449 §9).
//!
//! No specification governs the cache: our own design. The slot sits behind
//! a `std::sync::Mutex` that is only ever held to read or replace it, never
//! across an `.await`; a fetch runs as its own task and publishes its outcome
//! on a `tokio::sync::watch` channel every waiting caller holds, so a caller
//! that is dropped mid-wait never abandons the others.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::OnceLock;
use std::sync::PoisonError;
use std::time::Duration;
use std::time::Instant;

use http::HeaderMap;
use http::HeaderValue;
use http::Method;
use http::StatusCode;
use tokio::sync::watch;
use url::Url;

use crate::client::CallError;
use crate::client::ClientCredentials;
use crate::client::Endpoint;
use crate::client::RenewalError;
use crate::client::TokenError;
use crate::client::binding::IssuedToken;
use crate::client::dpop;
use crate::client::dpop::DpopError;
use crate::client::dpop::DpopKey;
use crate::client::endpoint;
use crate::metadata::Http;

/// The source of the current instant the cache reads expiry against.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Returns the current instant.
    fn now(&self) -> Instant;
}

/// The monotonic system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// One issued token, ready to send, and when it is renewed.
///
/// The `Debug` rendering never carries the token.
#[derive(Debug)]
pub struct Token {
    /// The token.
    issued: IssuedToken,
    /// The instant a new token is fetched from, when the token expires.
    renew_at: Option<Instant>,
}

impl Token {
    /// Returns the `Authorization` field value (RFC 6750 §2.1, RFC 9449 §7.1).
    #[must_use]
    pub const fn header(&self) -> &HeaderValue {
        self.issued.header()
    }

    /// Returns whether the token is still served at `now`.
    fn fresh(&self, now: Instant) -> bool {
        self.renew_at.is_none_or(|renew_at| now < renew_at)
    }
}

/// The credential of one attempt of [`TokenSource::send`]: the
/// `Authorization` value, and the `DPoP` proof of the attempt when the token
/// is `DPoP`-bound.
///
/// The `Debug` rendering carries neither: both values are marked sensitive.
#[derive(Debug, Clone)]
pub struct Attempt {
    /// The `Authorization` field value.
    authorization: HeaderValue,
    /// The value of the [`dpop::HEADER`], when the token is `DPoP`-bound.
    proof: Option<HeaderValue>,
}

impl Attempt {
    /// Returns the credential of `token` for a `method` request to `url`.
    fn of<E>(token: &Token, method: &Method, url: &Url) -> Result<Self, CallError<E>> {
        let proof = token
            .issued
            .proof(method, url)
            .map_err(|source| CallError::Proof { source })?
            .map(|proof| {
                HeaderValue::from_str(&proof).map(|mut value| {
                    value.set_sensitive(true);
                    value
                })
            })
            .transpose()
            .map_err(|_illegal| CallError::Proof {
                source: DpopError::Header,
            })?;
        Ok(Self {
            authorization: token.header().clone(),
            proof,
        })
    }

    /// Returns the `Authorization` field value.
    #[must_use]
    pub const fn authorization(&self) -> &HeaderValue {
        &self.authorization
    }

    /// Returns the value of the [`dpop::HEADER`], when the token is
    /// `DPoP`-bound.
    #[must_use]
    pub const fn proof(&self) -> Option<&HeaderValue> {
        self.proof.as_ref()
    }
}

impl AsRef<IssuedToken> for Token {
    fn as_ref(&self) -> &IssuedToken {
        &self.issued
    }
}

/// A response that names its status and headers, so a call can be sent
/// once more when the upstream refused the token or demanded a `DPoP`
/// nonce.
pub trait Answered {
    /// Returns the status the upstream answered.
    fn status(&self) -> StatusCode;

    /// Returns the headers the upstream answered with.
    fn headers(&self) -> &HeaderMap;
}

impl<B> Answered for http::Response<B> {
    fn status(&self) -> StatusCode {
        http::Response::status(self)
    }

    fn headers(&self) -> &HeaderMap {
        http::Response::headers(self)
    }
}

impl Answered for reqwest::Response {
    fn status(&self) -> StatusCode {
        reqwest::Response::status(self)
    }

    fn headers(&self) -> &HeaderMap {
        reqwest::Response::headers(self)
    }
}

/// What a fetch publishes to the callers waiting on it.
type Outcome = Result<Arc<Token>, Arc<TokenError>>;

/// The state of the one cached token.
#[derive(Debug)]
enum Slot {
    /// No token is held and none is being fetched.
    Empty,
    /// A token is held.
    Ready(Arc<Token>),
    /// A fetch is running; its outcome arrives on the receiver.
    Fetching(watch::Receiver<Option<Outcome>>),
}

/// What the cache shares with the fetch tasks it spawns.
#[derive(Debug)]
struct Inner {
    /// The grant.
    config: ClientCredentials,
    /// The HTTP engine the authorization server is called through.
    http: Http,
    /// The clock expiry is read against.
    clock: Arc<dyn Clock>,
    /// The token endpoint, once configured or discovered.
    token_endpoint: OnceLock<Url>,
    /// The cached token.
    slot: Mutex<Slot>,
}

/// The product's upstream token, obtained with the client credentials grant
/// and renewed before it expires.
///
/// The source is cheap to clone: clones share one cache.
#[derive(Debug, Clone)]
pub struct TokenSource {
    /// The cache and the grant.
    inner: Arc<Inner>,
}

impl TokenSource {
    /// Returns a source for `config`.
    ///
    /// Nothing is fetched until the first [`TokenSource::token`].
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Discovery`] when the HTTP engine cannot be
    /// built, the trust roots or the client certificate of `config.tls`
    /// included.
    pub fn new(config: ClientCredentials) -> Result<Self, TokenError> {
        Self::with_clock(config, Arc::new(SystemClock))
    }

    /// Returns a source like [`TokenSource::new`] that reads expiry against
    /// `clock`.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Discovery`] when the HTTP engine cannot be
    /// built.
    pub fn with_clock(
        config: ClientCredentials,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, TokenError> {
        let http = Http::with_tls(config.timeout, &config.tls)?;
        Ok(Self::assemble(config, http, clock))
    }

    /// Returns a source for `config` that calls the authorization server
    /// through `http`, a product's own engine ([`Http::from_client`]).
    ///
    /// The engine is used as built: `config.timeout` and `config.tls` are
    /// not applied to it, and its redirect policy is the product's.
    #[must_use]
    pub fn with_http(config: ClientCredentials, http: Http) -> Self {
        Self::assemble(config, http, Arc::new(SystemClock))
    }

    /// Returns the `DPoP` key the source's tokens are bound to, when they
    /// are.
    #[must_use]
    pub fn dpop_key(&self) -> Option<&Arc<DpopKey>> {
        self.inner.config.dpop_key()
    }

    /// Returns the trust roots of the grant's TLS material, which the
    /// introspection calls of a bearer source trust beside the platform's.
    pub(crate) fn root_certificates(&self) -> Option<&[u8]> {
        self.inner.config.tls.root_certificates.as_deref()
    }

    /// Returns the source of `config` over `http`, reading expiry against
    /// `clock`.
    fn assemble(config: ClientCredentials, http: Http, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                http,
                clock,
                token_endpoint: OnceLock::new(),
                slot: Mutex::new(Slot::Empty),
            }),
        }
    }

    /// Returns the current token, fetching one when none is held or the held
    /// one is within the refresh margin of its expiry.
    ///
    /// Concurrent callers that find no usable token share one fetch.
    ///
    /// # Errors
    ///
    /// Returns the [`TokenError`] of the fetch, shared by every caller that
    /// waited on it; the next call fetches again.
    pub async fn token(&self) -> Result<Arc<Token>, Arc<TokenError>> {
        let mut receiver = {
            let mut slot = lock(&self.inner.slot);
            let now = self.inner.clock.now();
            match &*slot {
                Slot::Ready(token) if token.fresh(now) => return Ok(Arc::clone(token)),
                Slot::Fetching(receiver) => receiver.clone(),
                Slot::Ready(_) | Slot::Empty => self.start(&mut slot),
            }
        };
        loop {
            if let Some(outcome) = receiver.borrow_and_update().clone() {
                return outcome;
            }
            if receiver.changed().await.is_err() {
                return Err(Arc::new(TokenError::Abandoned));
            }
        }
    }

    /// Drops the held token when it is the one `stale` renders, so the next
    /// [`TokenSource::token`] fetches a new one.
    ///
    /// A token another caller has already renewed stays.
    pub fn invalidate(&self, stale: &HeaderValue) {
        let mut slot = lock(&self.inner.slot);
        if matches!(&*slot, Slot::Ready(token) if token.header() == stale) {
            *slot = Slot::Empty;
        }
    }

    /// Sends `call` under the current token, and once more under a new one
    /// when the upstream answers `401`.
    ///
    /// The second answer is returned whatever it is: a token refused twice
    /// reaches the caller as the `401` it is, and the token endpoint is asked
    /// once per refusal, never in a loop (RFC 6750 §3.1 makes `401` the
    /// answer to an invalid token, which a renewal settles or not).
    ///
    /// A source whose tokens are `DPoP`-bound sends through
    /// [`TokenSource::send`], since a call handed the `Authorization` value
    /// alone cannot prove the key.
    ///
    /// # Errors
    ///
    /// Returns [`CallError::Unproven`] for a `DPoP`-bound source, with nothing
    /// sent, [`CallError::Token`] when no token could be obtained for the
    /// first attempt, [`CallError::Renewal`] when the upstream refused the
    /// token and no new one could be obtained, and [`CallError::Call`] when
    /// the call itself failed.
    pub async fn call<F, Fut, R, E>(&self, mut call: F) -> Result<R, CallError<E>>
    where
        F: FnMut(HeaderValue) -> Fut,
        Fut: Future<Output = Result<R, E>>,
        R: Answered,
    {
        if self.dpop_key().is_some() {
            return Err(CallError::Unproven);
        }
        let first = self
            .token()
            .await
            .map_err(|source| CallError::Token { source })?;
        let answered = call(first.header().clone())
            .await
            .map_err(|source| CallError::Call { source })?;
        if answered.status() != StatusCode::UNAUTHORIZED {
            return Ok(answered);
        }
        tracing::debug!("the upstream refused the token; renewing it once");
        self.invalidate(first.header());
        let renewed = self
            .token()
            .await
            .map_err(|source| CallError::Renewal(RenewalError::new(source)))?;
        call(renewed.header().clone())
            .await
            .map_err(|source| CallError::Call { source })
    }

    /// Sends `call`, a `method` request to `url`, under the current token,
    /// and once more when the upstream refuses it.
    ///
    /// Each [`Attempt`] carries the `Authorization` value and, for a
    /// `DPoP`-bound token, a proof of `method` and `url` signed for that
    /// attempt (RFC 9449 §4.2, §7.1), which the call sends in the
    /// [`dpop::HEADER`]. A `401` whose `DPoP` challenge demands a nonce is
    /// answered once with the same token and a new proof carrying the nonce,
    /// kept for `url`'s origin (RFC 9449 §9). Any other `401` renews the
    /// token once, as [`TokenSource::call`] does.
    ///
    /// # Errors
    ///
    /// Returns [`CallError::Token`] when no token could be obtained for the
    /// first attempt, [`CallError::Renewal`] when the upstream refused the
    /// token and no new one could be obtained, [`CallError::Proof`] when a
    /// proof could not be signed, with that attempt not sent, and
    /// [`CallError::Call`] when the call itself failed.
    pub async fn send<F, Fut, R, E>(
        &self,
        method: &Method,
        url: &Url,
        mut call: F,
    ) -> Result<R, CallError<E>>
    where
        F: FnMut(Attempt) -> Fut,
        Fut: Future<Output = Result<R, E>>,
        R: Answered,
    {
        let token = self
            .token()
            .await
            .map_err(|source| CallError::Token { source })?;
        let mut answered = call(Attempt::of(&token, method, url)?)
            .await
            .map_err(|source| CallError::Call { source })?;
        if let Some(key) = token.issued.dpop_key()
            && let Some(nonce) = dpop::resource_challenge(answered.status(), answered.headers())
        {
            tracing::debug!("the upstream demands a DPoP nonce; sending once more");
            key.remember(dpop::Role::Resource, url, nonce);
            answered = call(Attempt::of(&token, method, url)?)
                .await
                .map_err(|source| CallError::Call { source })?;
        }
        if answered.status() != StatusCode::UNAUTHORIZED {
            return Ok(answered);
        }
        tracing::debug!("the upstream refused the token; renewing it once");
        self.invalidate(token.header());
        let renewed = self
            .token()
            .await
            .map_err(|source| CallError::Renewal(RenewalError::new(source)))?;
        call(Attempt::of(&renewed, method, url)?)
            .await
            .map_err(|source| CallError::Call { source })
    }

    /// Starts a fetch, records it in `slot`, and returns its receiver.
    fn start(&self, slot: &mut Slot) -> watch::Receiver<Option<Outcome>> {
        let (sender, receiver) = watch::channel(None);
        *slot = Slot::Fetching(receiver.clone());
        let inner = Arc::clone(&self.inner);
        drop(tokio::spawn(async move {
            let outcome = inner.fetch().await.map(Arc::new).map_err(Arc::new);
            *lock(&inner.slot) = match &outcome {
                Ok(token) => Slot::Ready(Arc::clone(token)),
                Err(_) => Slot::Empty,
            };
            sender.send_replace(Some(outcome));
        }));
        receiver
    }
}

impl Inner {
    /// Returns a new token from the token endpoint, discovered first when
    /// only the issuer is configured.
    async fn fetch(&self) -> Result<Token, TokenError> {
        let endpoint = match (self.token_endpoint.get(), &self.config.endpoint) {
            (Some(url), _) | (None, Endpoint::Token(url)) => url.clone(),
            (None, Endpoint::Issuer(issuer)) => {
                let mutual_tls = self.config.tls.identity.is_some();
                let url = endpoint::discover(&self.http, issuer, mutual_tls).await?;
                self.token_endpoint.get_or_init(|| url).clone()
            }
        };
        let issued = self.clock.now();
        let response = endpoint::request_token(&self.http, &endpoint, &self.config).await?;
        let token = endpoint::credential(
            &self.config,
            &response.token_type,
            response.access_token,
            response.cnf.as_ref(),
        )?;
        tracing::debug!(
            expires_in = response.expires_in,
            "obtained an upstream token with the client credentials grant"
        );
        Ok(Token {
            issued: token,
            renew_at: renew_at(issued, response.expires_in, self.config.refresh_margin),
        })
    }
}

/// Returns the instant a token issued at `issued` for `expires_in` seconds is
/// renewed from, or `None` when it carries no lifetime.
///
/// The margin is capped at half the lifetime, so a token shorter than twice
/// the margin is still reused for half its life.
fn renew_at(issued: Instant, expires_in: Option<u64>, margin: Duration) -> Option<Instant> {
    // NOTE: RFC 6749 §5.1 makes `expires_in` RECOMMENDED; a token without one
    // is reused until the upstream refuses it, which renews it once.
    let lifetime = Duration::from_secs(expires_in?);
    issued.checked_add(lifetime.saturating_sub(margin.min(lifetime / 2)))
}

/// Returns the guard of `slot`.
fn lock(slot: &Mutex<Slot>) -> MutexGuard<'_, Slot> {
    // NOTE: no specification governs this: our own design; every write leaves
    // the slot whole, so a poisoned slot still holds a usable state.
    slot.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::renew_at;
    use crate::client::endpoint::authorization;
    use std::time::{Duration, Instant};

    #[test]
    fn a_token_is_renewed_the_margin_before_it_expires() {
        let issued = Instant::now();
        assert_eq!(
            Some(issued + Duration::from_secs(270)),
            renew_at(issued, Some(300), Duration::from_secs(30))
        );
    }

    #[test]
    fn a_short_token_keeps_half_its_life() {
        let issued = Instant::now();
        assert_eq!(
            Some(issued + Duration::from_secs(10)),
            renew_at(issued, Some(20), Duration::from_secs(30))
        );
    }

    #[test]
    fn a_token_without_a_lifetime_is_never_renewed_by_time() {
        assert_eq!(
            None,
            renew_at(Instant::now(), None, Duration::from_secs(30))
        );
    }

    #[test]
    fn a_bearer_credential_is_a_b64token_and_sensitive() {
        let bearer = |token| authorization("Bearer", token);
        let value = bearer("abc.DEF-ghi_~+/==").expect("a b64token");
        assert_eq!("Bearer abc.DEF-ghi_~+/==", value.to_str().expect("ASCII"));
        assert!(value.is_sensitive());
        assert!(bearer("").is_err());
        assert!(bearer("with space").is_err());
        assert!(bearer("a=b").is_err());
        let dpop = authorization("DPoP", "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU")
            .expect("the RFC 9449 §7.1 example token");
        assert_eq!(
            "DPoP Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
            dpop.to_str().expect("ASCII")
        );
    }
}
