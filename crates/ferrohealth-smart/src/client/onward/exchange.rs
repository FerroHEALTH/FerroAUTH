// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The onward token client: the checks before anything is sent, the
//! request of each grant, the response read, the onward check, and the
//! cache.
//!
//! No specification governs the cache: our own design. An entry is keyed
//! by a SHA-256 over the issuer, the grant, the hash of the subject token
//! and of the actor token, the target's audiences and indicators, the
//! scope and the profile's extra parameters, so a token issued for one
//! target never reaches another (RFC 8707 §2). It lives until a margin
//! before the earlier of the issued token's and the subject token's `exp`,
//! and the onward check runs again on every hit. Concurrent misses each
//! fetch; no token is ever logged.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::OnceLock;
use std::sync::PoisonError;
use std::time::Duration;

use http::HeaderValue;
use http::StatusCode;
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde_json::Map;
use serde_json::Value;
use url::Url;

use crate::client::ClientAuth;
use crate::client::ClientCredentials;
use crate::client::Endpoint;
use crate::client::OAuthError;
use crate::client::TokenError;
use crate::client::cache::bearer;
use crate::client::endpoint;
use crate::client::endpoint::Answer;
use crate::client::onward::ActorToken;
use crate::client::onward::OnwardError;
use crate::client::onward::Rejected;
use crate::client::onward::SubjectToken;
use crate::client::onward::Target;
use crate::client::onward::TokenType;
use crate::client::onward::check::Route;
use crate::client::onward::check::check;
use crate::client::onward::check::decode;
use crate::kind::CallerKind;
use crate::kind::IssuerKind;
use crate::metadata::Http;
use crate::profile::onward::OnwardGrant;
use crate::profile::onward::OnwardIndicator;
use crate::profile::onward::PreviewVariant;
use crate::resource::Settings;

/// The most entries the cache holds; the one renewed soonest makes room.
const MAX_ENTRIES: usize = 4096;

/// The source of the current time the check and the cache read, in seconds
/// since the epoch.
pub trait WallClock: Send + Sync + fmt::Debug {
    /// Returns the current time.
    fn now(&self) -> i64;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn now(&self) -> i64 {
        jiff::Timestamp::now().as_second()
    }
}

/// One onward token, ready to send.
///
/// The `Debug` rendering never carries the token: the header value is
/// marked sensitive.
#[derive(Debug, Clone)]
pub struct OnwardToken {
    /// The `Authorization` field value the token renders to.
    header: HeaderValue,
    /// When the client stops using it: the earlier of the issued token's
    /// and the subject token's `exp`.
    expires_at: i64,
}

impl OnwardToken {
    /// Returns the `Authorization` field value of the token (RFC 6750 §2.1).
    #[must_use]
    pub const fn header(&self) -> &HeaderValue {
        &self.header
    }

    /// Returns when the client stops using the token, in seconds since the
    /// epoch: the earlier of its own and the subject token's `exp`.
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

/// One cached token with the claims the check runs on again.
struct Entry {
    /// The token.
    token: OnwardToken,
    /// Its decoded claims.
    claims: Map<String, Value>,
    /// When a new one is fetched from, in seconds since the epoch.
    renew_at: i64,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("token", &self.token)
            .field("renew_at", &self.renew_at)
            .finish_non_exhaustive()
    }
}

/// The members of a token response the client reads (RFC 6749 §5.1, RFC
/// 8693 §2.2.1).
#[derive(Deserialize)]
struct Response {
    /// The issued token.
    access_token: String,
    /// How it is used, compared case-insensitively.
    token_type: String,
    /// What it is, under token exchange.
    issued_token_type: Option<String>,
    /// Its lifetime in seconds, when the server sent one.
    expires_in: Option<u64>,
    /// A refresh token, which the client refuses.
    refresh_token: Option<Value>,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("token_type", &self.token_type)
            .field("issued_token_type", &self.issued_token_type)
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// The claims challenge of an `interaction_required` error body.
#[derive(Deserialize)]
struct Challenge {
    /// The challenge, as received.
    claims: Option<String>,
}

/// What the client shares with its clones.
#[derive(Debug)]
struct Inner {
    /// The issuer of the onward tokens: its kind, profile and tables.
    issuer: Settings,
    /// How the client reaches and authenticates to its token endpoint.
    credentials: ClientCredentials,
    /// The issuer's `max_onward_lifetime`.
    lifetime: u64,
    /// The HTTP engine.
    http: Http,
    /// The clock.
    clock: Arc<dyn WallClock>,
    /// The token endpoint, once configured or discovered.
    token_endpoint: OnceLock<Url>,
    /// The cached tokens.
    cache: Mutex<BTreeMap<Vec<u8>, Entry>>,
}

/// The client of one issuer's onward grants, with its cache.
///
/// The client is cheap to clone: clones share one cache.
#[derive(Debug, Clone)]
pub struct Onward {
    /// The issuer, the credentials and the cache.
    inner: Arc<Inner>,
}

impl Onward {
    /// Returns the client of the onward grants `issuer` issues, reached and
    /// authenticated to as `credentials` say.
    ///
    /// # Errors
    ///
    /// [`OnwardError::Settings`] when `issuer` breaks a rule,
    /// [`OnwardError::Token`] when `credentials` lack the credential of
    /// their method or the HTTP engine cannot be built,
    /// [`OnwardError::IssuerKind`] for an issuer that is neither `persons`
    /// nor `federation`, [`OnwardError::MaxOnwardLifetime`] when its profile
    /// sets no `max_onward_lifetime`, and [`OnwardError::Federation`] when a
    /// `federation` issuer's table sets no `exchanges_from` or
    /// `person_mapping`.
    pub fn new(issuer: Settings, credentials: ClientCredentials) -> Result<Self, OnwardError> {
        Self::with_clock(issuer, credentials, Arc::new(SystemWallClock))
    }

    /// Returns a client as [`Onward::new`] does that reads the time from
    /// `clock`.
    ///
    /// # Errors
    ///
    /// As [`Onward::new`].
    pub fn with_clock(
        issuer: Settings,
        credentials: ClientCredentials,
        clock: Arc<dyn WallClock>,
    ) -> Result<Self, OnwardError> {
        let http =
            Http::with_tls(credentials.timeout, &credentials.tls).map_err(TokenError::from)?;
        Self::assemble(issuer, credentials, http, clock)
    }

    /// Returns a client as [`Onward::new`] does that calls the token
    /// endpoint through `http`, a product's own engine, used as built.
    ///
    /// # Errors
    ///
    /// As [`Onward::new`], with no engine to build.
    pub fn with_http(
        issuer: Settings,
        credentials: ClientCredentials,
        http: Http,
    ) -> Result<Self, OnwardError> {
        Self::assemble(issuer, credentials, http, Arc::new(SystemWallClock))
    }

    /// Returns the client after checking what it is built from.
    fn assemble(
        issuer: Settings,
        credentials: ClientCredentials,
        http: Http,
        clock: Arc<dyn WallClock>,
    ) -> Result<Self, OnwardError> {
        issuer
            .validate()
            .map_err(|source| OnwardError::Settings(Box::new(source)))?;
        credentials.validate()?;
        match issuer.kind {
            IssuerKind::Persons => {}
            IssuerKind::Federation => {
                let section = issuer
                    .federation
                    .as_ref()
                    .ok_or(OnwardError::Federation { key: "issuer" })?;
                if section.exchanges_from.is_empty() {
                    return Err(OnwardError::Federation {
                        key: "exchanges_from",
                    });
                }
                if section.person_mapping.is_none() {
                    return Err(OnwardError::Federation {
                        key: "person_mapping",
                    });
                }
            }
            kind => return Err(OnwardError::IssuerKind { kind }),
        }
        let lifetime = issuer
            .profile
            .max_onward_lifetime
            .ok_or(OnwardError::MaxOnwardLifetime)?;
        Ok(Self {
            inner: Arc::new(Inner {
                issuer,
                credentials,
                lifetime,
                http,
                clock,
                token_endpoint: OnceLock::new(),
                cache: Mutex::new(BTreeMap::new()),
            }),
        })
    }

    /// Returns a token for `target` on behalf of `subject`, delegated to
    /// `actor` when one is given, from the cache when it holds one that
    /// still passes the onward check.
    ///
    /// # Errors
    ///
    /// Before anything is sent: [`OnwardError::UserPrincipalRequired`] for
    /// a JWT bearer grant on behalf of a system or an organisation,
    /// [`OnwardError::Preview`] for a variant the profile labels preview,
    /// [`OnwardError::NoAudience`], [`OnwardError::OfflineAccess`],
    /// [`OnwardError::ActorToken`], [`OnwardError::Indicator`],
    /// [`OnwardError::NoScope`], [`OnwardError::Resource`],
    /// [`OnwardError::SubjectAudience`], and [`Rejected::NotMapped`] for a
    /// subject a `federation` issuer is not trusted to map. After:
    /// [`OnwardError::Token`] with the upstream status for a refused or
    /// unreadable answer, [`OnwardError::InteractionRequired`],
    /// [`OnwardError::RefreshToken`], [`OnwardError::IssuedTokenType`], and
    /// [`OnwardError::Rejected`] for an issued or cached token that fails
    /// the onward check.
    pub async fn token(
        &self,
        subject: &SubjectToken,
        actor: Option<&ActorToken>,
        target: &Target,
    ) -> Result<OnwardToken, OnwardError> {
        self.admit(subject, actor, target)?;
        let inner = &self.inner;
        let route = Route {
            issuer: &inner.issuer,
            client_id: &inner.credentials.client_id,
            lifetime: inner.lifetime,
        };
        let key = self.key(subject, actor, target);
        let now = inner.clock.now();
        let held = lock(&inner.cache)
            .get(&key)
            .filter(|entry| now < entry.renew_at)
            .map(|entry| (entry.token.clone(), entry.claims.clone()));
        if let Some((token, claims)) = held {
            if let Err(rejected) = check(
                &route,
                target,
                subject,
                actor.map(ActorToken::actor),
                &claims,
                now,
            ) {
                lock(&inner.cache).remove(&key);
                return Err(rejected.into());
            }
            tracing::debug!("served an onward token from the cache");
            return Ok(token);
        }
        let (header, claims, expires_in) = self.fetch(subject, actor, target).await?;
        let now = inner.clock.now();
        check(
            &route,
            target,
            subject,
            actor.map(ActorToken::actor),
            &claims,
            now,
        )?;
        let expires_at = [
            claims.get("exp").and_then(Value::as_i64),
            subject.claims().get("exp").and_then(Value::as_i64),
            expires_in
                .map(|seconds| now.saturating_add(i64::try_from(seconds).unwrap_or(i64::MAX))),
        ]
        .into_iter()
        .flatten()
        .min()
        .ok_or(Rejected::MissingClaim { claim: "exp" })?;
        let token = OnwardToken { header, expires_at };
        let renew_at = renew_at(now, expires_at, inner.credentials.refresh_margin);
        tracing::debug!(
            grant = inner.issuer.profile.onward_grant.as_str(),
            expires_at,
            "obtained an onward token"
        );
        let mut cache = lock(&inner.cache);
        cache.retain(|_key, entry| entry.renew_at > now);
        if cache.len() >= MAX_ENTRIES
            && let Some(soonest) = cache
                .iter()
                .min_by_key(|(_key, entry)| entry.renew_at)
                .map(|(key, _entry)| key.clone())
        {
            cache.remove(&soonest);
        }
        cache.insert(
            key,
            Entry {
                token: token.clone(),
                claims,
                renew_at,
            },
        );
        Ok(token)
    }

    /// Refuses, before anything is sent, a request the issuer's profile or
    /// the grant does not admit.
    fn admit(
        &self,
        subject: &SubjectToken,
        actor: Option<&ActorToken>,
        target: &Target,
    ) -> Result<(), OnwardError> {
        let issuer = &self.inner.issuer;
        let profile = &issuer.profile;
        let grant = profile.onward_grant;
        // NOTE: no specification governs this: our own design; the JWT bearer grant
        // exchanges a user principal's token only, never a system's.
        if grant == OnwardGrant::JwtBearer
            && matches!(
                subject.kind(),
                CallerKind::System | CallerKind::ExternalOrganisation(_)
            )
        {
            return Err(OnwardError::UserPrincipalRequired);
        }
        if actor.is_some() && profile.onward_preview.contains(&PreviewVariant::ActorToken) {
            return Err(OnwardError::Preview {
                variant: PreviewVariant::ActorToken,
            });
        }
        if grant == OnwardGrant::JwtBearer && actor.is_some() {
            return Err(OnwardError::ActorToken);
        }
        self.check_target(target)?;
        if profile.onward_subject_audience
            && !names(subject.claims(), &self.inner.credentials.client_id)
        {
            return Err(OnwardError::SubjectAudience);
        }
        if let Some(section) = issuer.federation.as_ref()
            && !section
                .exchanges_from
                .iter()
                .any(|listed| listed == subject.issuer())
        {
            return Err(Rejected::NotMapped.into());
        }
        Ok(())
    }

    /// Checks that `target` is one this issuer's grant can ask for: it
    /// names an audience, never asks `offline_access`, names its target in
    /// `scope` alone under the JWT bearer grant, and names a `resource` as
    /// an absolute URI without a fragment.
    ///
    /// [`Onward::token`] runs it before every request; a product runs it at
    /// load on the targets it declares.
    ///
    /// # Errors
    ///
    /// [`OnwardError::NoAudience`], [`OnwardError::OfflineAccess`],
    /// [`OnwardError::Indicator`], [`OnwardError::NoScope`] and
    /// [`OnwardError::Resource`].
    pub fn check_target(&self, target: &Target) -> Result<(), OnwardError> {
        let profile = &self.inner.issuer.profile;
        if target.audiences().is_empty() {
            return Err(OnwardError::NoAudience);
        }
        if target
            .scope()
            .is_some_and(|scope| scope.split(' ').any(|token| token == "offline_access"))
        {
            return Err(OnwardError::OfflineAccess);
        }
        match profile.onward_grant {
            OnwardGrant::JwtBearer if !target.indicators().is_empty() => {
                return Err(OnwardError::Indicator);
            }
            OnwardGrant::JwtBearer
                if target.scope().is_none_or(|scope| scope.trim().is_empty()) =>
            {
                return Err(OnwardError::NoScope);
            }
            OnwardGrant::TokenExchange if profile.onward_indicator == OnwardIndicator::Resource => {
                // NOTE: RFC 8707 §2, a resource "MUST be an absolute URI" and "MUST
                // NOT include a fragment component".
                let absolute = |indicator: &String| {
                    Url::parse(indicator).is_ok_and(|url| url.fragment().is_none())
                };
                if !target.indicators().iter().all(absolute) {
                    return Err(OnwardError::Resource);
                }
            }
            OnwardGrant::JwtBearer | OnwardGrant::TokenExchange => {}
        }
        Ok(())
    }

    /// Returns the cache key of a request.
    fn key(&self, subject: &SubjectToken, actor: Option<&ActorToken>, target: &Target) -> Vec<u8> {
        let profile = &self.inner.issuer.profile;
        let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
        let mut field = |bytes: &[u8]| {
            let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            context.update(&length.to_be_bytes());
            context.update(bytes);
        };
        let digest = |secret: &secrecy::SecretString| {
            aws_lc_rs::digest::digest(
                &aws_lc_rs::digest::SHA256,
                secret.expose_secret().as_bytes(),
            )
        };
        field(self.inner.issuer.issuer.as_bytes());
        field(profile.onward_grant.as_str().as_bytes());
        field(digest(subject.token()).as_ref());
        field(subject.token_type().uri().as_bytes());
        match actor {
            Some(actor) => {
                field(digest(actor.token()).as_ref());
                field(actor.token_type().uri().as_bytes());
                field(actor.actor().issuer.as_bytes());
                field(actor.actor().sub.as_bytes());
            }
            None => field(b""),
        }
        let mut audiences = target.audiences().to_vec();
        audiences.sort();
        let mut indicators = target.indicators().to_vec();
        indicators.sort();
        for list in [audiences, indicators] {
            field(&u64::try_from(list.len()).unwrap_or(u64::MAX).to_be_bytes());
            for item in list {
                field(item.as_bytes());
            }
        }
        field(target.scope().unwrap_or("").as_bytes());
        field(target.correlation_claim().unwrap_or("").as_bytes());
        for (name, value) in &profile.onward_parameters {
            field(name.as_bytes());
            field(value.as_bytes());
        }
        context.finish().as_ref().to_vec()
    }

    /// Returns the bearer header, the claims and the `expires_in` of a new
    /// token from the token endpoint.
    async fn fetch(
        &self,
        subject: &SubjectToken,
        actor: Option<&ActorToken>,
        target: &Target,
    ) -> Result<(HeaderValue, Map<String, Value>, Option<u64>), OnwardError> {
        let inner = &self.inner;
        let url = self.token_endpoint().await?;
        let profile = &inner.issuer.profile;
        let credentials = &inner.credentials;
        let answer = endpoint::post(&inner.http, &url, credentials, |form| {
            let grant = profile.onward_grant;
            form.append_pair("grant_type", grant.grant_type());
            match grant {
                OnwardGrant::TokenExchange => {
                    for indicator in target.indicators() {
                        form.append_pair(profile.onward_indicator.parameter(), indicator);
                    }
                    if let Some(scope) = target.scope() {
                        form.append_pair("scope", scope);
                    }
                    form.append_pair("subject_token", subject.token().expose_secret());
                    form.append_pair("subject_token_type", subject.token_type().uri());
                    if let Some(actor) = actor {
                        form.append_pair("actor_token", actor.token().expose_secret());
                        form.append_pair("actor_token_type", actor.token_type().uri());
                    }
                }
                OnwardGrant::JwtBearer => {
                    form.append_pair("assertion", subject.token().expose_secret());
                    if let Some(scope) = target.scope() {
                        form.append_pair("scope", scope);
                    }
                }
            }
            for (name, value) in &profile.onward_parameters {
                form.append_pair(name, value);
            }
            // NOTE: RFC 7523 §3 leaves `client_id` optional beside a client
            // assertion; a profile that needs it names it.
            if profile.onward_client_id
                && matches!(
                    credentials.client_auth,
                    ClientAuth::PrivateKeyJwt | ClientAuth::ClientSecretBasic
                )
            {
                form.append_pair("client_id", &credentials.client_id);
            }
        })
        .await?;
        if answer.status != StatusCode::OK {
            return Err(refusal(answer));
        }
        let response: Response = serde_json::from_str(&answer.body)
            .map_err(|source| TokenError::Malformed { source })?;
        if response.refresh_token.is_some() {
            return Err(OnwardError::RefreshToken);
        }
        if profile.onward_grant == OnwardGrant::TokenExchange
            && response
                .issued_token_type
                .as_deref()
                .and_then(TokenType::from_uri)
                .is_none()
        {
            return Err(OnwardError::IssuedTokenType {
                found: response.issued_token_type,
            });
        }
        if !response.token_type.eq_ignore_ascii_case("bearer") {
            return Err(TokenError::TokenType {
                found: response.token_type,
            }
            .into());
        }
        let header = bearer(&response.access_token)?;
        let claims = decode(&response.access_token)?;
        Ok((header, claims, response.expires_in))
    }

    /// Returns the token endpoint, discovered first when only the issuer is
    /// configured.
    async fn token_endpoint(&self) -> Result<Url, OnwardError> {
        let inner = &self.inner;
        match (inner.token_endpoint.get(), &inner.credentials.endpoint) {
            (Some(url), _) | (None, Endpoint::Token(url)) => Ok(url.clone()),
            (None, Endpoint::Issuer(issuer)) => {
                let mutual_tls = inner.credentials.tls.identity.is_some();
                let url = endpoint::discover(&inner.http, issuer, mutual_tls).await?;
                Ok(inner.token_endpoint.get_or_init(|| url).clone())
            }
        }
    }
}

/// Returns the error a status other than `200` is: `interaction_required`
/// with its claims challenge, or the refusal with its status.
fn refusal(answer: Answer) -> OnwardError {
    // NOTE: RFC 6749 §5.2 makes the error body JSON; one that is not is
    // legitimately absent here, and the refusal keeps the raw body.
    match serde_json::from_str::<OAuthError>(&answer.body) {
        Ok(error) if error.error == "interaction_required" => {
            // NOTE: OpenID Connect Core 1.0 §5.5 names a claims request `claims`;
            // a body without one is legitimately absent of a challenge.
            let challenge = serde_json::from_str::<Challenge>(&answer.body)
                .ok()
                .and_then(|challenge| challenge.claims);
            OnwardError::InteractionRequired {
                status: answer.status,
                error,
                challenge,
            }
        }
        _ => answer.refused().into(),
    }
}

/// Returns whether the `aud` of `claims` names `client`.
fn names(claims: &Map<String, Value>, client: &str) -> bool {
    match claims.get("aud") {
        Some(Value::String(one)) => one == client,
        Some(Value::Array(items)) => items.iter().any(|item| item.as_str() == Some(client)),
        _ => false,
    }
}

/// Returns when a token used until `expires_at` is renewed, `margin` before
/// it, the margin capped at half the time left from `now`.
fn renew_at(now: i64, expires_at: i64, margin: Duration) -> i64 {
    let left = expires_at.saturating_sub(now).max(0);
    let margin = i64::try_from(margin.as_secs())
        .unwrap_or(i64::MAX)
        .min(left.div_euclid(2));
    expires_at.saturating_sub(margin)
}

/// Returns the guard of the cache.
fn lock<T>(cache: &Mutex<T>) -> MutexGuard<'_, T> {
    // NOTE: no specification governs this: our own design; every write leaves
    // the cache whole, so a poisoned cache still holds a usable state.
    cache.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::renew_at;
    use std::time::Duration;

    #[test]
    fn a_token_is_renewed_the_margin_before_it_expires() {
        assert_eq!(1270, renew_at(1000, 1300, Duration::from_secs(30)));
    }

    #[test]
    fn a_short_token_keeps_half_its_life() {
        assert_eq!(1010, renew_at(1000, 1020, Duration::from_secs(30)));
    }

    #[test]
    fn an_expired_token_is_renewed_at_once() {
        assert_eq!(900, renew_at(1000, 900, Duration::from_secs(30)));
    }
}
