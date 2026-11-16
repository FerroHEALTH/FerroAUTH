// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The JWK Sets of the confidential asymmetric clients.
//!
//! A set comes by value from the registry, or is fetched from the
//! registered URL and cached as the client's `Cache-Control` allows ("The FHIR authorization server SHALL NOT cache a
//! JWKS for longer than the client's cache-control header indicates" and
//! "SHOULD cache a client's JWK Set according to the client's cache-control
//! header", SMART App Launch 2.2.0, Client Authentication: Asymmetric,
//! Signature Verification).

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use http::header;
use serde_json::Value;
use url::Url;

use crate::clients::{Client, ClientKeys};

/// How long one fetch of a JWK Set may take. No specification governs the
/// value: our own design.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest JWK Set read, which bounds what a client's server can make
/// FerroSMART hold. No specification governs the value: our own design.
pub const MAX_SET_BYTES: usize = 64 * 1024;

/// Why a client's JWK Set could not be read.
#[derive(Debug, thiserror::Error)]
pub enum KeysError {
    /// The fetch failed or timed out.
    #[error("the JWK Set could not be fetched")]
    Fetch(#[from] reqwest::Error),
    /// The server answered another status than `200`.
    #[error("the JWK Set URL answered {status}")]
    Status {
        /// The status.
        status: http::StatusCode,
    },
    /// The set is larger than [`MAX_SET_BYTES`].
    #[error("the JWK Set is larger than {MAX_SET_BYTES} bytes")]
    TooLarge,
    /// The body is no JSON.
    #[error("the JWK Set is no JSON")]
    Json(#[from] serde_json::Error),
    /// The client registers no JWK Set.
    #[error("the client registers no JWK Set")]
    NoKeys,
}

/// The JWK Sets read from client URLs, each until its `max-age` runs out.
#[derive(Debug)]
pub struct ClientKeySets {
    /// The HTTP client.
    http: reqwest::Client,
    /// The cached sets by URL, with the instant each goes stale.
    cache: Mutex<BTreeMap<String, (Value, Instant)>>,
}

impl ClientKeySets {
    /// Returns an empty cache over `http`.
    #[must_use]
    pub const fn new(http: reqwest::Client) -> Self {
        Self {
            http,
            cache: Mutex::new(BTreeMap::new()),
        }
    }

    /// Returns the JWK Set `client` registers; `refresh` skips the cache,
    /// for a `kid` the cached set does not hold.
    ///
    /// # Errors
    /// Returns [`KeysError`] when the set cannot be read.
    pub async fn get(&self, client: &Client, refresh: bool) -> Result<Value, KeysError> {
        match &client.keys {
            Some(ClientKeys::Set(set)) => Ok(set.clone()),
            Some(ClientKeys::Uri(url)) => self.fetched(url, refresh).await,
            None => Err(KeysError::NoKeys),
        }
    }

    /// Returns the set at `url`, from the cache while it is fresh.
    async fn fetched(&self, url: &Url, refresh: bool) -> Result<Value, KeysError> {
        let now = Instant::now();
        if !refresh {
            let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some((set, stale)) = cache.get(url.as_str())
                && now < *stale
            {
                return Ok(set.clone());
            }
        }
        let response = self
            .http
            .get(url.clone())
            .header(header::ACCEPT, "application/json")
            .timeout(FETCH_TIMEOUT)
            .send()
            .await?;
        if response.status() != http::StatusCode::OK {
            return Err(KeysError::Status {
                status: response.status(),
            });
        }
        let lifetime = max_age(response.headers().get(header::CACHE_CONTROL));
        let bytes = read_bounded(response).await?;
        let set: Value = serde_json::from_slice(&bytes)?;
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        match lifetime.and_then(|lifetime| now.checked_add(lifetime)) {
            Some(stale) => {
                cache.insert(url.as_str().to_owned(), (set.clone(), stale));
            }
            None => {
                cache.remove(url.as_str());
            }
        }
        Ok(set)
    }
}

/// Reads `response`'s body, refusing one past [`MAX_SET_BYTES`].
async fn read_bounded(mut response: reqwest::Response) -> Result<Vec<u8>, KeysError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_SET_BYTES {
            return Err(KeysError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Returns how long `cache_control` allows a set to be kept: its `max-age`,
/// and nothing under `no-store` or `no-cache` or without a `max-age` (RFC
/// 9111 §5.2.2.1, §5.2.2.4 and §5.2.2.5).
fn max_age(cache_control: Option<&http::HeaderValue>) -> Option<Duration> {
    // NOTE: RFC 9111 §5.2, a Cache-Control that is no visible ASCII states no
    // lifetime, so the set is not cached.
    let directives = cache_control?.to_str().ok()?;
    let mut age = None;
    for directive in directives.split(',').map(str::trim) {
        let lower = directive.to_ascii_lowercase();
        if lower == "no-store" || lower == "no-cache" {
            return None;
        }
        if let Some(seconds) = lower.strip_prefix("max-age=") {
            // NOTE: RFC 9111 §1.2.2, a max-age that is no delta-seconds states no
            // lifetime, so the set is not cached.
            age = seconds
                .trim_matches('"')
                .parse()
                .ok()
                .map(Duration::from_secs);
        }
    }
    age
}

#[cfg(test)]
mod tests {
    use super::max_age;
    use http::HeaderValue;
    use std::time::Duration;

    #[test]
    fn the_cache_lifetime_is_the_max_age_unless_storing_is_refused() {
        let of = |value: &'static str| max_age(Some(&HeaderValue::from_static(value)));
        assert_eq!(Some(Duration::from_secs(600)), of("public, max-age=600"));
        assert_eq!(Some(Duration::from_secs(60)), of("Max-Age=\"60\""));
        assert_eq!(None, of("no-store, max-age=600"));
        assert_eq!(None, of("max-age=600, no-cache"));
        assert_eq!(None, of("public"));
        assert_eq!(None, max_age(None));
    }
}
