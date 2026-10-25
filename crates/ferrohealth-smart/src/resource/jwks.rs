// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The authorization server's signing keys (RFC 7517), read at boot, read
//! again when they are older than their maximum age, and read again when a
//! token names a key the set does not hold.
//!
//! An unknown `kid` is how a key rotation reaches the resource server, so it
//! triggers one read of the set; a second unknown `kid` within the configured
//! interval reads nothing, so a stream of forged `kid`s cannot turn the
//! product into a load on the authorization server. A read that fails keeps
//! the previous set in use for the keys it holds and is not repeated inside
//! the interval (no specification governs the cache: our own design).
//! A set in which any object repeats a member name is refused (RFC 8259 §4).

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

#[cfg(feature = "fetch")]
use http::StatusCode;
use jsonwebtoken::Algorithm;
use jsonwebtoken::AlgorithmFamily;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::AlgorithmParameters;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::jwk::KeyOperations;
use jsonwebtoken::jwk::PublicKeyUse;
use serde::Deserialize;
#[cfg(feature = "fetch")]
use url::Url;

#[cfg(feature = "fetch")]
use crate::metadata::Http;
use crate::resource::ResourceError;

/// Where a key set is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// The `jwks_uri` the issuer's metadata names, read behind the `fetch`
    /// feature.
    #[cfg(feature = "fetch")]
    Uri(Url),
    /// A JWK Set file handed over out of band (`jwks_file`), re-read on the
    /// same schedule and never combined with a fetched set.
    File(PathBuf),
}

impl std::fmt::Display for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "fetch")]
            Self::Uri(url) => write!(f, "{url}"),
            Self::File(path) => write!(f, "{}", path.display()),
        }
    }
}

/// One signing key of the set.
#[derive(Clone)]
struct Key {
    /// The key's `kid`, when it names one.
    kid: Option<String>,
    /// The key's `alg`, when it names one.
    alg: Option<Algorithm>,
    /// The algorithm family the key belongs to.
    family: AlgorithmFamily,
    /// The verification key.
    verifier: DecodingKey,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .finish_non_exhaustive()
    }
}

/// The JWK Set document (RFC 7517 §5), each member read on its own.
#[derive(Deserialize)]
struct Document {
    /// The keys, as JSON objects.
    keys: Vec<serde_json::Value>,
}

/// The keys as last read.
#[derive(Debug)]
struct Cached {
    /// The usable signing keys.
    keys: Arc<[Key]>,
    /// When they were read.
    read_at: Instant,
    /// When a read was last tried, whether or not it succeeded.
    tried_at: Instant,
}

/// The key set of one authorization server.
#[derive(Debug)]
pub(super) struct KeySet {
    /// The engine a fetched set is read with.
    #[cfg(feature = "fetch")]
    http: Http,
    /// Where the set comes from.
    source: KeySource,
    /// How long a held set is used before it is read again.
    max_age: Duration,
    /// The shortest time between two reads an unknown `kid` or a failure
    /// triggers.
    interval: Duration,
    /// The keys as last read; the write lock is held across a read of the
    /// set, so concurrent misses share one fetch.
    cached: tokio::sync::RwLock<Cached>,
}

impl KeySet {
    /// Reads the set at `source`.
    pub(super) async fn load(
        #[cfg(feature = "fetch")] http: Http,
        source: KeySource,
        max_age: Duration,
        interval: Duration,
    ) -> Result<Self, ResourceError> {
        let keys = fetch(
            #[cfg(feature = "fetch")]
            &http,
            &source,
        )
        .await?;
        let now = Instant::now();
        Ok(Self {
            #[cfg(feature = "fetch")]
            http,
            source,
            max_age,
            interval,
            cached: tokio::sync::RwLock::new(Cached {
                keys: Arc::from(keys),
                read_at: now,
                tried_at: now,
            }),
        })
    }

    /// Returns how many usable keys the set holds.
    pub(super) async fn len(&self) -> usize {
        self.cached.read().await.keys.len()
    }

    /// Returns where the set comes from.
    pub(super) const fn source(&self) -> &KeySource {
        &self.source
    }

    /// Returns the key a token signed with `alg` under `kid` verifies with.
    ///
    /// A held set older than its maximum age is read again first; a miss
    /// reads the set again unless it was read within the interval.
    /// `Ok(None)` is a token no key of the set verifies, and an error a set
    /// that could not be read when a key was needed.
    pub(super) async fn find(
        &self,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> Result<Option<DecodingKey>, ResourceError> {
        {
            let cached = self.cached.read().await;
            if cached.read_at.elapsed() < self.max_age
                && let Some(key) = select(&cached.keys, kid, alg)
            {
                return Ok(Some(key));
            }
        }
        let mut cached = self.cached.write().await;
        let mut outcome = Ok(());
        if cached.read_at.elapsed() >= self.max_age {
            outcome = self.refresh(&mut cached).await;
        }
        if let Some(key) = select(&cached.keys, kid, alg) {
            return Ok(Some(key));
        }
        if cached.tried_at.elapsed() < self.interval {
            return outcome.map(|()| None);
        }
        tracing::info!(source = %self.source, "a token names a key the set does not hold; reading the set again");
        self.refresh(&mut cached).await?;
        Ok(select(&cached.keys, kid, alg))
    }

    /// Reads the set into `cached`, unless a read was tried within the
    /// interval, keeping the held keys when the read fails.
    async fn refresh(&self, cached: &mut Cached) -> Result<(), ResourceError> {
        // NOTE: no specification governs this: our own design, a failed read
        // is not repeated inside the interval, so an issuer that is down is
        // asked once per interval, not once per token.
        if cached.tried_at.elapsed() < self.interval && cached.tried_at != cached.read_at {
            return Err(ResourceError::KeySetBackoff {
                origin: self.source.clone(),
            });
        }
        cached.tried_at = Instant::now();
        match fetch(
            #[cfg(feature = "fetch")]
            &self.http,
            &self.source,
        )
        .await
        {
            Ok(keys) => {
                cached.keys = Arc::from(keys);
                cached.read_at = cached.tried_at;
                Ok(())
            }
            Err(error) => {
                tracing::warn!(source = %self.source, error = %error, "the key set could not be read; the held keys stay in use");
                Err(error)
            }
        }
    }
}

/// Returns the key of `keys` that verifies `alg` under `kid`.
///
/// A token without a `kid` (RFC 7515 §4.1.4 makes it optional) verifies with
/// the one key of its family when the set holds exactly one; two or more
/// candidates verify nothing, so a rotation never decides which key
/// verifies a request.
fn select(keys: &[Key], kid: Option<&str>, alg: Algorithm) -> Option<DecodingKey> {
    let mut candidates = keys
        .iter()
        .filter(|key| key.family == alg.family() && key.alg.is_none_or(|named| named == alg));
    if let Some(kid) = kid {
        return candidates
            .find(|key| key.kid.as_deref() == Some(kid))
            .map(|key| key.verifier.clone());
    }
    let only = candidates.next()?;
    candidates.next().is_none().then(|| only.verifier.clone())
}

/// Reads the set at `source` and keeps its usable signing keys.
async fn fetch(
    #[cfg(feature = "fetch")] http: &Http,
    source: &KeySource,
) -> Result<Vec<Key>, ResourceError> {
    let body =
        match source {
            #[cfg(feature = "fetch")]
            KeySource::Uri(url) => {
                let (url, status, body) = http.get(url.clone()).await?;
                if status != StatusCode::OK {
                    return Err(ResourceError::KeySetStatus { url, status, body });
                }
                body
            }
            KeySource::File(path) => tokio::fs::read_to_string(path).await.map_err(|source| {
                ResourceError::KeySetFile {
                    path: path.clone(),
                    source,
                }
            })?,
        };
    if let Err(error) = crate::metadata::repeats_no_name(body.as_bytes()) {
        // NOTE: RFC 8259 §4, only the repeated-name refusal reads as a data
        // error, so any other failure is a body that is no JSON at all.
        if error.classify() == serde_json::error::Category::Data {
            return Err(ResourceError::KeySetRepeatedName {
                origin: source.clone(),
                error,
            });
        }
        return Err(ResourceError::KeySet {
            origin: source.clone(),
            error,
        });
    }
    let document: Document =
        serde_json::from_str(&body).map_err(|error| ResourceError::KeySet {
            origin: source.clone(),
            error,
        })?;
    Ok(document.keys.iter().filter_map(usable).collect())
}

/// Returns the signing key `member` describes.
///
/// A member whose `use` is not `sig` (RFC 7517 §4.2), whose `key_ops` lack
/// `verify` (§4.3), that is a symmetric key, whose `alg` is no signature
/// algorithm, or that this reader cannot load verifies no token.
// NOTE: RFC 7517 §5 has a reader ignore a set member it does not understand,
// so such a member is legitimately absent here rather than a defective set.
fn usable(member: &serde_json::Value) -> Option<Key> {
    let alg = match member.get("alg").and_then(serde_json::Value::as_str) {
        None => None,
        Some(name) => Some(Algorithm::from_str(name).ok()?),
    };
    let jwk: Jwk = serde_json::from_value(member.clone()).ok()?;
    if jwk
        .common
        .public_key_use
        .as_ref()
        .is_some_and(|key_use| *key_use != PublicKeyUse::Signature)
    {
        return None;
    }
    if jwk
        .common
        .key_operations
        .as_ref()
        .is_some_and(|operations| !operations.contains(&KeyOperations::Verify))
    {
        return None;
    }
    let family = match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => AlgorithmFamily::Rsa,
        AlgorithmParameters::EllipticCurve(_) => AlgorithmFamily::Ec,
        AlgorithmParameters::OctetKeyPair(_) => AlgorithmFamily::Ed,
        AlgorithmParameters::OctetKey(_) | _ => return None,
    };
    let verifier = DecodingKey::from_jwk(&jwk).ok()?;
    Some(Key {
        kid: jwk.common.key_id,
        alg,
        family,
        verifier,
    })
}

#[cfg(test)]
mod tests {
    use super::usable;

    const N: &str = "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw";

    #[test]
    fn a_key_for_another_use_or_operation_and_a_symmetric_key_verify_nothing() {
        let encryption =
            serde_json::json!({ "kty": "RSA", "use": "enc", "kid": "e", "n": N, "e": "AQAB" });
        assert!(usable(&encryption).is_none());
        let signing_only = serde_json::json!({ "kty": "RSA", "key_ops": ["sign"], "kid": "s", "n": N, "e": "AQAB" });
        assert!(usable(&signing_only).is_none());
        let verifying = serde_json::json!({ "kty": "RSA", "use": "sig", "key_ops": ["verify"], "kid": "v", "n": N, "e": "AQAB" });
        assert!(usable(&verifying).is_some());
        let symmetric = serde_json::json!({ "kty": "oct", "k": "c2VjcmV0", "kid": "s" });
        assert!(usable(&symmetric).is_none());
    }
}
