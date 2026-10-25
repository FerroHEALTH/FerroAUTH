// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! HTTP Basic authentication (RFC 7617): a credential verified against a
//! store of Argon2id hashes, and a credential sent to an upstream.
//!
//! Only the PHC hash of a password is ever held; verification is `argon2`'s,
//! never a comparison of our own. An unknown user still pays the key
//! derivation against a decoy hash, so the response time carries no
//! account-existence signal (no specification governs the hash or the
//! decoy: our own design, after the OWASP Password Storage Cheat Sheet).
//! A Basic user carries the scope string its configuration grants it, so
//! the same check serves a Basic caller and a bearer caller.

use std::collections::BTreeMap;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use argon2::Argon2;
use argon2::PasswordHash;
use argon2::PasswordVerifier;
use aws_lc_rs::hmac;
use aws_lc_rs::rand::SystemRandom;
use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::GeneralPurpose;
use base64::engine::GeneralPurposeConfig;
use http::HeaderValue;
use secrecy::ExposeSecret;
use secrecy::SecretString;

use crate::refusal::Reason;
use crate::scope::is_scope_token;

/// The RFC 4648 §4 decoder of the RFC 7617 §2 credential, padded only:
/// RFC 7617 defers to RFC 4648 §4, and RFC 4648 §3.2 requires the pad
/// characters "unless the specification referring to this document
/// explicitly states otherwise", which RFC 7617 does not. A non-alphabet
/// byte, interior padding, or non-canonical trailing bits is refused too.
static BASIC_B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// The encoder of an outgoing credential, the same alphabet, padded.
static BASIC_B64_ENCODE: GeneralPurpose =
    GeneralPurpose::new(&alphabet::STANDARD, GeneralPurposeConfig::new());

/// The PHC verified when no configured user matches the presented name.
///
/// It is derived at the OWASP Password Storage Cheat Sheet §Argon2id floor,
/// so the work matches a real verification; a fixed salt, because nothing
/// verifies against it.
static ENUMERATION_DEFENCE_PHC: LazyLock<Option<String>> = LazyLock::new(|| {
    let params = argon2::Params::new(19_456, 2, 1, None).ok()?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2::password_hash::PasswordHasher::hash_password_with_salt(
        &argon2,
        b"no-such-user-placeholder",
        b"ferrohealth-enumeration-defence",
    )
    .ok()
    .map(|hash| hash.to_string())
});

/// A store entry or an outgoing credential that does not hold.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The hash of `username` is not a PHC string `argon2` can read.
    #[error("the password hash of user {username:?} is not a PHC string")]
    Malformed {
        /// The user whose hash is malformed.
        username: String,
    },
    /// The hash of `username` names an algorithm other than Argon2id.
    #[error("the password hash of user {username:?} is {found}, not argon2id")]
    Algorithm {
        /// The user whose hash is of another algorithm.
        username: String,
        /// The algorithm the hash names.
        found: String,
    },
    /// The user-id is empty, carries a colon or carries a control character,
    /// which RFC 7617 §2 forbids.
    #[error("the user-id {username:?} is empty or carries a colon or a control character")]
    UserId {
        /// The user-id.
        username: String,
    },
    /// A scope token of `username` is outside the RFC 6749 §3.3 character
    /// set.
    #[error("the scope {scope:?} of user {username:?} is outside the RFC 6749 scope character set")]
    Scope {
        /// The user.
        username: String,
        /// The scope token.
        scope: String,
    },
    /// A role of `username` is empty or carries whitespace or a control
    /// character.
    #[error("a role of user {username:?} is empty or carries whitespace or a control character")]
    Role {
        /// The user.
        username: String,
        /// The role.
        role: String,
    },
    /// Roles are granted to a user the store does not admit.
    #[error("roles are granted to the user {username:?}, whom the store does not admit")]
    UnknownUser {
        /// The user.
        username: String,
    },
    /// The key of the verified-credential cache could not be drawn from
    /// the system's random source.
    #[error("the key of the verified-credential cache could not be drawn")]
    CacheKey,
}

/// A credential that does not hold.
///
/// Every failure on the credential path is this one outcome, deliberately:
/// a caller must not learn from the `401` whether the header was malformed,
/// the user unknown, or the password wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the Basic credential does not hold")]
pub struct InvalidCredential;

/// The user a credential authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The user-id.
    pub username: String,
    /// The space-delimited scope the user's configuration grants it
    /// (RFC 6749 §3.3).
    pub scope: String,
    /// The roles the user's configuration grants it ([`crate::roles`]).
    pub roles: Vec<String>,
    /// Whether the credential was admitted from the verified-credential
    /// cache, without the key derivation.
    pub cached: bool,
}

/// One user of the store.
#[derive(Debug)]
struct Entry {
    /// The Argon2id PHC string of the password.
    hash: SecretString,
    /// The scope the user is granted.
    scope: String,
    /// The roles the user is granted.
    roles: Vec<String>,
}

/// The users a surface admits with HTTP Basic, by name, each with the
/// Argon2id PHC hash of its password and the scope it is granted.
#[derive(Debug, Default)]
pub struct PasswordStore {
    /// Each user, by user-id.
    users: BTreeMap<String, Entry>,
    /// The credentials verified within their lifetime, when the store keeps
    /// them.
    cache: Option<VerifiedCache>,
}

/// The most credentials a [`VerifiedCache`] holds; a full cache admits no
/// new entry until one expires (no specification governs the bound: our own
/// design).
const MAX_CACHED: usize = 4096;

/// The credentials that verified, each kept for the cache's lifetime under
/// a keyed hash of `user-id:password`, so the password itself is never
/// held.
struct VerifiedCache {
    /// How long a verified credential is kept.
    ttl: Duration,
    /// The HMAC key the entries are named with, drawn when the cache is
    /// built.
    key: hmac::Key,
    /// Each entry's expiry and user, by the keyed hash of its credential.
    entries: Mutex<BTreeMap<Vec<u8>, (Instant, Verified)>>,
}

impl std::fmt::Debug for VerifiedCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedCache")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl VerifiedCache {
    /// Returns an empty cache keeping a credential for `ttl`.
    fn new(ttl: Duration) -> Result<Self, StoreError> {
        let key = hmac::Key::generate(hmac::HMAC_SHA256, &SystemRandom::new())
            .map_err(|_unspecified| StoreError::CacheKey)?;
        Ok(Self {
            ttl,
            key,
            entries: Mutex::new(BTreeMap::new()),
        })
    }

    /// Returns the name of the credential `user_pass` in the cache.
    fn name(&self, user_pass: &str) -> Vec<u8> {
        hmac::sign(&self.key, user_pass.as_bytes())
            .as_ref()
            .to_vec()
    }

    /// Returns the user of `user_pass` when the cache holds it unexpired.
    fn get(&self, user_pass: &str) -> Option<Verified> {
        let name = self.name(user_pass);
        // NOTE: no specification governs the cache: our own design, and a
        // poisoned lock is a miss, which only costs the key derivation.
        let entries = self.entries.lock().ok()?;
        let (expires, verified) = entries.get(&name)?;
        (Instant::now() < *expires).then(|| verified.clone())
    }

    /// Keeps `verified` as the user of `user_pass` for the cache's lifetime,
    /// dropping the expired entries first.
    fn put(&self, user_pass: &str, verified: &Verified) {
        let now = Instant::now();
        let Some(expires) = now.checked_add(self.ttl) else {
            return;
        };
        let name = self.name(user_pass);
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|_name, (expiry, _verified)| *expiry > now);
            if entries.len() < MAX_CACHED {
                entries.insert(name, (expires, verified.clone()));
            }
        }
    }
}

impl PasswordStore {
    /// Returns an empty store, which admits no one.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns this store keeping a credential that verified for `ttl`, so a
    /// repeat request within it skips the key derivation; a zero `ttl`
    /// keeps none.
    ///
    /// Only a credential that verified is kept, named by an HMAC-SHA-256 of
    /// `user-id:password` under a key drawn here, never the password
    /// itself, so a wrong password always pays the derivation. No
    /// specification governs the cache: our own design.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CacheKey`] when the key cannot be drawn.
    pub fn with_cache(mut self, ttl: Duration) -> Result<Self, StoreError> {
        self.cache = if ttl.is_zero() {
            None
        } else {
            Some(VerifiedCache::new(ttl)?)
        };
        Ok(self)
    }

    /// Returns this store admitting `username` with the password `hash`
    /// names, an Argon2id PHC string, granted the space-delimited `scope`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for a hash that does not parse or names
    /// another algorithm, a user-id that is empty or carries a colon or a
    /// control character, or a scope token outside RFC 6749 §3.3.
    pub fn with_user(
        mut self,
        username: impl Into<String>,
        hash: SecretString,
        scope: impl Into<String>,
    ) -> Result<Self, StoreError> {
        let username = username.into();
        if !user_id_ok(&username) {
            return Err(StoreError::UserId { username });
        }
        let scope = scope.into();
        if let Some(bad) = scope
            .split(' ')
            .filter(|token| !token.is_empty())
            .find(|token| !is_scope_token(token))
        {
            return Err(StoreError::Scope {
                scope: bad.to_owned(),
                username,
            });
        }
        let parsed = PasswordHash::new(hash.expose_secret()).map_err(|_malformed| {
            StoreError::Malformed {
                username: username.clone(),
            }
        })?;
        if parsed.algorithm.as_str() != "argon2id" {
            return Err(StoreError::Algorithm {
                found: parsed.algorithm.as_str().to_owned(),
                username,
            });
        }
        self.users.insert(
            username,
            Entry {
                hash,
                scope,
                roles: Vec::new(),
            },
        );
        Ok(self)
    }

    /// Returns this store granting `roles` to `username`, a user it already
    /// admits.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownUser`] when the store admits no such
    /// user, and [`StoreError::Role`] for a role that is empty or carries
    /// whitespace or a control character ([`crate::roles::is_role`]).
    pub fn with_roles(mut self, username: &str, roles: Vec<String>) -> Result<Self, StoreError> {
        if let Some(bad) = roles.iter().find(|role| !crate::roles::is_role(role)) {
            return Err(StoreError::Role {
                username: username.to_owned(),
                role: bad.clone(),
            });
        }
        let entry = self
            .users
            .get_mut(username)
            .ok_or_else(|| StoreError::UnknownUser {
                username: username.to_owned(),
            })?;
        entry.roles = roles;
        Ok(self)
    }

    /// Returns how many users the store admits.
    #[must_use]
    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Returns whether the store admits no one.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    /// Returns the user a `Basic <credentials>` header value authenticates.
    ///
    /// The scheme is compared case-insensitively (RFC 9110 §11.1) and the
    /// octets are read as UTF-8 (RFC 7617 §2.1). The key derivation runs on
    /// the calling thread and takes tens of milliseconds, so an async caller
    /// runs it on a blocking thread.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCredential`] for a malformed header, an unknown user,
    /// or a password that does not match.
    pub fn verify(&self, header: &HeaderValue) -> Result<Verified, InvalidCredential> {
        self.check(header).map_err(|_reason| InvalidCredential)
    }

    /// Returns the user a `Basic <credentials>` header value authenticates,
    /// or which check refused it, for the gate's log.
    ///
    /// A credential the cache holds within its lifetime is admitted without
    /// the key derivation; one that verifies is added to it.
    pub(crate) fn check(&self, header: &HeaderValue) -> Result<Verified, Reason> {
        let raw = header.to_str().map_err(|_opaque| Reason::BasicMalformed)?;
        let (scheme, encoded) = raw.split_once(' ').ok_or(Reason::BasicMalformed)?;
        if !scheme.eq_ignore_ascii_case("Basic") {
            return Err(Reason::BasicMalformed);
        }
        let decoded = BASIC_B64
            .decode(encoded.trim())
            .map_err(|_malformed| Reason::BasicMalformed)?;
        let decoded = String::from_utf8(decoded).map_err(|_opaque| Reason::BasicMalformed)?;
        let (username, password) = decoded.split_once(':').ok_or(Reason::BasicMalformed)?;
        if let Some(verified) = self.cache.as_ref().and_then(|cache| cache.get(&decoded)) {
            return Ok(Verified {
                cached: true,
                ..verified
            });
        }
        let verified = self
            .verify_password(username, password)
            .map_err(|_invalid| Reason::BasicRejected)?;
        if let Some(cache) = &self.cache {
            cache.put(&decoded, &verified);
        }
        Ok(verified)
    }

    /// Returns `username` when `password` is the one its hash names.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCredential`] for an unknown user or a password that
    /// does not match.
    pub fn verify_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Verified, InvalidCredential> {
        let Some(entry) = self.users.get(username) else {
            if let Some(phc) = ENUMERATION_DEFENCE_PHC.as_deref()
                && let Ok(decoy) = PasswordHash::new(phc)
            {
                // The outcome is discarded deliberately: only the work matters.
                let _outcome = Argon2::default().verify_password(password.as_bytes(), &decoy);
            }
            return Err(InvalidCredential);
        };
        let parsed = PasswordHash::new(entry.hash.expose_secret())
            .map_err(|_malformed| InvalidCredential)?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_mismatch| InvalidCredential)?;
        Ok(Verified {
            username: username.to_owned(),
            scope: entry.scope.clone(),
            roles: entry.roles.clone(),
            cached: false,
        })
    }
}

/// Returns whether `username` is a user-id RFC 7617 §2 admits: not empty,
/// no colon, no control character.
fn user_id_ok(username: &str) -> bool {
    !username.is_empty() && !username.chars().any(|c| c == ':' || c.is_control())
}

/// A credential sent to an upstream with HTTP Basic.
///
/// The `Debug` rendering never carries the password.
#[derive(Clone)]
pub struct Credential {
    /// The user-id.
    username: String,
    /// The password.
    password: SecretString,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl Credential {
    /// Returns the credential of `username` with `password`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UserId`] for a user-id that is empty or carries
    /// a colon or a control character, which RFC 7617 §2 forbids.
    pub fn new(username: impl Into<String>, password: SecretString) -> Result<Self, StoreError> {
        let username = username.into();
        if !user_id_ok(&username) {
            return Err(StoreError::UserId { username });
        }
        Ok(Self { username, password })
    }

    /// Returns the user-id.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Returns the password, still behind [`SecretString`], for an HTTP
    /// client that takes the user-id and the password itself rather than
    /// the field value of [`Credential::header_value`].
    ///
    /// The value is read only through [`ExposeSecret`] at the call site, and
    /// its `Debug` rendering stays redacted.
    #[must_use]
    pub const fn password(&self) -> &SecretString {
        &self.password
    }

    /// Returns the `Authorization` field value of the credential (RFC 7617
    /// §2, UTF-8 then base64), marked sensitive so a header `Debug`
    /// rendering never shows it.
    #[must_use]
    pub fn header_value(&self) -> HeaderValue {
        let user_pass = format!("{}:{}", self.username, self.password.expose_secret());
        let encoded = BASIC_B64_ENCODE.encode(user_pass.as_bytes());
        // NOTE: RFC 4648 §4 emits only alphabet and pad characters, so the
        // value is always a legal field value and this never fails.
        let mut value = HeaderValue::from_str(&format!("Basic {encoded}"))
            .unwrap_or_else(|_never| HeaderValue::from_static("Basic"));
        value.set_sensitive(true);
        value
    }
}

#[cfg(test)]
mod tests {
    use super::{Credential, ENUMERATION_DEFENCE_PHC, InvalidCredential, PasswordStore, Verified};
    use crate::refusal::Reason;
    use argon2::password_hash::PasswordHasher;
    use argon2::{Argon2, PasswordHash};
    use base64::Engine as _;
    use http::HeaderValue;
    use secrecy::{ExposeSecret, SecretString};
    use std::time::Duration;

    fn hash(password: &str) -> SecretString {
        // A fixed salt keeps the test hermetic without a random source.
        SecretString::from(
            Argon2::default()
                .hash_password_with_salt(password.as_bytes(), b"synthetic-salt-16")
                .expect("the hash")
                .to_string(),
        )
    }

    fn store() -> PasswordStore {
        PasswordStore::new()
            .with_user("alice", hash("s3cret"), "system/*.rs")
            .expect("a well-formed hash")
    }

    fn header(scheme: &str, user: &str, password: &str) -> HeaderValue {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        HeaderValue::from_str(&format!("{scheme} {token}")).expect("a legal value")
    }

    fn raw(token: &str) -> HeaderValue {
        HeaderValue::from_str(&format!("Basic {token}")).expect("a legal value")
    }

    #[test]
    fn a_valid_credential_names_its_user_and_scope() {
        let verified = Verified {
            username: String::from("alice"),
            scope: String::from("system/*.rs"),
            roles: Vec::new(),
            cached: false,
        };
        assert_eq!(
            Ok(verified.clone()),
            store().verify(&header("Basic", "alice", "s3cret"))
        );
        assert_eq!(
            Ok(verified),
            store().verify(&header("basic", "alice", "s3cret"))
        );
    }

    #[test]
    fn a_verified_credential_is_cached_for_its_lifetime_and_a_wrong_one_never() {
        let store = store()
            .with_cache(Duration::from_secs(60))
            .expect("the cache key is drawn");
        let cache = store.cache.as_ref().expect("a cache");
        assert_eq!(None, cache.get("alice:s3cret"));
        assert!(store.verify(&header("Basic", "alice", "s3cret")).is_ok());
        assert_eq!(
            Some(String::from("alice")),
            cache.get("alice:s3cret").map(|verified| verified.username),
            "a repeat request skips the key derivation"
        );
        assert_eq!(
            Err(Reason::BasicRejected),
            store.check(&header("Basic", "alice", "nope"))
        );
        assert_eq!(
            None,
            cache.get("alice:nope"),
            "a wrong password is never kept"
        );
        assert_eq!(Err(Reason::BasicMalformed), store.check(&raw("QQ===")));
    }

    #[test]
    fn the_outcome_says_whether_the_cache_admitted_the_credential() {
        let cached = store()
            .with_cache(Duration::from_secs(60))
            .expect("the cache key is drawn");
        let first = cached
            .verify(&header("Basic", "alice", "s3cret"))
            .expect("verifies");
        assert!(!first.cached, "the first request pays the key derivation");
        let repeat = cached
            .verify(&header("Basic", "alice", "s3cret"))
            .expect("verifies");
        assert!(repeat.cached, "the repeat is admitted from the cache");
        let uncached = store();
        for _ in 0..2 {
            let verified = uncached
                .verify(&header("Basic", "alice", "s3cret"))
                .expect("verifies");
            assert!(!verified.cached, "no cache, never cached");
        }
    }

    #[test]
    fn a_cached_credential_expires_and_a_zero_lifetime_keeps_none() {
        let store = store()
            .with_cache(Duration::from_millis(1))
            .expect("the cache key is drawn");
        assert!(store.verify(&header("Basic", "alice", "s3cret")).is_ok());
        std::thread::sleep(Duration::from_millis(5));
        let cache = store.cache.as_ref().expect("a cache");
        assert_eq!(None, cache.get("alice:s3cret"), "expired");
        let none = PasswordStore::new()
            .with_cache(Duration::ZERO)
            .expect("no key needed");
        assert!(none.cache.is_none());
    }

    #[test]
    fn a_wrong_password_an_unknown_user_and_another_scheme_are_one_refusal() {
        assert_eq!(
            Err(InvalidCredential),
            store().verify(&header("Basic", "alice", "nope"))
        );
        assert_eq!(
            Err(InvalidCredential),
            store().verify(&header("Basic", "bob", "s3cret"))
        );
        assert_eq!(
            Err(InvalidCredential),
            store().verify(&header("Bearer", "alice", "s3cret"))
        );
    }

    #[test]
    fn an_unknown_user_pays_the_kdf_against_an_argon2id_decoy() {
        let phc = ENUMERATION_DEFENCE_PHC
            .as_deref()
            .expect("the decoy derives at the OWASP floor");
        let parsed = PasswordHash::new(phc).expect("the decoy parses");
        assert_eq!("argon2id", parsed.algorithm.as_str());
        let params = argon2::Params::try_from(&parsed).expect("the params");
        assert_eq!(19_456, params.m_cost());
        assert_eq!(2, params.t_cost());
        assert_eq!(1, params.p_cost());
        assert_eq!(
            Err(InvalidCredential),
            store().verify(&header("Basic", "no-such-user", "no-such-user-placeholder")),
            "the decoy never authenticates"
        );
    }

    #[test]
    fn the_padded_canonical_form_is_the_credential() {
        let padded = base64::engine::general_purpose::STANDARD.encode("alice:s3cre");
        assert!(padded.ends_with('='), "the fixture pads");
        assert_eq!(
            Err(InvalidCredential),
            store().verify(&raw(padded.trim_end_matches('=')))
        );
        assert_eq!(
            Err(InvalidCredential),
            store().verify(&raw("YWxpY2U6*zNjcmV0"))
        );
        assert_eq!(Err(InvalidCredential), store().verify(&raw("QQ===")));
        assert_eq!(
            Err(InvalidCredential),
            store().verify(&raw("YWx=pY2U6czNjcmV0"))
        );
    }

    #[test]
    fn a_store_refuses_a_bad_hash_user_id_or_scope() {
        assert!(
            PasswordStore::new()
                .with_user("alice", SecretString::from("not-a-phc"), "")
                .is_err()
        );
        assert!(
            PasswordStore::new()
                .with_user(
                    "alice",
                    SecretString::from("$pbkdf2-sha256$i=1000,l=32$c2FsdA$YWJj"),
                    ""
                )
                .is_err()
        );
        assert!(
            PasswordStore::new()
                .with_user("a:b", hash("x"), "")
                .is_err()
        );
        assert!(PasswordStore::new().with_user("", hash("x"), "").is_err());
        assert!(
            PasswordStore::new()
                .with_user("a\tb", hash("x"), "")
                .is_err()
        );
        assert!(
            PasswordStore::new()
                .with_user("a", hash("x"), "system/*.rs bad\"scope")
                .is_err()
        );
        assert!(PasswordStore::new().is_empty());
        assert_eq!(1, store().len());
    }

    #[test]
    fn an_outgoing_credential_is_rfc_7617_and_its_debug_hides_the_password() {
        let credential =
            Credential::new("ferro", SecretString::from("synthetic-pw")).expect("a legal user-id");
        let value = credential.header_value();
        assert_eq!(
            "Basic ZmVycm86c3ludGhldGljLXB3",
            value.to_str().expect("ASCII")
        );
        assert!(value.is_sensitive());
        assert!(!format!("{credential:?}").contains("synthetic-pw"));
        assert_eq!("ferro", credential.username());
        assert_eq!("synthetic-pw", credential.password().expose_secret());
        assert!(!format!("{:?}", credential.password()).contains("synthetic-pw"));
        assert!(Credential::new("fer:ro", SecretString::from("x")).is_err());
        let utf8 = Credential::new("Müller", SecretString::from("pässwörd")).expect("UTF-8");
        assert_eq!(
            "Basic TcO8bGxlcjpww6Rzc3fDtnJk",
            utf8.header_value().to_str().expect("ASCII")
        );
    }
}
