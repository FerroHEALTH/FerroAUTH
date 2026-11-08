// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The ring of keys a client signs its assertions with, and the JWK Set
//! (RFC 7517 §5) that publishes them.
//!
//! One key signs every assertion: the current key. A previous key stays
//! published, never signing, so an assertion it signed before a rotation
//! still verifies: for an overlap window, or until the ring is built again
//! without it. A next key is published ahead of a rotation, never signing,
//! so an authorization server that reads the set before the rotation
//! already holds the key the client signs with after it. Each key is
//! published under its `kid`, the RFC 7638 thumbprint unless one is
//! configured ([`AssertionKey::from_pem`]). The ring is shared as an `Arc`
//! by every grant and by a product's own signer. No specification governs
//! the rotation: our own design.

use std::time::Duration;
use std::time::Instant;

use crate::client::assertion::AssertionKey;

/// A ring that cannot be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyRingError {
    /// The previous key is the current key, so one key would be published
    /// under two roles.
    #[error("the previous key is the current key (kid {kid})")]
    SameKey {
        /// The `kid` both keys have.
        kid: String,
    },
    /// The next key is the current or the previous key.
    #[error("the next key is already the current or the previous key (kid {kid})")]
    NextReused {
        /// The `kid` the keys share.
        kid: String,
    },
}

/// The current signing key, the previous one while it stays published, and
/// the next one ahead of a rotation.
///
/// `Debug` shows each key's algorithm and `kid`, never a key.
#[derive(Debug, Clone)]
pub struct KeyRing {
    /// The key every assertion is signed with.
    current: AssertionKey,
    /// The previous key and the instant its overlap ends, `None` for a key
    /// published until the ring is built again without it.
    previous: Option<(AssertionKey, Option<Instant>)>,
    /// The key a later rotation makes current.
    next: Option<AssertionKey>,
}

impl KeyRing {
    /// Returns a ring that signs with `current` and publishes it alone.
    #[must_use]
    pub const fn new(current: AssertionKey) -> Self {
        Self {
            current,
            previous: None,
            next: None,
        }
    }

    /// Returns this ring publishing `previous` for `overlap` from now, never
    /// signing with it.
    ///
    /// # Errors
    ///
    /// Returns [`KeyRingError::SameKey`] when `previous` is the current key.
    pub fn with_previous_for(
        self,
        previous: AssertionKey,
        overlap: Duration,
    ) -> Result<Self, KeyRingError> {
        // NOTE: no specification governs this: our own design; a window past the
        // range of the clock never ends, so the previous key stays published.
        let until = Instant::now().checked_add(overlap);
        self.with_previous(previous, until)
    }

    /// Returns this ring publishing `previous` for as long as the ring
    /// lives, never signing with it.
    ///
    /// # Errors
    ///
    /// Returns [`KeyRingError::SameKey`] when `previous` is the current key.
    pub fn with_previous_until_removed(self, previous: AssertionKey) -> Result<Self, KeyRingError> {
        self.with_previous(previous, None)
    }

    /// Returns this ring publishing `next` for as long as it lives, never
    /// signing with it.
    ///
    /// # Errors
    ///
    /// Returns [`KeyRingError::NextReused`] when `next` is the current or the
    /// previous key.
    pub fn with_next(mut self, next: AssertionKey) -> Result<Self, KeyRingError> {
        let reused = next.kid() == self.current.kid()
            || self
                .previous
                .as_ref()
                .is_some_and(|(previous, _)| previous.kid() == next.kid());
        if reused {
            return Err(KeyRingError::NextReused {
                kid: next.kid().to_owned(),
            });
        }
        self.next = Some(next);
        Ok(self)
    }

    /// Returns this ring with `previous` published until `until`.
    fn with_previous(
        mut self,
        previous: AssertionKey,
        until: Option<Instant>,
    ) -> Result<Self, KeyRingError> {
        if previous.kid() == self.current.kid() {
            return Err(KeyRingError::SameKey {
                kid: previous.kid().to_owned(),
            });
        }
        self.previous = Some((previous, until));
        Ok(self)
    }

    /// Returns the key every assertion is signed with.
    #[must_use]
    pub const fn current(&self) -> &AssertionKey {
        &self.current
    }

    /// Returns the previous key while it is published at `now`.
    #[must_use]
    pub fn previous_at(&self, now: Instant) -> Option<&AssertionKey> {
        self.previous
            .as_ref()
            .filter(|(_, until)| until.is_none_or(|until| now < until))
            .map(|(key, _)| key)
    }

    /// Returns the previous key the ring was built with, published or not.
    #[must_use]
    pub fn retiring(&self) -> Option<&AssertionKey> {
        self.previous.as_ref().map(|(key, _)| key)
    }

    /// Returns the key published ahead of a rotation.
    #[must_use]
    pub const fn next(&self) -> Option<&AssertionKey> {
        self.next.as_ref()
    }

    /// Returns the JWK Set published at `now`: the current key, then the
    /// previous one while it is published, then the next one (RFC 7517 §5).
    #[must_use]
    pub fn published_at(&self, now: Instant) -> serde_json::Value {
        let keys: Vec<&AssertionKey> = std::iter::once(&self.current)
            .chain(self.previous_at(now))
            .chain(self.next.as_ref())
            .collect();
        crate::client::assertion::jwk_set(&keys)
    }

    /// Returns the JWK Set published now, as [`KeyRing::published_at`] does.
    #[must_use]
    pub fn published(&self) -> serde_json::Value {
        self.published_at(Instant::now())
    }
}

impl From<AssertionKey> for KeyRing {
    fn from(current: AssertionKey) -> Self {
        Self::new(current)
    }
}
