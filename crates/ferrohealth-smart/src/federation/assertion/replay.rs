// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Where each admitted exchange of eHDSI assertions is kept for the window
//! it is accepted in, so the same exchange presented again is refused.
//!
//! RFC 7522 §3 (item 6) has an authorization server keep "the set of used
//! ID values for the length of time for which the Assertion would be
//! considered valid based on the applicable `NotOnOrAfter` instant". The unit
//! kept here is the exchange: the identity assertion alone, as the
//! discovery phase presents it, or the identity assertion with one
//! Treatment Relationship Confirmation. The identity assertion "always takes
//! the role of a Supporting Token" (eHDSI Messaging Profile 10.0.0 §5.5.1)
//! and is presented again with each TRC of its session (SAML Profile 10.0.0
//! §6, non-normative), so a record keyed by its `ID` alone would refuse the
//! session's second exchange; a TRC names one identity assertion, so each
//! TRC is admitted once.
//!
//! The store is the product's: the [`ReplayGuard`] trait, which
//! [`crate::federation::assertion::Validator::new`] requires, so no exchange
//! is checked without one. The crate ships [`MemoryReplayGuard`], whose
//! refusal holds within one process only: a product that runs more than one
//! replica supplies a store all of them share.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::PoisonError;

use jiff::Timestamp;

/// The key one exchange is recorded under: the base64url SHA-256 of the
/// issuer and `ID` of each assertion presented, so a store holds a hash of
/// fixed length and never the values.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExchangeId(String);

impl ExchangeId {
    /// Returns the key of the exchange of the identity assertion `identity`
    /// and, past the discovery phase, the TRC `treatment`, each an
    /// `(issuer, ID)` pair.
    pub(super) fn of(identity: (&str, &str), treatment: Option<(&str, &str)>) -> Self {
        let mut input = Vec::from(b"ehdsi-exchange".as_slice());
        let parts = [Some(identity.0), Some(identity.1)]
            .into_iter()
            .chain([treatment.map(|t| t.0), treatment.map(|t| t.1)]);
        for part in parts {
            // NOTE: no specification governs the encoding: each part is length-prefixed, so
            // no two exchanges share an input (our own design).
            match part {
                Some(part) => {
                    input.push(1);
                    input.extend_from_slice(&part.len().to_be_bytes());
                    input.extend_from_slice(part.as_bytes());
                }
                None => input.push(0),
            }
        }
        Self(crate::sender::sha256(&input))
    }

    /// Returns the key as text, 43 base64url characters.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A store that could not answer whether an exchange was seen.
///
/// The exchange fails with it, so a store that fails never admits an
/// exchange.
#[derive(Debug, thiserror::Error)]
#[error("the eHDSI assertion replay store could not record the exchange")]
pub struct ReplayGuardError {
    /// What failed, the store's own error.
    #[source]
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl ReplayGuardError {
    /// Returns the failure of a store, caused by `source`.
    #[must_use]
    pub fn new(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            source: Box::new(source),
        }
    }
}

/// Where admitted exchanges are recorded.
///
/// An implementation records `exchange` and answers whether it was unseen
/// in one atomic step, so two requests that race with one exchange are not
/// both admitted. It keeps the record at least until `until`, the end of
/// the window the exchange is accepted in, and may drop it after.
pub trait ReplayGuard: Send + Sync + 'static {
    /// Records `exchange` until `until`, returning `true` when it was not
    /// recorded before and `false` for a replay.
    fn first_use<'a>(
        &'a self,
        exchange: &'a ExchangeId,
        until: Timestamp,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ReplayGuardError>> + Send + 'a>>;
}

/// The records of a [`MemoryReplayGuard`].
#[derive(Debug, Default)]
struct Seen {
    /// Each recorded exchange and when its record ends.
    by_id: BTreeMap<ExchangeId, Timestamp>,
    /// The same records in the order they end.
    by_end: BTreeSet<(Timestamp, ExchangeId)>,
}

/// A [`ReplayGuard`] in the memory of one process.
///
/// It refuses a replay to the process that recorded the exchange alone.
/// Records are dropped once their window ends; when `capacity` records are
/// held and none has ended, a new exchange fails rather than an old record
/// being dropped, so the store never forgets an exchange inside its window
/// (no specification governs the bound: our own design).
#[derive(Debug)]
pub struct MemoryReplayGuard {
    /// The records.
    seen: Mutex<Seen>,
    /// The most records held at once.
    capacity: usize,
}

impl Default for MemoryReplayGuard {
    fn default() -> Self {
        Self {
            seen: Mutex::new(Seen::default()),
            capacity: 100_000,
        }
    }
}

/// The failure of a [`MemoryReplayGuard`] that holds its capacity of
/// records inside their windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the in-memory eHDSI assertion replay store holds its capacity of records")]
pub struct GuardFull;

impl MemoryReplayGuard {
    /// Returns an empty store holding at most 100 000 records.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns an empty store holding at most `capacity` records.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            ..Self::default()
        }
    }

    /// Returns how many records the store holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .by_id
            .len()
    }

    /// Returns whether the store holds no record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Records `exchange` until `until`, as of `now`.
    fn record(
        &self,
        exchange: &ExchangeId,
        until: Timestamp,
        now: Timestamp,
    ) -> Result<bool, GuardFull> {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        while let Some((end, id)) = seen.by_end.first().cloned() {
            if end >= now {
                break;
            }
            seen.by_end.remove(&(end, id.clone()));
            seen.by_id.remove(&id);
        }
        if seen.by_id.contains_key(exchange) {
            return Ok(false);
        }
        if seen.by_id.len() >= self.capacity {
            return Err(GuardFull);
        }
        seen.by_id.insert(exchange.clone(), until);
        seen.by_end.insert((until, exchange.clone()));
        Ok(true)
    }
}

impl ReplayGuard for MemoryReplayGuard {
    fn first_use<'a>(
        &'a self,
        exchange: &'a ExchangeId,
        until: Timestamp,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ReplayGuardError>> + Send + 'a>> {
        let outcome = self
            .record(exchange, until, Timestamp::now())
            .map_err(ReplayGuardError::new);
        Box::pin(std::future::ready(outcome))
    }
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;

    use super::{ExchangeId, GuardFull, MemoryReplayGuard};

    fn at(second: i64) -> Timestamp {
        Timestamp::from_second(second).expect("a time")
    }

    #[test]
    fn an_exchange_is_recorded_once_within_its_window() {
        let guard = MemoryReplayGuard::new();
        let discovery = ExchangeId::of(("ncp-b", "ida"), None);
        let full = ExchangeId::of(("ncp-b", "ida"), Some(("ncp-b", "trc")));
        assert_eq!(Ok(true), guard.record(&discovery, at(100), at(0)));
        assert_eq!(
            Ok(false),
            guard.record(&discovery, at(100), at(0)),
            "a replay"
        );
        assert_eq!(Ok(true), guard.record(&full, at(100), at(0)), "a TRC");
        assert_eq!(Ok(false), guard.record(&full, at(100), at(0)), "a replay");
    }

    #[test]
    fn a_record_ends_with_its_window_and_a_full_store_refuses() {
        let guard = MemoryReplayGuard::with_capacity(1);
        let first = ExchangeId::of(("ncp-b", "first"), None);
        let second = ExchangeId::of(("ncp-b", "second"), None);
        assert_eq!(Ok(true), guard.record(&first, at(10), at(0)));
        assert_eq!(Err(GuardFull), guard.record(&second, at(10), at(0)));
        assert_eq!(Ok(true), guard.record(&second, at(20), at(11)));
        assert_eq!(1, guard.len(), "the ended record was dropped");
    }

    #[test]
    fn the_key_separates_its_parts_and_holds_no_value() {
        let key = ExchangeId::of(("ncp-b", "urn:uuid:ida"), Some(("ncp-b", "trc")));
        assert_eq!(43, key.as_str().len());
        assert!(!key.as_str().contains("ida"));
        assert_ne!(
            ExchangeId::of(("ab", "c"), None),
            ExchangeId::of(("a", "bc"), None)
        );
        assert_ne!(
            ExchangeId::of(("i", "d"), Some(("", ""))),
            ExchangeId::of(("i", "d"), None)
        );
    }
}
