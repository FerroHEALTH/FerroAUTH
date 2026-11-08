// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Where the `jti` of each accepted `DPoP` proof is kept for the window the
//! proof is accepted in, so a replay of the proof is refused (RFC 9449
//! §11.1).
//!
//! The store is the product's: the [`ReplayStore`] trait, supplied as a
//! product supplies its own [`crate::resource::Verifier`]. The crate ships
//! [`MemoryReplayStore`], whose refusal holds within one process only. RFC
//! 9449 §11.1 notes that single use "may not always be feasible in practice,
//! e.g., when multiple servers behind a single endpoint have no shared
//! state": a product that runs more than one replica supplies a store all
//! of them share. Only `DPoP` proofs are recorded, never a bearer access
//! token, which is presented on many requests within its life (RFC 6750
//! §1.2).

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::SystemTime;

/// The key one proof's `jti` is recorded under: the base64url SHA-256 of
/// the `jti`, so a store holds a hash and never the value (RFC 9449 §11.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProofId(String);

impl ProofId {
    /// Returns the key of the proof whose `jti` is `jti`.
    pub(crate) fn of(jti: &str) -> Self {
        Self(crate::sender::sha256(jti.as_bytes()))
    }

    /// Returns the key as text, 43 base64url characters.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A store that could not answer whether a proof was seen.
///
/// The check answers it with `503`, so a store that fails never admits a
/// proof.
#[derive(Debug, thiserror::Error)]
#[error("the DPoP replay store could not record the proof")]
pub struct ReplayStoreError {
    /// What failed, the store's own error.
    #[source]
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl ReplayStoreError {
    /// Returns the failure of a store, caused by `source`.
    #[must_use]
    pub fn new(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            source: Box::new(source),
        }
    }
}

/// Where accepted `DPoP` proofs are recorded.
///
/// An implementation records `proof` and answers whether it was unseen in
/// one atomic step, so two requests that race with one proof are not both
/// admitted. It keeps the record at least until `until`, the end of the
/// window the proof is accepted in, and may drop it after.
pub trait ReplayStore: Send + Sync + 'static {
    /// Records `proof` until `until`, returning `true` when it was not
    /// recorded before and `false` for a replay.
    fn first_use<'a>(
        &'a self,
        proof: &'a ProofId,
        until: SystemTime,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ReplayStoreError>> + Send + 'a>>;
}

/// Each record's end, by key, and the same records in the order they end.
type Records<K, T> = (BTreeMap<K, T>, BTreeSet<(T, K)>);

/// Single-use records kept in memory, each until the end of its window:
/// the one in-memory store behind [`MemoryReplayStore`] and the eHDSI
/// assertion replay guard.
#[derive(Debug)]
pub(crate) struct Ledger<K, T> {
    /// The records.
    seen: Mutex<Records<K, T>>,
    /// The most records held at once.
    capacity: usize,
}

impl<K: Ord + Clone, T: Ord + Copy> Ledger<K, T> {
    /// Returns an empty ledger holding at most `capacity` records.
    pub(crate) const fn new(capacity: usize) -> Self {
        Self {
            seen: Mutex::new((BTreeMap::new(), BTreeSet::new())),
            capacity,
        }
    }

    /// Returns how many records the ledger holds.
    pub(crate) fn len(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .0
            .len()
    }

    /// Records `key` until `until`, as of `now`, dropping every record that
    /// ended first: `Some(true)` for a new record, `Some(false)` for one
    /// held, and `None` when `capacity` records inside their windows are
    /// held, so no record is forgotten inside its window.
    pub(crate) fn record(&self, key: &K, until: T, now: T) -> Option<bool> {
        let mut guard = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        let (by_key, by_end) = &mut *guard;
        while let Some((end, id)) = by_end.first().cloned() {
            if end >= now {
                break;
            }
            by_end.remove(&(end, id.clone()));
            by_key.remove(&id);
        }
        if by_key.contains_key(key) {
            return Some(false);
        }
        if by_key.len() >= self.capacity {
            return None;
        }
        by_key.insert(key.clone(), until);
        by_end.insert((until, key.clone()));
        Some(true)
    }
}

/// A [`ReplayStore`] in the memory of one process.
///
/// It refuses a replay to the process that recorded the proof alone: a
/// replay to another replica is admitted there (RFC 9449 §11.1). Records
/// are dropped once their window ends; when `capacity` records are held
/// and none has ended, a new proof is refused with `503` rather than an old
/// record dropped, so the store never forgets a proof inside its window (no
/// specification governs the bound: our own design).
#[derive(Debug)]
pub struct MemoryReplayStore {
    /// The records.
    ledger: Ledger<ProofId, SystemTime>,
}

impl Default for MemoryReplayStore {
    fn default() -> Self {
        Self::with_capacity(100_000)
    }
}

/// The failure of a [`MemoryReplayStore`] that holds its capacity of
/// records inside their windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the in-memory DPoP replay store holds its capacity of records")]
pub struct StoreFull;

impl MemoryReplayStore {
    /// Returns an empty store holding at most 100 000 records.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns an empty store holding at most `capacity` records.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            ledger: Ledger::new(capacity),
        }
    }

    /// Returns how many records the store holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ledger.len()
    }

    /// Returns whether the store holds no record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Records `proof` until `until`, as of `now`.
    fn record(
        &self,
        proof: &ProofId,
        until: SystemTime,
        now: SystemTime,
    ) -> Result<bool, StoreFull> {
        self.ledger.record(proof, until, now).ok_or(StoreFull)
    }
}

impl ReplayStore for MemoryReplayStore {
    fn first_use<'a>(
        &'a self,
        proof: &'a ProofId,
        until: SystemTime,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ReplayStoreError>> + Send + 'a>> {
        let outcome = self
            .record(proof, until, SystemTime::now())
            .map_err(ReplayStoreError::new);
        Box::pin(std::future::ready(outcome))
    }
}

#[cfg(test)]
mod tests {
    use super::{MemoryReplayStore, ProofId, StoreFull};
    use std::time::{Duration, SystemTime};

    #[test]
    fn a_proof_is_recorded_once_within_its_window() {
        let store = MemoryReplayStore::new();
        let now = SystemTime::now();
        let until = now + Duration::from_secs(60);
        let proof = ProofId::of("e1j3V_bKic8-LAEB");
        assert_eq!(Ok(true), store.record(&proof, until, now));
        assert_eq!(Ok(false), store.record(&proof, until, now), "a replay");
        assert_eq!(
            Ok(true),
            store.record(&ProofId::of("another"), until, now),
            "another jti"
        );
    }

    #[test]
    fn a_record_ends_with_its_window_and_a_full_store_refuses() {
        let store = MemoryReplayStore::with_capacity(1);
        let now = SystemTime::now();
        let first = ProofId::of("first");
        assert_eq!(Ok(true), store.record(&first, now, now));
        assert_eq!(
            Err(StoreFull),
            store.record(&ProofId::of("second"), now, now),
            "the first record is still inside its window"
        );
        let later = now + Duration::from_secs(1);
        assert_eq!(Ok(true), store.record(&ProofId::of("second"), later, later));
        assert_eq!(1, store.len(), "the ended record was dropped");
    }

    #[test]
    fn the_key_is_a_hash_of_the_jti() {
        let id = ProofId::of("-BwC3ESc6acc2lTc");
        assert_eq!(43, id.as_str().len());
        assert!(!id.as_str().contains("BwC3ESc6acc2lTc"));
    }
}
