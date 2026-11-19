// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What the in-memory caches of this crate hold, for a product's memory
//! metrics.
//!
//! Four caches grow with traffic: the verified-credential cache of
//! [`crate::basic::PasswordStore`], the token verdicts of
//! [`crate::resource::ResourceServer`], the response cache of
//! [`crate::resource::introspection::Introspector`] and the records of
//! [`crate::sender::replay::MemoryReplayStore`]. Each reports a
//! [`CacheUsage`], which a product copies into its own gauges; the crate
//! links no metrics library. No specification governs the report: our own
//! design.

/// The cap, the entries and the estimated bytes of one in-memory cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CacheUsage {
    /// The most entries the cache holds at once.
    pub capacity: usize,
    /// The entries it holds now, among them any whose time has ended and
    /// that the next write drops.
    pub entries: usize,
    /// An estimate of the bytes the entries take: each key and value with
    /// the heap it owns, without the nodes of the collection that holds
    /// them.
    pub bytes: usize,
}

impl CacheUsage {
    /// Returns the usage of a cache of `capacity` holding `entries` entries
    /// in about `bytes` bytes.
    pub(crate) const fn new(capacity: usize, entries: usize, bytes: usize) -> Self {
        Self {
            capacity,
            entries,
            bytes,
        }
    }
}
