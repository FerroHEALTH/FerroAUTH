// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The clock every lifetime is counted on: wall-clock seconds, so a sealed
//! cookie opened by another instance reads the same times.
//!
//! A store runs on [`Clock::system`] unless it is built with
//! [`Sessions::with_clock`](crate::sessions::Sessions::with_clock). Behind the
//! `test-clock` feature, `ManualClock` is a time a test sets and moves, so a
//! console's session tests reach a timeout without waiting for it.

#[cfg(any(test, feature = "test-clock"))]
use std::sync::Arc;
#[cfg(any(test, feature = "test-clock"))]
use std::sync::atomic::{AtomicI64, Ordering};

/// Where a store reads the current time from; the default is the wall clock.
#[derive(Debug, Clone, Default)]
pub struct Clock(Source);

#[derive(Debug, Clone, Default)]
enum Source {
    #[default]
    System,
    #[cfg(any(test, feature = "test-clock"))]
    Manual(ManualClock),
}

impl Clock {
    /// The system's wall clock.
    #[must_use]
    pub fn system() -> Self {
        Self(Source::System)
    }

    /// The current time in whole seconds since the Unix epoch.
    pub(crate) fn now(&self) -> i64 {
        match &self.0 {
            Source::System => jiff::Timestamp::now().as_second(),
            #[cfg(any(test, feature = "test-clock"))]
            Source::Manual(manual) => manual.now(),
        }
    }
}

/// A time a test sets and moves, in whole seconds since the Unix epoch.
///
/// Every clone, and every [`Clock`] taken from it, reads the same time.
///
/// ```
/// use ferrohealth_session::clock::ManualClock;
///
/// let time = ManualClock::new(1_800_000_000);
/// let clock = time.clock();
/// time.advance(61);
/// assert_eq!(time.now(), 1_800_000_061);
/// ```
#[cfg(any(test, feature = "test-clock"))]
#[derive(Debug, Clone)]
pub struct ManualClock(Arc<AtomicI64>);

#[cfg(any(test, feature = "test-clock"))]
impl ManualClock {
    /// A manual time at `start` seconds since the Unix epoch.
    #[must_use]
    pub fn new(start: i64) -> Self {
        Self(Arc::new(AtomicI64::new(start)))
    }

    /// The clock a store reads this time from.
    #[must_use]
    pub fn clock(&self) -> Clock {
        Clock(Source::Manual(self.clone()))
    }

    /// The current manual time.
    #[must_use]
    pub fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    /// Sets the time to `seconds` since the Unix epoch.
    pub fn set(&self, seconds: i64) {
        self.0.store(seconds, Ordering::SeqCst);
    }

    /// Moves the time by `seconds`, saturating at the ends of `i64`.
    pub fn advance(&self, seconds: i64) {
        let mut now = self.now();
        while let Err(seen) = self.0.compare_exchange_weak(
            now,
            now.saturating_add(seconds),
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            now = seen;
        }
    }
}
