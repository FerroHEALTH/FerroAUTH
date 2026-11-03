// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The clock every lifetime is counted on: wall-clock seconds, so a sealed
//! cookie opened by another instance reads the same times.

#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicI64, Ordering};

/// Where the current time comes from.
#[derive(Debug, Clone, Default)]
pub(crate) enum Clock {
    /// The system's wall clock.
    #[default]
    System,
    /// A time the test sets and moves.
    #[cfg(test)]
    Manual(Arc<AtomicI64>),
}

impl Clock {
    /// The current time in whole seconds since the Unix epoch.
    pub(crate) fn now(&self) -> i64 {
        match self {
            Self::System => jiff::Timestamp::now().as_second(),
            #[cfg(test)]
            Self::Manual(now) => now.load(Ordering::SeqCst),
        }
    }
}

/// A manual clock at `start` and the handle that moves it.
#[cfg(test)]
pub(crate) fn manual(start: i64) -> (Clock, Arc<AtomicI64>) {
    let now = Arc::new(AtomicI64::new(start));
    (Clock::Manual(Arc::clone(&now)), now)
}
