// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The idle and the absolute lifetime of a session, and what is left of
//! them.
//!
//! The absolute lifetime runs from the sign-in time, which nothing moves.
//! The idle lifetime runs from the last request that counted as activity,
//! and never past the absolute end. An access token that no refresh token
//! can replace ends the session when it expires. No specification governs
//! the lifetimes: our own design, held to the OWASP Session Management Cheat
//! Sheet (idle and absolute timeouts).

use std::time::Duration;

use ferrohealth_ui::view::session::Left;

/// The two lifetimes of every session of a console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetimes {
    /// How long a session lives with no request that counts as activity.
    pub idle: Duration,
    /// How long a session lives from its sign-in, whatever the activity.
    pub absolute: Duration,
}

/// The times a session carries, in whole seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Times {
    /// When the operator signed in.
    pub(crate) signed_in: i64,
    /// When a request last counted as activity.
    pub(crate) touched: i64,
    /// When the access token expires, when no refresh token can replace it.
    pub(crate) last_token: Option<i64>,
}

impl Lifetimes {
    /// What a session with `times` has left at `now`, in whole seconds;
    /// `None` once either lifetime has passed.
    pub(crate) fn left(&self, times: Times, now: i64) -> Option<Left> {
        let mut absolute_end = times.signed_in.saturating_add(seconds(self.absolute));
        if let Some(expires) = times.last_token {
            absolute_end = absolute_end.min(expires);
        }
        let idle_end = times
            .touched
            .saturating_add(seconds(self.idle))
            .min(absolute_end);
        let idle = idle_end.saturating_sub(now);
        (idle > 0).then(|| Left {
            idle: whole(idle),
            absolute: whole(absolute_end.saturating_sub(now)),
        })
    }
}

/// `span` in whole seconds, saturating.
pub(crate) fn seconds(span: Duration) -> i64 {
    i64::try_from(span.as_secs()).unwrap_or(i64::MAX)
}

/// A count of seconds as the watch's wire carries it, saturating.
fn whole(span: i64) -> u32 {
    u32::try_from(span.max(0)).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Lifetimes, Times};

    const LIFETIMES: Lifetimes = Lifetimes {
        idle: Duration::from_secs(60),
        absolute: Duration::from_secs(600),
    };

    fn times(signed_in: i64, touched: i64) -> Times {
        Times {
            signed_in,
            touched,
            last_token: None,
        }
    }

    #[test]
    fn a_fresh_session_has_both_lifetimes_left() {
        let left = LIFETIMES.left(times(1000, 1000), 1000).expect("live");
        assert_eq!((60, 600), (left.idle, left.absolute), "nothing has passed");
    }

    #[test]
    fn the_idle_lifetime_counts_from_the_last_activity() {
        let left = LIFETIMES.left(times(1000, 1100), 1130).expect("live");
        assert_eq!((30, 470), (left.idle, left.absolute), "{left:?}");
        assert!(
            LIFETIMES.left(times(1000, 1100), 1160).is_none(),
            "sixty idle seconds end the session"
        );
    }

    #[test]
    fn the_absolute_lifetime_counts_from_the_sign_in_whatever_the_activity() {
        let left = LIFETIMES.left(times(1000, 1590), 1590).expect("live");
        assert_eq!(
            (10, 10),
            (left.idle, left.absolute),
            "the idle lifetime never runs past the absolute end"
        );
        assert!(
            LIFETIMES.left(times(1000, 1599), 1600).is_none(),
            "the absolute lifetime ends the session"
        );
    }

    #[test]
    fn an_access_token_no_refresh_token_replaces_ends_the_session() {
        let bounded = Times {
            last_token: Some(1040),
            ..times(1000, 1000)
        };
        let left = LIFETIMES.left(bounded, 1010).expect("live");
        assert_eq!((30, 30), (left.idle, left.absolute), "{left:?}");
        assert!(LIFETIMES.left(bounded, 1040).is_none(), "the token expired");
    }

    #[test]
    fn a_zero_idle_lifetime_admits_no_session() {
        let none = Lifetimes {
            idle: Duration::ZERO,
            ..LIFETIMES
        };
        assert!(none.left(times(1000, 1000), 1000).is_none(), "no window");
    }
}
