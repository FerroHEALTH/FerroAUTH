// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The behaviour of the engines over synthetic subjects and resources.

#![cfg_attr(
    any(feature = "cedar", feature = "remote"),
    expect(
        clippy::expect_used,
        reason = "a test support function fails the case the way a test body does"
    )
)]

#[cfg(feature = "cedar")]
mod cedar;
#[cfg(feature = "remote")]
mod remote;
