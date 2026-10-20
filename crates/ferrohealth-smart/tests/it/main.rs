// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The integration suite: one binary, one module per subject, every upstream
//! a `wiremock` stub and every key generated when the case runs.

#![expect(
    clippy::panic_in_result_fn,
    reason = "a Result-returning test still asserts; a failed assertion is how it fails"
)]
#![expect(
    clippy::expect_used,
    reason = "a test support function fails the case the way a test body does"
)]
#![cfg_attr(
    feature = "fetch",
    expect(
        clippy::panic,
        reason = "a test support function fails the case the way a test body does"
    )
)]

mod audit;
mod basic;
#[cfg(feature = "fetch")]
mod client;
mod config;
#[cfg(all(feature = "axum", feature = "fetch"))]
mod guard;
mod key_file;
#[cfg(all(feature = "openehr", feature = "fetch"))]
mod openehr;
#[cfg_attr(
    not(feature = "fetch"),
    expect(
        dead_code,
        reason = "the stub issuer's metadata and key set serve the fetch cases alone"
    )
)]
mod support;
#[cfg(feature = "fetch")]
mod tls;
#[cfg(feature = "fetch")]
mod token;
