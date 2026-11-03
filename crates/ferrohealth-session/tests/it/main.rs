// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The integration suite: the sign-in routes of a console against a test
//! OpenID Provider, a `wiremock` stub whose signing key is generated when
//! the case runs.

#![cfg(feature = "axum")]
#![expect(
    clippy::expect_used,
    reason = "a test support function fails the case the way a test body does"
)]

mod console;
mod flow;
mod provider;
