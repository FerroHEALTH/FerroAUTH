// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The integration tests of FerroSMART, one binary: the configuration and
//! the discovery routes, every key generated when the case runs.

#![expect(
    clippy::expect_used,
    reason = "a test support function fails the case the way a test body does"
)]

mod audit;
mod authorize;
mod clients;
mod config;
mod discovery;
mod ehr_launch;
mod ig_examples;
mod introspection;
mod launch;
mod refresh;
mod replicas;
mod revocation;
mod screenshots;
mod store;
mod support;
mod symmetric;
mod token;
mod upstream_vendors;
