// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! FerroSMART, the SMART App Launch 2.x authorization server of the
//! FerroHEALTH products (`docs/architecture.md` §13).
//!
//! It is the one component of the family that issues tokens and holds the
//! keys that sign them; any OpenID Connect provider upstream serves the
//! login. This crate is the server: its command line, its configuration,
//! its signing keys and the documents that describe it.

pub mod authorize;
pub mod cli;
pub mod client_keys;
pub mod clients;
pub mod command;
pub mod config;
pub mod discovery;
pub mod form;
pub mod introspect;
pub mod pages;
pub mod refresh;
pub mod revoke;
pub mod server;
pub mod store;
pub mod token;
pub mod upstream;
