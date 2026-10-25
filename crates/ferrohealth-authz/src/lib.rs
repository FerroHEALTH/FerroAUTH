// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The policy decision of the FerroHEALTH products: the request a policy
//! enforcement point puts, the decision it gets, and the engines that decide.
//!
//! `ferrohealth-smart` authenticates a caller and says who it is; this crate
//! decides what that subject may do with an object, in the vocabulary of NIST
//! SP 800-162 (attribute-based access control: subject, object and
//! environment attributes, a policy decision point and the enforcement point
//! that consults it).
//!
//! - [`request`]: the [`request::Subject`] read from `ferrohealth-smart`'s
//!   caller, the [`request::Request`] with its resource attributes (sets fan
//!   out, every combination must be permitted) and the [`request::Decision`]
//!   with the policies that made it.
//! - [`engine`]: the [`engine::PolicyEngine`] trait every engine implements,
//!   and [`engine::AuthzError`], the answer of an engine that cannot decide,
//!   which a product never reads as a permit.
//! - `cedar` (feature `cedar`): the embedded engine over the Cedar policy
//!   language, its schema written from the product's model and its policies
//!   validated strictly before they run.
//! - `remote` (feature `remote`): a remote decision point reached over HTTP,
//!   authorized with `ferrohealth-smart`'s client credentials token.
//!
//! Without a feature the crate holds the request model and the trait alone,
//! with no policy engine or HTTP client.

#![doc(test(attr(deny(warnings))))]

#[cfg(feature = "cedar")]
pub mod cedar;
pub mod engine;
#[cfg(feature = "remote")]
pub mod remote;
pub mod request;
