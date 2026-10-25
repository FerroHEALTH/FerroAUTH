// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The policy decision point a product consults: one trait every engine
//! implements, so a deployment swaps engines without a change in behaviour.
//!
//! An engine that cannot decide answers an [`AuthzError`], never a permit
//! and never a deny: a policy set that does not load, an evaluation that
//! fails, or a remote point that gives no decision is a fault the product
//! reports as one (NIST SP 800-162 §2 places the decision in the PDP; what
//! the PEP does when the PDP fails is our own design: it fails closed).

use crate::request::Decision;
use crate::request::Request;

/// A policy decision point.
#[async_trait::async_trait]
pub trait PolicyEngine: Send + Sync + std::fmt::Debug {
    /// Decides `request`: [`Decision::Permit`] when every combination of
    /// its resource attributes is permitted, [`Decision::Deny`] at the first
    /// that is not.
    ///
    /// # Errors
    ///
    /// An [`AuthzError`] when the engine cannot decide.
    async fn decide(&self, request: &Request<'_>) -> Result<Decision, AuthzError>;
}

/// Why an engine gave no decision.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthzError {
    /// The policy set, its schema or the product's model does not load.
    #[error("the policy set could not be loaded")]
    Load(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The request names a resource type or an action the model does not
    /// declare.
    #[error("the request names the undeclared {what} {name}")]
    Undeclared {
        /// `resource type` or `action`.
        what: &'static str,
        /// The name.
        name: String,
    },
    /// The evaluation failed, a policy that errored included: an erroring
    /// policy decides nothing, so its set decides nothing.
    #[error("the policy evaluation failed")]
    Evaluation(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// A remote decision point was not reached, or answered with no
    /// decision.
    #[error("the remote policy decision point gave no decision")]
    Remote(#[source] Box<dyn std::error::Error + Send + Sync>),
}
