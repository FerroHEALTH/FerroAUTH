// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The vendor adapter seam: [`IdpAdapter`], the code an issuer's profile
//! names by `adapter` where data cannot express a vendor's behaviour.
//!
//! The one case is a groups overage: an identity provider that leaves the
//! group claim out of a token above its limit puts an overage marker in its
//! place (`_claim_names` naming the claim, or `hasgroups` set to `true`), and
//! the groups are read from the provider's own interface, which the issuer
//! profile's preset documents. The party lookup calls the adapter before it
//! decides the outcome, and an adapter failure is [`GroupsCause::Adapter`]
//! carrying the upstream status, never an empty set of groups. No
//! specification governs the seam: our own design.
//!
//! [`GroupsCause::Adapter`]: crate::party::GroupsCause::Adapter

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use http::StatusCode;

use crate::resource::Caller;

/// Why an adapter could not read a caller's groups.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum AdapterError {
    /// The identity provider answered with a status other than success.
    #[error("the identity provider answered {status}")]
    Status {
        /// The status.
        status: StatusCode,
        /// The `Retry-After` the identity provider gave, when it gave one.
        retry_after: Option<Duration>,
    },
    /// The identity provider did not answer in time.
    #[error("the identity provider did not answer within {timeout:?}")]
    Timeout {
        /// The time allowed.
        timeout: Duration,
    },
    /// The token lacks a claim the adapter reads, or carries it in a form the
    /// adapter refuses; nothing was called.
    #[error("the token carries no usable {claim:?} claim for the adapter")]
    Claim {
        /// The claim.
        claim: String,
    },
    /// The identity provider could not be reached, or its answer does not
    /// read.
    #[error("the identity provider could not be read")]
    Unreadable {
        /// What failed.
        #[source]
        source: Arc<dyn std::error::Error + Send + Sync + 'static>,
    },
}

/// The code a profile's `adapter` names, registered with the party binding
/// under that name.
pub trait IdpAdapter: Send + Sync + 'static {
    /// Returns the groups the identity provider holds for `caller`, whose
    /// token carries a groups overage marker in place of its group claim.
    ///
    /// The values are compared with a membership's identifier as the token's
    /// group claim would be.
    fn resolve_groups<'a>(
        &'a self,
        caller: &'a Caller,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, AdapterError>> + Send + 'a>>;
}
