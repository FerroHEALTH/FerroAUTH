// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The values a `federation` caller carries beside its kind, each read
//! from the field its issuer's `[[auth.federation]]` table maps.

use crate::federation::ConsentReference;
use crate::federation::CorrelationId;
use crate::resource::Caller;

impl Caller {
    /// Returns the consent decision reference the caller's token asserts:
    /// the Consent entity of the IHE BALP 1.1.4 3:5.7.6 consent decision
    /// record, when the caller is an external person or organisation whose
    /// issuer's table maps `consent.reference` and the token carries it.
    #[must_use]
    pub fn consent_reference(&self) -> Option<ConsentReference> {
        self.kind()
            .external()
            .and_then(crate::federation::External::consent_reference)
    }

    /// Returns the correlation id of a chained organisation request the
    /// caller's token asserts, when the caller is an external person or
    /// organisation whose issuer's table maps `correlation_id` and the token
    /// carries it.
    #[must_use]
    pub fn correlation_id(&self) -> Option<CorrelationId> {
        self.kind()
            .external()
            .and_then(crate::federation::External::correlation_id)
    }
}
