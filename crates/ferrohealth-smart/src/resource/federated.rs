// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The values a `federation` caller carries beside its kind, each read
//! from the field its issuer's `[[auth.federation]]` table maps.

use crate::federation::ConsentReference;
use crate::federation::CorrelationId;
use crate::federation::MessageId;
use crate::federation::contact::NameId;
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

    /// Returns the `NameID` of the HP Identity Assertion with its format,
    /// for an external person admitted through a MyHealth@EU contact point
    /// (eHDSI SAML Profile 10.0.0 §2.1): `professional.hp_identifier` and
    /// `assertion.name_id_format`, when the token carries both.
    #[must_use]
    pub fn name_id(&self) -> Option<NameId> {
        self.kind()
            .external()
            .and_then(crate::federation::External::name_id)
    }

    /// Returns the UUID of the cross-border request message, for an
    /// external person admitted through a MyHealth@EU contact point whose
    /// token relays it (`message_id`), to join the contact point's audit
    /// entry.
    #[must_use]
    pub fn message_id(&self) -> Option<MessageId> {
        self.kind()
            .external()
            .and_then(crate::federation::External::message_id)
    }
}
