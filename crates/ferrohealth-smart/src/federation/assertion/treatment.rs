// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The Treatment Relationship Confirmation assertion (eHDSI SAML Profile
//! 10.0.0 §4), linked to the HP Identity Assertion it names.

use std::fmt;

use jiff::Timestamp;
use serde_json::Map;
use serde_json::Value;
use serde_json::json;

use crate::federation::Field;
use crate::federation::assertion::AssertionError;
use crate::federation::assertion::Envelope;
use crate::federation::assertion::Integrity;
use crate::federation::assertion::PURPOSE;
use crate::federation::assertion::SUBJECT;
use crate::federation::assertion::identity::IdentityAssertion;
use crate::federation::assertion::identity::PurposeOfUse;
use crate::federation::assertion::identity::purpose;
use crate::federation::assertion::required;
use crate::federation::assertion::text;
use crate::federation::contact::EhdsiCode;

/// The longest TRC window: "MUST NOT be more than 2 hours" (SAML Profile
/// 10.0.0 §4.1).
pub(super) const WINDOW: i64 = 2 * 60 * 60;

/// The authentication class of a TRC: "For TRC and NOK it MUST be"
/// `PreviousSession` (SAML Profile 10.0.0 §4.1).
const PREVIOUS_SESSION: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession";
/// The patient identifier's source (SAML Profile 10.0.0 §4.4).
const ID_SOURCE: &str = "urn:ehdsi:names:subject:patient-id-source";
/// The country of the PID issuer (SAML Profile 10.0.0 §4.4).
const PID_ISSUER_COUNTRY: &str = "urn:ehdsi:names:subject:pid-issuer-country";

/// How the patient identifier was obtained (SAML Profile 10.0.0 §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PatientIdSource {
    /// `EUDI_WALLET_PID`: from a verified EUDI Wallet PID presentation.
    EudiWalletPid,
    /// `MANUAL_ENTRY`.
    ManualEntry,
}

impl PatientIdSource {
    /// Returns the value as the profile spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EudiWalletPid => "EUDI_WALLET_PID",
            Self::ManualEntry => "MANUAL_ENTRY",
        }
    }
}

/// A validated Treatment Relationship Confirmation. The `Debug` rendering
/// carries no assertion content.
#[derive(Clone, PartialEq, Eq)]
pub struct TreatmentAssertion {
    /// `@ID`.
    id: String,
    /// `saml:Issuer`.
    issuer: String,
    /// `@NotBefore`.
    not_before: Timestamp,
    /// `@NotOnOrAfter`.
    not_on_or_after: Timestamp,
    /// The `@ID` of the identity assertion it names.
    identity_id: String,
    /// The patient identifier (`subject-id`).
    patient_id: String,
    /// The purpose of use that overrides the identity assertion's.
    purpose_of_use: Option<PurposeOfUse>,
    /// How the patient identifier was obtained.
    patient_id_source: Option<PatientIdSource>,
    /// The PID issuer's country.
    pid_issuer_country: Option<String>,
}

impl fmt::Debug for TreatmentAssertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TreatmentAssertion")
            .field("purpose_of_use", &self.purpose_of_use)
            .field("patient_id_source", &self.patient_id_source)
            .finish_non_exhaustive()
    }
}

impl TreatmentAssertion {
    /// Returns `@ID`.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns `saml:Issuer`.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns `Conditions/@NotBefore`.
    #[must_use]
    pub const fn not_before(&self) -> Timestamp {
        self.not_before
    }

    /// Returns `Conditions/@NotOnOrAfter`.
    #[must_use]
    pub const fn not_on_or_after(&self) -> Timestamp {
        self.not_on_or_after
    }

    /// Returns the `@ID` of the identity assertion the TRC names in `AssertionIDRef`.
    #[must_use]
    pub fn identity_id(&self) -> &str {
        &self.identity_id
    }

    /// Returns the patient identifier, as obtained by the identity traits
    /// handshake.
    #[must_use]
    pub fn patient_id(&self) -> &str {
        &self.patient_id
    }

    /// Returns the purpose of use that overrides the identity assertion's, when given.
    #[must_use]
    pub const fn purpose_of_use(&self) -> Option<PurposeOfUse> {
        self.purpose_of_use
    }

    /// Returns how the patient identifier was obtained, when given.
    #[must_use]
    pub const fn patient_id_source(&self) -> Option<PatientIdSource> {
        self.patient_id_source
    }

    /// Returns the ISO 3166-1 alpha-2 country of the PID issuer, when given.
    #[must_use]
    pub fn pid_issuer_country(&self) -> Option<&str> {
        self.pid_issuer_country.as_deref()
    }

    /// Returns the `trc` object of the `ehdsi` claim.
    pub(super) fn trc_claim(&self) -> Value {
        json!({
            "id": self.id,
            "not_before": self.not_before.as_second(),
            "not_on_or_after": self.not_on_or_after.as_second(),
        })
    }

    /// Returns the `patient` object of the `ehdsi` claim.
    pub(super) fn patient_claim(&self) -> Value {
        let mut patient = Map::new();
        patient.insert("id".into(), json!(self.patient_id));
        if let Some(source) = self.patient_id_source {
            patient.insert("id_source".into(), json!(source.as_str()));
        }
        Value::Object(patient)
    }
}

/// Reads the TRC from its checked envelope, linked to `identity`.
pub(super) fn read(
    envelope: &Envelope<'_, '_>,
    identity: &IdentityAssertion,
) -> Result<TreatmentAssertion, AssertionError> {
    if envelope.authentication_class.as_deref() != Some(PREVIOUS_SESSION) {
        return Err(Integrity::Structure("saml:AuthnContextClassRef").into());
    }
    // NOTE: SAML Profile 10.0.0 §4.1: the NameID is "The same identifier and encoding" as
    // the IdA's, and Advice names the IdA; Messaging Profile 10.0.0 §5.5.1 has NCP-A verify both.
    let reference = required(envelope.advice()?, "AssertionIDRef")
        .and_then(|node| text(node, "saml:AssertionIDRef"))?;
    let same_professional = envelope.name_id()?.is_some_and(|(value, format)| {
        value == identity.name_id().value() && format == Some(identity.name_id().format().as_str())
    });
    if reference != identity.id() || !same_professional {
        return Err(Integrity::Link.into());
    }
    // NOTE: the owner's decision on FerroHEALTH/FerroFED#1620 (2026-11-08): a missing TRC
    // patient id answers ERROR_SEC_DATA_INTEGRITY_NOT_ENSURED (Requirements Catalogue 11.01.02).
    let integrity = |field: Field| AssertionError::Attributes {
        code: EhdsiCode::SecDataIntegrityNotEnsured,
        missing: vec![field.as_str()],
    };
    let patient_id = envelope
        .single(SUBJECT)?
        .ok_or_else(|| integrity(Field::PatientId))?;
    let purpose_of_use = match envelope.values(PURPOSE) {
        [] => None,
        values => Some(purpose(values).ok_or_else(|| AssertionError::Attributes {
            code: EhdsiCode::HpiInsufficientInformation,
            missing: vec![Field::PurposeOfUse.as_str()],
        })?),
    };
    // NOTE: SAML Profile 10.0.0 §4.4: the source is EUDI_WALLET_PID or MANUAL_ENTRY, and the
    // PID issuer country "MUST be present when patient-id-source = EUDI_WALLET_PID".
    let patient_id_source = match envelope.single(ID_SOURCE)?.as_deref() {
        None => None,
        Some("EUDI_WALLET_PID") => Some(PatientIdSource::EudiWalletPid),
        Some("MANUAL_ENTRY") => Some(PatientIdSource::ManualEntry),
        Some(_) => return Err(integrity(Field::PatientIdSource)),
    };
    let pid_issuer_country = envelope.single(PID_ISSUER_COUNTRY)?;
    let from_wallet = patient_id_source == Some(PatientIdSource::EudiWalletPid);
    let country_valid = pid_issuer_country.as_deref().is_none_or(|country| {
        country.len() == 2 && country.chars().all(|c| c.is_ascii_uppercase())
    });
    if from_wallet != pid_issuer_country.is_some() || !country_valid {
        return Err(integrity(Field::PatientPidIssuerCountry));
    }
    Ok(TreatmentAssertion {
        id: envelope.id.clone(),
        issuer: envelope.issuer.clone(),
        not_before: envelope.not_before,
        not_on_or_after: envelope.not_on_or_after,
        identity_id: reference,
        patient_id,
        purpose_of_use,
        patient_id_source,
        pid_issuer_country,
    })
}
