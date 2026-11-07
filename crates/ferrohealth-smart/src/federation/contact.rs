// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The MyHealth@EU contact-point profile.
//!
//! A `contact_point = true` issuer is NCPeH-A's authorization server, whose
//! tokens carry what it read from the validated HP Identity Assertion and
//! Treatment Relationship Confirmation.
//!
//! The mandatory attributes are eHDSI SAML Profile 10.0.0 §2.1 and §2.3's;
//! a refusal carries the code name of the MyHealth@EU Requirements
//! Catalogue 10.0.0 §1.25, so a national connector maps each one to one. The
//! catalogue is read by its section and requirement id and none of its text
//! is reproduced. Country A never refuses on the description of the HP, the
//! role or the point of care (requirements 01 and 01.02), nor on the
//! assurance country B gave (Interoperability Specifications 8.0.1 §2.4.3):
//! the authentication class is only checked to be one of the seven, and
//! recorded.

use std::fmt;
use std::str::FromStr;

use serde_json::Map;
use serde_json::Value;

use crate::federation::Attribute;
use crate::federation::External;
use crate::federation::Field;
use crate::kind::Unclassified;
use crate::resource::Rejection;

/// A refusal code name of the MyHealth@EU Requirements Catalogue 10.0.0
/// §1.25.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EhdsiCode {
    /// The token names no professional (requirement 01).
    HpiNoInformation,
    /// The professional's attributes are incomplete, the missing fields
    /// listed (requirement 01).
    HpiInsufficientInformation,
    /// The token names no healthcare provider organisation (requirement 01).
    HpiHaiNoInformation,
    /// The token misses the point of care, the facility type or the home
    /// community (requirement 01).
    HpiPocNoInformation,
    /// The authentication class is missing or not one of the seven
    /// (requirement 01.01).
    HpiAuthenticationNotReceived,
    /// The assertion attributes are missing, or the token outlives an
    /// assertion's window (requirement 11.01.02).
    SecDataIntegrityNotEnsured,
    /// Any other invalid token, and a key set or an upstream the check
    /// needs that cannot be read (requirement 11).
    SecGeneric,
}

impl EhdsiCode {
    /// Returns the code name as §1.25 spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HpiNoInformation => "ERROR_HPI_NO_INFORMATION",
            Self::HpiInsufficientInformation => "ERROR_HPI_INSUFFICIENT_INFORMATION",
            Self::HpiHaiNoInformation => "ERROR_HPI_HAI_NO_INFORMATION",
            Self::HpiPocNoInformation => "ERROR_HPI_POC_NO_INFORMATION",
            Self::HpiAuthenticationNotReceived => "ERROR_HPI_AUTHENTICATION_NOT_RECEIVED",
            Self::SecDataIntegrityNotEnsured => "ERROR_SEC_DATA_INTEGRITY_NOT_ENSURED",
            Self::SecGeneric => "ERROR_SEC_GENERIC",
        }
    }

    /// Returns the id of the Requirements Catalogue 10.0.0 requirement the
    /// code answers, as the catalogue numbers it.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            Self::HpiNoInformation
            | Self::HpiInsufficientInformation
            | Self::HpiHaiNoInformation
            | Self::HpiPocNoInformation => "01",
            Self::HpiAuthenticationNotReceived => "01.01",
            Self::SecDataIntegrityNotEnsured => "11.01.02",
            Self::SecGeneric => "11",
        }
    }

    /// Returns the code a contact point answers `rejection` with: the code of
    /// a contact-point refusal, and `ERROR_SEC_GENERIC` for any other invalid
    /// token and for an unreadable key set or upstream.
    #[must_use]
    pub const fn of(rejection: &Rejection) -> Self {
        // NOTE: Requirements Catalogue 10.0.0 §1.25 has no code for an unreadable key
        // set, and its ERROR_REGISTRY_NOT_AVAILABLE is requirement 05's (Patient Summary), so
        // the verification failure takes requirement 11's ERROR_SEC_GENERIC.
        match rejection {
            Rejection::Unclassified {
                reason: Unclassified::ContactPoint { code, .. },
            } => *code,
            _ => Self::SecGeneric,
        }
    }
}

impl fmt::Display for EhdsiCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The authentication classes an HP Identity Assertion may carry (eHDSI SAML
/// Profile 10.0.0 §2.1, `AuthnContextClassRef`).
pub const AUTHENTICATION_CLASSES: [&str; 7] = [
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:X509",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:SPKI",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient",
];

/// The format of the HP Identity Assertion's `NameID`: one of the three
/// eHDSI SAML Profile 10.0.0 §2.1 allows ("MUST be").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum NameIdFormat {
    /// `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`.
    Unspecified,
    /// `urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName`.
    X509SubjectName,
    /// `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`.
    EmailAddress,
}

impl NameIdFormat {
    /// Every format §2.1 allows.
    pub const ALL: [Self; 3] = [Self::Unspecified, Self::X509SubjectName, Self::EmailAddress];

    /// Returns the format's URN, as §2.1 spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            Self::X509SubjectName => "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
            Self::EmailAddress => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        }
    }
}

impl fmt::Display for NameIdFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A `NameID` format other than the three eHDSI SAML Profile 10.0.0 §2.1
/// allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a NameID format of the eHDSI SAML Profile 10.0.0 §2.1")]
#[non_exhaustive]
pub struct UnknownNameIdFormat;

impl FromStr for NameIdFormat {
    type Err = UnknownNameIdFormat;

    /// Reads the URN exactly as §2.1 spells it.
    fn from_str(urn: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|format| format.as_str() == urn)
            .ok_or(UnknownNameIdFormat)
    }
}

/// The `NameID` of a contact-point token's HP Identity Assertion, with its
/// format.
///
/// One identifier is the pair, since one string under two formats names two
/// identifiers (eHDSI SAML Profile 10.0.0 §2.1).
///
/// The value is [`Field::ProfessionalHpIdentifier`] and the format
/// [`Field::AssertionNameIdFormat`]. The `Debug` rendering never carries the
/// value.
#[derive(Clone, PartialEq, Eq)]
pub struct NameId {
    /// The identifier, as asserted.
    value: String,
    /// Its format.
    format: NameIdFormat,
}

impl fmt::Debug for NameId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NameId")
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

impl NameId {
    /// Returns the identifier, as asserted.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the identifier's format.
    #[must_use]
    pub const fn format(&self) -> NameIdFormat {
        self.format
    }
}

impl External {
    /// Returns the HP Identity Assertion's `NameID` with its format, when the
    /// token carries `professional.hp_identifier` as one string and
    /// `assertion.name_id_format` as one of the three formats; a
    /// contact-point token is admitted only with both.
    #[must_use]
    pub fn name_id(&self) -> Option<NameId> {
        let text = |field| self.field(field).and_then(Attribute::text);
        // NOTE: a format outside eHDSI SAML Profile 10.0.0 §2.1's three is absent here,
        // as the contact-point check refuses it.
        let format = text(Field::AssertionNameIdFormat)?.parse().ok()?;
        Some(NameId {
            value: text(Field::ProfessionalHpIdentifier)?.to_owned(),
            format,
        })
    }
}

/// The longest an HP Identity Assertion is valid: "MUST NOT be more than 4
/// hours" (SAML Profile 10.0.0 §2.1).
const IDA_WINDOW: i64 = 4 * 60 * 60;

/// The longest a Treatment Relationship Confirmation is valid: "MUST NOT be
/// more than 2 hours" (SAML Profile 10.0.0 §4).
const TRC_WINDOW: i64 = 2 * 60 * 60;

/// The clock drift the windows admit: "within 60 seconds of the validity
/// window boundaries" (SAML Profile 10.0.0 §2.1).
const DRIFT: i64 = 60;

/// Returns the refusal of a contact-point token, or nothing when it carries
/// every mandatory attribute and lives within its assertions' windows.
pub(crate) fn check(external: &External, claims: &Map<String, Value>) -> Result<(), Unclassified> {
    let has = |field| external.field(field).is_some();
    let refuse =
        |code, missing: Vec<&'static str>| Err(Unclassified::ContactPoint { code, missing });
    // NOTE: the country and the issuing authority are configured, not asserted
    // (Requirements Catalogue 10.0.0 requirement 01), so they name no professional.
    let asserted = |field: &&Field| {
        field.professional()
            && !matches!(
                field,
                Field::ProfessionalCountryCode | Field::ProfessionalIssuingAuthorityName
            )
    };
    if !external.fields().keys().any(|field| asserted(&field)) {
        return refuse(EhdsiCode::HpiNoInformation, Vec::new());
    }
    // NOTE: eHDSI SAML Profile 10.0.0 §2.1 requires the NameID and its @Format, one of
    // three; a format outside them is refused beside a missing one (our own design).
    let present = |field: &Field| match field {
        Field::AssertionNameIdFormat => external
            .field(*field)
            .and_then(Attribute::text)
            .is_some_and(|format| format.parse::<NameIdFormat>().is_ok()),
        _ => has(*field),
    };
    let mut missing: Vec<&'static str> = [
        Field::ProfessionalHpIdentifier,
        Field::AssertionNameIdFormat,
        Field::ProfessionalName,
        Field::ProfessionalHpProfessionalRole,
    ]
    .into_iter()
    .filter(|field| !present(field))
    .map(Field::as_str)
    .collect();
    // NOTE: eHDSI SAML Profile 10.0.0 §2.3: `on-behalf-of` is "Mandatory if a
    // structural role is part of the category Clerical Support Workers", ISCO 44.
    let clerical = external
        .field(Field::ProfessionalHpProfessionalRole)
        .is_some_and(|role| role.values().contains(&"44"));
    if clerical && !has(Field::ProfessionalOnBehalfOf) {
        missing.push(Field::ProfessionalOnBehalfOf.as_str());
    }
    if !missing.is_empty() {
        return refuse(EhdsiCode::HpiInsufficientInformation, missing);
    }
    if !has(Field::ProviderHealthcareProviderIdentifier) {
        return refuse(
            EhdsiCode::HpiHaiNoInformation,
            vec![Field::ProviderHealthcareProviderIdentifier.as_str()],
        );
    }
    let missing: Vec<&'static str> = [
        Field::PointOfCare,
        Field::ProviderFacilityType,
        Field::ProviderHomeCommunityId,
    ]
    .into_iter()
    .filter(|field| !has(*field))
    .map(Field::as_str)
    .collect();
    if !missing.is_empty() {
        return refuse(EhdsiCode::HpiPocNoInformation, missing);
    }
    let authenticated = external
        .field(Field::ProfessionalAuthenticationMethod)
        .is_some_and(|class| {
            class
                .values()
                .iter()
                .any(|value| AUTHENTICATION_CLASSES.contains(value))
        });
    if !authenticated {
        return refuse(
            EhdsiCode::HpiAuthenticationNotReceived,
            vec![Field::ProfessionalAuthenticationMethod.as_str()],
        );
    }
    // NOTE: SAML Profile 10.0.0 §2.3 allows TREATMENT and EMERGENCY alone; §1.25 has
    // no dedicated code, so ERROR_HPI_INSUFFICIENT_INFORMATION is our own design.
    let purpose = external.field(Field::PurposeOfUse).is_some_and(|purpose| {
        let values = purpose.values();
        !values.is_empty()
            && values
                .iter()
                .all(|value| matches!(*value, "TREATMENT" | "EMERGENCY"))
    });
    if !purpose {
        return refuse(
            EhdsiCode::HpiInsufficientInformation,
            vec![Field::PurposeOfUse.as_str()],
        );
    }
    check_assertions(external, claims)
}

/// Refuses a token whose assertion attributes are missing or whose life
/// reaches past an assertion's window, or past 4 hours, with the drift the
/// profile admits (`ERROR_SEC_DATA_INTEGRITY_NOT_ENSURED`, requirement
/// 11.01.02).
fn check_assertions(external: &External, claims: &Map<String, Value>) -> Result<(), Unclassified> {
    let missing: Vec<&'static str> = [
        Field::AssertionIssuer,
        Field::AssertionId,
        Field::AssertionNotBefore,
        Field::AssertionNotOnOrAfter,
        Field::TrcId,
    ]
    .into_iter()
    .filter(|field| external.field(*field).is_none())
    .map(Field::as_str)
    .collect();
    let integrity = |missing| {
        Err(Unclassified::ContactPoint {
            code: EhdsiCode::SecDataIntegrityNotEnsured,
            missing,
        })
    };
    if !missing.is_empty() {
        return integrity(missing);
    }
    let time = |field| {
        external
            .field(field)
            .and_then(Attribute::text)
            .and_then(|text| text.parse::<i64>().ok())
    };
    let claim = |name| claims.get(name).and_then(Value::as_i64);
    let (Some(ida_start), Some(ida_end), Some(expires)) = (
        time(Field::AssertionNotBefore),
        time(Field::AssertionNotOnOrAfter),
        claim("exp"),
    ) else {
        return integrity(vec![Field::AssertionNotOnOrAfter.as_str()]);
    };
    let issued = claim("iat").unwrap_or(ida_start);
    let trc = (time(Field::TrcNotBefore), time(Field::TrcNotOnOrAfter));
    let within = ida_end.saturating_sub(ida_start) <= IDA_WINDOW.saturating_add(DRIFT)
        && expires <= ida_end.saturating_add(DRIFT)
        && expires.saturating_sub(issued) <= IDA_WINDOW.saturating_add(DRIFT)
        && trc.1.is_none_or(|end| expires <= end.saturating_add(DRIFT))
        && match trc {
            (Some(start), Some(end)) => {
                end.saturating_sub(start) <= TRC_WINDOW.saturating_add(DRIFT)
            }
            _ => true,
        };
    if within {
        Ok(())
    } else {
        integrity(vec!["exp"])
    }
}
