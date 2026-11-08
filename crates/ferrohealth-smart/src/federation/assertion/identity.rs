// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The HP Identity Assertion (eHDSI SAML Profile 10.0.0 §2).
//!
//! The attributes are checked in the order the contact-point token check
//! holds them to ([`crate::federation::contact`]), so an assertion and the
//! token it is exchanged for are refused with the same §1.25 code.

use std::fmt;

use serde_json::Map;
use serde_json::Value;
use serde_json::json;

use crate::federation::Field;
use crate::federation::assertion::AssertionError;
use crate::federation::assertion::Envelope;
use crate::federation::assertion::HL7;
use crate::federation::assertion::Integrity;
use crate::federation::assertion::PURPOSE;
use crate::federation::assertion::SAML;
use crate::federation::assertion::SUBJECT;
use crate::federation::assertion::Window;
use crate::federation::assertion::elements;
use crate::federation::assertion::is;
use crate::federation::assertion::text;
use crate::federation::assertion::treatment::TreatmentAssertion;
use crate::federation::contact::AUTHENTICATION_CLASSES;
use crate::federation::contact::EhdsiCode;
use crate::federation::contact::NameId;
use crate::federation::contact::NameIdFormat;

/// The longest identity assertion window: "MUST NOT be more than 4 hours" (SAML Profile
/// 10.0.0 §2.1).
pub(super) const WINDOW: i64 = 4 * 60 * 60;

/// The ISCO code system of the structural role (SAML Profile 10.0.0 §2.3).
const ISCO: &str = "2.16.840.1.113883.2.9.6.2.7";

/// The attribute names of SAML Profile 10.0.0 §2.3.
mod name {
    pub(super) const HOME_COMMUNITY: &str = "urn:ihe:iti:xca:2010:homeCommunityId";
    pub(super) const NPI: &str = "urn:oasis:names:tc:xspa:1.0:subject:npi";
    pub(super) const ROLE: &str = "urn:oasis:names:tc:xacml:2.0:subject:role";
    pub(super) const SPECIALITY: &str = "urn:ehdsi:names:wp3.4:subject:clinical-speciality";
    pub(super) const PERMISSION: &str = "urn:oasis:names:tc:xspa:1.0:subject:hl7:permission";
    pub(super) const ON_BEHALF_OF: &str = "urn:ehdsi:names:subject:on-behalf-of";
    pub(super) const ORGANIZATION: &str = "urn:oasis:names:tc:xspa:1.0:subject:organization";
    pub(super) const ORGANIZATION_ID: &str = "urn:oasis:names:tc:xspa:1.0:subject:organization-id";
    pub(super) const FACILITY_TYPE: &str = "urn:ehdsi:names:subject:healthcare-facility-type";
    pub(super) const POINT_OF_CARE: &str = "urn:oasis:names:tc:xspa:1.0:environment:locality";
}

/// The purpose of use: "For eHealth DSI only following values are allowed"
/// (SAML Profile 10.0.0 §2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PurposeOfUse {
    /// `TREATMENT`.
    Treatment,
    /// `EMERGENCY`, breaking the glass.
    Emergency,
}

impl PurposeOfUse {
    /// Returns the code as the profile spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Treatment => "TREATMENT",
            Self::Emergency => "EMERGENCY",
        }
    }
}

/// A structural role: the `code` and `codeSystem` of the HL7 v3 `Role` the
/// value carries (SAML Profile 10.0.0 §2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    /// The ISCO code.
    code: String,
    /// The code system, when given.
    code_system: Option<String>,
}

impl Role {
    /// Returns the code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the code system, when given.
    #[must_use]
    pub fn code_system(&self) -> Option<&str> {
        self.code_system.as_deref()
    }
}

/// A validated HP Identity Assertion. The `Debug` rendering carries no
/// assertion content.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentityAssertion {
    /// `@ID`.
    id: String,
    /// `saml:Issuer`.
    issuer: String,
    /// `NameID` with its format.
    name_id: NameId,
    /// The window and the session.
    window: Window,
    /// `AuthnContextClassRef`, one of the seven.
    authentication_class: String,
    /// `subject-id`, the full name.
    name: String,
    /// The structural roles.
    roles: Vec<Role>,
    /// `on-behalf-of`.
    on_behalf_of: Option<String>,
    /// `organization-id`.
    organization_id: String,
    /// `organization`, the name.
    organization: Option<String>,
    /// `healthcare-facility-type`.
    facility_type: String,
    /// `homeCommunityId`.
    home_community_id: String,
    /// `locality`, the point of care.
    point_of_care: String,
    /// `purposeofuse`.
    purpose_of_use: PurposeOfUse,
    /// `clinical-speciality`.
    speciality: Option<String>,
    /// `npi`.
    npi: Option<String>,
    /// `hl7:permission` values.
    permissions: Vec<String>,
}

impl fmt::Debug for IdentityAssertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityAssertion")
            .field("name_id", &self.name_id)
            .field("purpose_of_use", &self.purpose_of_use)
            .finish_non_exhaustive()
    }
}

impl IdentityAssertion {
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

    /// Returns the `NameID` with its format.
    #[must_use]
    pub const fn name_id(&self) -> &NameId {
        &self.name_id
    }

    /// Returns the window and session the assertion is valid in.
    #[must_use]
    pub const fn window(&self) -> Window {
        self.window
    }

    /// Returns the authentication class, as received.
    #[must_use]
    pub fn authentication_class(&self) -> &str {
        &self.authentication_class
    }

    /// Returns the HP's full name (`subject-id`).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the structural roles.
    #[must_use]
    pub fn roles(&self) -> &[Role] {
        &self.roles
    }

    /// Returns the role acted on behalf of, when given.
    #[must_use]
    pub fn on_behalf_of(&self) -> Option<&str> {
        self.on_behalf_of.as_deref()
    }

    /// Returns the healthcare professional organisation's identifier.
    #[must_use]
    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }

    /// Returns the organisation's name, when given.
    #[must_use]
    pub fn organization(&self) -> Option<&str> {
        self.organization.as_deref()
    }

    /// Returns the healthcare facility type.
    #[must_use]
    pub fn facility_type(&self) -> &str {
        &self.facility_type
    }

    /// Returns the home community id.
    #[must_use]
    pub fn home_community_id(&self) -> &str {
        &self.home_community_id
    }

    /// Returns the point of care's name.
    #[must_use]
    pub fn point_of_care(&self) -> &str {
        &self.point_of_care
    }

    /// Returns the purpose of use.
    #[must_use]
    pub const fn purpose_of_use(&self) -> PurposeOfUse {
        self.purpose_of_use
    }

    /// Returns the speciality, when given.
    #[must_use]
    pub fn speciality(&self) -> Option<&str> {
        self.speciality.as_deref()
    }

    /// Returns the national provider identifier, when given.
    #[must_use]
    pub fn npi(&self) -> Option<&str> {
        self.npi.as_deref()
    }

    /// Returns the permission values, as asserted.
    #[must_use]
    pub fn permissions(&self) -> &[String] {
        &self.permissions
    }

    /// Whether the assertion carries the permission `code`, such as
    /// `PPD-046` (SAML Profile 10.0.0 §2.5), as the whole value or its last
    /// `:`-separated part.
    #[must_use]
    pub fn has_permission(&self, code: &str) -> bool {
        self.permissions
            .iter()
            .any(|value| value == code || value.rsplit(':').next() == Some(code))
    }
}

/// Reads the identity assertion from its checked envelope.
pub(super) fn read(envelope: &Envelope<'_, '_>) -> Result<IdentityAssertion, AssertionError> {
    // NOTE: SAML Profile 10.0.0 §2.1: "Assertion consumers MUST reject any HCP Identity
    // Assertion that contains a SubjectConfirmationData element".
    if envelope
        .subject
        .descendants()
        .any(|node| is(node, SAML, "SubjectConfirmationData"))
    {
        return Err(Integrity::Confirmation.into());
    }
    let refuse = |code, missing: Vec<&'static str>| AssertionError::Attributes { code, missing };
    let (name_id, name, roles, on_behalf_of) = professional(envelope)?;
    let Some(organization_id) = envelope.single(name::ORGANIZATION_ID)? else {
        return Err(refuse(
            EhdsiCode::HpiHaiNoInformation,
            vec![Field::ProviderHealthcareProviderIdentifier.as_str()],
        ));
    };
    let point_of_care = envelope.single(name::POINT_OF_CARE)?;
    let facility_type = envelope.single(name::FACILITY_TYPE)?;
    let home_community_id = envelope.single(name::HOME_COMMUNITY)?;
    let (Some(point_of_care), Some(facility_type), Some(home_community_id)) = (
        point_of_care.clone(),
        facility_type.clone(),
        home_community_id.clone(),
    ) else {
        let missing = [
            (point_of_care.is_none(), Field::PointOfCare),
            (facility_type.is_none(), Field::ProviderFacilityType),
            (home_community_id.is_none(), Field::ProviderHomeCommunityId),
        ]
        .into_iter()
        .filter(|(absent, _)| *absent)
        .map(|(_, field)| field.as_str())
        .collect();
        return Err(refuse(EhdsiCode::HpiPocNoInformation, missing));
    };
    let Some(authentication_class) = envelope
        .authentication_class
        .clone()
        .filter(|class| AUTHENTICATION_CLASSES.contains(&class.as_str()))
    else {
        return Err(refuse(
            EhdsiCode::HpiAuthenticationNotReceived,
            vec![Field::ProfessionalAuthenticationMethod.as_str()],
        ));
    };
    // NOTE: SAML Profile 10.0.0 §2.3 allows TREATMENT and EMERGENCY alone; §1.25 has no
    // dedicated code, so ERROR_HPI_INSUFFICIENT_INFORMATION is our own design.
    let Some(purpose_of_use) = purpose(envelope.values(PURPOSE)) else {
        return Err(refuse(
            EhdsiCode::HpiInsufficientInformation,
            vec![Field::PurposeOfUse.as_str()],
        ));
    };
    let permissions = envelope
        .values(name::PERMISSION)
        .iter()
        .filter_map(|value| text(*value, "saml:AttributeValue").ok())
        .collect();
    Ok(IdentityAssertion {
        id: envelope.id.clone(),
        issuer: envelope.issuer.clone(),
        name_id,
        window: envelope.window,
        authentication_class,
        name,
        roles,
        on_behalf_of,
        organization_id,
        organization: envelope.single(name::ORGANIZATION)?,
        facility_type,
        home_community_id,
        point_of_care,
        purpose_of_use,
        speciality: envelope.single(name::SPECIALITY)?,
        npi: envelope.single(name::NPI)?,
        permissions,
    })
}

/// Reads the professional: the `NameID` with its format, the name, the
/// roles and `on-behalf-of`, refused `ERROR_HPI_NO_INFORMATION` when none
/// is present and `ERROR_HPI_INSUFFICIENT_INFORMATION` when one is missing.
fn professional(
    envelope: &Envelope<'_, '_>,
) -> Result<(NameId, String, Vec<Role>, Option<String>), AssertionError> {
    let refuse = |code, missing: Vec<&'static str>| AssertionError::Attributes { code, missing };
    let name_id = envelope.name_id()?;
    let name = envelope.single(SUBJECT)?;
    let roles = roles(envelope);
    if name_id.is_none() && name.is_none() && envelope.values(name::ROLE).is_empty() {
        return Err(refuse(EhdsiCode::HpiNoInformation, Vec::new()));
    }
    let format = name_id
        .as_ref()
        .and_then(|(_, format)| format.and_then(|format| format.parse::<NameIdFormat>().ok()));
    let on_behalf_of = envelope
        .values(name::ON_BEHALF_OF)
        .first()
        .and_then(|value| coded(*value).or_else(|| text(*value, "saml:AttributeValue").ok()));
    let mut missing = Vec::new();
    for (absent, field) in [
        (name_id.is_none(), Field::ProfessionalHpIdentifier),
        (format.is_none(), Field::AssertionNameIdFormat),
        (name.is_none(), Field::ProfessionalName),
        (roles.is_none(), Field::ProfessionalHpProfessionalRole),
    ] {
        if absent {
            missing.push(field.as_str());
        }
    }
    // NOTE: SAML Profile 10.0.0 §2.3: `on-behalf-of` is "Mandatory if a structural role is
    // part of the category Clerical Support Workers", ISCO 44.
    let clerical = roles
        .as_ref()
        .is_some_and(|roles| roles.iter().any(|role| role.code == "44"));
    if clerical && on_behalf_of.is_none() {
        missing.push(Field::ProfessionalOnBehalfOf.as_str());
    }
    let (Some((value, _)), Some(format), Some(name), Some(roles), true) =
        (name_id, format, name, roles, missing.is_empty())
    else {
        return Err(refuse(EhdsiCode::HpiInsufficientInformation, missing));
    };
    Ok((NameId::new(value, format), name, roles, on_behalf_of))
}

/// Returns the structural roles, each an HL7 v3 `Role` with a `code`
/// ("the Role SHALL be recorded under the `AttributeValue` with an element
/// `<Role>`", SAML Profile 10.0.0 §2.3), or nothing when any value is not.
fn roles(envelope: &Envelope<'_, '_>) -> Option<Vec<Role>> {
    let values = envelope.values(name::ROLE);
    if values.is_empty() {
        return None;
    }
    values
        .iter()
        .map(|value| {
            let role = only(*value, "Role")?;
            Some(Role {
                code: role
                    .attribute("code")
                    .filter(|code| !code.is_empty())?
                    .to_owned(),
                code_system: role.attribute("codeSystem").map(str::to_owned),
            })
        })
        .collect()
}

/// Returns the purpose of use of `values`: one HL7 v3 `PurposeOfUse` whose
/// `code` is `TREATMENT` or `EMERGENCY` (SAML Profile 10.0.0 §2.3, §4.3).
pub(super) fn purpose(values: &[roxmltree::Node<'_, '_>]) -> Option<PurposeOfUse> {
    let [value] = values else {
        return None;
    };
    match only(*value, "PurposeOfUse")?.attribute("code")? {
        "TREATMENT" => Some(PurposeOfUse::Treatment),
        "EMERGENCY" => Some(PurposeOfUse::Emergency),
        _ => None,
    }
}

/// Returns the one HL7 v3 element `name` an attribute value holds.
fn only<'a, 'input>(
    value: roxmltree::Node<'a, 'input>,
    name: &'static str,
) -> Option<roxmltree::Node<'a, 'input>> {
    let mut children = value.children().filter(roxmltree::Node::is_element);
    let element = children.next()?;
    (children.next().is_none() && elements(value, HL7, name).next() == Some(element))
        .then_some(element)
}

/// Returns the `code` of the one HL7 v3 `Role` a value holds.
fn coded(value: roxmltree::Node<'_, '_>) -> Option<String> {
    only(value, "Role")?.attribute("code").map(str::to_owned)
}

/// Returns the `ehdsi` claim of a contact-point token for `identity` and,
/// past the discovery phase, `treatment`.
///
/// The claim is the field set [`crate::federation::Mapping::Ehdsi`] reads,
/// each named as [`Field::as_str`] spells it, the times in seconds since the
/// epoch.
///
/// The TRC's purpose of use, when present, "overwrites the purpose of use
/// attribute contained with the HP identity assertion" (SAML Profile 10.0.0
/// §4.3).
#[must_use]
pub fn ehdsi_claim(identity: &IdentityAssertion, treatment: Option<&TreatmentAssertion>) -> Value {
    let mut professional = Map::new();
    professional.insert("hp_identifier".into(), json!(identity.name_id.value()));
    professional.insert("name".into(), json!(identity.name));
    let roles: Vec<Value> = identity
        .roles
        .iter()
        .map(|role| json!({ "system": role.code_system.as_deref().unwrap_or(ISCO), "code": role.code }))
        .collect();
    professional.insert("hp_professional_role".into(), Value::Array(roles));
    professional.insert(
        "authentication_method".into(),
        json!(identity.authentication_class),
    );
    insert(
        &mut professional,
        "on_behalf_of",
        identity.on_behalf_of.as_deref(),
    );
    insert(
        &mut professional,
        "speciality",
        identity.speciality.as_deref(),
    );
    insert(&mut professional, "npi", identity.npi.as_deref());
    if !identity.permissions.is_empty() {
        professional.insert("permissions".into(), json!(identity.permissions));
    }
    let mut provider = Map::new();
    provider.insert(
        "healthcare_provider_identifier".into(),
        json!(identity.organization_id),
    );
    insert(
        &mut provider,
        "healthcare_provider_name",
        identity.organization.as_deref(),
    );
    provider.insert("facility_type".into(), json!(identity.facility_type));
    provider.insert(
        "home_community_id".into(),
        json!(identity.home_community_id),
    );
    let purpose = treatment
        .and_then(TreatmentAssertion::purpose_of_use)
        .unwrap_or(identity.purpose_of_use);
    let mut claim = json!({
        "professional": professional,
        "provider": provider,
        "point_of_care": identity.point_of_care,
        "purpose_of_use": purpose.as_str(),
        "assertion": {
            "issuer": identity.issuer,
            "id": identity.id,
            "name_id_format": identity.name_id.format().as_str(),
            "not_before": identity.window.not_before.as_second(),
            "not_on_or_after": identity.window.not_on_or_after.as_second(),
        },
    });
    if let (Some(treatment), Some(object)) = (treatment, claim.as_object_mut()) {
        object.insert("trc".into(), treatment.trc_claim());
        object.insert("patient".into(), treatment.patient_claim());
    }
    claim
}

/// Inserts `value` under `key` when present.
fn insert(object: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        object.insert(key.to_owned(), json!(value));
    }
}
