// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The care role a treatment relationship attests: the field
//! `trc.care_role` a `federation` issuer's table maps, one coded value with
//! its code system (FerroHEALTH/FerroSMART#751).

use std::error::Error as StdError;

use ferrohealth_smart::federation::Attribute;
use ferrohealth_smart::federation::Code;
use ferrohealth_smart::federation::FederationSection;
use ferrohealth_smart::federation::Field;
use ferrohealth_smart::federation::Source;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::Unclassified;
use serde_json::Value;
use serde_json::json;

use crate::federation::Harness;
use crate::federation::iua;
use crate::federation::professional;
use crate::federation::refused;

type Outcome = Result<(), Box<dyn StdError>>;

/// The code system of the cases' care roles, invented for them.
const SYSTEM: &str = "urn:example:care-role";

/// Returns the IUA table with `trc.care_role` read from the claim
/// `care_role`.
fn mapped() -> FederationSection {
    let mut section = iua();
    section.fields.insert(
        Field::TrcCareRole,
        vec![Source::Claim(String::from("care_role"))],
    );
    section
}

/// Returns a professional's claims carrying `role` as `care_role`.
fn with_role(role: Value) -> Value {
    let mut claims = professional();
    if let Some(members) = claims.as_object_mut() {
        members.insert(String::from("care_role"), role);
    }
    claims
}

#[tokio::test]
async fn a_mapped_care_role_reaches_the_caller_with_its_system() -> Outcome {
    let claims = with_role(json!([{ "system": SYSTEM, "code": "treating" }]));
    let caller = Harness::new().admit(mapped(), &claims).await?;
    let CallerKind::ExternalPerson(person) = caller.kind() else {
        return Err("an external person".into());
    };
    assert_eq!(
        Some(&Attribute::Codes(vec![Code {
            system: Some(String::from(SYSTEM)),
            code: String::from("treating"),
        }])),
        person.field(Field::TrcCareRole)
    );
    Ok(())
}

#[tokio::test]
async fn a_configured_care_role_is_a_coded_constant() -> Outcome {
    let mut section = iua();
    section.fields.insert(
        Field::TrcCareRole,
        vec![Source::Coded {
            system: String::from(SYSTEM),
            code: String::from("treating"),
        }],
    );
    let caller = Harness::new().admit(section, &professional()).await?;
    let CallerKind::ExternalPerson(person) = caller.kind() else {
        return Err("an external person".into());
    };
    assert!(person.field(Field::TrcCareRole).is_some());
    let mut plain = iua();
    plain.fields.insert(
        Field::TrcCareRole,
        vec![Source::Constant(String::from("treating"))],
    );
    assert_eq!(
        Some(Unclassified::Attribute {
            field: "trc.care_role"
        }),
        refused(Harness::new().admit(plain, &professional()).await),
        "a constant without its system"
    );
    Ok(())
}

// NOTE: no specification governs the form: our own design, in which the care role
// is one code with its system, so no consumer matches a code of another system.
#[tokio::test]
async fn a_care_role_other_than_one_systemed_code_is_refused_naming_the_field() -> Outcome {
    for role in [
        json!("treating"),
        json!(["treating"]),
        json!([{ "code": "treating" }]),
        json!([{ "system": SYSTEM, "code": "treating" }, { "system": SYSTEM, "code": "consulting" }]),
    ] {
        assert_eq!(
            Some(Unclassified::Attribute {
                field: "trc.care_role"
            }),
            refused(
                Harness::new()
                    .admit(mapped(), &with_role(role.clone()))
                    .await
            ),
            "{role}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_token_without_a_care_role_carries_none() -> Outcome {
    let caller = Harness::new().admit(mapped(), &professional()).await?;
    let CallerKind::ExternalPerson(person) = caller.kind() else {
        return Err("an external person".into());
    };
    assert_eq!(None, person.field(Field::TrcCareRole));
    Ok(())
}

#[test]
fn the_field_loads_from_toml_by_its_name() -> Outcome {
    let section: FederationSection = toml::from_str(
        "[fields]\n\"trc.care_role\" = [{ constant = \"treating\", system = \"urn:example:care-role\" }]\n",
    )?;
    assert_eq!(
        Some(&vec![Source::Coded {
            system: String::from(SYSTEM),
            code: String::from("treating"),
        }]),
        section.fields.get(&Field::TrcCareRole)
    );
    assert_eq!("trc.care_role", Field::TrcCareRole.as_str());
    Ok(())
}
