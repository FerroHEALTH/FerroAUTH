// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The consent decision reference a `federation` token carries: the field
//! `consent.reference` its issuer's table maps, read onto the caller as a
//! typed value (IHE BALP 1.1.4 3:5.7.6, the consent decision record).

use std::error::Error as StdError;

use ferrohealth_smart::federation::FederationSection;
use ferrohealth_smart::federation::Field;
use ferrohealth_smart::federation::Source;
use ferrohealth_smart::kind::Unclassified;
use serde_json::json;

use crate::federation::Harness;
use crate::federation::iua;
use crate::federation::professional;
use crate::federation::refused;

type Outcome = Result<(), Box<dyn StdError>>;

/// The reference the cases' tokens carry, a FHIR Consent of the issuer.
const REFERENCE: &str = "https://consent.partner.example.org/fhir/Consent/c-1";

/// Returns the IUA table with `consent.reference` read from the claim
/// `consent_ref`.
fn mapped() -> FederationSection {
    let mut section = iua();
    section.fields.insert(
        Field::ConsentReference,
        vec![Source::Claim(String::from("consent_ref"))],
    );
    section
}

#[tokio::test]
async fn a_mapped_consent_reference_reaches_the_caller() -> Outcome {
    let mut claims = professional();
    claims["consent_ref"] = json!(REFERENCE);
    let caller = Harness::new().admit(mapped(), &claims).await?;
    let reference = caller.consent_reference().ok_or("a consent reference")?;
    assert_eq!(REFERENCE, reference.as_str());
    Ok(())
}

#[tokio::test]
async fn a_token_without_the_reference_carries_none() -> Outcome {
    let caller = Harness::new().admit(mapped(), &professional()).await?;
    assert_eq!(None, caller.consent_reference());
    Ok(())
}

#[tokio::test]
async fn an_issuer_that_maps_no_reference_carries_none() -> Outcome {
    let mut claims = professional();
    claims["consent_ref"] = json!(REFERENCE);
    let caller = Harness::new().admit(iua(), &claims).await?;
    assert_eq!(
        None,
        caller.consent_reference(),
        "a claim the table does not map is never read as the reference"
    );
    Ok(())
}

// NOTE: no specification governs the form: our own design, in which the
// reference is one string and a coded value refuses the token naming the field.
#[tokio::test]
async fn a_coded_reference_is_refused_naming_the_field() -> Outcome {
    let mut claims = professional();
    claims["consent_ref"] = json!([REFERENCE]);
    assert_eq!(
        Some(Unclassified::Attribute {
            field: "consent.reference"
        }),
        refused(Harness::new().admit(mapped(), &claims).await)
    );
    Ok(())
}

#[tokio::test]
async fn the_reference_renders_no_value() -> Outcome {
    let mut claims = professional();
    claims["consent_ref"] = json!(REFERENCE);
    let caller = Harness::new().admit(mapped(), &claims).await?;
    let reference = caller.consent_reference().ok_or("a consent reference")?;
    let rendered = format!("{reference:?}");
    assert!(!rendered.contains("c-1"), "{rendered}");
    Ok(())
}

#[test]
fn the_field_loads_from_toml_by_its_name() -> Outcome {
    let section: FederationSection =
        toml::from_str("[fields]\n\"consent.reference\" = [{ claim = \"consent_ref\" }]\n")?;
    assert_eq!(
        Some(&vec![Source::Claim(String::from("consent_ref"))]),
        section.fields.get(&Field::ConsentReference)
    );
    assert_eq!("consent.reference", Field::ConsentReference.as_str());
    Ok(())
}
