// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The consent decision reference through the federation exchange: the
//! token a `federation` issuer issues for a caller that carries one must
//! carry the same reference (IHE BALP 1.1.4 3:5.7.6, the consent decision
//! record), read under that issuer's own table.

use std::collections::BTreeMap;

use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::client::onward::Rejected;
use ferrohealth_smart::federation::Attribute;
use ferrohealth_smart::federation::External;
use ferrohealth_smart::federation::FederationSection;
use ferrohealth_smart::federation::Field;
use ferrohealth_smart::federation::Source;
use ferrohealth_smart::kind::CallerKind;
use serde_json::Value;
use serde_json::json;

use super::federation::Case;
use super::federation::issued;
use super::federation::partner;
use super::federation::professional;
use super::federation::section;

/// The reference the caller's token carries.
const REFERENCE: &str = "https://consent.example.org/fhir/Consent/c-1";

/// Returns the federation issuer's table with `consent.reference` read from
/// the claim `consent_ref` of the tokens it issues.
fn mapped() -> FederationSection {
    let mut section = section();
    section.fields.insert(
        Field::ConsentReference,
        vec![Source::Claim(String::from("consent_ref"))],
    );
    section
}

/// Returns a professional of another party whose token carried `reference`
/// as its consent decision reference.
fn carrying(reference: Option<&str>) -> CallerKind {
    let fields = reference
        .map(|value| {
            BTreeMap::from([(
                Field::ConsentReference,
                Attribute::Text(String::from(value)),
            )])
        })
        .unwrap_or_default();
    CallerKind::ExternalPerson(Box::new(External::new("remote-person-1", fields)))
}

/// Returns the issued token carrying `reference` in `consent_ref`.
fn issued_with(reference: &str) -> Value {
    let mut token = issued();
    token
        .as_object_mut()
        .map(|claims| claims.insert(String::from("consent_ref"), json!(reference)));
    token
}

#[tokio::test]
async fn an_issued_token_that_keeps_the_reference_is_accepted() {
    let case = Case::start(mapped()).await;
    let outcome = case
        .exchange(
            &professional(),
            carrying(Some(REFERENCE)),
            &issued_with(REFERENCE),
            &partner(),
        )
        .await;
    assert!(outcome.is_ok(), "{outcome:?}");
}

#[tokio::test]
async fn an_issued_token_that_drops_the_reference_is_refused() {
    let case = Case::start(mapped()).await;
    let outcome = case
        .exchange(
            &professional(),
            carrying(Some(REFERENCE)),
            &issued(),
            &partner(),
        )
        .await;
    assert!(
        matches!(outcome, Err(OnwardError::Rejected(Rejected::Consent))),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn an_issued_token_naming_another_reference_is_refused() {
    let case = Case::start(mapped()).await;
    let outcome = case
        .exchange(
            &professional(),
            carrying(Some(REFERENCE)),
            &issued_with("https://consent.example.org/fhir/Consent/c-2"),
            &partner(),
        )
        .await;
    assert!(
        matches!(outcome, Err(OnwardError::Rejected(Rejected::Consent))),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn an_issuer_whose_table_maps_no_reference_cannot_keep_one() {
    let case = Case::start(section()).await;
    let outcome = case
        .exchange(
            &professional(),
            carrying(Some(REFERENCE)),
            &issued_with(REFERENCE),
            &partner(),
        )
        .await;
    assert!(
        matches!(outcome, Err(OnwardError::Rejected(Rejected::Consent))),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_caller_without_a_reference_takes_the_one_the_issuer_decides() {
    let case = Case::start(mapped()).await;
    let outcome = case
        .exchange(
            &professional(),
            carrying(None),
            &issued_with(REFERENCE),
            &partner(),
        )
        .await;
    assert!(outcome.is_ok(), "{outcome:?}");
}
