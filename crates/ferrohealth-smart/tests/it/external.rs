// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The external party a downstream crate builds for its own tests (feature
//! `test-support`), and the two caller kinds that carry it.

use std::collections::BTreeMap;

use ferrohealth_smart::federation::Attribute;
use ferrohealth_smart::federation::External;
use ferrohealth_smart::federation::Field;
use ferrohealth_smart::kind::CallerKind;

fn external() -> External {
    External::new(
        "synthetic-remote-subject",
        BTreeMap::from([(
            Field::ProfessionalName,
            Attribute::Text(String::from("Synthetic Professional")),
        )]),
    )
}

// NOTE: no specification governs the constructor: our own design, so a downstream crate tests a
// policy over the two external kinds without a federation token (#272).
#[test]
fn an_external_built_for_a_test_reads_back_what_it_was_given() {
    let built = external();
    assert_eq!("synthetic-remote-subject", built.remote_subject());
    assert_eq!(
        Some(&Attribute::Text(String::from("Synthetic Professional"))),
        built.field(Field::ProfessionalName)
    );
    assert_eq!(1, built.fields().len());
}

#[test]
fn an_external_built_for_a_test_renders_no_value() {
    let rendered = format!("{:?}", external());
    assert!(!rendered.contains("synthetic-remote-subject"), "{rendered}");
    assert!(!rendered.contains("Synthetic Professional"), "{rendered}");
}

#[test]
fn both_external_kinds_carry_a_built_external() {
    let person = CallerKind::ExternalPerson(Box::new(external()));
    let organisation = CallerKind::ExternalOrganisation(Box::new(external()));
    assert_eq!("external_person", person.as_str());
    assert_eq!("external_organisation", organisation.as_str());
}
