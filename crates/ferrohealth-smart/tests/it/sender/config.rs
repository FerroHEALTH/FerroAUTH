// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The configuration of sender-constrained tokens: the per-issuer
//! `sender_constraint` key and the surface's `[auth.dpop]` table.

use std::time::Duration;

use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::sender::SenderConstraint;
use ferrohealth_smart::sender::proof::ProofSettingsError;

/// Returns the section `text` describes.
fn section(text: &str) -> AuthSection {
    toml::from_str(text).expect("the section parses")
}

/// One `persons` issuer table, with `extra` keys.
fn issuer(extra: &str) -> String {
    format!(
        "[[issuer]]\nissuer = \"https://as.example.org\"\nkind = \"persons\"\naudience = [\"a\"]\n{extra}\n"
    )
}

#[test]
fn an_issuer_requires_a_sender_constraint_when_it_says_so() {
    let required = section(&issuer("sender_constraint = \"required\""))
        .resolve()
        .expect("the section resolves");
    assert_eq!(
        Some(SenderConstraint::Required),
        required
            .issuers
            .first()
            .map(|settings| settings.sender_constraint)
    );
    let default = section(&issuer(""))
        .resolve()
        .expect("the section resolves");
    assert_eq!(
        Some(SenderConstraint::None),
        default
            .issuers
            .first()
            .map(|settings| settings.sender_constraint),
        "no constraint unless the issuer sets one"
    );
    assert!(
        toml::from_str::<AuthSection>(&issuer("sender_constraint = \"optional\"")).is_err(),
        "a value outside none and required does not parse"
    );
}

#[test]
fn the_dpop_table_names_the_external_url_and_the_window() {
    let resolved = section(&format!(
        "[dpop]\nexternal_url = \"https://ehr.example.org/fhir\"\nmax_age = \"30s\"\n{}",
        issuer("")
    ))
    .resolve()
    .expect("the section resolves");
    let dpop = resolved.dpop.expect("the table resolves");
    assert_eq!("https://ehr.example.org/fhir", dpop.external_url.as_str());
    assert_eq!(Duration::from_secs(30), dpop.max_age);
    assert_eq!(Duration::from_secs(10), dpop.clock_skew);
    assert!(
        section(&issuer(""))
            .resolve()
            .expect("resolves")
            .dpop
            .is_none(),
        "no table, no DPoP"
    );
}

#[test]
fn a_dpop_table_that_breaks_a_rule_refuses_the_start() {
    for (table, expected) in [
        ("external_url = \"\"", None),
        (
            "external_url = \"https://ehr.example.org/?q\"",
            Some(ProofSettingsError::ExternalUrl),
        ),
        (
            "external_url = \"https://ehr.example.org\"\nmax_age = \"0s\"",
            Some(ProofSettingsError::MaxAge {
                max_age: Duration::ZERO,
            }),
        ),
        (
            "external_url = \"https://ehr.example.org\"\nalgorithms = [\"HS256\"]",
            Some(ProofSettingsError::SymmetricAlgorithm {
                algorithm: jsonwebtoken::Algorithm::HS256,
            }),
        ),
    ] {
        let outcome = section(&format!("[dpop]\n{table}\n{}", issuer(""))).resolve();
        match expected {
            None => assert!(
                matches!(
                    outcome,
                    Err(ConfigError::Missing {
                        key: "auth.dpop.external_url"
                    })
                ),
                "{table}: {outcome:?}"
            ),
            Some(expected) => assert!(
                matches!(&outcome, Err(ConfigError::Dpop { source }) if *source == expected),
                "{table}: {outcome:?}"
            ),
        }
    }
}
