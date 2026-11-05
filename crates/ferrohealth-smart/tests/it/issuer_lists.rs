// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `[auth]` lists read per issuer, `scopeless_subjects` and
//! `role_claims`: an entry holds for the tokens of the issuer it names, a
//! bare entry only when the section trusts one issuer, and a section that
//! trusts several refuses a bare entry or one naming an issuer it does not
//! trust.

use std::collections::BTreeSet;
use std::error::Error as StdError;

use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::IssuerEntry;
use ferrohealth_smart::config::IssuerKey;
use ferrohealth_smart::resource::Compartment;
use ferrohealth_smart::resource::IssuerSet;
use ferrohealth_smart::resource::Verifier;
use ferrohealth_smart::scope::Permission;
use jsonwebtoken::Algorithm;

use crate::support::AUDIENCE;
use crate::support::Issuer;
use crate::support::ec_key;
use crate::support::mint;
use crate::support::server;

const ONE: &str = "https://one.example.org";
const TWO: &str = "https://two.example.org";

/// Returns a section trusting `issuers` with the two lists given.
fn section(issuers: &[&str], scopeless: &[&str], roles: &[&str]) -> AuthSection {
    let entries = issuers
        .iter()
        .map(|&issuer| IssuerEntry {
            issuer: issuer.to_owned(),
            ..IssuerEntry::default()
        })
        .collect();
    AuthSection {
        issuer: IssuerKey::List(entries),
        audience: vec![String::from(AUDIENCE)],
        scopeless_subjects: scopeless.iter().map(|&entry| entry.to_owned()).collect(),
        role_claims: roles.iter().map(|&entry| entry.to_owned()).collect(),
        ..AuthSection::default()
    }
}

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|&value| value.to_owned()).collect()
}

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|&value| value.to_owned()).collect()
}

#[test]
fn each_issuer_receives_only_the_entries_that_name_it() -> Result<(), Box<dyn StdError>> {
    let resolved = section(
        &[ONE, TWO],
        &["https://one.example.org#svc"],
        &[
            "https://one.example.org#realm_access.roles",
            "https://two.example.org#groups",
            "https://one.example.org#roles",
        ],
    )
    .resolve()?;
    assert_eq!(set(&["svc"]), resolved.issuers[0].scopeless_subjects);
    assert_eq!(
        owned(&["realm_access.roles", "roles"]),
        resolved.issuers[0].role_claims
    );
    assert!(resolved.issuers[1].scopeless_subjects.is_empty());
    assert_eq!(owned(&["groups"]), resolved.issuers[1].role_claims);
    Ok(())
}

#[test]
fn a_bare_scopeless_subject_is_refused_beside_several_issuers() {
    let refused = section(&[ONE, TWO], &["svc"], &[]).resolve();
    assert!(
        matches!(
            &refused,
            Err(ConfigError::Unqualified { key: "auth.scopeless_subjects", entry })
                if entry == "svc"
        ),
        "{refused:?}"
    );
    let message = refused.err().map(|error| error.to_string());
    assert_eq!(
        Some(String::from(
            "the auth.scopeless_subjects entry \"svc\" names no issuer and the section trusts \
             several: write it as \"<issuer>#svc\" for each issuer it holds for"
        )),
        message
    );
}

#[test]
fn a_bare_role_claim_is_refused_beside_several_issuers() {
    assert!(matches!(
        section(&[ONE, TWO], &[], &["https://one.example.org#roles", "groups"]).resolve(),
        Err(ConfigError::Unqualified { key: "auth.role_claims", entry }) if entry == "groups"
    ));
}

#[test]
fn the_default_role_claims_are_refused_beside_several_issuers() {
    let mut auth = section(&[ONE, TWO], &[], &[]);
    auth.role_claims = AuthSection::default().role_claims;
    assert!(matches!(
        auth.resolve(),
        Err(ConfigError::Unqualified {
            key: "auth.role_claims",
            ..
        })
    ));
}

#[test]
fn several_issuers_with_empty_lists_resolve_and_read_no_role() -> Result<(), Box<dyn StdError>> {
    let resolved = section(&[ONE, TWO], &[], &[]).resolve()?;
    for settings in &resolved.issuers {
        assert!(settings.scopeless_subjects.is_empty());
        assert_eq!(Vec::<String>::new(), settings.role_claims);
    }
    Ok(())
}

#[test]
fn an_entry_naming_an_untrusted_issuer_is_refused() {
    assert!(matches!(
        section(&[ONE, TWO], &["https://three.example.org#svc"], &[]).resolve(),
        Err(ConfigError::UnknownIssuer { key: "auth.scopeless_subjects", issuer })
            if issuer == "https://three.example.org"
    ));
    assert!(matches!(
        section(&[ONE], &[], &["https://one.example.org/#roles"]).resolve(),
        Err(ConfigError::UnknownIssuer { key: "auth.role_claims", issuer })
            if issuer == "https://one.example.org/"
    ));
}

#[test]
fn one_issuer_keeps_its_bare_entries() -> Result<(), Box<dyn StdError>> {
    let section: AuthSection = toml::from_str(
        r#"
        issuer = "https://one.example.org"
        audience = ["http://ferro.invalid/fhir"]
        scopeless_subjects = ["svc", "https://one.example.org#batch", "etl#7"]
        role_claims = ["realm_access.roles", "https://one.example.org#groups"]
        "#,
    )?;
    let resolved = section.resolve()?;
    assert_eq!(
        set(&["svc", "batch", "etl#7"]),
        resolved.issuers[0].scopeless_subjects
    );
    assert_eq!(
        owned(&["realm_access.roles", "groups"]),
        resolved.issuers[0].role_claims
    );
    Ok(())
}

#[test]
fn a_qualified_role_claim_path_is_still_checked() {
    assert!(matches!(
        section(
            &[ONE, TWO],
            &[],
            &["https://one.example.org#realm_access..roles"]
        )
        .resolve(),
        Err(ConfigError::Missing {
            key: "auth.role_claims"
        })
    ));
}

/// Two stub issuers behind one `IssuerSet` resolved from `auth`.
async fn trusted(
    one: &Issuer,
    two: &Issuer,
    scopeless: &[String],
    roles: &[String],
) -> Result<IssuerSet, Box<dyn StdError>> {
    let mut auth = section(&[one.uri().as_str(), two.uri().as_str()], &[], &[]);
    auth.scopeless_subjects = scopeless.to_vec();
    auth.role_claims = roles.to_vec();
    let mut set = IssuerSet::new();
    for settings in auth.resolve()?.issuers {
        set = set.with(server(settings).await);
    }
    Ok(set)
}

#[tokio::test]
async fn a_scopeless_subject_holds_only_for_the_issuer_it_names() -> Result<(), Box<dyn StdError>> {
    let one_key = ec_key("k1", Algorithm::ES256);
    let two_key = ec_key("k2", Algorithm::ES256);
    let one = Issuer::start(&[&one_key]).await;
    let two = Issuer::start(&[&two_key]).await;
    let set = trusted(
        &one,
        &two,
        &[format!("{}#synthetic-client-sub", one.uri())],
        &[],
    )
    .await?;
    let from_one = set.verify(&mint(&one_key, &one.claims("openid"))).await?;
    assert_eq!(
        Some(Compartment::Any),
        from_one.reach(Permission::Delete, "Condition")
    );
    let from_two = set.verify(&mint(&two_key, &two.claims("openid"))).await?;
    assert!(!from_two.scopeless(), "the same sub from the other issuer");
    assert_eq!(None, from_two.reach(Permission::Delete, "Condition"));
    Ok(())
}

#[tokio::test]
async fn roles_are_read_only_from_the_issuer_a_claim_names() -> Result<(), Box<dyn StdError>> {
    let one_key = ec_key("k1", Algorithm::ES256);
    let two_key = ec_key("k2", Algorithm::ES256);
    let one = Issuer::start(&[&one_key]).await;
    let two = Issuer::start(&[&two_key]).await;
    let set = trusted(&one, &two, &[], &[format!("{}#roles", one.uri())]).await?;
    let mut one_claims = one.claims("system/Condition.r");
    one_claims["roles"] = serde_json::json!(["ADMIN"]);
    let from_one = set.verify(&mint(&one_key, &one_claims)).await?;
    assert!(from_one.has_role("ADMIN"));
    let mut two_claims = two.claims("system/Condition.r");
    two_claims["roles"] = serde_json::json!(["ADMIN"]);
    two_claims["groups"] = serde_json::json!(["ADMIN"]);
    let from_two = set.verify(&mint(&two_key, &two_claims)).await?;
    assert!(from_two.roles().is_empty(), "{:?}", from_two.roles());
    Ok(())
}
