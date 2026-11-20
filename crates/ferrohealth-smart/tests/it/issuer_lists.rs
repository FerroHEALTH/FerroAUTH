// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What holds per issuer: `scopeless_subjects` entries are `{ issuer, sub }`
//! and hold for that issuer's app-only tokens alone, `role_claims` sit on
//! each `[auth.issuer.<name>]` table and read that issuer's tokens alone, and the
//! string forms of both are refused naming the replacement.

use std::collections::BTreeSet;
use std::error::Error as StdError;

use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::IssuerEntry;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::profile::ProfileKeys;
use ferrohealth_smart::resource::Compartment;
use ferrohealth_smart::resource::IssuerSet;
use ferrohealth_smart::resource::Verifier;
use ferrohealth_smart::scope::Permission;
use jsonwebtoken::Algorithm;

use crate::support::AUDIENCE;
use crate::support::CLIENT;
use crate::support::Issuer;
use crate::support::ec_key;
use crate::support::mint;
use crate::support::server;

const ONE: &str = "https://one.example.org";
const TWO: &str = "https://two.example.org";

/// Returns the `persons` issuer table of `issuer` reading roles from
/// `roles`, its client first-party.
fn entry(issuer: &str, roles: &[&str]) -> IssuerEntry {
    IssuerEntry {
        issuer: ferrohealth_secret::secret_url::SecretUrl::new(issuer),
        kind: Some(IssuerKind::Persons),
        audience: vec![String::from(AUDIENCE)],
        role_claims: Some(roles.iter().map(|&role| role.to_owned()).collect()),
        profile: ProfileKeys {
            first_party_clients: Some(vec![String::from(CLIENT)]),
            ..ProfileKeys::default()
        },
        ..IssuerEntry::default()
    }
}

/// Returns a section trusting `entries`, named `i1` on, each with the
/// subjects of `scopeless` that name its issuer.
fn section(entries: Vec<IssuerEntry>, scopeless: &[(String, String)]) -> AuthSection {
    let issuer = entries
        .into_iter()
        .enumerate()
        .map(|(index, mut entry)| {
            entry.scopeless_subjects = scopeless
                .iter()
                .filter(|(issuer, _)| issuer == entry.issuer.expose())
                .map(|(_, sub)| sub.clone())
                .collect();
            (format!("i{}", index + 1), entry)
        })
        .collect();
    AuthSection {
        issuer,
        ..AuthSection::default()
    }
}

/// Returns the subject `sub` of `issuer`.
fn subject(issuer: &str, sub: &str) -> (String, String) {
    (issuer.to_owned(), sub.to_owned())
}

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|&value| value.to_owned()).collect()
}

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|&value| value.to_owned()).collect()
}

#[test]
fn each_issuer_receives_only_its_own_entries() -> Result<(), Box<dyn StdError>> {
    let resolved = section(
        vec![
            entry(ONE, &["realm_access.roles", "roles"]),
            entry(TWO, &["groups"]),
        ],
        &[subject(ONE, "svc")],
    )
    .resolve(&[])?;
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
fn a_string_scopeless_subject_and_a_section_level_role_claims_are_refused_at_load() {
    for text in [
        "scopeless_subjects = [\"svc\"]",
        "scopeless_subjects = [\"https://one.example.org#svc\"]",
        "role_claims = [\"https://one.example.org#roles\"]",
    ] {
        let read = toml::from_str::<AuthSection>(&format!(
            "{text}\n[issuer.i2]\nissuer = \"{ONE}\"\nkind = \"persons\"\naudience = [\"a\"]\n"
        ));
        assert!(read.is_err(), "{text} is no key or shape of the section");
    }
}

#[test]
fn an_entry_naming_an_issuer_outside_its_table_is_no_key_of_the_section() {
    // NOTE: no specification governs the allowlist: our own design (#730), each
    // issuer's subjects sit on its own table, so no entry can name an untrusted one.
    let read = toml::from_str::<AuthSection>(&format!(
        "scopeless_subjects = [{{ issuer = \"https://three.example.org\", sub = \"svc\" }}]\n\
         [issuer.one]\nissuer = \"{ONE}\"\nkind = \"persons\"\naudience = [\"a\"]\n"
    ));
    assert!(
        read.is_err(),
        "a section-level scopeless_subjects is refused"
    );
}

#[test]
fn a_scopeless_subject_is_refused_on_a_patients_issuer() {
    let mut patients = entry(ONE, &[]);
    patients.kind = Some(IssuerKind::Patients);
    assert!(matches!(
        section(vec![patients], &[subject(ONE, "svc")]).resolve(&[]),
        Err(ConfigError::Issuer { issuer, .. }) if issuer == ONE
    ));
}

#[test]
fn a_role_claim_path_is_still_checked() {
    assert!(matches!(
        section(vec![entry(ONE, &["realm_access..roles"])], &[]).resolve(&[]),
        Err(ConfigError::Missing {
            key: "auth.issuer.role_claims"
        })
    ));
}

/// The stub issuers of `auth` behind one `IssuerSet`.
async fn trusted(auth: &AuthSection) -> Result<IssuerSet, Box<dyn StdError>> {
    let mut set = IssuerSet::new();
    for settings in auth.resolve(&[])?.issuers {
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
    let auth = section(
        vec![entry(&one.uri(), &[]), entry(&two.uri(), &[])],
        &[subject(&one.uri(), CLIENT)],
    );
    let set = trusted(&auth).await?;
    // NOTE: RFC 9068 §5, a client credentials token whose `sub` is its
    // `client_id` is app-only, the one kind the allowlist admits.
    let app_only = |issuer: &Issuer| {
        let mut claims = issuer.claims("openid");
        claims["sub"] = serde_json::json!(CLIENT);
        claims
    };
    let from_one = set.verify(&mint(&one_key, &app_only(&one))).await?;
    assert_eq!(&CallerKind::System, from_one.kind());
    assert_eq!(
        Some(Compartment::Any),
        from_one.reach(Permission::Delete, "Condition")
    );
    let from_two = set.verify(&mint(&two_key, &app_only(&two))).await?;
    assert!(!from_two.scopeless(), "the same sub from the other issuer");
    assert_eq!(None, from_two.reach(Permission::Delete, "Condition"));
    Ok(())
}

#[tokio::test]
async fn roles_are_read_only_from_the_issuer_that_names_the_claim() -> Result<(), Box<dyn StdError>>
{
    let one_key = ec_key("k1", Algorithm::ES256);
    let two_key = ec_key("k2", Algorithm::ES256);
    let one = Issuer::start(&[&one_key]).await;
    let two = Issuer::start(&[&two_key]).await;
    let auth = section(
        vec![entry(&one.uri(), &["roles"]), entry(&two.uri(), &[])],
        &[],
    );
    let set = trusted(&auth).await?;
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
