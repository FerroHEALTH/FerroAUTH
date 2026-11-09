// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `[[auth.party]]` tables as a deployment writes them, and every rule
//! they are loaded under.

use super::*;

/// Returns the `[auth]` section `text` reads as.
fn section(text: &str) -> Result<AuthSection, toml::de::Error> {
    toml::from_str(text)
}

/// The issuer tables of the configuration cases.
const ISSUERS: &str = r#"
[[issuer]]
issuer = "https://login.example.org/tenant-1/v2.0"
kind = "persons"
profile = "entra"
audience = ["api://ferro"]
first_party_clients = ["first-party-app"]
jwks_file = "/dev/null"

[[issuer]]
issuer = "https://as.example.org/realms/other"
kind = "persons"
audience = ["api://ferro"]
jwks_file = "/dev/null"

[[issuer]]
issuer = "https://as.example.org/realms/machines"
kind = "machines"
audience = ["api://ferro"]
jwks_file = "/dev/null"
"#;

/// Returns the party error a section of [`ISSUERS`] and `party` resolves to.
fn party_error(party: &str) -> Result<PartyError, Box<dyn StdError>> {
    match section(&format!("{ISSUERS}{party}"))?.resolve() {
        Err(ConfigError::Party { source }) => Ok(source),
        other => Err(format!("a party error, not {other:?}").into()),
    }
}

#[test]
fn a_table_that_sets_claim_is_an_unknown_key_at_load() {
    let read = section(&format!(
        r#"{ISSUERS}
[[party]]
issuer = "https://login.example.org/tenant-1/v2.0"
identifier_issuer = "urn:example:ferro:login"
identifier_type = "guid"
claim = "sub"
"#
    ));
    assert!(read.is_err(), "claim is no key of the table");
}

// NOTE: no specification governs the configuration: our own design, in which two tables
// never share an identifier_issuer, because two subject spaces would merge.
#[test]
fn two_tables_sharing_an_identifier_issuer_fail_to_load_naming_both() -> Outcome2 {
    let error = party_error(
        r#"
[[party]]
issuer = "https://login.example.org/tenant-1/v2.0"
identifier_issuer = "urn:example:ferro:login"
identifier_type = "guid"

[[party]]
issuer = "https://as.example.org/realms/other"
identifier_issuer = "urn:example:ferro:login"
identifier_type = "login"
"#,
    )?;
    assert_eq!(
        PartyError::SharedIdentifierIssuer {
            first: String::from(ISSUER),
            second: String::from("https://as.example.org/realms/other"),
            identifier_issuer: String::from(IDENTIFIERS),
        },
        error
    );
    Ok(())
}

// NOTE: OpenID Connect Core 1.0 §5.7: `email`, `phone_number`, `preferred_username` and
// `name` "MUST NOT be used as unique identifiers for the End-User".
#[test]
fn a_banned_claim_as_key_fails_to_load() -> Outcome2 {
    let banned = ISSUERS.replacen(
        "profile = \"entra\"",
        "profile = \"entra\"\nperson_key = \"email\"",
        1,
    );
    let text = format!(
        "{banned}
[[party]]
issuer = \"https://login.example.org/tenant-1/v2.0\"
identifier_issuer = \"urn:example:ferro:login\"
identifier_type = \"guid\"
"
    );
    assert!(
        matches!(section(&text)?.resolve(), Err(ConfigError::Issuer { .. })),
        "the profile refuses the key at load"
    );
    let source: Arc<dyn PartySource> = FakeSource::answering(one_professional());
    let unstable = Profile {
        person_key: String::from("preferred_username"),
        ..profile()
    };
    assert_eq!(
        Err(PartyError::UnstableKey {
            issuer: String::from(ISSUER),
            claim: String::from("preferred_username"),
        }),
        PartyBinding::new(source)
            .with_issuer(table(), IssuerKind::Persons, &unstable)
            .map(|_binding| ())
    );
    Ok(())
}

// NOTE: no specification governs the configuration: our own design; a table binds only
// a trusted persons issuer, and its unknown keys are refused.
#[test]
fn a_table_loads_with_deny_unknown_fields_and_binds_only_a_persons_issuer() -> Outcome2 {
    let unknown = section(&format!(
        "{ISSUERS}
[[party]]
issuer = \"https://login.example.org/tenant-1/v2.0\"
identifier_issuer = \"urn:example:ferro:login\"
identifier_type = \"guid\"
match = \"exact\"
"
    ));
    assert!(
        unknown.is_err_and(|error| error.to_string().contains("match")),
        "an unknown key is refused naming it"
    );
    assert!(matches!(
        party_error(
            r#"
[[party]]
issuer = "https://as.example.org/realms/machines"
identifier_issuer = "urn:example:ferro:machines"
identifier_type = "login"
"#,
        )?,
        PartyError::NotPersons {
            kind: Some(IssuerKind::Machines),
            ..
        }
    ));
    let resolved = section(&format!(
        "{ISSUERS}
[[party]]
issuer = \"https://login.example.org/tenant-1/v2.0\"
identifier_issuer = \"urn:example:ferro:login\"
identifier_type = \"guid\"
group_claim = \"groups\"
group_identifier_issuer = \"urn:example:ferro:groups\"
"
    ))?
    .resolve()?;
    assert_eq!(vec![table()], resolved.party);
    let source: Arc<dyn PartySource> = FakeSource::answering(one_professional());
    let binding = PartyBinding::new(source).with_resolved(&resolved)?;
    assert!(format!("{binding:?}").contains(ISSUER), "{binding:?}");
    Ok(())
}
