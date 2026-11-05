// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `[[auth.party]]` table, one per `persons` issuer whose logins are
//! bound, and the rules it is loaded under.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;

use crate::config::Removed;
use crate::kind::IssuerKind;
use crate::profile::Profile;

/// One `[[auth.party]]` table: where the logins of one `persons` issuer are
/// looked up.
///
/// It names no key claim: the issuer profile's `person_key` is the key, so
/// the binding, the classification and `person_equality` read one claim.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PartySection {
    /// The `persons` issuer whose logins the table binds.
    pub issuer: String,
    /// The issuer of the identifiers the key is matched against; no two
    /// tables share one.
    pub identifier_issuer: String,
    /// The type of those identifiers, which declares the key's canonical
    /// form: `guid` or `uuid` is compared in lower case, any other type
    /// exactly.
    pub identifier_type: String,
    /// The claim naming the groups the token asserts, an array of strings;
    /// empty to read no group.
    pub group_claim: String,
    /// The issuer of the group identifiers the group claim names; set with
    /// `group_claim`.
    pub group_identifier_issuer: String,
    /// Whether a guest of the issuer is looked up; a guest is not by
    /// default.
    pub guests: bool,
    /// Removed: the issuer profile's `person_key` names the key claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim: Removed,
}

/// A party binding that breaks a rule, naming the table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PartyError {
    /// A table sets `claim`, which the issuer profile's `person_key`
    /// replaces.
    #[error(
        "auth.party.claim of {issuer:?} is removed: the issuer profile's person_key \
         {person_key:?} names the key claim"
    )]
    Claim {
        /// The table's issuer.
        issuer: String,
        /// The issuer profile's `person_key`.
        person_key: String,
    },
    /// A table names no trusted `persons` issuer.
    #[error("the [[auth.party]] table of {issuer:?} names no trusted persons issuer")]
    NotPersons {
        /// The table's issuer.
        issuer: String,
        /// Its kind, when the section trusts it.
        kind: Option<IssuerKind>,
    },
    /// Two tables name one issuer.
    #[error("two [[auth.party]] tables name the issuer {issuer:?}")]
    DuplicateIssuer {
        /// The issuer.
        issuer: String,
    },
    /// Two tables share an `identifier_issuer`, which would merge two
    /// subject spaces.
    #[error(
        "the [[auth.party]] tables of {first:?} and {second:?} share the identifier_issuer \
         {identifier_issuer:?}"
    )]
    SharedIdentifierIssuer {
        /// The first table's issuer.
        first: String,
        /// The second table's issuer.
        second: String,
        /// The identifier issuer they share.
        identifier_issuer: String,
    },
    /// A key the table needs is empty.
    #[error("{key} of the [[auth.party]] table of {issuer:?} is empty")]
    Missing {
        /// The table's issuer.
        issuer: String,
        /// The key.
        key: &'static str,
    },
    /// `group_claim` and `group_identifier_issuer` are not set together.
    #[error(
        "group_claim and group_identifier_issuer of the [[auth.party]] table of {issuer:?} \
         are set together or not at all"
    )]
    Groups {
        /// The table's issuer.
        issuer: String,
    },
    /// The issuer profile's `person_key` is a claim never accepted as a key
    /// (OpenID Connect Core 1.0 §5.7, or the profile's `unstable_claims`).
    #[error("the person_key {claim:?} of {issuer:?} is never accepted as a key")]
    UnstableKey {
        /// The table's issuer.
        issuer: String,
        /// The claim.
        claim: String,
    },
    /// The issuer profile names an adapter the binding has not registered.
    #[error("the profile of {issuer:?} names the adapter {adapter:?}, which is not registered")]
    Adapter {
        /// The table's issuer.
        issuer: String,
        /// The adapter.
        adapter: String,
    },
    /// A Basic user is mapped twice, or to an identifier issuer no table
    /// names.
    #[error("the Basic user {user:?} is mapped twice or to an identifier issuer no table names")]
    BasicKey {
        /// The user-id.
        user: String,
    },
    /// A Basic user of the store maps to no key.
    #[error("the Basic user {user:?} maps to no party key")]
    BasicUnmapped {
        /// The user-id.
        user: String,
    },
}

/// Checks the `tables` of a section whose issuers `issuer` describes, by
/// identifier, as its kind and its profile.
pub(crate) fn check_tables<'p>(
    tables: &[PartySection],
    issuer: impl Fn(&str) -> Option<(IssuerKind, &'p Profile)>,
) -> Result<(), PartyError> {
    let mut by_identifier: BTreeMap<&str, &str> = BTreeMap::new();
    let mut seen = Vec::new();
    for table in tables {
        let described = issuer(&table.issuer);
        check_table(
            table,
            described.map(|(kind, _)| kind),
            described.map(|(_, profile)| profile),
        )?;
        if seen.contains(&table.issuer.as_str()) {
            return Err(PartyError::DuplicateIssuer {
                issuer: table.issuer.clone(),
            });
        }
        seen.push(table.issuer.as_str());
        if let Some(first) = by_identifier.insert(&table.identifier_issuer, &table.issuer) {
            return Err(PartyError::SharedIdentifierIssuer {
                first: first.to_owned(),
                second: table.issuer.clone(),
                identifier_issuer: table.identifier_issuer.clone(),
            });
        }
    }
    Ok(())
}

/// Checks one table against its issuer's `kind` and `profile`.
pub(crate) fn check_table(
    table: &PartySection,
    kind: Option<IssuerKind>,
    profile: Option<&Profile>,
) -> Result<(), PartyError> {
    let issuer = || table.issuer.clone();
    let (Some(IssuerKind::Persons), Some(profile)) = (kind, profile) else {
        return Err(PartyError::NotPersons {
            issuer: issuer(),
            kind,
        });
    };
    if table.claim.is_some() {
        return Err(PartyError::Claim {
            issuer: issuer(),
            person_key: profile.person_key.clone(),
        });
    }
    for (key, value) in [
        ("auth.party.identifier_issuer", &table.identifier_issuer),
        ("auth.party.identifier_type", &table.identifier_type),
    ] {
        if value.trim().is_empty() {
            return Err(PartyError::Missing {
                issuer: issuer(),
                key,
            });
        }
    }
    if table.group_claim.trim().is_empty() != table.group_identifier_issuer.trim().is_empty() {
        return Err(PartyError::Groups { issuer: issuer() });
    }
    if profile.is_unstable(&profile.person_key) {
        return Err(PartyError::UnstableKey {
            issuer: issuer(),
            claim: profile.person_key.clone(),
        });
    }
    Ok(())
}

/// Returns `value` in the canonical form `identifier_type` declares: lower
/// case for a GUID, the value itself for any other type.
pub(crate) fn canonical(identifier_type: &str, value: &str) -> String {
    // NOTE: no vendored specification governs the case of a GUID: our own design,
    // which compares one in lower case.
    if identifier_type.eq_ignore_ascii_case("guid") || identifier_type.eq_ignore_ascii_case("uuid")
    {
        value.to_ascii_lowercase()
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(issuer: &str, identifier_issuer: &str) -> PartySection {
        PartySection {
            issuer: issuer.to_owned(),
            identifier_issuer: identifier_issuer.to_owned(),
            identifier_type: String::from("guid"),
            ..PartySection::default()
        }
    }

    #[test]
    fn a_guid_key_is_compared_in_lower_case_and_any_other_exactly() {
        assert_eq!(
            "0a1b2c3d-aaaa-bbbb-cccc-ddddeeeeffff",
            canonical("GUID", "0A1B2C3D-AAAA-bbbb-CCCC-DDDDEEEEFFFF")
        );
        assert_eq!(
            "Ab-1",
            canonical("login", "Ab-1"),
            "exact for any other type"
        );
    }

    #[test]
    fn two_tables_of_one_issuer_are_refused() {
        let profile = Profile::default();
        let tables = [table("https://a", "urn:a"), table("https://a", "urn:b")];
        assert_eq!(
            Err(PartyError::DuplicateIssuer {
                issuer: String::from("https://a")
            }),
            check_tables(&tables, |_| Some((IssuerKind::Persons, &profile)))
        );
    }

    #[test]
    fn a_group_claim_needs_its_identifier_issuer() {
        let mut table = table("https://a", "urn:a");
        table.group_claim = String::from("groups");
        assert!(matches!(
            check_table(&table, Some(IssuerKind::Persons), Some(&Profile::default())),
            Err(PartyError::Groups { .. })
        ));
    }
}
