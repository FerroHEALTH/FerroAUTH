// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The roles a caller holds, read from its token's claims.
//!
//! RFC 9068 §2.2.3.1 has an authorization server that puts authorization
//! attributes in a JWT access token use the `groups`, `roles` and
//! `entitlements` attributes of the SCIM `User` resource (RFC 7643 §4.1.2) as
//! claim types. A deployment names the claims it reads on each
//! `[[auth.issuer]]` ([`crate::config::IssuerEntry::role_claims`], by
//! default those three); a dotted path reaches into a JSON object, for an
//! authorization server that nests them. A claim name may itself contain a
//! dot (OpenID Connect Core 1.0 §5.1.2 lets it be any string; Microsoft
//! Entra ID writes a directory extension as `extn.<name>`), so at each
//! level the member named by the longest run of the remaining steps is
//! taken first (no specification governs the reading of a path: our own
//! design). Each value is a role:
//! an array element that is a string, an element that is an object with a
//! string `value` sub-attribute (a SCIM multi-valued attribute, RFC 7643
//! §2.4), each member name of an object, for an issuer that keys what it
//! knows of each role by the role (ZITADEL's project role claims), or, for
//! an issuer that writes one string, each of its whitespace-separated
//! words. A role keeps the spelling
//! the issuer gave it, trimmed, and appears once; a role requirement matches
//! it without regard to ASCII case (no specification governs the matching:
//! our own design).

use serde_json::Map;
use serde_json::Value;

/// The claims RFC 9068 §2.2.3.1 names for roles, read when a deployment
/// names none.
pub const DEFAULT_CLAIMS: [&str; 3] = ["roles", "groups", "entitlements"];

/// Returns [`DEFAULT_CLAIMS`] as the owned list a configuration holds.
#[must_use]
pub fn default_claims() -> Vec<String> {
    DEFAULT_CLAIMS
        .iter()
        .map(|&claim| claim.to_owned())
        .collect()
}

/// Returns the roles the claims at `paths` carry, in the order they are
/// first met.
///
/// A path that is absent, or whose value is neither a string, an array nor
/// an object, carries none; an array element that is neither a string nor
/// an object with a string `value` is skipped. An object carries each of
/// its member names, whatever the member's value.
#[must_use]
pub fn from_claims<S: AsRef<str>>(claims: &Map<String, Value>, paths: &[S]) -> Vec<String> {
    let mut roles = Vec::new();
    for path in paths {
        match lookup(claims, path.as_ref()) {
            Some(Value::Array(items)) => {
                let values = items.iter().filter_map(|item| match item {
                    Value::Object(complex) => complex.get("value").and_then(Value::as_str),
                    other => other.as_str(),
                });
                for item in values {
                    push(&mut roles, item);
                }
            }
            Some(Value::String(words)) => {
                for word in words.split_whitespace() {
                    push(&mut roles, word);
                }
            }
            Some(Value::Object(members)) => {
                for name in members.keys() {
                    push(&mut roles, name);
                }
            }
            _ => {}
        }
    }
    roles
}

/// Returns the string at the dotted claim `path`, trimmed, or `None` when
/// the path is absent, its value is not a string, or the string is blank.
#[must_use]
pub fn claim_text<'a>(claims: &'a Map<String, Value>, path: &str) -> Option<&'a str> {
    lookup(claims, path)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

/// Returns whether `role` is one a configuration may grant: not empty and
/// without whitespace or a control character, so it reads back as one role.
#[must_use]
pub fn is_role(role: &str) -> bool {
    !role.is_empty() && !role.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Returns whether `held` contains `role`, ignoring ASCII case.
#[must_use]
pub fn holds<S: AsRef<str>>(held: &[S], role: &str) -> bool {
    held.iter()
        .any(|name| name.as_ref().eq_ignore_ascii_case(role))
}

/// Adds `raw`, trimmed, unless it is empty or already present.
pub(crate) fn push(roles: &mut Vec<String>, raw: &str) {
    let role = raw.trim();
    if !role.is_empty() && !roles.iter().any(|held| held == role) {
        roles.push(role.to_owned());
    }
}

/// Returns whether `path` is a dotted claim path [`lookup`] can follow: not
/// blank, no empty step, and no whitespace (no specification governs the
/// rule: our own design).
pub(crate) fn well_formed(path: &str) -> bool {
    !path.split('.').any(str::is_empty) && !path.contains(char::is_whitespace)
}

/// Returns the value at the dotted `path`, each step a member of an object.
///
/// A member's name may hold dots, so at each level the member named by the
/// longest run of the remaining steps, joined by `.`, is taken first; a
/// shorter run reaches into an object only when no longer one leads to a
/// value.
pub(crate) fn lookup<'a>(claims: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    if let Some(value) = claims.get(path) {
        return Some(value);
    }
    path.char_indices()
        .rev()
        .filter(|&(_, c)| c == '.')
        .find_map(|(at, _)| {
            let (name, rest) = (path.get(..at)?, path.get(at.checked_add(1)?..)?);
            lookup(claims.get(name)?.as_object()?, rest)
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn claims(value: &Value) -> Map<String, Value> {
        value.as_object().cloned().expect("an object")
    }

    #[test]
    fn the_default_claims_are_read_in_order_and_once() {
        let claims = claims(&json!({
            "roles": ["clinician", "admin"],
            "groups": ["admin", "ward-3"],
            "entitlements": "read-only  export"
        }));
        assert_eq!(
            from_claims(&claims, &DEFAULT_CLAIMS),
            ["clinician", "admin", "ward-3", "read-only", "export"]
        );
    }

    #[test]
    fn a_scim_complex_value_names_its_role() {
        let claims = claims(&json!({
            "groups": [
                { "value": "e9e30dba", "display": "Tour Guides" },
                { "display": "no value" },
                "ward-3"
            ]
        }));
        assert_eq!(from_claims(&claims, &["groups"]), ["e9e30dba", "ward-3"]);
    }

    // NOTE: docs/specs/zitadel/apps/docs/content/guides/integrate/retrieve-user-roles.mdx,
    // the sample response of the project role claim, member names and values as published.
    #[test]
    fn an_object_names_its_roles_by_its_member_names() {
        let claims = claims(&json!({
            "urn:zitadel:iam:org:project:223281986649719041:roles": {
                "cfo": {
                    "223281939119866113": "corporate.user-authorizations-io8epz.zitadel.cloud"
                },
                "corporate member": {
                    "223279178798072065": "org-a.user-authorizations-io8epz.zitadel.cloud",
                    "223279223391912193": "org-b.user-authorizations-io8epz.zitadel.cloud"
                }
            },
            "nested": { "roles": { "auditor": true } }
        }));
        let mut roles = from_claims(
            &claims,
            &[
                "urn:zitadel:iam:org:project:223281986649719041:roles",
                "nested.roles",
            ],
        );
        roles.sort();
        assert_eq!(roles, ["auditor", "cfo", "corporate member"]);
    }

    #[test]
    fn a_dotted_path_reaches_into_an_object() {
        let claims = claims(&json!({ "realm_access": { "roles": ["auditor"] } }));
        assert_eq!(from_claims(&claims, &["realm_access.roles"]), ["auditor"]);
        assert_eq!(claim_text(&claims, "realm_access"), None);
    }

    // NOTE: docs/specs/entra-docs/docs/identity-platform/optional-claims.md, Directory
    // extension formatting: a directory extension is emitted in a JWT as `extn.<name>`.
    #[test]
    fn a_claim_name_may_hold_a_dot() {
        let claims = claims(&json!({
            "extn.fhirUser": "Practitioner/1",
            "https://example.org/claims": { "roles": ["auditor"] },
            "nested": { "extn.roles": ["clerk"] }
        }));
        assert_eq!(claim_text(&claims, "extn.fhirUser"), Some("Practitioner/1"));
        assert_eq!(
            from_claims(&claims, &["https://example.org/claims.roles"]),
            ["auditor"]
        );
        assert_eq!(from_claims(&claims, &["nested.extn.roles"]), ["clerk"]);
        assert_eq!(claim_text(&claims, "extn.missing"), None);
    }

    #[test]
    fn the_longest_member_name_is_taken_first() {
        let claims = claims(&json!({
            "a.b": { "c": "longer" },
            "a": { "b": { "c": "shorter" }, "x": "only nested" },
            "a.b.c": "whole"
        }));
        assert_eq!(claim_text(&claims, "a.b.c"), Some("whole"));
        assert_eq!(claim_text(&claims, "a.x"), Some("only nested"));
        let mut without_whole = claims.clone();
        without_whole.remove("a.b.c");
        assert_eq!(claim_text(&without_whole, "a.b.c"), Some("longer"));
    }

    #[test]
    fn absent_and_other_values_carry_no_role() {
        let claims = claims(&json!({ "roles": 3, "groups": [1, " ", "x"], "nested": "a" }));
        assert_eq!(
            from_claims(&claims, &["roles", "groups", "missing", "nested.deeper"]),
            ["x"]
        );
    }

    #[test]
    fn claim_text_trims_and_refuses_blank() {
        let claims = claims(&json!({ "acr": " substantial ", "blank": "  ", "n": 1 }));
        assert_eq!(claim_text(&claims, "acr"), Some("substantial"));
        assert_eq!(claim_text(&claims, "blank"), None);
        assert_eq!(claim_text(&claims, "n"), None);
    }

    #[test]
    fn a_role_is_one_word_and_matched_without_case() {
        assert!(is_role("ADMIN"));
        assert!(!is_role(""));
        assert!(!is_role("two words"));
        assert!(holds(&["Admin"], "ADMIN"));
        assert!(!holds(&["Admin"], "admins"));
    }
}
