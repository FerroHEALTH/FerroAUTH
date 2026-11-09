// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `authorization_details` of a token request (RFC 9396), taken as JSON
//! text and sent as written.
//!
//! The text is held to the shape RFC 9396 §2 gives the parameter before it
//! is ever sent: a JSON array of one or more objects, each with a non-empty
//! string `type`, and each common data field of §2.2 it uses of the type
//! that section gives it. No object of it may repeat a name. The members a
//! `type` defines beyond those are the authorization server's to judge (§2.1,
//! §5), so they pass as written. The details a token response states it
//! granted (§7) are read to the same shape.

use std::collections::BTreeSet;

use serde::Deserialize;

/// The `authorization_details` of one request, as written, and the types it
/// names.
///
/// `Debug` shows the types alone, never a member.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationDetails {
    /// The text, as written.
    text: String,
    /// The types the objects name.
    types: BTreeSet<String>,
}

impl std::fmt::Debug for AuthorizationDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationDetails")
            .field("types", &self.types)
            .finish_non_exhaustive()
    }
}

/// An `authorization_details` text that does not have the shape of RFC 9396
/// §2.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthorizationDetailsError {
    /// The text is no JSON, or an object of it repeats a name.
    #[error("the authorization_details is not JSON whose objects repeat no name")]
    Json {
        /// What the JSON reader reported.
        #[source]
        source: crate::json::JsonError,
    },
    /// The JSON is not an array of objects, or a common data field is not of
    /// the type RFC 9396 §2.2 gives it.
    #[error(
        "the authorization_details is not an array of objects whose common fields have their RFC 9396 §2.2 types"
    )]
    Shape {
        /// What the JSON reader reported.
        #[source]
        source: crate::json::JsonError,
    },
    /// The array holds no object (RFC 9396 §2).
    #[error("the authorization_details names no authorization details object (RFC 9396 §2)")]
    Empty,
    /// An object has no `type`, or an empty one (RFC 9396 §2).
    #[error("authorization details object {index} has no type (RFC 9396 §2)")]
    Untyped {
        /// The object's position in the array, from zero.
        index: usize,
    },
}

/// One authorization details object, read for its shape (RFC 9396 §2,
/// §2.2): its `type` and the common data fields, every other member unread.
#[derive(Deserialize)]
struct Detail {
    /// The type.
    #[serde(rename = "type")]
    kind: Option<String>,
    /// The locations.
    #[serde(rename = "locations")]
    _locations: Option<Vec<String>>,
    /// The actions.
    #[serde(rename = "actions")]
    _actions: Option<Vec<String>>,
    /// The data types.
    #[serde(rename = "datatypes")]
    _datatypes: Option<Vec<String>>,
    /// The identifier.
    #[serde(rename = "identifier")]
    _identifier: Option<String>,
    /// The privileges.
    #[serde(rename = "privileges")]
    _privileges: Option<Vec<String>>,
}

impl AuthorizationDetails {
    /// Reads `text` as the value of the `authorization_details` parameter
    /// (RFC 9396 §2).
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationDetailsError::Json`] for text that is no JSON
    /// or repeats a name in an object, [`AuthorizationDetailsError::Shape`]
    /// for JSON that is no array of objects or whose common data fields are
    /// of another type, [`AuthorizationDetailsError::Empty`] for an empty
    /// array, and [`AuthorizationDetailsError::Untyped`] for an object
    /// without a `type`.
    pub fn parse(text: &str) -> Result<Self, AuthorizationDetailsError> {
        crate::metadata::repeats_no_name(text.as_bytes())
            .map_err(|source| AuthorizationDetailsError::Json { source })?;
        let details: Vec<Detail> =
            serde_json::from_str(text).map_err(|source| AuthorizationDetailsError::Shape {
                source: source.into(),
            })?;
        if details.is_empty() {
            return Err(AuthorizationDetailsError::Empty);
        }
        let mut types = BTreeSet::new();
        for (index, detail) in details.into_iter().enumerate() {
            match detail.kind {
                Some(kind) if !kind.is_empty() => {
                    types.insert(kind);
                }
                _ => return Err(AuthorizationDetailsError::Untyped { index }),
            }
        }
        Ok(Self {
            text: text.trim().to_owned(),
            types,
        })
    }

    /// Returns the text the request carries, as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns every `type` the objects name, each once, in order.
    #[must_use]
    pub const fn types(&self) -> &BTreeSet<String> {
        &self.types
    }
}

#[cfg(test)]
mod tests {
    use super::AuthorizationDetails;

    /// RFC 9396 §2, Figure 3: a combined request.
    const FIGURE_3: &str = r#"[{"type": "account_information", "actions": ["list_accounts", "read_balances", "read_transactions"], "locations": ["https://example.com/accounts"]}, {"type": "payment_initiation", "actions": ["initiate", "status", "cancel"], "locations": ["https://example.com/payments"], "instructedAmount": {"currency": "EUR", "amount": "123.50"}, "creditorName": "Merchant A", "creditorAccount": {"iban": "DE02100100109307118603"}, "remittanceInformationUnstructured": "Ref Number Merchant"}]"#;

    #[test]
    fn the_rfc_9396_example_is_taken_and_sent_as_written() {
        let details = AuthorizationDetails::parse(FIGURE_3).expect("taken");
        assert_eq!(FIGURE_3, details.as_str());
        assert_eq!(
            vec!["account_information", "payment_initiation"],
            details
                .types()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        );
        let shown = format!("{details:?}");
        assert!(!shown.contains("DE02100100109307118603"), "{shown}");
    }

    #[test]
    fn a_text_outside_rfc_9396_section_2_is_refused() {
        for (text, why) in [
            ("not json", "no JSON"),
            (r#"{"type": "a"}"#, "an object, not an array"),
            ("[]", "an empty array"),
            ("[1]", "an array of numbers"),
            (r#"[{"actions": ["read"]}]"#, "no type"),
            (r#"[{"type": ""}]"#, "an empty type"),
            (r#"[{"type": 7}]"#, "a type that is no string"),
            (
                r#"[{"type": "a", "locations": "https://x"}]"#,
                "locations not an array",
            ),
            (r#"[{"type": "a", "actions": [1]}]"#, "actions not strings"),
            (
                r#"[{"type": "a", "identifier": ["x"]}]"#,
                "identifier not a string",
            ),
            (r#"[{"type": "a", "type": "b"}]"#, "a repeated name"),
        ] {
            assert!(AuthorizationDetails::parse(text).is_err(), "{why}");
        }
    }
}
