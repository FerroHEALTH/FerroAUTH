// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The table forms a [`Marker`] and a [`Delegate`] are written in, the
//! conversions that hold each table to exactly one form, and the helpers a
//! profile overlay sets its keys with.

use serde::Deserialize;
use serde::Serialize;

use crate::profile::Delegate;
use crate::profile::Marker;

/// The table form of a [`Marker`].
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct MarkerTable {
    /// The claim of `{ claim, value }`.
    #[serde(skip_serializing_if = "Option::is_none")]
    claim: Option<String>,
    /// The value of `{ claim, value }`.
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    /// The claim of `{ absent_claim }`.
    #[serde(skip_serializing_if = "Option::is_none")]
    absent_claim: Option<String>,
    /// The subjects of `{ subjects }`.
    #[serde(skip_serializing_if = "Option::is_none")]
    subjects: Option<Vec<String>>,
    /// The `{ sub_is_client = true }` form.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    sub_is_client: bool,
    /// The claim of `{ differs_from_iss }`.
    #[serde(skip_serializing_if = "Option::is_none")]
    differs_from_iss: Option<String>,
}

impl TryFrom<MarkerTable> for Marker {
    type Error = String;

    fn try_from(table: MarkerTable) -> Result<Self, Self::Error> {
        match table {
            MarkerTable {
                claim: Some(claim),
                value: Some(value),
                absent_claim: None,
                subjects: None,
                sub_is_client: false,
                differs_from_iss: None,
            } => Ok(Self::Claim { claim, value }),
            MarkerTable {
                claim: None,
                value: None,
                absent_claim: Some(claim),
                subjects: None,
                sub_is_client: false,
                differs_from_iss: None,
            } => Ok(Self::Absent { claim }),
            MarkerTable {
                claim: None,
                value: None,
                absent_claim: None,
                subjects: Some(subjects),
                sub_is_client: false,
                differs_from_iss: None,
            } => Ok(Self::Subjects(subjects)),
            MarkerTable {
                claim: None,
                value: None,
                absent_claim: None,
                subjects: None,
                sub_is_client: true,
                differs_from_iss: None,
            } => Ok(Self::SubIsClient),
            MarkerTable {
                claim: None,
                value: None,
                absent_claim: None,
                subjects: None,
                sub_is_client: false,
                differs_from_iss: Some(claim),
            } => Ok(Self::DiffersFromIssuer { claim }),
            _ => Err(String::from(
                "a marker is exactly one of { claim, value }, { absent_claim }, { subjects }, \
                 { sub_is_client = true } and { differs_from_iss }",
            )),
        }
    }
}

impl From<Marker> for MarkerTable {
    fn from(marker: Marker) -> Self {
        match marker {
            Marker::Claim { claim, value } => Self {
                claim: Some(claim),
                value: Some(value),
                ..Self::default()
            },
            Marker::Absent { claim } => Self {
                absent_claim: Some(claim),
                ..Self::default()
            },
            Marker::Subjects(subjects) => Self {
                subjects: Some(subjects),
                ..Self::default()
            },
            Marker::SubIsClient => Self {
                sub_is_client: true,
                ..Self::default()
            },
            Marker::DiffersFromIssuer { claim } => Self {
                differs_from_iss: Some(claim),
                ..Self::default()
            },
        }
    }
}

/// The table form of a [`Delegate`].
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct DelegateTable {
    /// The actor's issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    /// The actor's `sub`.
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    /// The client.
    #[serde(skip_serializing_if = "Option::is_none")]
    client: Option<String>,
}

impl TryFrom<DelegateTable> for Delegate {
    type Error = String;

    fn try_from(table: DelegateTable) -> Result<Self, Self::Error> {
        match table {
            DelegateTable {
                issuer,
                sub: Some(sub),
                client: None,
            } => Ok(Self::Actor { issuer, sub }),
            DelegateTable {
                issuer: None,
                sub: None,
                client: Some(client),
            } => Ok(Self::Client(client)),
            _ => Err(String::from(
                "a delegate is { sub } with an optional issuer, or { client }",
            )),
        }
    }
}

impl From<Delegate> for DelegateTable {
    fn from(delegate: Delegate) -> Self {
        match delegate {
            Delegate::Actor { issuer, sub } => Self {
                issuer,
                sub: Some(sub),
                client: None,
            },
            Delegate::Client(client) => Self {
                client: Some(client),
                ..Self::default()
            },
        }
    }
}

/// Replaces `slot` with `value` when one is set.
pub(super) fn set<T>(slot: &mut T, value: Option<T>) {
    if let Some(value) = value {
        *slot = value;
    }
}

/// Replaces the optional `slot` with `value` when one is set.
pub(super) fn set_some<T>(slot: &mut Option<T>, value: Option<T>) {
    if value.is_some() {
        *slot = value;
    }
}
