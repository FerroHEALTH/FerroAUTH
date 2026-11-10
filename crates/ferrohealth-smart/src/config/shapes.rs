// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! How the sections are written and compared beyond their derives: the
//! rendering that redacts a secret, and the comparison of a secret by its
//! value.

use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::Serializer;

use crate::config::REDACTED;

/// Writes a set secret as [`REDACTED`], never its value, so a product can
/// render its running configuration (no specification governs the
/// rendering: our own design).
#[expect(
    clippy::ref_option,
    reason = "serde's serialize_with hands the field over by reference"
)]
pub(super) fn redact<S: Serializer>(
    secret: &Option<SecretString>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match secret {
        Some(_) => serializer.serialize_str(REDACTED),
        None => serializer.serialize_none(),
    }
}

/// Whether two optional secrets are both unset or both set to the same
/// value; the value is read for the comparison and goes nowhere else (no
/// specification governs configuration equality: our own design).
pub(super) fn same_secret(left: Option<&SecretString>, right: Option<&SecretString>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.expose_secret() == right.expose_secret(),
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    }
}
