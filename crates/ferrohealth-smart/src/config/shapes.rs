// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! How the sections are read and written beyond their derives: the keys
//! that keep a removed form, read by the value's shape so that
//! `AuthSection::resolve` refuses it naming its replacement, and the
//! rendering that masks a URL's userinfo and redacts a secret.

use secrecy::SecretString;
use serde::Deserialize;
use serde::Serializer;

use crate::config::IssuerEntry;
use crate::config::IssuerKey;
use crate::config::REDACTED;
use crate::config::ScopelessSubject;
use crate::config::mask_userinfo;

impl<'de> Deserialize<'de> for IssuerKey {
    // NOTE: serde's `untagged` drops each variant's own error, so the form is chosen
    // by the value's shape and an entry's refusal, naming its key, reaches the caller.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(IssuerKeyVisitor)
    }
}

/// Reads [`IssuerKey`] by the shape of the value: a string or a list.
struct IssuerKeyVisitor;

impl<'de> serde::de::Visitor<'de> for IssuerKeyVisitor {
    type Value = IssuerKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a list of issuer tables")
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<IssuerKey, E> {
        Ok(IssuerKey::Flat(value.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<IssuerKey, E> {
        Ok(IssuerKey::Flat(value))
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, seq: A) -> Result<IssuerKey, A::Error> {
        Vec::<IssuerEntry>::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
            .map(IssuerKey::List)
    }
}

impl<'de> Deserialize<'de> for ScopelessSubject {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ScopelessVisitor)
    }
}

/// The table form of a [`ScopelessSubject`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopelessTable {
    /// The issuer.
    issuer: String,
    /// The `sub`.
    sub: String,
}

/// Reads [`ScopelessSubject`] by the shape of the value: a string or a
/// table.
struct ScopelessVisitor;

impl<'de> serde::de::Visitor<'de> for ScopelessVisitor {
    type Value = ScopelessSubject;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a table { issuer, sub }")
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<ScopelessSubject, E> {
        Ok(ScopelessSubject::Text(value.to_owned()))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<ScopelessSubject, A::Error> {
        ScopelessTable::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(
            |table| ScopelessSubject::Qualified {
                issuer: table.issuer,
                sub: table.sub,
            },
        )
    }
}

/// Writes a URL with its userinfo masked ([`mask_userinfo`]).
#[expect(
    clippy::ptr_arg,
    reason = "serde's serialize_with hands the field over as its own type"
)]
pub(super) fn masked_url<S: Serializer>(text: &String, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&mask_userinfo(text))
}

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
