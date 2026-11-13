// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `[auth]` section of a product whose standing answers the three lists
//! ([`ProductStandingSection`]): read as [`AuthSection`] with the three keys
//! unknown, and resolved with the product's standing on every issuer.
//!
//! The section is read through [`AuthSection`]'s own reader, every key
//! checked against the reader's field list without the three, so a refused
//! key and any other unknown one fail alike, naming the keys the section
//! accepts (no specification governs the configuration model: our own
//! design).

use std::fmt;
use std::sync::Arc;
use std::sync::OnceLock;

use serde::Deserialize;
use serde::Deserializer;
use serde::de::DeserializeSeed;
use serde::de::Error as _;
use serde::de::MapAccess;
use serde::de::SeqAccess;
use serde::de::Visitor;
use serde::de::value::StringDeserializer;

use crate::config::AuthSection;
use crate::config::ConfigError;
use crate::config::ProductStandingSection;
use crate::config::Resolved;
use crate::config::TlsBuilder;
use crate::kind::standing::Standing;
use crate::kind::standing::StandingSource;

/// One table the reader holds to a narrower field list.
struct Level {
    /// The keys the table's own reader knows and this reader refuses.
    refused: &'static [&'static str],
    /// The keys it accepts: the reader's own, without the refused ones.
    accepted: OnceLock<Vec<&'static str>>,
    /// The key whose array of tables is held to a level of its own.
    nested: Option<(&'static str, &'static Level)>,
}

impl Level {
    /// Returns the keys accepted out of `fields`, the table reader's own.
    fn accepted(&'static self, fields: &'static [&'static str]) -> &'static [&'static str] {
        self.accepted
            .get_or_init(|| {
                fields
                    .iter()
                    .copied()
                    .filter(|field| !self.refused.contains(field))
                    .collect()
            })
            .as_slice()
    }
}

/// Each `[[auth.issuer]]` table, without the client lists.
static ISSUER: Level = Level {
    refused: &["first_party_clients", "delegates"],
    accepted: OnceLock::new(),
    nested: None,
};

/// The `[auth]` table, without the scopeless subjects.
static SECTION: Level = Level {
    refused: &["scopeless_subjects"],
    accepted: OnceLock::new(),
    nested: Some(("issuer", &ISSUER)),
};

impl<'de> Deserialize<'de> for ProductStandingSection {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        AuthSection::deserialize(Table {
            inner: deserializer,
            level: &SECTION,
        })
        .map(Self)
    }
}

impl ProductStandingSection {
    /// Resolves the section as [`AuthSection::resolve`] does, every
    /// issuer's standing questions answered by `standing`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::ListedBesideStanding`] when the section,
    /// built in code, sets `scopeless_subjects` or an issuer's
    /// `first_party_clients` or `delegates`, and every [`ConfigError`] of
    /// [`AuthSection::resolve`].
    pub fn resolve(&self, standing: Arc<dyn Standing>) -> Result<Resolved, ConfigError> {
        self.listed()?;
        self.0
            .resolve_over(None, &StandingSource::Product(standing))
    }

    /// Resolves the section as [`ProductStandingSection::resolve`] does,
    /// every `tls` table built by `tls`, the product's reader of TLS
    /// material.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] as [`ProductStandingSection::resolve`] does,
    /// and [`ConfigError::TlsBuild`] when `tls` refuses a table.
    pub fn resolve_with_tls(
        &self,
        tls: &dyn TlsBuilder,
        standing: Arc<dyn Standing>,
    ) -> Result<Resolved, ConfigError> {
        self.listed()?;
        self.0
            .resolve_over(Some(tls), &StandingSource::Product(standing))
    }

    /// Refuses a list the product's standing answers, set in code.
    fn listed(&self) -> Result<(), ConfigError> {
        let listed = |key| ConfigError::ListedBesideStanding { key };
        if !self.0.scopeless_subjects.is_empty() {
            return Err(listed("auth.scopeless_subjects"));
        }
        for entry in self.0.issuers() {
            if entry.first_party_clients.is_some() {
                return Err(listed("auth.issuer.first_party_clients"));
            }
            if entry.delegates.is_some() {
                return Err(listed("auth.issuer.delegates"));
            }
        }
        Ok(())
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for ProductStandingSection {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("ProductStandingSection")
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut issuer = crate::config::IssuerEntry::json_schema(generator);
        without(&mut issuer, ISSUER.refused);
        let mut section = AuthSection::json_schema(generator);
        without(&mut section, SECTION.refused);
        if let Some(items) = section
            .get_mut("properties")
            .and_then(|properties| properties.get_mut("issuer"))
            .and_then(|property| property.get_mut("items"))
        {
            *items = issuer.to_value();
        }
        section
    }
}

/// Removes the properties `keys` from the object `schema` describes.
#[cfg(feature = "schema")]
fn without(schema: &mut schemars::Schema, keys: &[&str]) {
    if let Some(properties) = schema
        .get_mut("properties")
        .and_then(serde_json::Value::as_object_mut)
    {
        for key in keys {
            properties.remove(*key);
        }
    }
}

/// A table's deserializer, whose keys are held to `level`.
struct Table<D> {
    /// The deserializer of the table.
    inner: D,
    /// The keys it accepts.
    level: &'static Level,
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Table<D> {
    type Error = D::Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.inner.deserialize_any(visitor)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        let level = self.level;
        self.inner.deserialize_struct(
            name,
            fields,
            Fields {
                visitor,
                level,
                accepted: level.accepted(fields),
            },
        )
    }

    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map enum identifier ignored_any
    }
}

/// The table reader's visitor, handed the table's entries held to a level.
struct Fields<V> {
    /// The table reader's own visitor.
    visitor: V,
    /// The level the entries are held to.
    level: &'static Level,
    /// The keys it accepts.
    accepted: &'static [&'static str],
}

impl<'de, V: Visitor<'de>> Visitor<'de> for Fields<V> {
    type Value = V::Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.visitor.expecting(f)
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<V::Value, A::Error> {
        self.visitor.visit_map(Entries {
            map,
            level: self.level,
            accepted: self.accepted,
            nested: None,
        })
    }
}

/// A table's entries, each key checked against the accepted ones.
struct Entries<A> {
    /// The entries.
    map: A,
    /// The level they are held to.
    level: &'static Level,
    /// The keys it accepts.
    accepted: &'static [&'static str],
    /// The level the next value's tables are held to, after its key.
    nested: Option<&'static Level>,
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for Entries<A> {
    type Error = A::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, A::Error> {
        let Some(key) = self.map.next_key::<String>()? else {
            return Ok(None);
        };
        if !self.accepted.contains(&key.as_str()) {
            return Err(A::Error::unknown_field(&key, self.accepted));
        }
        self.nested = self
            .level
            .nested
            .and_then(|(nested, level)| (nested == key).then_some(level));
        seed.deserialize(StringDeserializer::<A::Error>::new(key))
            .map(Some)
    }

    fn next_value_seed<S: DeserializeSeed<'de>>(&mut self, seed: S) -> Result<S::Value, A::Error> {
        match self.nested.take() {
            Some(level) => self.map.next_value_seed(Nested { seed, level }),
            None => self.map.next_value_seed(seed),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        self.map.size_hint()
    }
}

/// The seed of an array of tables, each held to `level`.
struct Nested<S> {
    /// The array reader's own seed.
    seed: S,
    /// The level each table is held to.
    level: &'static Level,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Nested<S> {
    type Value = S::Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<S::Value, D::Error> {
        self.seed.deserialize(Array {
            inner: deserializer,
            level: self.level,
        })
    }
}

/// The deserializer of an array of tables, each held to `level`.
struct Array<D> {
    /// The array's deserializer.
    inner: D,
    /// The level each table is held to.
    level: &'static Level,
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Array<D> {
    type Error = D::Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.inner.deserialize_any(Tables {
            visitor,
            level: self.level,
        })
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.inner.deserialize_seq(Tables {
            visitor,
            level: self.level,
        })
    }

    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

/// The array reader's visitor, handed the elements held to a level.
struct Tables<V> {
    /// The array reader's own visitor.
    visitor: V,
    /// The level each table is held to.
    level: &'static Level,
}

impl<'de, V: Visitor<'de>> Visitor<'de> for Tables<V> {
    type Value = V::Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.visitor.expecting(f)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<V::Value, A::Error> {
        self.visitor.visit_seq(Elements {
            seq,
            level: self.level,
        })
    }
}

/// The elements of an array of tables, each held to `level`.
struct Elements<A> {
    /// The elements.
    seq: A,
    /// The level each is held to.
    level: &'static Level,
}

impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for Elements<A> {
    type Error = A::Error;

    fn next_element_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, A::Error> {
        self.seq.next_element_seed(Element {
            seed,
            level: self.level,
        })
    }

    fn size_hint(&self) -> Option<usize> {
        self.seq.size_hint()
    }
}

/// The seed of one table of an array, held to `level`.
struct Element<S> {
    /// The table reader's own seed.
    seed: S,
    /// The level it is held to.
    level: &'static Level,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Element<S> {
    type Value = S::Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<S::Value, D::Error> {
        self.seed.deserialize(Table {
            inner: deserializer,
            level: self.level,
        })
    }
}
