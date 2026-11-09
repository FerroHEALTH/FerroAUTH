// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `[auth.idp]` table: one table per vendor adapter a profile may name
//! ([`crate::idp`]), each read only in a build that compiles its adapter in.
//!
//! A build without an adapter's feature refuses its table as an unknown
//! key, so a deployment never configures an adapter its binary lacks. No
//! specification governs the table: our own design.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Deserialize;
use serde::Serialize;

use crate::config::ConfigError;
use crate::party::adapter::IdpAdapter;

/// The `[auth.idp]` table.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdpSection {
    /// The Microsoft Graph access of the `idp-entra` adapter
    /// (`[auth.idp.entra]`), which resolves an Entra ID groups overage.
    #[cfg(feature = "idp-entra")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entra: Option<Box<crate::idp::entra::GraphSection>>,
}

impl IdpSection {
    /// Returns the adapter of every table set, under the name a profile's
    /// `adapter` gives it.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Adapter`] naming the adapter whose table is refused.
    #[cfg_attr(
        not(feature = "idp-entra"),
        expect(
            clippy::unnecessary_wraps,
            clippy::unused_self,
            reason = "a build with an adapter's feature reads its table and can refuse it"
        )
    )]
    pub(crate) fn adapters(&self) -> Result<Adapters, ConfigError> {
        #[cfg_attr(
            not(feature = "idp-entra"),
            expect(unused_mut, reason = "only an adapter's feature adds to the map")
        )]
        let mut adapters: BTreeMap<String, Arc<dyn IdpAdapter>> = BTreeMap::new();
        #[cfg(feature = "idp-entra")]
        if let Some(entra) = &self.entra {
            let adapter = entra.adapter().map_err(|source| ConfigError::Adapter {
                adapter: crate::idp::entra::NAME,
                source: Box::new(source),
            })?;
            adapters.insert(crate::idp::entra::NAME.to_owned(), Arc::new(adapter));
        }
        Ok(Adapters(adapters))
    }
}

/// The vendor adapters the `[auth.idp]` tables build, by the name a
/// profile's `adapter` gives them; the party binding registers each
/// ([`crate::party::binding::PartyBinding::with_resolved`]).
#[derive(Clone, Default)]
pub struct Adapters(BTreeMap<String, Arc<dyn IdpAdapter>>);

impl Adapters {
    /// Returns each adapter with its name, in name order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Arc<dyn IdpAdapter>)> {
        self.0
            .iter()
            .map(|(name, adapter)| (name.as_str(), adapter))
    }

    /// Returns whether no adapter is built.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Adapters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}
