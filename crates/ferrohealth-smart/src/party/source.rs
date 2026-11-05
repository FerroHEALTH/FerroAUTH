// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The store a product supplies: the [`PartySource`] it implements over its
//! own parties, the [`Query`] the library asks and the [`Lookup`] it answers.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use crate::party::Markers;
use crate::party::Membership;
use crate::party::PartyRef;
use crate::party::PartyState;
use crate::party::Represented;

/// What the library asks the source: every party carrying the identifier
/// `value` of `identifier_type` under `identifier_issuer`.
///
/// The value is already in the canonical form the type declares, and the
/// source compares it exactly. The `Debug` rendering leaves out the value.
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Query<'a> {
    /// The `identifier_issuer` of the `[[auth.party]]` table.
    pub identifier_issuer: &'a str,
    /// The `identifier_type` of the table.
    pub identifier_type: &'a str,
    /// The key value, canonical.
    pub value: &'a str,
    /// The `group_identifier_issuer` the memberships are reported under,
    /// when the table reads groups.
    pub group_identifier_issuer: Option<&'a str>,
}

impl fmt::Debug for Query<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Query")
            .field("identifier_issuer", &self.identifier_issuer)
            .field("identifier_type", &self.identifier_type)
            .field("group_identifier_issuer", &self.group_identifier_issuer)
            .finish_non_exhaustive()
    }
}

/// One party the source finds carrying the identifier, with its state, its
/// markers, its memberships and its representation relationships.
///
/// The `Debug` rendering names the party, the state and the markers alone.
#[derive(Clone, PartialEq, Eq)]
pub struct PartyRecord {
    /// The party.
    party: PartyRef,
    /// Its state.
    state: PartyState,
    /// Its binding markers.
    markers: Markers,
    /// The groups it belongs to, under the query's
    /// `group_identifier_issuer`.
    memberships: Vec<Membership>,
    /// The subjects it has a recorded representation relationship to.
    represents: Vec<Represented>,
}

impl PartyRecord {
    /// Returns the record of `party` in `state` carrying `markers`, with no
    /// membership and no representation relationship.
    #[must_use]
    pub const fn new(party: PartyRef, state: PartyState, markers: Markers) -> Self {
        Self {
            party,
            state,
            markers,
            memberships: Vec::new(),
            represents: Vec::new(),
        }
    }

    /// Returns this record belonging to the groups of `memberships`.
    #[must_use]
    pub fn with_memberships(mut self, memberships: Vec<Membership>) -> Self {
        self.memberships = memberships;
        self
    }

    /// Returns this record representing the subjects of `represents`.
    #[must_use]
    pub fn with_represents(mut self, represents: Vec<Represented>) -> Self {
        self.represents = represents;
        self
    }

    /// Returns the party.
    #[must_use]
    pub const fn party(&self) -> &PartyRef {
        &self.party
    }

    /// Returns the party's state.
    #[must_use]
    pub const fn state(&self) -> PartyState {
        self.state
    }

    /// Returns the party's markers.
    #[must_use]
    pub const fn markers(&self) -> Markers {
        self.markers
    }

    /// Returns the party's memberships.
    #[must_use]
    pub fn memberships(&self) -> &[Membership] {
        &self.memberships
    }

    /// Returns the party's representation relationships.
    #[must_use]
    pub fn represents(&self) -> &[Represented] {
        &self.represents
    }

    /// Returns the record's parts: the party, its markers, its memberships
    /// and its relationships.
    pub(crate) fn into_parts(self) -> (PartyRef, Markers, Vec<Membership>, Vec<Represented>) {
        (self.party, self.markers, self.memberships, self.represents)
    }
}

impl fmt::Debug for PartyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartyRecord")
            .field("party", &self.party)
            .field("state", &self.state)
            .field("markers", &self.markers)
            .finish_non_exhaustive()
    }
}

/// What the source finds for a [`Query`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Lookup {
    /// The parties carrying the identifier: none, one, or more.
    Parties(Vec<PartyRecord>),
    /// The identifier is the tombstone of a deleted party, and no party
    /// carries it.
    Deprovisioned,
}

/// The source could not answer: its store failed, timed out or refused the
/// read.
///
/// It is never an empty [`Lookup`]: the library answers it as an error, so
/// a product never reads a failure as no match.
#[derive(Debug, thiserror::Error)]
#[error("the party source could not answer")]
pub struct SourceError {
    /// What the store reported.
    #[source]
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl SourceError {
    /// Returns the failure `source` reports.
    #[must_use]
    pub fn new(source: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>) -> Self {
        Self {
            source: source.into(),
        }
    }
}

/// The product's store of parties, read on every request.
///
/// A product implements it over its own store with indexed reads that meet
/// its latency budget; the library holds no cache, so a change in the store
/// takes effect on the next request. The source compares the query's value
/// exactly, reports every party carrying it, never chooses between two, and
/// answers a failure of its store as a [`SourceError`].
pub trait PartySource: Send + Sync + 'static {
    /// Returns every party carrying the identifier `query` names, or the
    /// tombstone of a deleted one.
    fn lookup<'a>(
        &'a self,
        query: &'a Query<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Lookup, SourceError>> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_query_debug_leaves_out_the_key_value() {
        let query = Query {
            identifier_issuer: "urn:example:login",
            identifier_type: "guid",
            value: "5ba552d6-secret",
            group_identifier_issuer: None,
        };
        let text = format!("{query:?}");
        assert!(!text.contains("5ba552d6-secret"), "{text}");
        assert!(text.contains("urn:example:login"), "{text}");
    }
}
