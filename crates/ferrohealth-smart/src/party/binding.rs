// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! [`PartyBinding`]: the bound issuers, the Basic users' keys, the adapters
//! and the source, and the one lookup per request.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::Value;

use crate::basic::PasswordStore;
use crate::config::Resolved;
use crate::kind::CallerKind;
use crate::kind::IssuerKind;
use crate::party::Bound;
use crate::party::GroupsCause;
use crate::party::Identifier;
use crate::party::Marker;
use crate::party::Outcome;
use crate::party::PartyState;
use crate::party::adapter::IdpAdapter;
use crate::party::config::PartyError;
use crate::party::config::PartySection;
use crate::party::config::canonical;
use crate::party::config::check_table;
use crate::party::source::Lookup;
use crate::party::source::PartySource;
use crate::party::source::Query;
use crate::party::source::SourceError;
use crate::profile::Profile;
use crate::resource::Caller;
use crate::resource::Via;

/// One bound issuer: its table and the adapter its profile names.
#[derive(Debug, Clone)]
struct Issuer {
    /// The `[[auth.party]]` table.
    table: PartySection,
    /// The adapter the issuer's profile names.
    adapter: Option<String>,
}

/// The key a Basic user is looked up by.
#[derive(Clone)]
struct BasicKey {
    /// The `identifier_issuer` of the table whose identifiers it is.
    identifier_issuer: String,
    /// The key value.
    value: String,
}

/// The party binding of a surface: where each login is looked up, and the
/// source it is looked up in.
///
/// Built once at start; [`PartyBinding::resolve`] reads the source on every
/// request and holds no cache.
pub struct PartyBinding {
    /// The product's store.
    source: Arc<dyn PartySource>,
    /// The bound issuers, by identifier.
    issuers: BTreeMap<String, Issuer>,
    /// The Basic users' keys, by user-id.
    basic: BTreeMap<String, BasicKey>,
    /// The adapters, by the name a profile gives them.
    adapters: BTreeMap<String, Arc<dyn IdpAdapter>>,
}

impl std::fmt::Debug for PartyBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartyBinding")
            .field("issuers", &self.issuers.keys().collect::<Vec<_>>())
            .field("basic", &self.basic.len())
            .field("adapters", &self.adapters.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl PartyBinding {
    /// Returns a binding over `source` that binds no issuer yet.
    #[must_use]
    pub fn new(source: Arc<dyn PartySource>) -> Self {
        Self {
            source,
            issuers: BTreeMap::new(),
            basic: BTreeMap::new(),
            adapters: BTreeMap::new(),
        }
    }

    /// Returns this binding calling `adapter` for an issuer whose profile
    /// names `name`; register adapters before the issuers that name them.
    #[must_use]
    pub fn with_adapter(mut self, name: impl Into<String>, adapter: Arc<dyn IdpAdapter>) -> Self {
        self.adapters.insert(name.into(), adapter);
        self
    }

    /// Returns this binding binding the logins of the issuer `table` names,
    /// an issuer of `kind` whose tokens follow `profile`.
    ///
    /// # Errors
    ///
    /// The [`PartyError`] naming the rule `table` breaks: an issuer that is
    /// not `persons`, a `claim` key, an empty key, `group_claim` without
    /// `group_identifier_issuer`, an unstable `person_key`, an adapter not
    /// registered, or an issuer or `identifier_issuer` another table names.
    pub fn with_issuer(
        mut self,
        table: PartySection,
        kind: IssuerKind,
        profile: &Profile,
    ) -> Result<Self, PartyError> {
        check_table(&table, Some(kind), Some(profile))?;
        if self.issuers.contains_key(table.issuer.expose()) {
            return Err(PartyError::DuplicateIssuer {
                issuer: crate::config::shown(&table.issuer),
            });
        }
        if let Some(other) = self
            .issuers
            .values()
            .find(|other| other.table.identifier_issuer == table.identifier_issuer)
        {
            return Err(PartyError::SharedIdentifierIssuer {
                first: crate::config::shown(&other.table.issuer),
                second: crate::config::shown(&table.issuer),
                identifier_issuer: table.identifier_issuer,
            });
        }
        if let Some(adapter) = &profile.adapter
            && !self.adapters.contains_key(adapter)
        {
            return Err(PartyError::Adapter {
                issuer: crate::config::shown(&table.issuer),
                adapter: adapter.clone(),
            });
        }
        self.issuers.insert(
            table.issuer.expose().to_owned(),
            Issuer {
                adapter: profile.adapter.clone(),
                table,
            },
        );
        Ok(self)
    }

    /// Returns this binding with every adapter the `[auth.idp]` tables of
    /// `resolved` build, binding every `[[auth.party]]` table of `resolved`
    /// against its issuer's kind and profile.
    ///
    /// # Errors
    ///
    /// The [`PartyError`] of [`PartyBinding::with_issuer`].
    pub fn with_resolved(mut self, resolved: &Resolved) -> Result<Self, PartyError> {
        for (name, adapter) in resolved.adapters.iter() {
            self = self.with_adapter(name, Arc::clone(adapter));
        }
        let mut profiles: BTreeMap<&str, (IssuerKind, &Profile)> = BTreeMap::new();
        for settings in &resolved.issuers {
            profiles.insert(&settings.issuer, (settings.kind, &settings.profile));
        }
        #[cfg(feature = "fetch")]
        for settings in &resolved.introspection {
            profiles.insert(&settings.issuer, (settings.kind, &settings.profile));
        }
        resolved.party.iter().try_fold(self, |binding, table| {
            let (kind, profile) =
                profiles
                    .get(table.issuer.expose())
                    .copied()
                    .ok_or_else(|| PartyError::NotPersons {
                        issuer: crate::config::shown(&table.issuer),
                        kind: None,
                    })?;
            binding.with_issuer(table.clone(), kind, profile)
        })
    }

    /// Returns this binding looking the Basic user `user` up by the key
    /// `value` among the identifiers of `identifier_issuer`, the identifier
    /// issuer of a bound table.
    ///
    /// # Errors
    ///
    /// [`PartyError::BasicKey`] when `user` is mapped already, or no bound
    /// table names `identifier_issuer`.
    pub fn with_basic_user(
        mut self,
        user: impl Into<String>,
        identifier_issuer: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, PartyError> {
        let user = user.into();
        let identifier_issuer = identifier_issuer.into();
        let bound = self
            .issuers
            .values()
            .any(|issuer| issuer.table.identifier_issuer == identifier_issuer);
        if !bound || self.basic.contains_key(&user) {
            return Err(PartyError::BasicKey { user });
        }
        self.basic.insert(
            user,
            BasicKey {
                identifier_issuer,
                value: value.into(),
            },
        );
        Ok(self)
    }

    /// Checks that every Basic user of `store` maps to a key, since a Basic
    /// credential is always a person's.
    ///
    /// # Errors
    ///
    /// [`PartyError::BasicUnmapped`] naming the first user that maps to
    /// none.
    pub fn check_basic(&self, store: &PasswordStore) -> Result<(), PartyError> {
        match store.users().find(|user| !self.basic.contains_key(*user)) {
            Some(user) => Err(PartyError::BasicUnmapped {
                user: user.to_owned(),
            }),
            None => Ok(()),
        }
    }

    /// Returns what `caller`'s login resolves to, or `None` for a caller
    /// that is never looked up: a `Patient`, a `System`, an
    /// `ExternalPerson`, an `ExternalOrganisation`, or a guest its issuer's
    /// table does not admit.
    ///
    /// The source is called at most once, and not at all for a credential
    /// without a key, a token whose groups cannot be read, or an issuer
    /// with no table, whose logins no party carries.
    ///
    /// # Errors
    ///
    /// [`SourceError`] when the source could not answer, which is never
    /// read as no match.
    pub async fn resolve(&self, caller: &Caller) -> Result<Option<Outcome>, SourceError> {
        let (needed, guest) = match caller.kind() {
            CallerKind::Guest(inner) => match needed(inner) {
                Some(needed) => (needed, true),
                None => return Ok(None),
            },
            kind => match needed(kind) {
                Some(needed) => (needed, false),
                None => return Ok(None),
            },
        };
        let (table, adapter, key) = if caller.via() == Via::Basic {
            let Some(key) = self.basic.get(caller.subject()) else {
                return Ok(Some(Outcome::KeyClaimMissing));
            };
            let Some(issuer) = self
                .issuers
                .values()
                .find(|issuer| issuer.table.identifier_issuer == key.identifier_issuer)
            else {
                return Ok(Some(Outcome::KeyClaimMissing));
            };
            (&issuer.table, None, key.value.as_str())
        } else {
            let Some(issuer) = caller.issuer().and_then(|issuer| self.issuers.get(issuer)) else {
                return Ok(Some(Outcome::Unbound));
            };
            if guest && !issuer.table.guests {
                return Ok(None);
            }
            let Some(key) = caller.person_key().filter(|key| !key.trim().is_empty()) else {
                return Ok(Some(Outcome::KeyClaimMissing));
            };
            (&issuer.table, issuer.adapter.as_deref(), key)
        };
        let asserted = match self.groups(caller, table, adapter).await {
            Ok(groups) => groups,
            Err(cause) => return Ok(Some(Outcome::GroupsUnavailable(cause))),
        };
        let value = canonical(&table.identifier_type, key);
        let query = Query {
            identifier_issuer: &table.identifier_issuer,
            identifier_type: &table.identifier_type,
            value: &value,
            group_identifier_issuer: (!table.group_claim.is_empty())
                .then_some(table.group_identifier_issuer.as_str()),
        };
        let lookup = self.source.lookup(&query).await?;
        Ok(Some(decide(lookup, table, value, needed, guest, &asserted)))
    }

    /// Returns the groups `caller`'s token asserts under `table`, through
    /// `adapter` on an overage, or why they cannot be read.
    async fn groups(
        &self,
        caller: &Caller,
        table: &PartySection,
        adapter: Option<&str>,
    ) -> Result<BTreeSet<String>, GroupsCause> {
        if table.group_claim.is_empty() {
            return Ok(BTreeSet::new());
        }
        let claims = caller.claims();
        // NOTE: the overage markers the issuer profiles document, our own design:
        // `_claim_names` names the group claim, or `hasgroups` is `true`, in its place.
        let overage = claims
            .get("_claim_names")
            .and_then(Value::as_object)
            .is_some_and(|names| names.contains_key(&table.group_claim))
            || claims.get("hasgroups") == Some(&Value::Bool(true));
        if overage {
            let adapter = adapter
                .and_then(|name| self.adapters.get(name))
                .ok_or(GroupsCause::Overage)?;
            return adapter
                .resolve_groups(caller)
                .await
                .map(|groups| groups.into_iter().collect())
                .map_err(GroupsCause::Adapter);
        }
        match claims.get(&table.group_claim) {
            None => Ok(BTreeSet::new()),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_owned)
                        .ok_or(GroupsCause::Malformed)
                })
                .collect(),
            Some(_) => Err(GroupsCause::Malformed),
        }
    }
}

/// Returns the marker a caller of `kind` needs, or `None` for a kind that
/// is never looked up.
const fn needed(kind: &CallerKind) -> Option<Marker> {
    match kind {
        CallerKind::Person | CallerKind::Delegated { .. } => Some(Marker::Professional),
        CallerKind::Representative { .. } => Some(Marker::Representative),
        _ => None,
    }
}

/// Returns the outcome of `lookup` for a login of `value` under `table`,
/// whose caller needs `needed` and asserts the groups `asserted`.
fn decide(
    lookup: Lookup,
    table: &PartySection,
    value: String,
    needed: Marker,
    guest: bool,
    asserted: &BTreeSet<String>,
) -> Outcome {
    let mut parties = match lookup {
        Lookup::Deprovisioned => return Outcome::Deprovisioned,
        Lookup::Parties(parties) => parties,
    };
    parties.sort_by(|left, right| left.party().cmp(right.party()));
    parties.dedup_by(|left, right| left.party() == right.party());
    let record = match parties.len() {
        0 => return Outcome::Unbound,
        1 => match parties.pop() {
            Some(record) => record,
            None => return Outcome::Unbound,
        },
        count => return Outcome::Ambiguous { count },
    };
    let state = record.state();
    let (party, markers, memberships, represents) = record.into_parts();
    match state {
        PartyState::Inactive => return Outcome::Inactive { party },
        PartyState::Abandoned => return Outcome::Abandoned { party },
        PartyState::Active | PartyState::Incomplete => {}
    }
    if !markers.carry(needed) {
        return Outcome::WrongMarker {
            party,
            markers,
            needed,
        };
    }
    let mut groups = Vec::new();
    for membership in memberships {
        if asserted.contains(membership.identifier()) && !groups.contains(membership.group()) {
            groups.push(membership.group().clone());
        }
    }
    Outcome::Party(Box::new(Bound {
        party,
        identifier: Identifier::new(
            table.identifier_issuer.clone(),
            table.identifier_type.clone(),
            value,
        ),
        markers,
        groups,
        represents,
        provisional: state == PartyState::Incomplete,
        guest,
    }))
}
