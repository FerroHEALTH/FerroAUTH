// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Who answers the standing questions of the caller classification.
//!
//! There are three: through which clients a `persons` issuer's people sign
//! in or are acted for, which RFC 8693 actors are declared delegates, and
//! which system subjects are admitted without a scope.
//! By default the issuer's configured lists answer them
//! ([`StandingSource::Lists`]): `first_party_clients`, `delegates` and
//! `scopeless_subjects`. A product that keeps them as its own data answers
//! them itself through a [`Standing`] ([`StandingSource::Product`]), asked
//! while the token is classified, on every request. No specification
//! governs which clients a resource server admits for a person or which
//! subjects it admits without a scope: our own design, since SMART App
//! Launch 2.2.0 and RFC 8693 §4.1 leave both to the resource server.

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::kind::Actor;
use crate::profile::Delegate;
use crate::profile::Profile;

/// What a client is to a `persons` issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientStanding {
    /// A client a person signs in through: its token is the person's, or
    /// their representative's.
    FirstParty,
    /// A third-party client that acts for a person: its token is
    /// [`CallerKind::Delegated`](crate::kind::CallerKind::Delegated), and
    /// it carries no representation.
    Delegate,
    /// Neither: its token is refused as
    /// [`Unclassified::UnlistedClient`](crate::kind::Unclassified::UnlistedClient).
    Unlisted,
}

/// An identifier as an issuer issued it: a `sub` or a `client_id` is
/// unique only within its issuer (RFC 7519 §4.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Issued<'a> {
    /// The issuer.
    pub issuer: &'a str,
    /// The identifier.
    pub id: &'a str,
}

impl<'a> Issued<'a> {
    /// Returns the identifier `id` of `issuer`.
    #[must_use]
    pub const fn new(issuer: &'a str, id: &'a str) -> Self {
        Self { issuer, id }
    }
}

/// The product's standing could not answer: its store failed or refused the
/// read.
///
/// It is never a negative answer: the token is refused as
/// [`Rejection::Upstream`](crate::resource::Rejection::Upstream), which
/// answers `503`, so a failure of the store never reads as an unlisted
/// client.
#[derive(Debug, thiserror::Error)]
#[error("the product's standing could not answer")]
pub struct StandingError {
    /// What the store reported.
    #[source]
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl StandingError {
    /// Returns the failure `source` reports.
    #[must_use]
    pub fn new(source: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>) -> Self {
        Self {
            source: source.into(),
        }
    }

    /// Returns what the store reported, for the [`Rejection::Upstream`]
    /// the token is refused with.
    ///
    /// [`Rejection::Upstream`]: crate::resource::Rejection::Upstream
    pub(crate) fn into_source(self) -> Arc<dyn std::error::Error + Send + Sync + 'static> {
        Arc::from(self.source)
    }
}

/// The answer of one [`Standing`] question.
pub type Answer<'a, T> = Pin<Box<dyn Future<Output = Result<T, StandingError>> + Send + 'a>>;

/// The product's answers to the standing questions, asked on every request
/// whose token needs one.
///
/// The crate asks at most one question per token and holds no cache, so a
/// change the product makes takes effect on the next request. The product
/// answers from memory or from reads that meet its latency budget; the
/// crate forces no read. A product that answers through a `Standing` sets
/// none of the three lists, which the settings refuse beside it.
pub trait Standing: Send + Sync + 'static {
    /// Returns the standing of the client `client.id` that a person's
    /// token of the `persons` issuer `client.issuer` names.
    ///
    /// Asked for a token that names no RFC 8693 actor and is not app-only.
    fn client<'a>(&'a self, client: Issued<'a>) -> Answer<'a, ClientStanding>;

    /// Returns whether `actor`, the current actor a person's token of the
    /// `persons` issuer `issuer` names in `act`, is a declared delegate.
    ///
    /// Asked for a token whose `act` chain holds within the profile's
    /// `max_actor_chain`; `actor.issuer` is the token's issuer when `act`
    /// names none (RFC 8693 §4.1).
    fn delegate<'a>(&'a self, issuer: &'a str, actor: &'a Actor) -> Answer<'a, bool>;

    /// Returns whether the subject `subject.id` of the issuer
    /// `subject.issuer` is admitted without a scope.
    ///
    /// Asked only for a [`CallerKind::System`] caller of a `persons` or a
    /// `machines` issuer. A token that carries a resource scope of either
    /// grammar still reaches only what its scopes grant
    /// ([`Caller::scopeless`]).
    ///
    /// [`CallerKind::System`]: crate::kind::CallerKind::System
    /// [`Caller::scopeless`]: crate::resource::Caller::scopeless
    fn scopeless<'a>(&'a self, subject: Issued<'a>) -> Answer<'a, bool>;
}

/// Who answers an issuer's standing questions.
#[derive(Clone, Default)]
pub enum StandingSource {
    /// The issuer's configured lists: the profile's `first_party_clients`
    /// and `delegates`, and the settings' `scopeless_subjects`.
    #[default]
    Lists,
    /// The product, through its [`Standing`]; the three lists are then
    /// refused.
    Product(Arc<dyn Standing>),
}

impl fmt::Debug for StandingSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lists => f.write_str("Lists"),
            Self::Product(_) => f.debug_tuple("Product").finish_non_exhaustive(),
        }
    }
}

impl PartialEq for StandingSource {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Lists, Self::Lists) => true,
            (Self::Product(left), Self::Product(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl Eq for StandingSource {}

impl StandingSource {
    /// Returns the standing of `client` under `profile`'s lists or the
    /// product's answer.
    pub(crate) async fn client(
        &self,
        profile: &Profile,
        client: Issued<'_>,
    ) -> Result<ClientStanding, StandingError> {
        match self {
            Self::Product(standing) => standing.client(client).await,
            Self::Lists => Ok(listed_client(profile, client.id)),
        }
    }

    /// Returns whether `actor` of a token of `issuer` is a declared delegate
    /// under `profile`'s lists or the product's answer.
    pub(crate) async fn delegate(
        &self,
        profile: &Profile,
        issuer: &str,
        actor: &Actor,
    ) -> Result<bool, StandingError> {
        match self {
            Self::Product(standing) => standing.delegate(issuer, actor).await,
            Self::Lists => Ok(listed_delegate(profile, issuer, actor)),
        }
    }

    /// Returns whether `subject` is admitted without a scope, by the
    /// issuer's `listed` subjects or the product's answer.
    pub(crate) async fn scopeless(
        &self,
        listed: &BTreeSet<String>,
        subject: Issued<'_>,
    ) -> Result<bool, StandingError> {
        match self {
            Self::Product(standing) => standing.scopeless(subject).await,
            Self::Lists => Ok(listed.contains(subject.id)),
        }
    }

    /// Returns the first list set beside the product's standing, which the
    /// settings refuse, so no list is ever read in two places.
    pub(crate) fn listed_beside(
        &self,
        profile: &Profile,
        scopeless_subjects: &BTreeSet<String>,
    ) -> Option<&'static str> {
        if matches!(self, Self::Lists) {
            return None;
        }
        [
            (
                "first_party_clients",
                profile.first_party_clients.is_empty(),
            ),
            ("delegates", profile.delegates.is_empty()),
            ("scopeless_subjects", scopeless_subjects.is_empty()),
        ]
        .into_iter()
        .find_map(|(key, empty)| (!empty).then_some(key))
    }
}

/// Returns the standing `profile`'s lists give the client `id`: first party
/// when `first_party_clients` lists it, else a delegate when `delegates`
/// does.
pub(crate) fn listed_client(profile: &Profile, id: &str) -> ClientStanding {
    if profile
        .first_party_clients
        .iter()
        .any(|listed| listed == id)
    {
        ClientStanding::FirstParty
    } else if profile
        .delegates
        .iter()
        .any(|delegate| matches!(delegate, Delegate::Client(listed) if listed == id))
    {
        ClientStanding::Delegate
    } else {
        ClientStanding::Unlisted
    }
}

/// Returns whether `profile`'s `delegates` list `actor` of a token of
/// `issuer`, an entry naming no issuer standing for the token's own.
pub(crate) fn listed_delegate(profile: &Profile, issuer: &str, actor: &Actor) -> bool {
    profile.delegates.iter().any(|delegate| match delegate {
        Delegate::Actor {
            issuer: listed,
            sub,
        } => *sub == actor.sub && listed.as_deref().unwrap_or(issuer) == actor.issuer,
        Delegate::Client(_) => false,
    })
}
