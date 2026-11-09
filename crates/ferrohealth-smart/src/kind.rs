// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Who stands behind a credential: the kind of issuer a token comes from and
//! the [`CallerKind`] the token's claims make its caller.
//!
//! RFC 9068 §2.2 has `sub` name the resource owner when one is involved and
//! "an identifier the authorization server uses to indicate the client
//! application" when none is, and that is a SHOULD, so whether a token names
//! a person is read from the issuer's profile ([`crate::profile`]), never
//! from `sub` alone. RFC 8693 §4.1 names an actor in `act`. A Basic
//! credential is a person's, never a system's: a machine authenticates with
//! the client credentials grant (RFC 6749 §4.4) and is classified from its
//! token. How callers are classified is our own design over those sources.

use std::fmt;

use serde::Deserialize;
use serde::Serialize;
use serde_json::Map;
use serde_json::Value;

use crate::federation::Context;
use crate::federation::External;
use crate::federation::Outcome;
use crate::profile::Delegate;
use crate::profile::Profile;

/// Whose tokens an issuer signs, declared on every `[[auth.issuer]]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IssuerKind {
    /// Professionals and other people of the deployment, signing in through
    /// the deployment's own clients; also the app-only tokens of its
    /// machines.
    Persons,
    /// Patients, each token naming only the record subject (the `patient`
    /// context of SMART on openEHR `master08-scopes`).
    Patients,
    /// Machines, through the client credentials grant only.
    Machines,
    /// Another party's issuer, whose tokens name its professionals or its
    /// organisation.
    Federation,
}

impl IssuerKind {
    /// Returns the configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Persons => "persons",
            Self::Patients => "patients",
            Self::Machines => "machines",
            Self::Federation => "federation",
        }
    }
}

impl fmt::Display for IssuerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An RFC 8693 §4.1 actor: "the combination of the two claims `iss` and
/// `sub` might be necessary to uniquely identify an actor".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    /// The actor's issuer, the token's own when `act` names none.
    pub issuer: String,
    /// The actor's `sub`.
    pub sub: String,
}

/// Who stands behind a caller's credential.
///
/// The `Debug` rendering names the kind and never a represented subject or
/// a ground.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallerKind {
    /// The patient, on a `patients` issuer, the token naming only the
    /// record subject.
    Patient,
    /// A machine: an app-only token by the issuer's profile.
    System,
    /// A person through a declared actor or third-party client.
    Delegated {
        /// The RFC 8693 actor, when the delegation is an `act` claim.
        actor: Option<Actor>,
    },
    /// A person acting for another subject, on a `persons` issuer that
    /// declares `representation`.
    Representative {
        /// The represented subject's identifier, as asserted.
        represented: String,
        /// The ground of the representation, as asserted.
        ground: Option<String>,
    },
    /// A person under their own account, through a first-party client, or
    /// through HTTP Basic.
    Person,
    /// Someone acting for the patient, on a `patients` issuer that declares
    /// `act_represents_patient`: the token's top-level `act` names them
    /// (RFC 8693 §4.1) and its `sub` the patient.
    PatientRepresentative {
        /// The current actor, the representative.
        actor: Actor,
    },
    /// A guest by the issuer's profile, with the kind it would otherwise
    /// have; a product admits one only by a setting of its own.
    Guest(Box<CallerKind>),
    /// A professional of another party, on a `federation` issuer, with what
    /// the token asserts about them.
    ExternalPerson(Box<External>),
    /// Another party's organisation, on a `federation` issuer.
    ExternalOrganisation(Box<External>),
}

impl fmt::Debug for CallerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delegated { actor } => f.debug_struct("Delegated").field("actor", actor).finish(),
            Self::PatientRepresentative { actor } => f
                .debug_struct("PatientRepresentative")
                .field("actor", actor)
                .finish(),
            Self::Representative { .. } => f.debug_struct("Representative").finish_non_exhaustive(),
            Self::Guest(kind) => f.debug_tuple("Guest").field(kind).finish(),
            Self::ExternalPerson(external) => {
                f.debug_tuple("ExternalPerson").field(external).finish()
            }
            Self::ExternalOrganisation(external) => f
                .debug_tuple("ExternalOrganisation")
                .field(external)
                .finish(),
            Self::Patient => f.write_str("Patient"),
            Self::System => f.write_str("System"),
            Self::Person => f.write_str("Person"),
        }
    }
}

impl CallerKind {
    /// Returns the name the audit line records.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Patient => "patient",
            Self::System => "system",
            Self::Delegated { .. } => "delegated",
            Self::Representative { .. } => "representative",
            Self::Person => "person",
            Self::PatientRepresentative { .. } => "patient_representative",
            Self::Guest(_) => "guest",
            Self::ExternalPerson(_) => "external_person",
            Self::ExternalOrganisation(_) => "external_organisation",
        }
    }

    /// Returns what a `federation` token asserts about the other party,
    /// for an [`CallerKind::ExternalPerson`] or an
    /// [`CallerKind::ExternalOrganisation`].
    #[must_use]
    pub fn external(&self) -> Option<&External> {
        match self {
            Self::ExternalPerson(external) | Self::ExternalOrganisation(external) => Some(external),
            _ => None,
        }
    }
}

/// Why a valid token matches no step of the classification for its issuer's
/// kind. Each names a check or a configured claim, never a claim value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Unclassified {
    /// A claim the profile's `expect` names is absent or holds another
    /// value.
    #[error("the claim {claim} does not hold the value the profile expects")]
    Expected {
        /// The claim.
        claim: String,
    },
    /// A token that is not app-only lacks a claim the profile's
    /// `user_claims` names.
    #[error("a user token lacks the claim {claim}")]
    UserClaim {
        /// The claim.
        claim: String,
    },
    /// The token carries the profile's impersonation marker.
    #[error("the token carries the impersonation marker")]
    Impersonation,
    /// The profile's app-only markers disagree about the token.
    #[error("the app-only markers disagree")]
    MarkersDisagree,
    /// A scope claim is present in another JSON form than the profile's.
    #[error("the scope claim {claim} is not in the profile's form")]
    ScopeForm {
        /// The claim.
        claim: String,
    },
    /// A `patients` token does not name only the record subject: it lacks a
    /// `patient/` scope or carries a `user/` or `system/` one.
    #[error("a patients token does not name only the record subject")]
    NotPatientContext,
    /// A `patients` token names an actor in `act`, and its issuer does not
    /// declare `act_represents_patient`.
    #[error("a patients token names an actor its issuer does not read as a representative")]
    PatientActor,
    /// A `machines` token is not app-only.
    #[error("a machines token is not app-only")]
    NotAppOnly,
    /// A `persons` token names no client.
    #[error("a persons token names no client")]
    NoClient,
    /// A `persons` token's client is neither first-party nor a delegate.
    #[error("the client is neither first-party nor a declared delegate")]
    UnlistedClient,
    /// The `act` actor is not a declared delegate.
    #[error("the actor is not a declared delegate")]
    UnlistedActor,
    /// The `act` chain is deeper than the profile admits, or `act` is not
    /// an object with a string `sub`.
    #[error("the act chain is deeper than admitted or malformed")]
    ActorChain,
    /// A representation claim arrives together with an `act`.
    #[error("a representation claim arrives together with an act")]
    RepresentationWithAct,
    /// A representation claim arrives through a delegate client.
    #[error("a representation claim arrives through a delegate client")]
    RepresentationThroughDelegate,
    /// A token that names a professional misses required fields, each named.
    #[error("a federation token names a professional and misses {missing:?}")]
    ExternalIncomplete {
        /// The fields it misses.
        missing: Vec<&'static str>,
    },
    /// A token misses fields the issuer's table requires, each named.
    #[error("a federation token misses the required fields {missing:?}")]
    RequiredFields {
        /// The fields it misses.
        missing: Vec<&'static str>,
    },
    /// An attribute is outside the bounds the issuer's table declares.
    #[error("the attribute {field} is outside the declared bounds")]
    OutOfBounds {
        /// The field.
        field: &'static str,
    },
    /// An attribute holds a control or bidi-control character, or is too
    /// long.
    #[error("the attribute {field} holds a refused character or is too long")]
    Attribute {
        /// The field.
        field: &'static str,
    },
    /// Two sources of one field give different values.
    #[error("the sources of {field} disagree")]
    SourcesDisagree {
        /// The field.
        field: &'static str,
    },
    /// The `authorization_details` carry no single entry of a declared type
    /// whose `locations` names this node.
    #[error("no declared authorization_details entry names this node")]
    AuthorizationDetails,
    /// A token that names no professional carries no organisation statement.
    #[error("a federation token names no professional and states no organisation access")]
    NoOrganisationStatement,
    /// A professional's authentication is below the level a domestic
    /// federation issuer requires.
    #[error("the professional's authentication is below the required level")]
    AssuranceTooLow,
    /// The Verifiable Presentations do not read.
    #[error("the verifiable presentations do not read")]
    Presentations,
    /// A contact-point token misses an attribute or outlives its assertions,
    /// with the MyHealth@EU Requirements Catalogue 10.0.0 §1.25 code name.
    #[error("a contact-point token is refused as {code}, missing {missing:?}")]
    ContactPoint {
        /// The §1.25 code name.
        code: crate::federation::contact::EhdsiCode,
        /// The fields it misses, for `ERROR_HPI_INSUFFICIENT_INFORMATION`.
        missing: Vec<&'static str>,
    },
    /// The issuer's kind has no step this build classifies.
    #[error("no step classifies a token of a {kind} issuer")]
    NoStep {
        /// The kind.
        kind: IssuerKind,
    },
}

/// What a classification read from a token's claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Classified {
    /// The kind.
    pub(crate) kind: CallerKind,
    /// The client the profile's client claims name.
    pub(crate) client: Option<String>,
    /// Whether the profile's markers call the token app-only.
    pub(crate) app_only: bool,
}

/// Returns the kind of the caller whose verified `claims` an issuer of
/// `kind` signed under `profile`.
pub(crate) fn classify(
    kind: IssuerKind,
    profile: &Profile,
    federation: Option<&Context<'_>>,
    claims: &Map<String, Value>,
) -> Result<Classified, Unclassified> {
    for (claim, value) in &profile.expect {
        let holds = match claims.get(claim) {
            Some(Value::String(text)) => text == value,
            Some(Value::Number(number)) => number.to_string() == *value,
            Some(Value::Bool(flag)) => flag.to_string() == *value,
            _ => false,
        };
        if !holds {
            return Err(Unclassified::Expected {
                claim: claim.clone(),
            });
        }
    }
    if profile
        .impersonation_marker
        .as_ref()
        .is_some_and(|marker| claims.contains_key(marker))
    {
        return Err(Unclassified::Impersonation);
    }
    let client = profile.client(claims).map(str::to_owned);
    let app_only = app_only(profile, claims, client.as_deref())?;
    if !app_only
        && let Some(claim) = profile
            .user_claims
            .iter()
            .find(|claim| !claims.contains_key(*claim))
    {
        return Err(Unclassified::UserClaim {
            claim: claim.clone(),
        });
    }
    let classified = |kind| Classified {
        kind,
        client: client.clone(),
        app_only,
    };
    match kind {
        IssuerKind::Patients => {
            let scope =
                profile
                    .scope_claim
                    .read(claims)
                    .map_err(|_form| Unclassified::ScopeForm {
                        claim: profile.scope_claim.claim.clone(),
                    })?;
            // NOTE: SMART on openEHR `master08-scopes`: the `patient` context alone,
            // with no `user/` or `system/` grant, names only the record subject.
            if !app_only
                && grants_in(&scope, "patient")
                && !grants_in(&scope, "user")
                && !grants_in(&scope, "system")
            {
                Ok(classified(patient(profile, claims)?))
            } else {
                Err(Unclassified::NotPatientContext)
            }
        }
        IssuerKind::Machines | IssuerKind::Persons if app_only => {
            Ok(classified(CallerKind::System))
        }
        IssuerKind::Machines => Err(Unclassified::NotAppOnly),
        IssuerKind::Persons => {
            let person = person(profile, claims, client.as_deref())?;
            let guest = profile
                .guest
                .iter()
                .any(|marker| marker.matches(claims, client.as_deref()));
            Ok(classified(if guest {
                CallerKind::Guest(Box::new(person))
            } else {
                person
            }))
        }
        IssuerKind::Federation => {
            let context = federation.ok_or(Unclassified::NoStep { kind })?;
            Ok(classified(
                match crate::federation::read::classify(claims, client.as_deref(), context)? {
                    Outcome::Person(external) => CallerKind::ExternalPerson(Box::new(external)),
                    Outcome::Organisation(external) => {
                        CallerKind::ExternalOrganisation(Box::new(external))
                    }
                },
            ))
        }
    }
}

/// Returns whether the profile's app-only markers call the token app-only,
/// refusing a token they disagree about.
fn app_only(
    profile: &Profile,
    claims: &Map<String, Value>,
    client: Option<&str>,
) -> Result<bool, Unclassified> {
    let mut verdicts = profile
        .app_only
        .iter()
        .map(|marker| marker.matches(claims, client));
    let first = verdicts.next().unwrap_or(false);
    if verdicts.any(|verdict| verdict != first) {
        return Err(Unclassified::MarkersDisagree);
    }
    Ok(first)
}

/// Returns the kind of a `persons` token that is not app-only: delegated
/// through a declared actor or client, a representative, or the person.
fn person(
    profile: &Profile,
    claims: &Map<String, Value>,
    client: Option<&str>,
) -> Result<CallerKind, Unclassified> {
    let client = client.ok_or(Unclassified::NoClient)?;
    let represented = profile.representation.as_ref().and_then(|representation| {
        text(claims, &representation.claim).map(|represented| (representation, represented))
    });
    if let Some(act) = claims.get("act") {
        if represented.is_some() {
            return Err(Unclassified::RepresentationWithAct);
        }
        let token_issuer = text(claims, "iss").unwrap_or_default();
        let actor = actor(act, &token_issuer, profile.max_actor_chain)?;
        let listed = profile.delegates.iter().any(|delegate| match delegate {
            Delegate::Actor { issuer, sub } => {
                *sub == actor.sub && issuer.as_deref().unwrap_or(&token_issuer) == actor.issuer
            }
            Delegate::Client(_) => false,
        });
        return if listed {
            Ok(CallerKind::Delegated { actor: Some(actor) })
        } else {
            Err(Unclassified::UnlistedActor)
        };
    }
    let first_party = profile
        .first_party_clients
        .iter()
        .any(|listed| listed == client);
    let delegate = profile
        .delegates
        .iter()
        .any(|delegate| matches!(delegate, Delegate::Client(listed) if listed == client));
    match (first_party, delegate, represented) {
        (true, _, Some((representation, represented))) => Ok(CallerKind::Representative {
            represented,
            ground: representation
                .ground_claim
                .as_deref()
                .and_then(|claim| text(claims, claim)),
        }),
        (true, _, None) => Ok(CallerKind::Person),
        (false, true, Some(_)) => Err(Unclassified::RepresentationThroughDelegate),
        (false, true, None) => Ok(CallerKind::Delegated { actor: None }),
        (false, false, _) => Err(Unclassified::UnlistedClient),
    }
}

/// Returns the kind of a `patients` token that names only the record
/// subject: the patient, or, when it names an actor in `act`, the patient's
/// representative under a profile that declares `act_represents_patient`.
fn patient(profile: &Profile, claims: &Map<String, Value>) -> Result<CallerKind, Unclassified> {
    let Some(act) = claims.get("act") else {
        return Ok(CallerKind::Patient);
    };
    if !profile.act_represents_patient {
        return Err(Unclassified::PatientActor);
    }
    // NOTE: RFC 8693 §4.1, only the top-level `act` is the current actor, and a
    // nested one is "informational only", so no depth is held against it.
    let token_issuer = text(claims, "iss").unwrap_or_default();
    let (actor, _) = current_actor(act, &token_issuer)?;
    Ok(CallerKind::PatientRepresentative { actor })
}

/// Returns the current actor `act` names, with its object, refusing an
/// `act` that is no object with a string `sub`.
fn current_actor<'a>(
    act: &'a Value,
    token_issuer: &str,
) -> Result<(Actor, &'a Map<String, Value>), Unclassified> {
    let object = act.as_object().ok_or(Unclassified::ActorChain)?;
    let sub = object
        .get("sub")
        .and_then(Value::as_str)
        .filter(|sub| !sub.trim().is_empty())
        .ok_or(Unclassified::ActorChain)?;
    let issuer = object
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or(token_issuer);
    Ok((
        Actor {
            issuer: issuer.to_owned(),
            sub: sub.to_owned(),
        },
        object,
    ))
}

/// Returns the actor `act` names, refusing a chain deeper than `max`.
pub(crate) fn actor(act: &Value, token_issuer: &str, max: usize) -> Result<Actor, Unclassified> {
    let (actor, object) = current_actor(act, token_issuer)?;
    let mut depth = 1_usize;
    let mut current = object;
    while let Some(prior) = current.get("act") {
        depth = depth.saturating_add(1);
        current = prior.as_object().ok_or(Unclassified::ActorChain)?;
    }
    if depth > max {
        return Err(Unclassified::ActorChain);
    }
    Ok(actor)
}

/// Returns the string claim `name`, trimmed, when it is not blank.
fn text(claims: &Map<String, Value>, name: &str) -> Option<String> {
    crate::roles::claim_text(claims, name).map(str::to_owned)
}

/// Returns whether a token of the space-delimited `scope` names `context`,
/// the `<context>/` prefix both SMART grammars share.
pub(crate) fn grants_in(scope: &str, context: &str) -> bool {
    scope.split(' ').any(|token| {
        token
            .strip_prefix(context)
            .is_some_and(|rest| rest.starts_with('/'))
    })
}
