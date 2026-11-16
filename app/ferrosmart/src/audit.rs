// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! FerroSMART's audit records, behind `[ferrosmart.audit]`.
//!
//! Every token request is recorded as the authorization server's audit event
//! of ITI-71 Get Authorization Token (IHE IUA, ITI TF-2 3.71.5.1): `EventID`
//! `110114` User Authentication, `EventTypeCode` `ITI-71` User Authorization,
//! the client as the source application and the token as a security
//! resource. Every login at the upstream provider is recorded as a DICOM
//! User Authentication event of type `110122` Login (DICOM PS3.15 A.5.3.12).
//! Each is written as a FHIR R4 `AuditEvent` through `ihe-atna`, stored in a
//! spool on disk and sent from there over the ITI-20 ATX: FHIR Feed (ITI
//! TF-2 §3.20.4.2) by the `ihe-atna` forwarder.
//!
//! Recording fails closed: a step whose record has no place in the spool
//! does not happen, the contract of `ihe-atna`'s `AuditRecorder`. No
//! specification governs that rule or the `AuditEvent` rendering of the two
//! DICOM events: our own design.
//!
//! None of these events is an access to personal electronic health data, so
//! none is an access record of Regulation (EU) 2025/327 Annex II 3.2; the
//! patient picker, which reads Patient resources, writes that record.

use std::sync::Arc;

use ihe_atna::atna::forwarder::{Forwarder, Status};
use ihe_atna::atna::spool::reserve::Reservation;
use ihe_atna::atna::spool::{Content, Spool, SpoolError};
use ihe_atna::balp::{
    APPLICATION, Coded, DESTINATION_ROLE, Described, Detail, Direction, EventKind, Exchange,
    IHE_TRANSACTIONS, LOGIN, NetworkAddress, Observer, Outcome, Peer, RecordError, SOURCE_ROLE,
    SYSTEM_OBJECT, USER_AUTHENTICATION, What,
};
use ihe_atna::user::{OnBehalfOf, User};
use url::Url;

use crate::config::settings::AuditSettings;

/// The `EventTypeCode` of the authorization server's ITI-71 audit event (IHE
/// IUA, ITI TF-2 3.71.5.1).
pub const USER_AUTHORIZATION: Coded =
    Coded::fixed(IHE_TRANSACTIONS, "ITI-71", "User Authorization");

/// The participant object role of the token: "13" Security Resource (IHE
/// IUA, ITI TF-2 3.71.5.1; FHIR R4 `object-role`).
pub const SECURITY_RESOURCE: Coded = Coded::fixed(
    "http://terminology.hl7.org/CodeSystem/object-role",
    "13",
    "Security Resource",
);

/// The `detail` names of the token entity. No specification governs the
/// names: our own design.
pub mod detail {
    /// The client the token was issued to.
    pub const CLIENT_ID: &str = "client_id";
    /// The resource server the token is for.
    pub const AUDIENCE: &str = "aud";
    /// The scope the token grants.
    pub const SCOPE: &str = "scope";
}

/// How a client that named no `client_id` is shown as the source of a
/// token request. No specification governs the words: our own design.
pub const UNIDENTIFIED_CLIENT: &str = "unidentified client";

/// Why the audit lane could not start.
#[derive(Debug, thiserror::Error)]
#[error("the audit spool at {} could not be opened", path.display())]
pub struct OpenError {
    /// The spool's directory.
    path: std::path::PathBuf,
    /// Why it could not be opened.
    #[source]
    source: SpoolError,
}

/// Why a record could not be stored.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecordFailure {
    /// The `AuditEvent` could not be written.
    #[error("the AuditEvent could not be written")]
    Write(#[source] RecordError),
    /// The spool had no room for it, or could not store it.
    #[error("the audit spool could not store the record")]
    Spool(#[source] SpoolError),
}

/// The audit lane: the spool, the forwarder that delivers it, and
/// FerroSMART as the recording system.
#[derive(Debug, Clone)]
pub struct Audit {
    /// The forwarder whose spool stores the records.
    forwarder: Arc<Forwarder<Spool>>,
    /// The recording system.
    observer: Arc<Observer>,
}

impl Audit {
    /// Opens the spool `settings` names. Nothing is delivered until
    /// [`Audit::spawn`].
    ///
    /// # Errors
    ///
    /// Returns [`OpenError`] when the spool cannot be opened.
    pub fn open(settings: &AuditSettings) -> Result<Self, OpenError> {
        let spool = Spool::open_for(&settings.spool_dir, settings.bounds, Content::AuditEvents)
            .map_err(|source| OpenError {
                path: settings.spool_dir.clone(),
                source,
            })?;
        Ok(Self {
            forwarder: Forwarder::fhir_feed(spool, settings.feed.clone()),
            observer: Arc::new(settings.observer.clone()),
        })
    }

    /// Starts delivering the spool, oldest record first, until
    /// [`Audit::stop`].
    #[must_use]
    pub fn spawn(&self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(Arc::clone(&self.forwarder).run())
    }

    /// Asks the delivery to end; a record not yet delivered stays in the
    /// spool for the next start.
    pub fn stop(&self) {
        self.forwarder.stop();
    }

    /// Returns what the spool holds and how its deliveries went.
    #[must_use]
    pub fn status(&self) -> Status {
        self.forwarder.status()
    }

    /// Takes the place of one record before the step it records, so a step
    /// whose record could not be stored is refused before it happens.
    ///
    /// # Errors
    ///
    /// Returns [`RecordFailure::Spool`] when the spool has no room.
    pub fn reserve(&self) -> Result<Place, RecordFailure> {
        // NOTE: no specification governs this: our own design; a record of this
        // lane runs to a few kilobytes, so a 16 KiB place holds one.
        let reservation = self
            .forwarder
            .reserve(16 << 10)
            .map_err(RecordFailure::Spool)?;
        Ok(Place {
            reservation,
            observer: Arc::clone(&self.observer),
        })
    }

    /// Stores the record of `exchange`.
    ///
    /// # Errors
    ///
    /// Returns the [`RecordFailure`] of a record that could not be written
    /// or stored.
    pub async fn record(&self, exchange: &Exchange) -> Result<(), RecordFailure> {
        let record = exchange
            .audit_event(&self.observer)
            .map_err(RecordFailure::Write)?;
        self.forwarder
            .submit(record.into_bytes())
            .await
            .map_err(RecordFailure::Spool)
    }
}

/// The place of one record in the spool, given back when dropped unfilled.
#[derive(Debug)]
pub struct Place {
    /// The place.
    reservation: Reservation,
    /// The recording system.
    observer: Arc<Observer>,
}

impl Place {
    /// Stores the record of `exchange` in this place.
    ///
    /// # Errors
    ///
    /// Returns the [`RecordFailure`] of a record that could not be written
    /// or stored.
    pub async fn record(self, exchange: &Exchange) -> Result<(), RecordFailure> {
        let record = exchange
            .audit_event(&self.observer)
            .map_err(RecordFailure::Write)?;
        self.reservation
            .push(record.into_bytes())
            .await
            .map_err(RecordFailure::Spool)
    }
}

/// An access token FerroSMART issued, as its record names it.
#[derive(Debug, Clone, Copy)]
pub struct Token<'a> {
    /// The issuer, the system of the token's `jti`.
    pub issuer: &'a str,
    /// The token's `jti`.
    pub jti: &'a str,
    /// The client it was issued to.
    pub client_id: &'a str,
    /// The resource server it is for.
    pub audience: &'a str,
    /// The scope it grants.
    pub scope: &'a str,
    /// The person it was issued for, when one logged in.
    pub subject: Option<&'a str>,
}

/// A token request, as its record names it.
#[derive(Debug, Clone, Copy)]
pub struct TokenRequest<'a> {
    /// The client the request names, when it names one.
    pub client_id: Option<&'a str>,
    /// The address the request came from.
    pub from: std::net::IpAddr,
    /// The token endpoint.
    pub endpoint: &'a Url,
}

/// Returns the ITI-71 record of `request`: `issued` when a token was
/// issued, or the OAuth `error` it was refused with (IHE IUA, ITI TF-2
/// 3.71.5.1).
#[must_use]
pub fn token_request(request: TokenRequest<'_>, answer: Result<Token<'_>, &str>) -> Exchange {
    let client = Peer {
        who: request
            .client_id
            .or_else(|| answer.ok().map(|token| token.client_id))
            .unwrap_or(UNIDENTIFIED_CLIENT)
            .to_owned(),
        network: NetworkAddress::Ip(request.from),
    };
    let (outcome, outcome_description, on_behalf, entities) = match answer {
        Ok(token) => {
            let on_behalf = token.subject.map_or(OnBehalfOf::System, |subject| {
                OnBehalfOf::User(
                    User::new(
                        token.issuer.to_owned(),
                        subject.to_owned(),
                        token.client_id.to_owned(),
                    )
                    .with_audience(Some(token.audience.to_owned()))
                    .with_token_id(Some(token.jti.to_owned())),
                )
            });
            let entity = Described {
                what: Some(What::Identifier {
                    system: Some(token.issuer.to_owned()),
                    value: token.jti.to_owned(),
                }),
                kind: SYSTEM_OBJECT,
                role: Some(SECURITY_RESOURCE),
                name: None,
                description: None,
                details: vec![
                    Detail::new(detail::CLIENT_ID, token.client_id),
                    Detail::new(detail::AUDIENCE, token.audience),
                    Detail::new(detail::SCOPE, token.scope),
                ],
                security_labels: Vec::new(),
            };
            (
                Outcome::Success,
                None,
                on_behalf,
                vec![ihe_atna::balp::Entity::Described(entity)],
            )
        }
        Err(error) => (
            Outcome::MinorFailure,
            Some(error.to_owned()),
            OnBehalfOf::System,
            Vec::new(),
        ),
    };
    Exchange {
        kind: EventKind {
            profile: "",
            event_type: USER_AUTHENTICATION,
            subtypes: vec![USER_AUTHORIZATION],
            action: "E",
            client: APPLICATION,
            server: DESTINATION_ROLE,
        },
        recorded: jiff::Timestamp::now(),
        outcome,
        outcome_description,
        direction: Direction::Received {
            client,
            endpoint: NetworkAddress::uri(request.endpoint),
        },
        on_behalf,
        entities,
        security: Vec::new(),
    }
}

/// A person who logged in, as the record of the login names them.
#[derive(Debug, Clone, Copy)]
pub struct Person<'a> {
    /// FerroSMART's issuer, which the subject is FerroSMART's own under.
    pub issuer: &'a str,
    /// The person's pairwise subject.
    pub subject: &'a str,
    /// Their name, when the provider gave one.
    pub name: Option<&'a str>,
    /// The client the login was for, when it was for one.
    pub client_id: Option<&'a str>,
}

/// Returns the record of a login at the provider at `provider`: the person
/// who logged in, or the reason it failed (DICOM PS3.15 A.5.3.12, User
/// Authentication, `110122` Login).
#[must_use]
pub fn login(provider: &Url, answer: Result<Person<'_>, &str>) -> Exchange {
    let (outcome, outcome_description, on_behalf) = match answer {
        Ok(person) => {
            let user = match person.client_id {
                Some(client_id) => User::new(
                    person.issuer.to_owned(),
                    person.subject.to_owned(),
                    client_id.to_owned(),
                ),
                None => User::local(person.subject.to_owned())
                    .with_issuer(Some(person.issuer.to_owned())),
            };
            (
                Outcome::Success,
                None,
                OnBehalfOf::User(user.with_name(person.name.map(str::to_owned))),
            )
        }
        Err(reason) => (
            Outcome::MinorFailure,
            Some(reason.to_owned()),
            OnBehalfOf::System,
        ),
    };
    Exchange {
        kind: EventKind {
            profile: "",
            event_type: USER_AUTHENTICATION,
            subtypes: vec![LOGIN],
            action: "E",
            client: SOURCE_ROLE,
            server: DESTINATION_ROLE,
        },
        recorded: jiff::Timestamp::now(),
        outcome,
        outcome_description,
        direction: Direction::Sent {
            server: Peer::server(provider),
        },
        on_behalf,
        entities: Vec::new(),
        security: Vec::new(),
    }
}
