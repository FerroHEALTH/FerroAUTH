// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! FerroSMART's audit records (`docs/architecture.md` §13.2).
//!
//! Every token request is recorded as the authorization server's audit event
//! of ITI-71 Get Authorization Token in the form of BALP 1.1.4's profile
//! `IHE.IUA.71`: type `110114` User Authentication, subtype `ITI-71`, the
//! client and the authorization server as agents, the person as
//! `agent:user` when one logged in, and the request itself, its secrets
//! left out, as the one `token-request` entity. Every login at the upstream
//! provider is recorded as a DICOM User Authentication event of type
//! `110122` Login (DICOM PS3.15 A.5.3.12), whose `AuditEvent` form is our
//! own design.
//!
//! Each record is a FHIR R4 `AuditEvent` written through `ihe-atna` into
//! FerroSMART's own store, in the transaction of the action it records: an
//! issued token and its record commit together, and a request that writes
//! nothing else commits its record alone or fails. With
//! `[ferrosmart.audit.feed]` the store is the outbox the `ihe-atna`
//! forwarder delivers from to an Audit Record Repository over the ITI-20
//! ATX: FHIR Feed (ITI TF-2 §3.20.4.2). No specification governs where the
//! records are kept or the failing closed: our own design.
//!
//! None of these events is an access to personal electronic health data, so
//! none is an access record of Regulation (EU) 2025/327 Annex II 3.2; the
//! patient picker, which reads Patient resources, writes that record.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ihe_atna::atna::forwarder::{Outbox, OutboxError};
use ihe_atna::atna::spool::{Depth, Stored};
use ihe_atna::balp::{
    APPLICATION, Coded, DESTINATION_ROLE, Direction, Entity, EventKind, Exchange, IHE_TRANSACTIONS,
    LOGIN, NetworkAddress, Observer, Outcome, Peer, RecordError, SOURCE_ROLE, USER_AUTHENTICATION,
};
use ihe_atna::user::{OnBehalfOf, User};
use secrecy::{ExposeSecret as _, SecretSlice, SecretString};
use tokio::sync::Notify;
use url::Url;

use crate::store::audit::AuditRow;
use crate::store::{Store, StoreError};

/// The canonical URL of BALP 1.1.4's profile of the ITI-71 audit event.
pub const IUA_71: &str = "https://profiles.ihe.net/ITI/BALP/StructureDefinition/IHE.IUA.71";

/// The subtype of the ITI-71 audit event (BALP 1.1.4 `IHE.IUA.71`,
/// `AuditEvent.subtype`).
pub const USER_AUTHORIZATION: Coded =
    Coded::fixed(IHE_TRANSACTIONS, "ITI-71", "User Authorization");

/// The type of the authorization server's own agent (BALP 1.1.4
/// `IHE.IUA.71`, `agent:auth-server`).
pub const AUTHZ_OAUTH_SERVICE: Coded = Coded::fixed(
    "https://profiles.ihe.net/ITI/BALP/CodeSystem/UserAgentTypes",
    "AuthzOauthService",
    "OAuth Authorization Server",
);

/// The token request parameters whose values a record leaves out: the PKCE
/// verifier the profile names, and the credentials RFC 6749 has kept
/// confidential (§10.3 to §10.5) with the client assertion of RFC 7521.
pub const WITHHELD: [&str; 5] = [
    "code_verifier",
    "code",
    "refresh_token",
    "client_secret",
    "client_assertion",
];

/// How a client that named no `client_id` is shown as the source of a
/// token request. No specification governs the words: our own design.
pub const UNIDENTIFIED_CLIENT: &str = "unidentified client";

/// Why a record could not be stored.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecordFailure {
    /// The `AuditEvent` could not be written.
    #[error("the AuditEvent could not be written")]
    Write(#[source] RecordError),
    /// The written `AuditEvent` is no UTF-8 text.
    #[error("the AuditEvent is no UTF-8 text")]
    Text(#[source] std::str::Utf8Error),
    /// The store could not keep it.
    #[error("the audit record could not be stored")]
    Store(#[source] StoreError),
}

/// FerroSMART as the recording system, and the wake of the feed's
/// forwarder.
#[derive(Debug, Clone)]
pub struct Audit {
    /// The recording system.
    observer: Arc<Observer>,
    /// Woken once a record is stored, so the forwarder sends it.
    stored: Arc<Notify>,
}

impl Audit {
    /// Returns the audit lane that names `observer` as the recording system.
    #[must_use]
    pub fn new(observer: Observer) -> Self {
        Self {
            observer: Arc::new(observer),
            stored: Arc::new(Notify::new()),
        }
    }

    /// Returns the row `exchange` is stored as: `kind`, and the person and
    /// the client it names.
    ///
    /// # Errors
    ///
    /// Returns the [`RecordFailure`] of an `AuditEvent` that could not be
    /// written.
    pub fn row(
        &self,
        exchange: &Exchange,
        kind: &'static str,
        subject: Option<&str>,
        client_id: Option<&str>,
    ) -> Result<AuditRow, RecordFailure> {
        let record = exchange
            .audit_event(&self.observer)
            .map_err(RecordFailure::Write)?
            .into_bytes();
        let document = std::str::from_utf8(record.expose_secret())
            .map_err(RecordFailure::Text)?
            .to_owned();
        Ok(AuditRow {
            recorded_at: exchange.recorded.to_string(),
            kind,
            outcome: exchange.outcome.code(),
            subject: subject.map(str::to_owned),
            client_id: client_id.map(str::to_owned),
            document,
        })
    }

    /// Stores the record `row` alone in `store`.
    ///
    /// # Errors
    ///
    /// Returns [`RecordFailure::Store`] when the store cannot keep it.
    pub async fn record(&self, store: &Store, row: &AuditRow) -> Result<(), RecordFailure> {
        store
            .record_audit(row)
            .await
            .map_err(RecordFailure::Store)?;
        self.committed();
        Ok(())
    }

    /// Wakes the forwarder once a record committed.
    pub fn committed(&self) {
        self.stored.notify_one();
    }

    /// Returns the outbox the feed's forwarder delivers from: `store`, read
    /// again once a record commits or every `idle`.
    #[must_use]
    pub fn outbox(&self, store: Store, idle: Duration) -> StoreOutbox {
        StoreOutbox {
            store,
            stored: Arc::clone(&self.stored),
            idle,
            waiting: AtomicUsize::new(0),
            refused: AtomicUsize::new(0),
        }
    }
}

/// The store as the outbox of the ITI-20 FHIR Feed: the records not yet
/// delivered, oldest first; one the repository refused is stamped so and
/// kept for an operator.
#[derive(Debug)]
pub struct StoreOutbox {
    /// The store.
    store: Store,
    /// Woken once a record commits.
    stored: Arc<Notify>,
    /// How long to wait for a wake before reading the store again.
    idle: Duration,
    /// The records awaiting delivery at the last read.
    waiting: AtomicUsize,
    /// The records the repository refused, at the last read.
    refused: AtomicUsize,
}

/// The forwarder's error for a store failure.
fn outbox_error(error: impl std::error::Error + Send + Sync + 'static) -> OutboxError {
    OutboxError(Box::new(error))
}

#[async_trait::async_trait]
impl Outbox for StoreOutbox {
    async fn oldest(&self) -> Result<Option<Stored>, OutboxError> {
        let (oldest, waiting) = self
            .store
            .oldest_undelivered()
            .await
            .map_err(outbox_error)?;
        self.waiting.store(
            usize::try_from(waiting).unwrap_or(usize::MAX),
            Ordering::Relaxed,
        );
        let refused = self
            .store
            .audit_refused_count()
            .await
            .map_err(outbox_error)?;
        self.refused.store(
            usize::try_from(refused).unwrap_or(usize::MAX),
            Ordering::Relaxed,
        );
        let Some((sequence, document)) = oldest else {
            return Ok(None);
        };
        let message = serde_json::to_vec(&document).map_err(outbox_error)?;
        Ok(Some(Stored {
            sequence: u64::try_from(sequence).map_err(outbox_error)?,
            message: SecretSlice::from(message),
        }))
    }

    async fn stored(&self) {
        tokio::select! {
            () = self.stored.notified() => {}
            () = tokio::time::sleep(self.idle) => {}
        }
    }

    async fn remove(&self, sequence: u64) -> Result<(), OutboxError> {
        let sequence = i64::try_from(sequence).map_err(outbox_error)?;
        self.store
            .audit_delivered(sequence)
            .await
            .map_err(outbox_error)
    }

    async fn quarantine(&self, sequence: u64) -> Result<(), OutboxError> {
        let sequence = i64::try_from(sequence).map_err(outbox_error)?;
        tracing::error!(
            seq = sequence,
            "the Audit Record Repository refused an audit record; it is kept for an operator"
        );
        self.store
            .audit_refused(sequence)
            .await
            .map_err(outbox_error)
    }

    fn depth(&self) -> Depth {
        let quarantined = self.refused.load(Ordering::Relaxed);
        Depth {
            messages: self
                .waiting
                .load(Ordering::Relaxed)
                .saturating_add(quarantined),
            bytes: 0,
            quarantined,
        }
    }

    fn is_durable(&self) -> bool {
        true
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
    /// The request's `Content-Type`, when it named one.
    pub content_type: Option<&'a str>,
    /// The request body as sent.
    pub body: &'a [u8],
}

/// Returns the request as `entity:token-request` holds it.
///
/// That is "the http request in raw form, without the `code_verifier`
/// value" (BALP 1.1.4 `IHE.IUA.71`): the request line, the `Host` and
/// `Content-Type` headers and the form, with the value of every
/// [`WITHHELD`] parameter left out.
#[must_use]
pub fn raw_request(request: &TokenRequest<'_>) -> SecretString {
    let form: String = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(
            url::form_urlencoded::parse(request.body).map(|(name, value)| {
                let shown = if WITHHELD.contains(&name.as_ref()) {
                    std::borrow::Cow::Borrowed("")
                } else {
                    value
                };
                (name, shown)
            }),
        )
        .finish();
    let mut text = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\n",
        request.endpoint.path(),
        request.endpoint.host_str().unwrap_or_default()
    );
    if let Some(content_type) = request.content_type {
        text.push_str("Content-Type: ");
        text.push_str(content_type);
        text.push_str("\r\n");
    }
    text.push_str("\r\n");
    text.push_str(&form);
    SecretString::from(text)
}

/// Returns the ITI-71 record of `request` in the form of BALP 1.1.4's
/// `IHE.IUA.71`: `issued` when a token was issued, or the OAuth `error` it
/// was refused with.
#[must_use]
pub fn token_request(request: &TokenRequest<'_>, answer: Result<Token<'_>, &str>) -> Exchange {
    let client = Peer {
        who: request
            .client_id
            .or_else(|| answer.ok().map(|token| token.client_id))
            .unwrap_or(UNIDENTIFIED_CLIENT)
            .to_owned(),
        network: NetworkAddress::Ip(request.from),
    };
    let (outcome, outcome_description, on_behalf) = match answer {
        Ok(token) => (
            Outcome::Success,
            None,
            token.subject.map_or(OnBehalfOf::System, |subject| {
                OnBehalfOf::User(
                    User::new(
                        token.issuer.to_owned(),
                        subject.to_owned(),
                        token.client_id.to_owned(),
                    )
                    .with_audience(Some(token.audience.to_owned()))
                    .with_token_id(Some(token.jti.to_owned())),
                )
            }),
        ),
        Err(error) => (
            Outcome::MinorFailure,
            Some(error.to_owned()),
            OnBehalfOf::System,
        ),
    };
    Exchange {
        kind: EventKind {
            profile: IUA_71,
            event_type: USER_AUTHENTICATION,
            subtypes: vec![USER_AUTHORIZATION],
            action: "E",
            client: APPLICATION,
            server: AUTHZ_OAUTH_SERVICE,
        },
        recorded: jiff::Timestamp::now(),
        outcome,
        outcome_description,
        direction: Direction::Received {
            client,
            endpoint: NetworkAddress::uri(request.endpoint),
        },
        on_behalf,
        entities: vec![Entity::Query(raw_request(request))],
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
