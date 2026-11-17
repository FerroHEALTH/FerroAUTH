// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The store as the outbox the `ihe-atna` forwarder delivers from to an
//! Audit Record Repository (ITI TF-2 §3.20.4.2).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ihe_atna::atna::forwarder::{Outbox, OutboxError};
use ihe_atna::atna::spool::{Depth, Stored};
use secrecy::SecretSlice;
use tokio::sync::Notify;

use crate::store::Store;

/// The store as the outbox of the ITI-20 FHIR Feed: the records not yet
/// delivered, oldest first; one the repository refused is stamped so and
/// kept for an operator.
#[derive(Debug)]
pub struct StoreOutbox {
    /// The store.
    pub(super) store: Store,
    /// Woken once a record commits.
    pub(super) stored: Arc<Notify>,
    /// How long to wait for a wake before reading the store again.
    pub(super) idle: Duration,
    /// The records awaiting delivery at the last read.
    pub(super) waiting: AtomicUsize,
    /// The records the repository refused, at the last read.
    pub(super) refused: AtomicUsize,
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
