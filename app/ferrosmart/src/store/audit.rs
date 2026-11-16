// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! FerroSMART's own audit records (`docs/architecture.md` §13.2): written in
//! the transaction of the action they record, read back by subject and time,
//! and the outbox the ITI-20 FHIR Feed delivers from.

use serde_json::Value;
use sqlx::Row as _;

use crate::store::{Store, StoreError};

/// One audit record to store.
#[derive(Debug, Clone)]
pub struct AuditRow {
    /// When the action ended, as RFC 3339.
    pub recorded_at: String,
    /// What was recorded, such as `token` or `login`.
    pub kind: &'static str,
    /// The `AuditEvent.outcome` code.
    pub outcome: &'static str,
    /// The person the record names, by their pairwise subject.
    pub subject: Option<String>,
    /// The client the record names.
    pub client_id: Option<String>,
    /// The `AuditEvent` as FHIR JSON.
    pub document: String,
}

/// Which records a reader asks for, newest first.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Only the records naming this person.
    pub subject: Option<String>,
    /// Only the records from this instant on, as RFC 3339.
    pub since: Option<String>,
    /// Only the records before this instant, as RFC 3339.
    pub until: Option<String>,
    /// The most records returned.
    pub limit: i64,
}

impl Store {
    /// Stores `row` alone: for an action that writes nothing else.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn record_audit(&self, row: &AuditRow) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        insert(&mut tx, row).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Returns the records `query` asks for, newest first, each an
    /// `AuditEvent`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn audit_records(&self, query: &AuditQuery) -> Result<Vec<Value>, StoreError> {
        let rows = sqlx::query(
            "SELECT document FROM audit_record \
             WHERE ($1::text IS NULL OR subject = $1) \
               AND ($2::timestamptz IS NULL OR recorded_at >= $2::timestamptz) \
               AND ($3::timestamptz IS NULL OR recorded_at < $3::timestamptz) \
             ORDER BY recorded_at DESC, seq DESC LIMIT $4",
        )
        .bind(query.subject.as_deref())
        .bind(query.since.as_deref())
        .bind(query.until.as_deref())
        .bind(query.limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                row.try_get::<Value, _>("document")
                    .map_err(StoreError::from)
            })
            .collect()
    }

    /// Returns the oldest record the feed has not delivered nor seen
    /// refused, with how many wait.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails.
    pub async fn oldest_undelivered(&self) -> Result<(Option<(i64, Value)>, i64), StoreError> {
        let oldest = sqlx::query(
            "SELECT seq, document FROM audit_record \
             WHERE delivered_at IS NULL AND refused_at IS NULL ORDER BY seq LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?
        .map(|row| Ok::<_, sqlx::Error>((row.try_get("seq")?, row.try_get("document")?)))
        .transpose()?;
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_record WHERE delivered_at IS NULL AND refused_at IS NULL",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok((oldest, waiting))
    }

    /// Stamps the record `seq` delivered.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn audit_delivered(&self, seq: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE audit_record SET delivered_at = now() WHERE seq = $1")
            .bind(seq)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Stamps the record `seq` refused by the repository, keeping it for an
    /// operator.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn audit_refused(&self, seq: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE audit_record SET refused_at = now() WHERE seq = $1")
            .bind(seq)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Returns how many records the repository refused.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn audit_refused_count(&self) -> Result<i64, StoreError> {
        Ok(
            sqlx::query_scalar("SELECT count(*) FROM audit_record WHERE refused_at IS NOT NULL")
                .fetch_one(&self.pool)
                .await?,
        )
    }
}

/// Inserts `row` in `tx`.
pub(crate) async fn insert(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &AuditRow,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO audit_record (recorded_at, kind, outcome, subject, client_id, document) \
         VALUES ($1::timestamptz, $2, $3, $4, $5, $6::jsonb)",
    )
    .bind(&row.recorded_at)
    .bind(row.kind)
    .bind(row.outcome)
    .bind(row.subject.as_deref())
    .bind(row.client_id.as_deref())
    .bind(&row.document)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
