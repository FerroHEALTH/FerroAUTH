// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The launches EHRs registered (`docs/architecture.md` §13.6 item 3).
//!
//! Each is kept as the SHA-256 of its opaque value and redeemed once, each write in
//! a [`Transaction`] with its audit record. No specification governs the
//! storage: our own design.

use sqlx::Row as _;
use sqlx::types::Json;

use crate::launch::context::Context;
use crate::store::{StoreError, Transaction, insert_jti};

/// A launch to record.
#[derive(Debug, Clone, Copy)]
pub struct NewLaunch<'a> {
    /// The SHA-256 of the opaque value, base64url.
    pub launch_hash: &'a str,
    /// The EHR client that registered it.
    pub ehr_client_id: &'a str,
    /// The app it launches.
    pub client_id: &'a str,
    /// The resource server it is for.
    pub audience: &'a str,
    /// The context.
    pub context: &'a Context,
    /// When it lapses, in seconds since the epoch.
    pub expires_at: i64,
}

/// A launch redeemed at the authorization endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redeemed {
    /// The EHR client that registered it.
    pub ehr_client_id: String,
    /// The context.
    pub context: Context,
}

impl Transaction {
    /// Records `launch`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn record_launch(&mut self, launch: &NewLaunch<'_>) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO launch (launch_hash, ehr_client_id, client_id, audience, context, expires_at) \
             VALUES ($1, $2, $3, $4, $5, to_timestamp($6))",
        )
        .bind(launch.launch_hash)
        .bind(launch.ehr_client_id)
        .bind(launch.client_id)
        .bind(launch.audience)
        .bind(Json(launch.context))
        .bind(launch.expires_at)
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Redeems the launch whose hash is `launch_hash` for the app
    /// `client_id` at the resource server `audience`, in one statement so
    /// two replicas never both redeem it: none when it is unknown, used,
    /// lapsed, or bound to another app or server.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails or the
    /// stored context cannot be read.
    pub async fn redeem_launch(
        &mut self,
        launch_hash: &str,
        client_id: &str,
        audience: &str,
    ) -> Result<Option<Redeemed>, StoreError> {
        let row = sqlx::query(
            "UPDATE launch SET used_at = now() \
             WHERE launch_hash = $1 AND client_id = $2 AND audience = $3 \
             AND used_at IS NULL AND expires_at > now() \
             RETURNING ehr_client_id, context",
        )
        .bind(launch_hash)
        .bind(client_id)
        .bind(audience)
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|row| {
            Ok(Redeemed {
                ehr_client_id: row.try_get("ehr_client_id")?,
                context: row.try_get::<Json<Context>, _>("context")?.0,
            })
        })
        .transpose()
    }

    /// Records the `jti` of a launch JWT the EHR `issuer` signed, kept until
    /// `expires_at`, and returns whether it was unseen: a `false` is a
    /// replay.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn first_launch_use(
        &mut self,
        issuer: &str,
        jti: &str,
        expires_at: i64,
    ) -> Result<bool, StoreError> {
        insert_jti(&mut *self.tx, issuer, jti, expires_at).await
    }
}
