// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The organisation approvals of the clients and what was issued on them
//! (`docs/architecture.md` §13.6 item 6, §13.9).

use sqlx::Row as _;

use crate::clients::Approval;
use crate::store::{Store, StoreError, Transaction};

impl Store {
    /// Returns every client's stored organisation approval, by client id.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn approvals(&self) -> Result<Vec<(String, Approval)>, StoreError> {
        let rows = sqlx::query(
            "SELECT client_id, approved_scope, approved_by, \
             extract(epoch FROM approved_at)::bigint AS approved_at, first_party \
             FROM client WHERE approved_at IS NOT NULL ORDER BY client_id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok((
                    row.try_get("client_id")?,
                    Approval {
                        scopes: row.try_get("approved_scope")?,
                        approved_by: row.try_get("approved_by")?,
                        approved_at: row.try_get("approved_at")?,
                        first_party: row.try_get("first_party")?,
                    },
                ))
            })
            .collect()
    }

    /// Returns the clients `subject` holds a live grant of under their
    /// standing organisation approval, by client id.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn approved_apps(&self, subject: &str) -> Result<Vec<(String, String)>, StoreError> {
        self.scopes_by_client(
            "SELECT DISTINCT ON (g.client_id) g.client_id, g.scope \
             FROM authorization_grant g JOIN client c ON c.client_id = g.client_id \
             WHERE g.subject = $1 AND g.revoked_at IS NULL AND g.approved_at = c.approved_at \
             ORDER BY g.client_id, g.created_at DESC",
            subject,
        )
        .await
    }
}

impl Transaction {
    /// Withdraws the organisation approval of `client_id` given at
    /// `approved_at` (seconds since the epoch): every grant issued on it is
    /// revoked with its access and refresh tokens, and every code issued on
    /// it and not yet redeemed is dropped. Returns the grants revoked.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails.
    pub async fn withdraw_approval(
        &mut self,
        client_id: &str,
        approved_at: i64,
    ) -> Result<u64, StoreError> {
        sqlx::query(
            "UPDATE access_token SET revoked_at = now() WHERE revoked_at IS NULL AND grant_id IN \
             (SELECT id FROM authorization_grant WHERE client_id = $1 AND approved_at = to_timestamp($2))",
        )
        .bind(client_id)
        .bind(approved_at)
        .execute(&mut *self.tx)
        .await?;
        sqlx::query(
            "UPDATE refresh_token SET revoked_at = now() WHERE revoked_at IS NULL AND grant_id IN \
             (SELECT id FROM authorization_grant WHERE client_id = $1 AND approved_at = to_timestamp($2))",
        )
        .bind(client_id)
        .bind(approved_at)
        .execute(&mut *self.tx)
        .await?;
        let revoked = sqlx::query(
            "UPDATE authorization_grant SET revoked_at = now() \
             WHERE client_id = $1 AND approved_at = to_timestamp($2) AND revoked_at IS NULL",
        )
        .bind(client_id)
        .bind(approved_at)
        .execute(&mut *self.tx)
        .await?;
        sqlx::query(
            "DELETE FROM authorization_code \
             WHERE client_id = $1 AND approved_at = to_timestamp($2) AND redeemed_at IS NULL",
        )
        .bind(client_id)
        .bind(approved_at)
        .execute(&mut *self.tx)
        .await?;
        Ok(revoked.rows_affected())
    }
}
