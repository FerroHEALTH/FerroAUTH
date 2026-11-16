// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The consents people chose to remember (`docs/architecture.md` §13.6
//! item 6, §13.9).

use sqlx::Row as _;

use crate::store::{Store, StoreError, Transaction};

impl Store {
    /// Returns the scopes `subject` chose to remember for `client_id`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn remembered(
        &self,
        subject: &str,
        client_id: &str,
    ) -> Result<Option<String>, StoreError> {
        let row = sqlx::query("SELECT scope FROM consent WHERE subject = $1 AND client_id = $2")
            .bind(subject)
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| row.try_get("scope").map_err(StoreError::from))
            .transpose()
    }

    /// Returns every consent `subject` remembered, by client.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn consents(&self, subject: &str) -> Result<Vec<(String, String)>, StoreError> {
        let rows = sqlx::query(
            "SELECT client_id, scope FROM consent WHERE subject = $1 ORDER BY client_id",
        )
        .bind(subject)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| Ok((row.try_get("client_id")?, row.try_get("scope")?)))
            .collect()
    }
}

impl Transaction {
    /// Remembers that `subject` gave `client_id` the scopes `scope`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn remember(
        &mut self,
        subject: &str,
        client_id: &str,
        scope: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO consent (subject, client_id, scope) VALUES ($1, $2, $3) \
             ON CONFLICT (subject, client_id) DO UPDATE SET scope = $3, granted_at = now()",
        )
        .bind(subject)
        .bind(client_id)
        .bind(scope)
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }
    /// Forgets the consent `subject` gave `client_id` and revokes the
    /// grants, refresh tokens and access tokens issued to the client about
    /// them ("revoking it revokes the grants it covered",
    /// `docs/architecture.md` §13.6 item 6), and returns whether there was
    /// one.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails; nothing is
    /// changed then.
    pub async fn revoke_consent(
        &mut self,
        subject: &str,
        client_id: &str,
    ) -> Result<bool, StoreError> {
        let forgotten = sqlx::query("DELETE FROM consent WHERE subject = $1 AND client_id = $2")
            .bind(subject)
            .bind(client_id)
            .execute(&mut *self.tx)
            .await?;
        sqlx::query(
            "UPDATE access_token SET revoked_at = now() \
             WHERE subject = $1 AND client_id = $2 AND revoked_at IS NULL",
        )
        .bind(subject)
        .bind(client_id)
        .execute(&mut *self.tx)
        .await?;
        sqlx::query(
            "UPDATE refresh_token SET revoked_at = now() WHERE revoked_at IS NULL AND grant_id IN \
             (SELECT id FROM authorization_grant WHERE subject = $1 AND client_id = $2)",
        )
        .bind(subject)
        .bind(client_id)
        .execute(&mut *self.tx)
        .await?;
        sqlx::query(
            "UPDATE authorization_grant SET revoked_at = now() \
             WHERE subject = $1 AND client_id = $2 AND revoked_at IS NULL",
        )
        .bind(subject)
        .bind(client_id)
        .execute(&mut *self.tx)
        .await?;
        Ok(forgotten.rows_affected() == 1)
    }
}
