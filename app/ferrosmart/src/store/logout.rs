// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The logouts a person is asked to confirm at the end-session endpoint
//! (OpenID Connect RP-Initiated Logout 1.0 §2), and the end of a person's
//! online grants once they confirm.
//!
//! A pending logout lives as long as an authorization request does and is
//! taken once, when the person decides or when the browser comes back from
//! the upstream provider. No specification governs the storage: our own
//! design.

use sqlx::Row as _;

use crate::store::{Store, StoreError, Transaction};

/// A logout waiting for the person's answer.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingLogout {
    /// Its id, the value of the browser's logout cookie.
    pub id: String,
    /// The client that asked, when the request named one.
    pub client_id: Option<String>,
    /// The person the ID Token hint names, by their FerroSMART `sub`.
    pub subject: Option<String>,
    /// The registered `post_logout_redirect_uri` the browser goes back to.
    pub redirect_uri: Option<String>,
    /// The client's `state`, sent back with the redirect.
    pub state: Option<String>,
    /// The token the confirmation form carries.
    pub form_token: String,
    /// The `state` sent to the upstream provider's end-session endpoint.
    pub upstream_state: String,
    /// When it lapses, in seconds since the epoch.
    pub expires_at: i64,
}

impl std::fmt::Debug for PendingLogout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingLogout")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// Reads a `pending_logout` row.
fn read(row: &sqlx::postgres::PgRow) -> Result<PendingLogout, StoreError> {
    Ok(PendingLogout {
        id: row.try_get("id")?,
        client_id: row.try_get("client_id")?,
        subject: row.try_get("subject")?,
        redirect_uri: row.try_get("redirect_uri")?,
        state: row.try_get("state")?,
        form_token: row.try_get("form_token")?,
        upstream_state: row.try_get("upstream_state")?,
        expires_at: row.try_get("expires_at")?,
    })
}

/// The columns [`read`] takes, as a literal the statements are built of.
macro_rules! columns {
    () => {
        "id, client_id, subject, redirect_uri, state, form_token, upstream_state, \
         extract(epoch FROM expires_at)::bigint AS expires_at"
    };
}

impl Store {
    /// Records `logout` until the person answers.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn begin_logout(&self, logout: &PendingLogout) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO pending_logout (id, client_id, subject, redirect_uri, state, form_token, \
             upstream_state, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8))",
        )
        .bind(&logout.id)
        .bind(&logout.client_id)
        .bind(&logout.subject)
        .bind(&logout.redirect_uri)
        .bind(&logout.state)
        .bind(&logout.form_token)
        .bind(&logout.upstream_state)
        .bind(logout.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns the live pending logout `id`, if any.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn pending_logout(&self, id: &str) -> Result<Option<PendingLogout>, StoreError> {
        let row = sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM pending_logout WHERE id = $1 AND expires_at > now()"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(read).transpose()
    }

    /// Takes the live pending logout `id` whose upstream `state` is
    /// `upstream_state`, so it is answered once.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn take_logout(
        &self,
        id: &str,
        upstream_state: &str,
    ) -> Result<Option<PendingLogout>, StoreError> {
        let row = sqlx::query(concat!(
            "DELETE FROM pending_logout WHERE id = $1 AND upstream_state = $2 \
             AND expires_at > now() RETURNING ",
            columns!()
        ))
        .bind(id)
        .bind(upstream_state)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(read).transpose()
    }
}

impl Transaction {
    /// Ends the person `subject`'s live `online_access` grants and the
    /// upstream sessions they were issued under, returning the grants
    /// ended (OpenID Connect RP-Initiated Logout 1.0 §2: "the OP MUST log
    /// out the End-User").
    ///
    /// An `offline_access` grant outlives the login, as it does a
    /// back-channel logout (`docs/architecture.md` §13.6 item 7).
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails.
    pub async fn log_out_person(&mut self, subject: &str) -> Result<Vec<String>, StoreError> {
        let grants: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM authorization_grant WHERE subject = $1 AND access = 'online' \
             AND revoked_at IS NULL ORDER BY id",
        )
        .bind(subject)
        .fetch_all(&mut *self.tx)
        .await?;
        sqlx::query(
            "UPDATE upstream_session SET ended_at = now() WHERE ended_at IS NULL AND id IN \
             (SELECT upstream_session FROM authorization_grant WHERE id = ANY($1))",
        )
        .bind(&grants)
        .execute(&mut *self.tx)
        .await?;
        for grant in &grants {
            super::grant::revoke_in(&mut self.tx, grant).await?;
        }
        Ok(grants)
    }

    /// Takes the pending logout `id`, so a second confirmation finds none.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn take_pending_logout(
        &mut self,
        id: &str,
    ) -> Result<Option<PendingLogout>, StoreError> {
        let row = sqlx::query(concat!(
            "DELETE FROM pending_logout WHERE id = $1 AND expires_at > now() RETURNING ",
            columns!()
        ))
        .bind(id)
        .fetch_optional(&mut *self.tx)
        .await?;
        row.as_ref().map(read).transpose()
    }
}
