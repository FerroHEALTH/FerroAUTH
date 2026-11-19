// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The authorization requests between the endpoint and the code, and the
//! codes they issue (`docs/architecture.md` §13.9).

use sqlx::Row as _;
use sqlx::types::Json;

use crate::launch::context::Context;

use crate::store::{Code, Login, Pending, Purpose, Store, StoreError, Transaction};

/// The columns of a pending authorization, as [`read_pending`] reads them.
const PENDING: &str = "SELECT id, client_id, redirect_uri, scope, state, nonce, code_challenge, \
    audience, upstream_state, upstream_nonce, upstream_verifier, form_token, subject, fhir_user, \
    display_name, offered_scope, auth_time, extract(epoch FROM expires_at)::bigint AS expires, purpose, \
    upstream_session, launch_context FROM pending_authorization";

impl Store {
    /// Records the authorization request `pending`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn begin_authorization(&self, pending: &Pending) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO pending_authorization (id, client_id, redirect_uri, scope, state, nonce, \
             code_challenge, audience, upstream_state, upstream_nonce, upstream_verifier, form_token, \
             expires_at, purpose, launch_context) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
             to_timestamp($13), $14, $15)",
        )
        .bind(&pending.id)
        .bind(&pending.client_id)
        .bind(&pending.redirect_uri)
        .bind(&pending.scope)
        .bind(&pending.state)
        .bind(&pending.nonce)
        .bind(&pending.code_challenge)
        .bind(&pending.audience)
        .bind(&pending.upstream_state)
        .bind(&pending.upstream_nonce)
        .bind(&pending.upstream_verifier)
        .bind(&pending.form_token)
        .bind(pending.expires_at)
        .bind(pending.purpose.as_str())
        .bind(pending.launch_context.as_ref().map(Json))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns the live authorization request `id`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn pending(&self, id: &str) -> Result<Option<Pending>, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "{PENDING} WHERE id = $1 AND expires_at > now()"
        )))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| read_pending(&row)).transpose()
    }

    /// Returns the live authorization request whose upstream login carried
    /// `upstream_state`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn pending_by_upstream(
        &self,
        upstream_state: &str,
    ) -> Result<Option<Pending>, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "{PENDING} WHERE upstream_state = $1 AND expires_at > now()"
        )))
        .bind(upstream_state)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| read_pending(&row)).transpose()
    }

    /// Puts `context` in the launch context of the pending request `id`,
    /// as the patient picker chose it.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn set_launch_context(&self, id: &str, context: &Context) -> Result<(), StoreError> {
        sqlx::query("UPDATE pending_authorization SET launch_context = $2 WHERE id = $1")
            .bind(id)
            .bind(Json(context))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Puts `context` in the launch context of the pending request `id` and
    /// narrows what the consent page offers to `offered`, as the picker
    /// chose a patient and no encounter.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn set_launch_context_offering(
        &self,
        id: &str,
        context: &Context,
        offered: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE pending_authorization SET launch_context = $2, offered_scope = $3 WHERE id = $1",
        )
        .bind(id)
        .bind(Json(context))
        .bind(offered)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Records who logged in for the request `id` and what the consent
    /// page offers them.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn logged_in(&self, id: &str, login: &Login) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE pending_authorization SET subject = $2, fhir_user = $3, display_name = $4, \
             offered_scope = $5, auth_time = $6, upstream_session = $7 WHERE id = $1",
        )
        .bind(id)
        .bind(&login.subject)
        .bind(&login.fhir_user)
        .bind(&login.display_name)
        .bind(&login.offered_scope)
        .bind(login.auth_time)
        .bind(&login.upstream_session)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Ends the request `id`, whatever its outcome, and returns it when it
    /// was still live, so it is decided once.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn finish(&self, id: &str) -> Result<Option<Pending>, StoreError> {
        let row = sqlx::query(
            "DELETE FROM pending_authorization WHERE id = $1 AND expires_at > now() \
             RETURNING id, client_id, redirect_uri, scope, state, nonce, code_challenge, audience, \
             upstream_state, upstream_nonce, upstream_verifier, form_token, subject, fhir_user, \
             display_name, offered_scope, auth_time, extract(epoch FROM expires_at)::bigint AS expires, purpose, \
             upstream_session, launch_context",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| read_pending(&row)).transpose()
    }

    /// Returns the code whose SHA-256 is `hash`, with whether it was
    /// redeemed before, while it lives.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn code(&self, hash: &str) -> Result<Option<(Code, bool)>, StoreError> {
        let row = sqlx::query(
            "SELECT client_id, redirect_uri, code_challenge, audience, subject, fhir_user, scope, \
             nonce, auth_time, extract(epoch FROM expires_at)::bigint AS expires, upstream_session, \
             redeemed_at IS NOT NULL AS redeemed, launch_context, \
             extract(epoch FROM approved_at)::bigint AS approved_at FROM authorization_code \
             WHERE code_hash = $1 AND expires_at > now()",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| -> Result<(Code, bool), StoreError> {
            Ok((
                Code {
                    client_id: row.try_get("client_id")?,
                    redirect_uri: row.try_get("redirect_uri")?,
                    code_challenge: row.try_get("code_challenge")?,
                    audience: row.try_get("audience")?,
                    subject: row.try_get("subject")?,
                    fhir_user: row.try_get("fhir_user")?,
                    scope: row.try_get("scope")?,
                    nonce: row.try_get("nonce")?,
                    auth_time: row.try_get("auth_time")?,
                    expires_at: row.try_get("expires")?,
                    upstream_session: row.try_get("upstream_session")?,
                    launch_context: launch_context(&row)?,
                    approved_at: row.try_get("approved_at")?,
                },
                row.try_get("redeemed")?,
            ))
        })
        .transpose()
    }

    /// Marks the code whose SHA-256 is `hash` redeemed, and returns whether
    /// this call redeemed it: `false` when another request did first.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn redeem(&self, hash: &str) -> Result<bool, StoreError> {
        let done = sqlx::query(
            "UPDATE authorization_code SET redeemed_at = now() \
             WHERE code_hash = $1 AND redeemed_at IS NULL",
        )
        .bind(hash)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }
}

impl Transaction {
    /// Records the authorization code `code`, by the SHA-256 `hash` of its
    /// value.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn issue_code(&mut self, hash: &str, code: &Code) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO authorization_code (code_hash, client_id, redirect_uri, code_challenge, \
             audience, subject, fhir_user, scope, nonce, auth_time, expires_at, upstream_session, \
             launch_context, approved_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, to_timestamp($11), $12, $13, \
             to_timestamp($14))",
        )
        .bind(hash)
        .bind(&code.client_id)
        .bind(&code.redirect_uri)
        .bind(&code.code_challenge)
        .bind(&code.audience)
        .bind(&code.subject)
        .bind(&code.fhir_user)
        .bind(&code.scope)
        .bind(&code.nonce)
        .bind(code.auth_time)
        .bind(code.expires_at)
        .bind(&code.upstream_session)
        .bind(code.launch_context.as_ref().map(Json))
        .bind(code.approved_at)
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }
    /// Revokes every access token issued for the code whose SHA-256 is
    /// `hash` ("SHOULD revoke (when possible) all access tokens and refresh
    /// tokens previously issued based on that authorization code", OAuth 2.1
    /// draft §4.1.3).
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn revoke_code(&mut self, hash: &str) -> Result<u64, StoreError> {
        let done = sqlx::query(
            "UPDATE access_token SET revoked_at = now() WHERE code_hash = $1 AND revoked_at IS NULL",
        )
        .bind(hash)
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected())
    }
}

/// Reads a pending authorization row.
fn read_pending(row: &sqlx::postgres::PgRow) -> Result<Pending, StoreError> {
    let id: String = row.try_get("id")?;
    let purpose = match row.try_get::<String, _>("purpose")?.as_str() {
        "manage" => Purpose::Manage,
        "authorize" => Purpose::Authorize,
        _ => return Err(StoreError::Corrupt { client_id: id }),
    };
    Ok(Pending {
        id,
        client_id: row.try_get("client_id")?,
        redirect_uri: row.try_get("redirect_uri")?,
        scope: row.try_get("scope")?,
        state: row.try_get("state")?,
        nonce: row.try_get("nonce")?,
        code_challenge: row.try_get("code_challenge")?,
        audience: row.try_get("audience")?,
        upstream_state: row.try_get("upstream_state")?,
        upstream_nonce: row.try_get("upstream_nonce")?,
        upstream_verifier: row.try_get("upstream_verifier")?,
        form_token: row.try_get("form_token")?,
        subject: row.try_get("subject")?,
        fhir_user: row.try_get("fhir_user")?,
        display_name: row.try_get("display_name")?,
        offered_scope: row.try_get("offered_scope")?,
        auth_time: row.try_get("auth_time")?,
        expires_at: row.try_get("expires")?,
        purpose,
        upstream_session: row.try_get("upstream_session")?,
        launch_context: launch_context(row)?,
    })
}

/// Reads the `launch_context` column of `row`.
fn launch_context(row: &sqlx::postgres::PgRow) -> Result<Option<Context>, StoreError> {
    Ok(row
        .try_get::<Option<Json<Context>>, _>("launch_context")?
        .map(|context| context.0))
}
