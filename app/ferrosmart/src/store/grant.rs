// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The grants, their refresh tokens and the upstream sessions an
//! `online_access` grant lives in (`docs/architecture.md` §13.9).
//!
//! A grant is what a person gave a client; every token issued under it
//! names it, so revoking the grant revokes them all in one transaction
//! (RFC 7009 §2.1). A refresh token is stored as its SHA-256.

use serde_json::Value;
use sqlx::Row as _;

use crate::store::{Store, StoreError, Transaction};

/// How long a grant's refresh tokens may outlive the person's presence
/// (SMART App Launch 2.2.0, Scopes for requesting a refresh token).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// `offline_access`: refresh tokens last without the person.
    Offline,
    /// `online_access`: refresh tokens last while the person's upstream
    /// login does (`docs/architecture.md` §13.6 item 7).
    Online,
}

impl Access {
    /// Returns the access as the store writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Online => "online",
        }
    }
}

/// A grant to record.
#[derive(Debug, Clone, Copy)]
pub struct NewGrant<'a> {
    /// Its id, drawn at random.
    pub id: &'a str,
    /// The client it was given to.
    pub client_id: &'a str,
    /// The person's FerroSMART `sub`.
    pub subject: &'a str,
    /// The person's `fhirUser`, when granted.
    pub fhir_user: Option<&'a str>,
    /// The resource server its tokens are for.
    pub audience: &'a str,
    /// The scope granted.
    pub scope: &'a str,
    /// The launch context parameters of the token response, as one JSON
    /// object.
    pub context: &'a Value,
    /// When the person logged in, in seconds since the epoch.
    pub auth_time: Option<i64>,
    /// The refresh access granted, if any.
    pub access: Option<Access>,
    /// The upstream session an `online_access` grant lives in.
    pub upstream_session: Option<&'a str>,
}

/// What introspection reads of a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRecord {
    /// Its id.
    pub id: String,
    /// The client it was given to.
    pub client_id: String,
    /// The person's FerroSMART `sub`.
    pub subject: String,
    /// The person's `fhirUser`, when granted.
    pub fhir_user: Option<String>,
    /// The resource server its tokens are for.
    pub audience: String,
    /// The scope granted.
    pub scope: String,
    /// The launch context parameters, one JSON object.
    pub context: Value,
    /// The refresh access granted, if any.
    pub access: Option<Access>,
}

/// The outcome of redeeming a refresh token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rotation {
    /// The token was live: it is used now, and its successor recorded.
    Rotated(GrantRecord),
    /// The token was rotated before: its grant is revoked now, with every
    /// token under it (RFC 9700 §4.14.2).
    Reused {
        /// The grant revoked.
        grant_id: String,
    },
    /// The token was issued to another client.
    OtherClient,
    /// The token is unknown, lapsed or revoked, or its grant or session
    /// ended.
    Invalid,
}

/// When a refresh token issued now lapses unused, by the access of its
/// grant, in seconds since the epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdleUntil {
    /// For an `offline_access` grant.
    pub offline: i64,
    /// For an `online_access` grant.
    pub online: i64,
}

/// A recorded access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRecord {
    /// The client it was issued to.
    pub client_id: String,
    /// Its `sub`.
    pub subject: String,
    /// Its `aud`.
    pub audience: String,
    /// Its `scope`.
    pub scope: String,
    /// Its `iat`, in seconds since the epoch.
    pub issued_at: i64,
    /// Its `exp`, in seconds since the epoch.
    pub expires_at: i64,
    /// Whether it is unexpired and neither it nor its grant is revoked.
    pub active: bool,
    /// The grant it was issued under; none for a client credentials token.
    pub grant: Option<GrantRecord>,
}

/// A recorded refresh token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshRecord {
    /// The grant it was issued under.
    pub grant: GrantRecord,
    /// When it lapses unused, in seconds since the epoch.
    pub expires_at: i64,
    /// Whether it can be redeemed now: unexpired, unused, neither it nor
    /// its grant revoked, and, for `online_access`, its session not ended.
    pub active: bool,
}

/// The grant columns a joined query reads, prefixed `g_`.
const GRANT_COLUMNS: &str = "g.id AS g_id, g.client_id AS g_client_id, g.subject AS g_subject, \
    g.fhir_user AS g_fhir_user, g.audience AS g_audience, g.scope AS g_scope, g.context AS g_context, \
    g.access AS g_access";

impl Store {
    /// Records the grant `grant`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn create_grant(&self, grant: &NewGrant<'_>) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO authorization_grant (id, client_id, subject, fhir_user, audience, scope, \
             context, auth_time, access, upstream_session) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(grant.id)
        .bind(grant.client_id)
        .bind(grant.subject)
        .bind(grant.fhir_user)
        .bind(grant.audience)
        .bind(grant.scope)
        .bind(grant.context)
        .bind(grant.auth_time)
        .bind(grant.access.map(Access::as_str))
        .bind(grant.upstream_session)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Records the refresh token whose SHA-256 is `hash` under the grant
    /// `grant_id`, lapsing unused at `expires_at` (seconds since the epoch).
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn issue_refresh(
        &self,
        hash: &str,
        grant_id: &str,
        expires_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO refresh_token (token_hash, grant_id, expires_at) \
             VALUES ($1, $2, to_timestamp($3))",
        )
        .bind(hash)
        .bind(grant_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns the access token `jti`, with its grant.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails and
    /// [`StoreError::Corrupt`] for a row the server never writes.
    pub async fn access_token(&self, jti: &str) -> Result<Option<AccessRecord>, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT t.client_id, t.subject, t.audience, t.scope, \
             extract(epoch FROM t.issued_at)::bigint AS issued, \
             extract(epoch FROM t.expires_at)::bigint AS expires, \
             (t.revoked_at IS NULL AND t.expires_at > now() AND g.revoked_at IS NULL) AS active, \
             {GRANT_COLUMNS} \
             FROM access_token t LEFT JOIN authorization_grant g ON g.id = t.grant_id \
             WHERE t.jti = $1"
        )))
        .bind(jti)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let grant = match row.try_get::<Option<String>, _>("g_id")? {
            Some(_) => Some(read_grant(&row)?),
            None => None,
        };
        Ok(Some(AccessRecord {
            client_id: row.try_get("client_id")?,
            subject: row.try_get("subject")?,
            audience: row.try_get("audience")?,
            scope: row.try_get("scope")?,
            issued_at: row.try_get("issued")?,
            expires_at: row.try_get("expires")?,
            active: row.try_get("active")?,
            grant,
        }))
    }

    /// Returns the refresh token whose SHA-256 is `hash`, with its grant.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails and
    /// [`StoreError::Corrupt`] for a row the server never writes.
    pub async fn refresh_token(&self, hash: &str) -> Result<Option<RefreshRecord>, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT extract(epoch FROM r.expires_at)::bigint AS expires, \
             ({LIVE_REFRESH}) AS active, {GRANT_COLUMNS} \
             FROM refresh_token r JOIN authorization_grant g ON g.id = r.grant_id \
             LEFT JOIN upstream_session s ON s.id = g.upstream_session \
             WHERE r.token_hash = $1"
        )))
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(RefreshRecord {
                grant: read_grant(&row)?,
                expires_at: row.try_get("expires")?,
                active: row.try_get("active")?,
            })
        })
        .transpose()
    }

    /// Records the upstream login `session` of the person `subject` at the
    /// provider `issuer`, with the provider's session id `sid` when its ID
    /// Token carried one.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn begin_session(
        &self,
        session: &str,
        issuer: &str,
        subject: &str,
        sid: Option<&str>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO upstream_session (id, issuer, subject, sid) VALUES ($1, $2, $3, $4)",
        )
        .bind(session)
        .bind(issuer)
        .bind(subject)
        .bind(sid)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// The condition under which the refresh token `r` of grant `g`, in the
/// session `s`, can be redeemed.
const LIVE_REFRESH: &str = "r.revoked_at IS NULL AND r.used_at IS NULL AND r.expires_at > now() \
    AND g.revoked_at IS NULL \
    AND (g.access = 'offline' OR (g.access = 'online' AND s.id IS NOT NULL AND s.ended_at IS NULL))";

/// Reads the `g_` columns of a joined row.
fn read_grant(row: &sqlx::postgres::PgRow) -> Result<GrantRecord, StoreError> {
    let id: String = row.try_get("g_id")?;
    let context: Value = row.try_get("g_context")?;
    if !context.is_object() {
        return Err(StoreError::Corrupt { client_id: id });
    }
    let access = match row.try_get::<Option<String>, _>("g_access")?.as_deref() {
        Some("offline") => Some(Access::Offline),
        Some("online") => Some(Access::Online),
        None => None,
        Some(_) => return Err(StoreError::Corrupt { client_id: id }),
    };
    Ok(GrantRecord {
        access,
        client_id: row.try_get("g_client_id")?,
        subject: row.try_get("g_subject")?,
        fhir_user: row.try_get("g_fhir_user")?,
        audience: row.try_get("g_audience")?,
        scope: row.try_get("g_scope")?,
        context,
        id,
    })
}

/// Revokes the grant `grant_id` with every token under it inside `tx`, and
/// returns whether the grant was live.
async fn revoke_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    grant_id: &str,
) -> Result<bool, StoreError> {
    let revoked = sqlx::query(
        "UPDATE authorization_grant SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(grant_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE refresh_token SET revoked_at = now() WHERE grant_id = $1 AND revoked_at IS NULL",
    )
    .bind(grant_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE access_token SET revoked_at = now() WHERE grant_id = $1 AND revoked_at IS NULL",
    )
    .bind(grant_id)
    .execute(&mut **tx)
    .await?;
    Ok(revoked.rows_affected() == 1)
}

impl Transaction {
    /// Redeems the refresh token whose SHA-256 is `hash` for `client_id`,
    /// in one transaction that holds the token's row: a live token is
    /// marked used and its successor `successor` (a SHA-256 too) recorded
    /// under the same grant, lapsing as `idle` says; a token used before
    /// revokes its grant (RFC 9700 §4.14.2; OAuth 2.1 draft §4.3.1).
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails; nothing is
    /// changed then, and [`StoreError::Corrupt`] for a row the server never
    /// writes.
    pub async fn rotate(
        &mut self,
        hash: &str,
        client_id: &str,
        successor: &str,
        idle: IdleUntil,
    ) -> Result<Rotation, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT r.used_at IS NOT NULL AS used, ({LIVE_REFRESH}) AS active, {GRANT_COLUMNS} \
             FROM refresh_token r JOIN authorization_grant g ON g.id = r.grant_id \
             LEFT JOIN upstream_session s ON s.id = g.upstream_session \
             WHERE r.token_hash = $1 FOR UPDATE OF r"
        )))
        .bind(hash)
        .fetch_optional(&mut *self.tx)
        .await?;
        let Some(row) = row else {
            return Ok(Rotation::Invalid);
        };
        let grant = read_grant(&row)?;
        if grant.client_id != client_id {
            return Ok(Rotation::OtherClient);
        }
        if row.try_get::<bool, _>("used")? {
            revoke_in(&mut self.tx, &grant.id).await?;
            return Ok(Rotation::Reused { grant_id: grant.id });
        }
        let expires_at = match grant.access {
            Some(Access::Offline) => idle.offline,
            Some(Access::Online) => idle.online,
            None => return Ok(Rotation::Invalid),
        };
        if !row.try_get::<bool, _>("active")? {
            return Ok(Rotation::Invalid);
        }
        sqlx::query("UPDATE refresh_token SET used_at = now() WHERE token_hash = $1")
            .bind(hash)
            .execute(&mut *self.tx)
            .await?;
        sqlx::query(
            "INSERT INTO refresh_token (token_hash, grant_id, predecessor, expires_at) \
             VALUES ($1, $2, $3, to_timestamp($4))",
        )
        .bind(successor)
        .bind(&grant.id)
        .bind(hash)
        .bind(expires_at)
        .execute(&mut *self.tx)
        .await?;
        Ok(Rotation::Rotated(grant))
    }
    /// Revokes the grant `grant_id` with every refresh and access token
    /// issued under it, in one transaction, and returns whether the grant
    /// was live.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails; nothing is
    /// changed then.
    pub async fn revoke_grant(&mut self, grant_id: &str) -> Result<bool, StoreError> {
        let revoked = revoke_in(&mut self.tx, grant_id).await?;
        Ok(revoked)
    }
    /// Ends the upstream session `session`, and returns whether it was
    /// live; the `online_access` grants in it refresh no more.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn end_session(&mut self, session: &str) -> Result<bool, StoreError> {
        let ended = sqlx::query(
            "UPDATE upstream_session SET ended_at = now() WHERE id = $1 AND ended_at IS NULL",
        )
        .bind(session)
        .execute(&mut *self.tx)
        .await?;
        Ok(ended.rows_affected() == 1)
    }
    /// Revokes the access token `jti` alone, and returns whether it was
    /// unrevoked.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn revoke_access_token(&mut self, jti: &str) -> Result<bool, StoreError> {
        let revoked = sqlx::query(
            "UPDATE access_token SET revoked_at = now() WHERE jti = $1 AND revoked_at IS NULL",
        )
        .bind(jti)
        .execute(&mut *self.tx)
        .await?;
        Ok(revoked.rows_affected() == 1)
    }
}
