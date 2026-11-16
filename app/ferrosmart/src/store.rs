// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The PostgreSQL store, which holds every piece of FerroSMART's state so
//! any replica answers any request (`docs/architecture.md` §13.9).
//!
//! The migrations ship in the binary and run at start; `sqlx` takes a
//! PostgreSQL advisory lock around them, so replicas starting together
//! migrate once. No specification governs the storage: our own design.

pub mod audit;
pub mod grant;
pub mod launch;

use std::time::Duration;

use secrecy::ExposeSecret as _;
use serde_json::Value;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::types::Json;
use sqlx::{Postgres, Row as _};

use crate::clients::{Client, ClientKeys, ClientKind, GrantType};
use crate::launch::context::Context;

/// How long a request waits for a connection before the store answers that
/// it is unavailable. No specification governs the value: our own design.
pub const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// Why the store failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database refused or failed a statement, or cannot be reached.
    #[error("the database failed")]
    Database(#[from] sqlx::Error),
    /// A migration failed.
    #[error("the database could not be migrated")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// An audited write was to commit without its audit record.
    #[error("an audited write has no audit record")]
    Unrecorded,
    /// A stored row holds a value the server never writes.
    #[error("the stored row `{client_id}` holds a value the server never writes")]
    Corrupt {
        /// The client.
        client_id: String,
    },
}

/// The store: a pool of connections to one database.
#[derive(Debug, Clone)]
pub struct Store {
    /// The pool.
    pool: PgPool,
}

impl Store {
    /// Connects to the database `url` names with at most `max_connections`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the database cannot be reached.
    pub async fn connect(
        url: &secrecy::SecretString,
        max_connections: u32,
    ) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(ACQUIRE_TIMEOUT)
            .connect(url.expose_secret())
            .await?;
        Ok(Self { pool })
    }

    /// Returns a store over the database `url` names that connects on first
    /// use, for a server whose routes may never reach it.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when `url` does not parse.
    pub fn connect_lazy(
        url: &secrecy::SecretString,
        max_connections: u32,
    ) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(ACQUIRE_TIMEOUT)
            .connect_lazy(url.expose_secret())?;
        Ok(Self { pool })
    }

    /// Runs the migrations the binary carries.
    ///
    /// # Errors
    /// Returns [`StoreError::Migrate`] when a migration fails.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    /// Replaces the clients the configuration registered with `clients`,
    /// in one transaction: each is written, and a configured client no
    /// longer listed is removed.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails; nothing is
    /// changed then.
    pub async fn register(&self, clients: &[Client]) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        let ids: Vec<&str> = clients
            .iter()
            .map(|client| client.client_id.as_str())
            .collect();
        sqlx::query("DELETE FROM client WHERE source = 'config' AND NOT (client_id = ANY($1))")
            .bind(&ids)
            .execute(&mut *tx)
            .await?;
        for client in clients {
            upsert(&mut tx, client).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Returns the client registered as `client_id`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails and
    /// [`StoreError::Corrupt`] for a row the server never writes.
    pub async fn client(&self, client_id: &str) -> Result<Option<Client>, StoreError> {
        let row = sqlx::query(
            "SELECT client_id, name, kind, jwks_uri, jwks, redirect_uris, scopes, grant_types \
             FROM client WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| read_client(&row)).transpose()
    }

    /// Records the assertion `jti` of `issuer`, kept until `expires_at`
    /// (seconds since the epoch), and returns whether it was unseen: a
    /// `false` is a replay.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn first_use(
        &self,
        issuer: &str,
        jti: &str,
        expires_at: i64,
    ) -> Result<bool, StoreError> {
        let inserted = sqlx::query(
            "INSERT INTO seen_jti (issuer, jti, expires_at) VALUES ($1, $2, to_timestamp($3)) \
             ON CONFLICT (issuer, jti) DO NOTHING",
        )
        .bind(issuer)
        .bind(jti)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(inserted.rows_affected() == 1)
    }

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
             redeemed_at IS NOT NULL AS redeemed, launch_context FROM authorization_code \
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

    /// Returns whether the access token `jti` was revoked.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn revoked(&self, jti: &str) -> Result<bool, StoreError> {
        let row = sqlx::query(
            "SELECT revoked_at IS NOT NULL AS revoked FROM access_token WHERE jti = $1",
        )
        .bind(jti)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(row) => row.try_get("revoked")?,
            None => false,
        })
    }

    /// Records the access token `token` describes.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn record_token(&self, token: &IssuedToken<'_>) -> Result<(), StoreError> {
        insert_token(&self.pool, token).await
    }

    /// Deletes the assertion ids, the access and refresh tokens and the
    /// launches past their expiry, and the grants an hour old with no token
    /// left.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails.
    pub async fn sweep(&self) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM seen_jti WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM access_token WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM refresh_token WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        // NOTE: no specification governs this: our own design, an hour's margin so
        // a grant recorded just before its first token is never swept between them.
        sqlx::query(
            "DELETE FROM authorization_grant g WHERE g.created_at < now() - interval '1 hour' \
             AND NOT EXISTS (SELECT 1 FROM refresh_token r WHERE r.grant_id = g.id) \
             AND NOT EXISTS (SELECT 1 FROM access_token t WHERE t.grant_id = g.id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("DELETE FROM pending_authorization WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM authorization_code WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM launch WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Returns whether the database answers a statement, for readiness.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when it does not.
    pub async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
}

/// Writes `client` as a configured client.
async fn upsert(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    client: &Client,
) -> Result<(), StoreError> {
    let (jwks_uri, jwks) = match &client.keys {
        Some(ClientKeys::Uri(url)) => (Some(url.as_str().to_owned()), None),
        Some(ClientKeys::Set(set)) => (None, Some(set.clone())),
        None => (None, None),
    };
    let grants: Vec<&str> = client
        .grant_types
        .iter()
        .map(|grant| grant.as_str())
        .collect();
    sqlx::query(
        "INSERT INTO client (client_id, name, kind, jwks_uri, jwks, redirect_uris, scopes, grant_types, source) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'config') \
         ON CONFLICT (client_id) DO UPDATE SET name = $2, kind = $3, jwks_uri = $4, jwks = $5, \
         redirect_uris = $6, scopes = $7, grant_types = $8, source = 'config', updated_at = now()",
    )
    .bind(&client.client_id)
    .bind(&client.name)
    .bind(client.kind.as_str())
    .bind(jwks_uri)
    .bind(jwks)
    .bind(&client.redirect_uris)
    .bind(&client.scopes)
    .bind(&grants)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Reads a `client` row.
fn read_client(row: &sqlx::postgres::PgRow) -> Result<Client, StoreError> {
    let client_id: String = row.try_get("client_id")?;
    let corrupt = || StoreError::Corrupt {
        client_id: client_id.clone(),
    };
    let kind = match row.try_get::<String, _>("kind")?.as_str() {
        "public" => ClientKind::Public,
        "confidential_asymmetric" => ClientKind::ConfidentialAsymmetric,
        _ => return Err(corrupt()),
    };
    let keys = match (
        row.try_get::<Option<String>, _>("jwks_uri")?,
        row.try_get::<Option<Value>, _>("jwks")?,
    ) {
        (Some(uri), None) => Some(ClientKeys::Uri(uri.parse().map_err(|_unparsed| corrupt())?)),
        (None, Some(set)) => Some(ClientKeys::Set(set)),
        (None, None) => None,
        (Some(_), Some(_)) => return Err(corrupt()),
    };
    let grant_types = row
        .try_get::<Vec<String>, _>("grant_types")?
        .iter()
        .map(|grant| match grant.as_str() {
            "authorization_code" => Ok(GrantType::AuthorizationCode),
            "client_credentials" => Ok(GrantType::ClientCredentials),
            "refresh_token" => Ok(GrantType::RefreshToken),
            _ => Err(corrupt()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Client {
        name: row.try_get("name")?,
        kind,
        keys,
        redirect_uris: row.try_get("redirect_uris")?,
        scopes: row.try_get("scopes")?,
        grant_types,
        client_id,
    })
}

/// What the store records of an issued access token.
#[derive(Debug, Clone, Copy)]
pub struct IssuedToken<'a> {
    /// Its `jti`.
    pub jti: &'a str,
    /// The client it was issued to.
    pub client_id: &'a str,
    /// Its `sub`.
    pub subject: &'a str,
    /// Its `aud`.
    pub audience: &'a str,
    /// Its `scope`.
    pub scope: &'a str,
    /// Its `iat`, in seconds since the epoch.
    pub issued_at: i64,
    /// Its `exp`, in seconds since the epoch.
    pub expires_at: i64,
    /// The grant it was issued under; none for a client credentials token.
    pub grant_id: Option<&'a str>,
    /// The SHA-256 of the authorization code it was issued for, if any.
    pub code_hash: Option<&'a str>,
}

/// The columns of a pending authorization, as [`read_pending`] reads them.
const PENDING: &str = "SELECT id, client_id, redirect_uri, scope, state, nonce, code_challenge, \
    audience, upstream_state, upstream_nonce, upstream_verifier, form_token, subject, fhir_user, \
    display_name, offered_scope, auth_time, extract(epoch FROM expires_at)::bigint AS expires, purpose, \
    upstream_session, launch_context FROM pending_authorization";

/// An authorization request between the authorization endpoint and the
/// code.
#[derive(Clone, PartialEq, Eq)]
pub struct Pending {
    /// Its id, the browser's cookie.
    pub id: String,
    /// The client; none on a management visit.
    pub client_id: Option<String>,
    /// The client's redirect URI.
    pub redirect_uri: String,
    /// The scope the client requested.
    pub scope: String,
    /// The client's `state`.
    pub state: String,
    /// The client's OpenID Connect `nonce`.
    pub nonce: Option<String>,
    /// The client's PKCE challenge.
    pub code_challenge: String,
    /// The resource server the token is for.
    pub audience: String,
    /// The upstream login's `state`.
    pub upstream_state: String,
    /// The upstream login's `nonce`.
    pub upstream_nonce: String,
    /// The upstream login's PKCE verifier, a secret.
    pub upstream_verifier: String,
    /// The token the consent form carries, against cross-site posts.
    pub form_token: String,
    /// The person's FerroSMART `sub`, once they logged in.
    pub subject: Option<String>,
    /// Their `fhirUser`, when the provider carries one.
    pub fhir_user: Option<String>,
    /// The name the consent page greets them by.
    pub display_name: Option<String>,
    /// The scopes the consent page offers.
    pub offered_scope: Option<String>,
    /// When they logged in, in seconds since the epoch.
    pub auth_time: Option<i64>,
    /// When the request lapses, in seconds since the epoch.
    pub expires_at: i64,
    /// What the login is for.
    pub purpose: Purpose,
    /// The upstream session the person logged in under.
    pub upstream_session: Option<String>,
    /// The launch context of an EHR launch.
    pub launch_context: Option<Context>,
}

/// What a login is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// An app's authorization request.
    Authorize,
    /// The person's own visit to the management page.
    Manage,
}

impl Purpose {
    /// Returns the purpose as the store writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authorize => "authorize",
            Self::Manage => "manage",
        }
    }
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// Who logged in for a pending request, and what they are offered.
#[derive(Debug, Clone)]
pub struct Login {
    /// The FerroSMART `sub`.
    pub subject: String,
    /// The `fhirUser`, if any.
    pub fhir_user: Option<String>,
    /// The name to greet them by, if any.
    pub display_name: Option<String>,
    /// The scopes the consent page offers.
    pub offered_scope: String,
    /// When they logged in.
    pub auth_time: i64,
    /// The upstream session they logged in under.
    pub upstream_session: Option<String>,
}

/// An authorization code's grant.
#[expect(
    clippy::struct_field_names,
    reason = "`code_challenge` is the parameter's name in RFC 7636 §4.3"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    /// The client.
    pub client_id: String,
    /// The redirect URI of the request.
    pub redirect_uri: String,
    /// The PKCE challenge.
    pub code_challenge: String,
    /// The resource server.
    pub audience: String,
    /// The person's `sub`.
    pub subject: String,
    /// Their `fhirUser`.
    pub fhir_user: Option<String>,
    /// The scope granted.
    pub scope: String,
    /// The client's `nonce`.
    pub nonce: Option<String>,
    /// When the person logged in.
    pub auth_time: i64,
    /// When the code lapses.
    pub expires_at: i64,
    /// The upstream session the person logged in under, which an
    /// `online_access` grant ends with.
    pub upstream_session: Option<String>,
    /// The launch context of an EHR launch.
    pub launch_context: Option<Context>,
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

/// Inserts the access token `token` through `executor`, a pool or a
/// transaction.
pub(crate) async fn insert_token<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    token: &IssuedToken<'_>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO access_token (jti, client_id, subject, audience, scope, issued_at, expires_at, code_hash, grant_id) \
         VALUES ($1, $2, $3, $4, $5, to_timestamp($6), to_timestamp($7), $8, $9)",
    )
    .bind(token.jti)
    .bind(token.client_id)
    .bind(token.subject)
    .bind(token.audience)
    .bind(token.scope)
    .bind(token.issued_at)
    .bind(token.expires_at)
    .bind(token.code_hash)
    .bind(token.grant_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// One transaction of the store: an audited write and its audit record,
/// committed together or not at all.
///
/// [`Transaction::commit`] refuses a transaction that wrote no record, so
/// no audited write commits without one. No specification governs this:
/// our own design (`docs/architecture.md` §13.2).
#[derive(Debug)]
pub struct Transaction {
    /// The open transaction.
    tx: sqlx::Transaction<'static, Postgres>,
    /// Whether an audit record was written in it.
    recorded: bool,
}

impl Store {
    /// Opens a transaction for an audited write.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when no connection can be had.
    pub async fn begin(&self) -> Result<Transaction, StoreError> {
        Ok(Transaction {
            tx: self.pool.begin().await?,
            recorded: false,
        })
    }
}

impl Transaction {
    /// Writes the audit record `row` in this transaction.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn record(&mut self, row: &audit::AuditRow) -> Result<(), StoreError> {
        audit::insert(&mut self.tx, row).await?;
        self.recorded = true;
        Ok(())
    }

    /// Commits the write with its record.
    ///
    /// # Errors
    /// Returns [`StoreError::Unrecorded`] when no record was written, and
    /// [`StoreError::Database`] when the commit fails; nothing is kept then.
    pub async fn commit(self) -> Result<(), StoreError> {
        if !self.recorded {
            return Err(StoreError::Unrecorded);
        }
        self.tx.commit().await?;
        Ok(())
    }

    /// Records the access token `token`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn insert_token(&mut self, token: &IssuedToken<'_>) -> Result<(), StoreError> {
        insert_token(&mut *self.tx, token).await
    }

    /// Records the authorization code `code`, by the SHA-256 `hash` of its
    /// value.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn issue_code(&mut self, hash: &str, code: &Code) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO authorization_code (code_hash, client_id, redirect_uri, code_challenge, \
             audience, subject, fhir_user, scope, nonce, auth_time, expires_at, upstream_session, \
             launch_context) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, to_timestamp($11), $12, $13)",
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
