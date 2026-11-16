// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The routes and the stack around them.
//!
//! The issuer's routes sit under `[server] base_path`, which is the
//! issuer's path; the RFC 8414 metadata sits beside it at the root, the
//! well-known suffix inserted between the host and the issuer's path
//! (RFC 8414 §3). The discovery documents and the JWK Set answer any
//! origin (SMART App Launch 2.2.0, Considerations for CORS support: "For
//! requests from any origin, CORS configuration permits access to the
//! public discovery endpoints").

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use ferrohealth_health::lifecycle::Lifecycle;
use ferrohealth_health::registry::{Check, HealthIndicator, Outcome, Registry};
use ferrohealth_server::health::Health;
use ferrohealth_server::stack::{Stack, StackPolicy};
use ferrohealth_smart::metadata::ServerMetadata;
use http::{HeaderValue, header};
use serde_json::Value;

use crate::config::settings::Settings;
use crate::discovery::{self, JWKS_ROUTE, SMART_CONFIGURATION_ROUTE};
use crate::store::Store;

/// The `Cache-Control` of the JWK Set: an hour, and a next key is published
/// at least that long before it signs (`docs/architecture.md` §13.11). No
/// specification governs the value: our own design.
pub const JWKS_CACHE_CONTROL: &str = "public, max-age=3600";

/// What every request reads.
#[derive(Debug)]
pub struct AppState {
    /// The settings the server runs on.
    settings: Settings,
    /// The RFC 8414 metadata, built once.
    metadata: ServerMetadata,
    /// The SMART configuration, built once.
    smart: Value,
    /// The process's phase, which the drain moves.
    lifecycle: Lifecycle,
    /// The store.
    store: Store,
}

impl AppState {
    /// Returns the state of the server `settings` describe over `store`.
    #[must_use]
    pub fn new(settings: Settings, store: Store) -> Self {
        let metadata = discovery::metadata(&settings);
        let smart = discovery::smart_configuration(&metadata);
        Self {
            settings,
            metadata,
            smart,
            lifecycle: Lifecycle::default(),
            store,
        }
    }

    /// Returns the store.
    #[must_use]
    pub const fn store(&self) -> &Store {
        &self.store
    }

    /// Returns the settings.
    #[must_use]
    pub const fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Returns the process's phase.
    #[must_use]
    pub const fn lifecycle(&self) -> &Lifecycle {
        &self.lifecycle
    }
}

/// Returns the whole application: the routes inside the family's stack.
pub fn router(state: Arc<AppState>) -> Router {
    let registry = Registry::new(vec![Arc::new(Database(state.store.clone()))]);
    let health = Health::new(registry, state.lifecycle.clone());
    let section = state.settings.server.clone();
    let issuer = Router::new()
        .route(SMART_CONFIGURATION_ROUTE, get(smart_configuration))
        .route(JWKS_ROUTE, get(jwks))
        .with_state(Arc::clone(&state));
    let beside = Router::new()
        .route(&state.settings.metadata_path(), get(metadata))
        .with_state(state);
    Stack::new(issuer, health, &section, StackPolicy::default())
        .beside(beside)
        .into_router()
}

/// `GET /.well-known/oauth-authorization-server{path}` (RFC 8414 §3).
async fn metadata(State(state): State<Arc<AppState>>) -> Response {
    public(Json(&state.metadata).into_response())
}

/// `GET {issuer}/.well-known/smart-configuration`, answered as
/// `application/json` whatever the `Accept` header (SMART App Launch 2.2.0,
/// Conformance, Using well-known).
async fn smart_configuration(State(state): State<Arc<AppState>>) -> Response {
    public(Json(&state.smart).into_response())
}

/// `GET {issuer}/jwks`, the JWK Set (RFC 7517 §5), cacheable as
/// [`JWKS_CACHE_CONTROL`] says.
async fn jwks(State(state): State<Arc<AppState>>) -> Response {
    let mut response = public(Json(state.settings.keys.published()).into_response());
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(JWKS_CACHE_CONTROL),
    );
    response
}

/// Returns `response` readable from any origin.
fn public(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

/// The readiness indicator of the database: down while it answers no
/// statement, naming no URL and no error text.
#[derive(Debug)]
struct Database(Store);

impl HealthIndicator for Database {
    fn name(&self) -> &'static str {
        "database"
    }

    fn check(&self) -> Check<'_> {
        Box::pin(async {
            match self.0.ping().await {
                Ok(()) => Outcome::up(),
                Err(_unreachable) => Outcome::down("the database answers no statement"),
            }
        })
    }
}
