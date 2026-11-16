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
use axum::routing::{get, post};
use ferrohealth_health::lifecycle::Lifecycle;
use ferrohealth_health::registry::{Check, HealthIndicator, Outcome, Registry};
use ferrohealth_server::health::Health;
use ferrohealth_server::stack::{Stack, StackPolicy};
use ferrohealth_smart::metadata::ServerMetadata;
use http::{HeaderValue, StatusCode, header};
use serde_json::Value;

use crate::audit::Audit;
use crate::authorize::{self, AUTHORIZE_ROUTE, CALLBACK_ROUTE, CONSENT_ROUTE, MANAGE_ROUTE};
use crate::client_keys::ClientKeySets;
use crate::config::settings::Settings;
use crate::discovery::{
    self, JWKS_ROUTE, OPENID_CONFIGURATION_ROUTE, SMART_CONFIGURATION_ROUTE, TOKEN_ROUTE,
};
use crate::store::Store;
use ferrohealth_smart::oidc::RelyingParty;

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
    /// The OpenID Connect discovery document, once people log in.
    openid: Option<Value>,
    /// The process's phase, which the drain moves.
    lifecycle: Lifecycle,
    /// The store.
    store: Store,
    /// The clients' JWK Sets.
    client_keys: ClientKeySets,
    /// The relying party of the upstream login, when people log in.
    relying_party: Option<RelyingParty>,
    /// The audit lane every login and token is recorded in.
    audit: Audit,
}

impl AppState {
    /// Returns the state of the server `settings` describe over `store`,
    /// recording in `audit`.
    #[must_use]
    pub fn new(settings: Settings, store: Store, audit: Audit) -> Self {
        let metadata = discovery::metadata(&settings, false);
        let smart = discovery::smart_configuration(&metadata, false);
        Self {
            settings,
            metadata,
            smart,
            openid: None,
            lifecycle: Lifecycle::default(),
            store,
            client_keys: ClientKeySets::new(reqwest::Client::new()),
            relying_party: None,
            audit,
        }
    }

    /// Returns this state logging people in through `party`, and serving
    /// the authorization code flow.
    #[must_use]
    pub fn with_login(mut self, party: RelyingParty) -> Self {
        let metadata = discovery::metadata(&self.settings, true);
        self.smart = discovery::smart_configuration(&metadata, true);
        self.openid = Some(discovery::openid_configuration(&metadata));
        self.metadata = metadata;
        self.relying_party = Some(party);
        self
    }

    /// Returns the relying party of the upstream login, when people log in.
    #[must_use]
    pub const fn relying_party(&self) -> Option<&RelyingParty> {
        self.relying_party.as_ref()
    }

    /// Returns the clients' JWK Sets.
    #[must_use]
    pub const fn client_keys(&self) -> &ClientKeySets {
        &self.client_keys
    }

    /// Returns the audit lane.
    #[must_use]
    pub const fn audit(&self) -> &Audit {
        &self.audit
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
        .route(TOKEN_ROUTE, post(crate::token::token))
        .route(OPENID_CONFIGURATION_ROUTE, get(openid_configuration))
        .route(
            AUTHORIZE_ROUTE,
            get(authorize::authorize_get).post(authorize::authorize_post),
        )
        .route(CALLBACK_ROUTE, get(authorize::callback))
        .route(
            CONSENT_ROUTE,
            get(authorize::consent_get).post(authorize::consent_post),
        )
        .route(
            MANAGE_ROUTE,
            get(authorize::manage_get).post(authorize::manage_post),
        )
        .with_state(Arc::clone(&state));
    // NOTE: FerroUI docs/consoles.md, "How a console builds": the asset router at
    // its prefix, from the root, the path the shell's tags name.
    let beside = Router::new()
        .route(&state.settings.metadata_path(), get(metadata))
        .with_state(state)
        .nest_service(
            ferrohealth_ui::serve::PREFIX,
            ferrohealth_ui::serve::axum_router::router::<()>(),
        );
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

/// `GET {issuer}/.well-known/openid-configuration` (OpenID Connect
/// Discovery 1.0 §4), served once people log in, since the document
/// describes an OpenID Provider.
async fn openid_configuration(State(state): State<Arc<AppState>>) -> Response {
    match &state.openid {
        Some(document) => public(Json(document).into_response()),
        None => StatusCode::NOT_FOUND.into_response(),
    }
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
