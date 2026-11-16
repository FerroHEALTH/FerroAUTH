// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The server's configuration, read by `ferrohealth-config`.
//!
//! The layers are the defaults, a TOML file, the `FERROSMART__` environment
//! overrides and the `--set` arguments. [`Config`] is the tree as written,
//! every default in its struct's `Default` impl; [`Config::resolve`] turns
//! it into the checked [`settings::Settings`] the server runs on. An
//! override names its key by path, `FERROSMART__FERROSMART__ISSUER` for
//! `[ferrosmart] issuer`, and `RUST_LOG` sets `telemetry.filter`. No
//! specification governs the configuration: our own design
//! (`docs/architecture.md` §13.10).
//!
//! ```toml
//! [server]
//! listen = "0.0.0.0:8080"
//!
//! [ferrosmart]
//! issuer = "https://smart.example.org"
//! access_token_lifetime = "5m"
//! refresh_idle = "30d"
//! online_idle = "8h"
//!
//! [ferrosmart.keys]
//! private_key_file = "/run/secrets/ferrosmart-rs256.pem"
//! next_private_key_file = "/run/secrets/ferrosmart-rs256-next.pem"
//!
//! [ferrosmart.database]
//! url_file = "/run/secrets/ferrosmart-database-url"
//!
//! [[ferrosmart.resource]]
//! base = "https://ehr.example.org/fhir"
//! kind = "fhir"
//!
//! [[ferrosmart.client]]
//! client_id = "bulk-export"
//! name = "Bulk export"
//! kind = "confidential_asymmetric"
//! jwks_uri = "https://export.example.org/jwks.json"
//! scopes = ["system/Patient.rs", "system/Observation.rs"]
//! grant_types = ["client_credentials"]
//!
//! [ferrosmart.audit.feed]
//! url = "https://audit.example.org/fhir"
//! ```

pub mod error;
pub mod settings;

use std::collections::BTreeMap;
use std::path::PathBuf;

use ferrohealth_config::loader::{Loaded, Loader};
use ferrohealth_config::units::Duration as Span;
use ferrohealth_server::cli::ConfigArgs;
use ferrohealth_server::section::ServerSection;
use ferrohealth_telemetry::section::TelemetrySection;
use serde::{Deserialize, Serialize};

use crate::config::error::Error;

/// The prefix of every environment override and of `FERROSMART_CONFIG`.
pub const PREFIX: &str = "FERROSMART";

/// Returns the loader of the configuration: the `FERROSMART` namespace,
/// with `RUST_LOG` as the alias of `telemetry.filter`.
///
/// # Errors
/// Returns [`Error::Load`] when the namespace is refused, which it never is
/// for [`PREFIX`].
pub fn loader() -> Result<Loader, Error> {
    Ok(Loader::new(PREFIX)?.alias("RUST_LOG", "telemetry.filter"))
}

impl Config {
    /// Reads the configuration of the running process: the file `args`
    /// names (or `FERROSMART_CONFIG` does), the environment, and the `--set`
    /// pairs of `args`, last.
    ///
    /// # Errors
    /// Returns [`Error::Load`] with every refusal of the loader.
    pub fn load(args: &ConfigArgs) -> Result<Loaded<Self>, Error> {
        Ok(loader()?.load_with(args.config.as_deref(), &args.sets)?)
    }

    /// Reads `text` as the configuration file and applies `environment`
    /// over it, for a test that states both.
    ///
    /// # Errors
    /// Returns [`Error::Load`] with every refusal of the loader.
    pub fn from_sources(
        text: Option<&str>,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, Error> {
        let loaded = loader()?.load_sources::<Self>(text, None, environment)?;
        Ok(loaded.into_parts().0)
    }
}

/// The configuration tree as written.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// `[server]`: the listener, its TLS and the stack of every family
    /// server.
    pub server: ServerSection,
    /// `[telemetry]`: the console log of `ferrohealth-telemetry`.
    pub telemetry: TelemetrySection,
    /// `[ferrosmart]`: the authorization server itself.
    pub ferrosmart: FerroSmartSection,
}

/// `[ferrosmart]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FerroSmartSection {
    /// The issuer identifier (RFC 8414 §2): an `https` URL with no query and
    /// no fragment, whose path is `[server] base_path`.
    pub issuer: String,
    /// How long an access token lives: five minutes by default, which SMART
    /// Backend Services recommends and keeps every grant within SMART App
    /// Launch's one hour.
    pub access_token_lifetime: Span,
    /// How long an `offline_access` refresh token lasts unused: thirty days
    /// by default. Each refresh rotates it and starts the time again, so an
    /// idle grant lapses (OAuth 2.1 draft §4.3.3, "Refresh tokens SHOULD
    /// expire if the client has been inactive for some time").
    pub refresh_idle: Span,
    /// How long an `online_access` refresh token lasts unused: eight hours
    /// by default, and never past the end of the person's upstream login
    /// (`docs/architecture.md` §13.6 item 7).
    pub online_idle: Span,
    /// `[ferrosmart.keys]`: the key ring that signs every token.
    pub keys: KeysSection,
    /// `[ferrosmart.database]`: the PostgreSQL database of the state.
    pub database: DatabaseSection,
    /// `[[ferrosmart.client]]`: the registered clients.
    pub client: Vec<crate::clients::ClientSection>,
    /// `[[ferrosmart.resource]]`: the FHIR and openEHR servers a token may
    /// be for, each its own audience.
    pub resource: Vec<ResourceSection>,
    /// `[ferrosmart.upstream]`: the OpenID Connect provider people log in
    /// at; without it the server answers Backend Services alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<crate::upstream::UpstreamSection>,
    /// `[[ferrosmart.role]]`: the scopes each upstream role may be granted,
    /// the policy as content (`docs/architecture.md` §13.6 item 5).
    pub role: Vec<RoleSection>,
    /// `[ferrosmart.branding]`: the deployment's name and words on the
    /// pages, content and never code (13.15).
    pub branding: BrandingSection,
    /// `[ferrosmart.audit]`: where every login and token is recorded.
    pub audit: AuditSection,
}

/// `[ferrosmart.branding]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrandingSection {
    /// The name the pages carry, such as the hospital's.
    pub name: String,
    /// The deployment's own words on the consent page, such as what it does
    /// with the access a person gives; empty for none.
    pub consent_text: String,
    /// The `smart_style_url` an app's token response carries: an https URL
    /// of the deployment's SMART style document; empty for none.
    pub smart_style_url: String,
}

impl Default for BrandingSection {
    fn default() -> Self {
        Self {
            name: String::from("FerroSMART"),
            consent_text: String::new(),
            smart_style_url: String::new(),
        }
    }
}

/// `[ferrosmart.audit]`: how FerroSMART names itself in its audit records,
/// and the Audit Record Repository it forwards them to. No specification
/// governs the section's shape: our own design.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditSection {
    /// How FerroSMART names itself as the recording system
    /// (`AuditEvent.source.observer`); empty takes the issuer's host.
    pub source_id: String,
    /// The site FerroSMART runs at (`AuditEvent.source.site`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// `[ferrosmart.audit.feed]`: the repository's FHIR base, an `https`
    /// URL the records are created under as `[base]/AuditEvent`, with its
    /// timeouts, TLS and credentials; without it the records stay in
    /// FerroSMART's own store alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feed: Option<ferrohealth_smart::config::endpoint::EndpointSection>,
}

/// One `[[ferrosmart.role]]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoleSection {
    /// The role, as the upstream role claims carry it.
    pub name: String,
    /// The `user/` and `patient/` scopes a person holding it may be
    /// granted.
    pub scopes: Vec<String>,
}

/// One `[[ferrosmart.resource]]` table: a server whose base URL is the
/// `aud` of the tokens issued for it (SMART App Launch 2.2.0, Obtain
/// authorization code, `aud`; RFC 9068 §3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceSection {
    /// The server's base URL, as its clients name it.
    pub base: String,
    /// The API the server serves.
    pub kind: ResourceKind,
}

/// The API a resource server serves.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// A FHIR server.
    #[default]
    Fhir,
    /// An openEHR server (the SMART on openEHR draft).
    Openehr,
}

impl Default for FerroSmartSection {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            access_token_lifetime: Span::from_mins(5),
            refresh_idle: Span::from_days(30),
            online_idle: Span::from_hours(8),
            keys: KeysSection::default(),
            database: DatabaseSection::default(),
            client: Vec::new(),
            resource: Vec::new(),
            upstream: None,
            role: Vec::new(),
            branding: BrandingSection::default(),
            audit: AuditSection::default(),
        }
    }
}

/// `[ferrosmart.keys]`: the RSA keys that sign under `RS256`, the one
/// algorithm RFC 9068 §2.1 and OpenID Connect Discovery §3 have every
/// authorization server support.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeysSection {
    /// The PEM file of the key that signs.
    pub private_key_file: Option<PathBuf>,
    /// The `kid` the key is published under; its RFC 7638 thumbprint when
    /// empty.
    pub kid: String,
    /// The PEM file of the key that signed before a rotation, published and
    /// never signing.
    pub previous_private_key_file: Option<PathBuf>,
    /// How long the previous key stays published; zero for as long as the
    /// server runs with it configured.
    pub previous_key_overlap: Span,
    /// The PEM file of the key a rotation makes current, published ahead of
    /// it and never signing.
    pub next_private_key_file: Option<PathBuf>,
}

impl Default for KeysSection {
    fn default() -> Self {
        Self {
            private_key_file: None,
            kid: String::new(),
            previous_private_key_file: None,
            previous_key_overlap: Span::from_secs(0),
            next_private_key_file: None,
        }
    }
}

/// `[ferrosmart.database]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseSection {
    /// The PostgreSQL connection URL, a secret; exclusive with `url_file`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<ferrohealth_secret::secret::Secret>,
    /// The file holding the connection URL.
    pub url_file: Option<PathBuf>,
    /// The most connections one replica holds.
    pub max_connections: u32,
}

impl Default for DatabaseSection {
    fn default() -> Self {
        Self {
            url: None,
            url_file: None,
            max_connections: 16,
        }
    }
}
