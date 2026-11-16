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
//!
//! [ferrosmart.keys]
//! private_key_file = "/run/secrets/ferrosmart-rs256.pem"
//! next_private_key_file = "/run/secrets/ferrosmart-rs256-next.pem"
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
    /// `[ferrosmart.keys]`: the key ring that signs every token.
    pub keys: KeysSection,
}

impl Default for FerroSmartSection {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            access_token_lifetime: Span::from_mins(5),
            keys: KeysSection::default(),
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
