// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Why a configuration was refused: each refusal names the key, never a
//! value, so no secret reaches a message, a `Debug` rendering or a log.

use std::path::PathBuf;

/// A refused configuration.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The file, the environment or a `--set` pair does not read as the
    /// tree: a file that cannot be read, bad TOML, an unknown key, or a value
    /// of the wrong type.
    #[error(transparent)]
    Load(#[from] ferrohealth_config::error::ConfigError),
    /// A key the server needs is not set.
    #[error("`{key}` is not set")]
    Missing {
        /// The key.
        key: &'static str,
    },
    /// The issuer is no URL the rule of RFC 8414 §2 admits.
    #[error("`ferrosmart.issuer` is not an issuer identifier")]
    Issuer {
        /// Why.
        #[source]
        source: ferrohealth_smart::metadata::DiscoveryError,
    },
    /// The issuer's path is not the base path the server serves under.
    #[error("the path of `ferrosmart.issuer` is not `server.base_path`")]
    IssuerPath,
    /// A lifetime that must be positive is zero.
    #[error("`{key}` must be greater than zero")]
    Zero {
        /// The key.
        key: &'static str,
    },
    /// A key file cannot be read.
    #[error("`{key}` cannot be read at {}", path.display())]
    KeyFile {
        /// The key.
        key: &'static str,
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// A key file holds no RSA private key that signs under `RS256`.
    #[error("`{key}` holds no RSA private key for RS256")]
    Key {
        /// The key.
        key: &'static str,
        /// Why.
        #[source]
        source: ferrohealth_smart::client::assertion::AssertionError,
    },
    /// The keys of the ring repeat one another.
    #[error("`ferrosmart.keys` names one key twice")]
    KeyRing {
        /// Why.
        #[source]
        source: ferrohealth_smart::client::keys::KeyRingError,
    },
}
