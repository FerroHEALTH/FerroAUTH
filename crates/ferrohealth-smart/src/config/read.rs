// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The readers every configuration table shares: a secret from its value or
//! its `_file` sibling, and a URL naming the key it came from.

use std::path::Path;

use secrecy::ExposeSecret;
use secrecy::SecretString;
use url::Url;

use crate::config::ConfigError;

/// Returns the secret of `key`: the value or the trimmed content of its
/// `_file` sibling, exactly one of which is set.
pub(crate) fn secret(
    value: Option<&SecretString>,
    file: Option<&Path>,
    key: &'static str,
) -> Result<SecretString, ConfigError> {
    match (value, file) {
        (Some(_), Some(_)) | (None, None) => Err(ConfigError::Secret { key }),
        (Some(value), None) => Ok(SecretString::from(value.expose_secret().to_owned())),
        (None, Some(path)) => {
            let text = std::fs::read_to_string(path).map_err(|source| ConfigError::SecretFile {
                path: path.to_path_buf(),
                source,
            })?;
            Ok(SecretString::from(
                text.trim_end_matches(['\n', '\r']).to_owned(),
            ))
        }
    }
}

/// Returns `text` as a URL, or the refusal naming `key`.
pub(crate) fn parse_url(text: &str, key: &'static str) -> Result<Url, ConfigError> {
    text.parse()
        .map_err(|_malformed| ConfigError::Missing { key })
}
