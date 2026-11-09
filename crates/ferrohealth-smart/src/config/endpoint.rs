// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The table of one outbound integration: where it is, how long a call may
//! take, how a failed call is retried, its TLS and its credential.
//!
//! Every FerroHEALTH product writes each outbound integration with these
//! keys, so an operator learns them once. Serde refuses
//! `deny_unknown_fields` beside `flatten`, so a product cannot splice
//! shared keys into a table of its own: it embeds this one type. No
//! specification governs the keys: our own design.

use ferrohealth_config::tls::TlsClientSection;
use ferrohealth_config::units::Duration;
use ferrohealth_secret::secret_url::SecretUrl;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::ConfigError;
use crate::config::credentials::CredentialsSection;

/// One outbound integration.
///
/// `Debug` and `Serialize` render `url` with its userinfo and its query
/// masked, as [`SecretUrl`] renders itself, so a product that logs or dumps
/// the section writes no credential the URL carries.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub struct EndpointSection {
    /// The service's URL (RFC 3986); required. It renders with its
    /// userinfo and its query masked, in `Debug` and when serialized.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub url: SecretUrl,
    /// How long one whole call may take; never zero.
    pub timeout: Duration,
    /// How long opening the connection may take; unset, only `timeout`
    /// bounds it.
    pub connect_timeout: Option<Duration>,
    /// How a failed call is tried again.
    pub retry: RetrySection,
    /// The TLS of the connection, built by the product's reader of TLS
    /// material.
    pub tls: TlsClientSection,
    /// The credential the calls carry: HTTP Basic or the client credentials
    /// grant.
    pub credentials: CredentialsSection,
}

impl Default for EndpointSection {
    fn default() -> Self {
        Self {
            url: SecretUrl::default(),
            timeout: Duration::from_secs(10),
            connect_timeout: None,
            retry: RetrySection::default(),
            tls: TlsClientSection::default(),
            credentials: CredentialsSection::default(),
        }
    }
}

/// The `retry` table of an [`EndpointSection`]: the tries of one call, with
/// a backoff that doubles from `initial_backoff` up to `max_backoff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub struct RetrySection {
    /// How many times one call is tried in all; 1 tries once.
    pub max_attempts: u32,
    /// The wait before the second try.
    pub initial_backoff: Duration,
    /// The longest wait between two tries.
    pub max_backoff: Duration,
}

impl Default for RetrySection {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(5),
        }
    }
}

impl RetrySection {
    /// Returns the waits between the tries of one call: `max_attempts - 1`
    /// of them, the first `initial_backoff` and each later one twice the one
    /// before, never longer than `max_backoff`.
    pub fn delays(&self) -> impl Iterator<Item = std::time::Duration> + use<> {
        let max = self.max_backoff.get();
        let first = self.initial_backoff.get().min(max);
        let retries = usize::try_from(self.max_attempts.saturating_sub(1)).unwrap_or(usize::MAX);
        std::iter::successors(Some(first), move |delay: &std::time::Duration| {
            Some(delay.saturating_mul(2).min(max))
        })
        .take(retries)
    }
}

impl EndpointSection {
    /// Checks the table and returns its URL: a URL is set and parses, the
    /// timeouts are not zero, a call is tried at least once, and the
    /// backoff does not start past its own bound. Its credential is
    /// resolved separately, through [`CredentialsSection::resolve`] or
    /// [`CredentialsSection::resolve_with_tls`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Missing`] for no URL or one that does not
    /// parse, and [`ConfigError::Endpoint`] naming the rule another key
    /// breaks.
    pub fn validate(&self) -> Result<Url, ConfigError> {
        if self.url.is_empty() {
            return Err(ConfigError::Missing { key: "url" });
        }
        let url = crate::config::read::parse_url(self.url.expose(), "url")?;
        if self.timeout.is_zero() {
            return Err(ConfigError::Endpoint {
                rule: "timeout is zero",
            });
        }
        if self.connect_timeout.is_some_and(Duration::is_zero) {
            return Err(ConfigError::Endpoint {
                rule: "connect_timeout is zero",
            });
        }
        if self.retry.max_attempts == 0 {
            return Err(ConfigError::Endpoint {
                rule: "retry.max_attempts is 0; 1 tries once",
            });
        }
        if self.retry.initial_backoff > self.retry.max_backoff {
            return Err(ConfigError::Endpoint {
                rule: "retry.initial_backoff is longer than retry.max_backoff",
            });
        }
        Ok(url)
    }
}
