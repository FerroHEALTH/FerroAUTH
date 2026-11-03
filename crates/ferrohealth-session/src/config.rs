// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `[oidc]` and `[session]` sections every console embeds in its
//! configuration.
//!
//! Both are read with `deny_unknown_fields`, every default lives in the
//! section's `Default`, and every secret is a
//! `ferrohealth_secret::secret::Secret` read inline or from the file its
//! `<key>_file` sibling names. [`OidcSection::check`] and
//! [`SessionSection::check`] refuse a section the console cannot run with,
//! naming the key and never the secret.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use ferrohealth_secret::file::{SecretError, read_secret, require_secret};
use ferrohealth_secret::secret::Secret;
use ferrohealth_smart::client::Tls;
use ferrohealth_smart::metadata::{DiscoveryError, Http, ServerMetadata};
use ferrohealth_smart::oidc::{OFFLINE_ACCESS, OPENID, OidcError, Provider, RelyingParty};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::lifetime::Lifetimes;

/// The fewest bytes a sealing key decodes to: the 512 bits the `cookie`
/// crate's `Key` derives its signing and encryption halves from.
pub const KEY_BYTES: usize = 64;

/// Why a section was refused, or the provider could not be reached.
///
/// No variant carries a secret.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A secret could not be read.
    #[error(transparent)]
    Secret(#[from] SecretError),
    /// A required key is empty.
    #[error("{key} is not set")]
    Missing {
        /// The key.
        key: &'static str,
    },
    /// A key is not a URL.
    #[error("{key} is not a URL")]
    Url {
        /// The key.
        key: &'static str,
        /// What the parser said.
        #[source]
        source: url::ParseError,
    },
    /// A URL is not one its key admits: a provider URL that is not `https`
    /// off loopback, or a redirection endpoint with userinfo or a fragment.
    #[error("{key} {reason}")]
    UrlShape {
        /// The key.
        key: &'static str,
        /// What the key requires.
        reason: &'static str,
    },
    /// `scopes` lacks `openid` (OpenID Connect Core 1.0 §3.1.2.1).
    #[error("oidc.scopes must hold openid")]
    NoOpenId,
    /// `scopes` lists `offline_access`, which `offline_access = true` asks
    /// for (OpenID Connect Core 1.0 §11).
    #[error("oidc.scopes must not list offline_access; set oidc.offline_access = true")]
    OfflineAccessScope,
    /// A lifetime or a bound is zero.
    #[error("{key} must be greater than zero")]
    Zero {
        /// The key.
        key: &'static str,
    },
    /// The absolute lifetime is shorter than the idle one.
    #[error("session.absolute_timeout_s must be at least session.idle_timeout_s")]
    AbsoluteBeforeIdle,
    /// A sealed store has no key.
    #[error("session.store = \"sealed\" needs session.key or session.key_file")]
    NoKey,
    /// A key is set for a store that seals nothing.
    #[error("session.key is set, but session.store = \"memory\" seals nothing")]
    KeyUnused,
    /// The sealing key is not base64.
    #[error("session.key is not base64")]
    KeyBase64 {
        /// What the decoder said.
        #[source]
        source: base64::DecodeError,
    },
    /// The sealing key decodes to too few bytes.
    #[error("session.key decodes to {found} bytes; it needs at least {KEY_BYTES}")]
    KeyShort {
        /// How many bytes it decodes to.
        found: usize,
    },
    /// A sealed store with `offline_access`, which would put a refresh
    /// token in a browser cookie.
    #[error("oidc.offline_access cannot be used with session.store = \"sealed\"")]
    OfflineAccessSealed,
    /// The trust roots of `oidc.ca_file` could not be read.
    #[error("oidc.ca_file names {}, which could not be read", path.display())]
    CaFile {
        /// The file.
        path: PathBuf,
        /// What the file system said.
        #[source]
        source: std::io::Error,
    },
    /// The HTTP engine could not be built.
    #[error("the OpenID Provider's client could not be built")]
    Http(#[source] DiscoveryError),
    /// The provider's metadata could not be read or names no endpoint the
    /// sign-in needs.
    #[error("the OpenID Provider could not be read")]
    Provider(#[source] OidcError),
}

/// `[oidc]`: the console's client at its OpenID Provider.
///
/// With `issuer` alone, the endpoints are discovered (RFC 8414 §3, OpenID
/// Connect Discovery 1.0 §4); each endpoint given here takes the place of
/// the discovered one.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OidcSection {
    /// The provider's issuer identifier, which an ID Token's `iss` must
    /// equal exactly (OpenID Connect Core 1.0 §3.1.3.7).
    pub issuer: String,
    /// The authorization endpoint (RFC 6749 §3.1).
    pub authorization_endpoint: Option<String>,
    /// The token endpoint (RFC 6749 §3.2).
    pub token_endpoint: Option<String>,
    /// The JWK Set of the keys that sign the ID Tokens.
    pub jwks_uri: Option<String>,
    /// The end-session endpoint (OpenID Connect RP-Initiated Logout 1.0 §2).
    pub end_session_endpoint: Option<String>,
    /// The revocation endpoint (RFC 7009 §2).
    pub revocation_endpoint: Option<String>,
    /// The console's client identifier (RFC 6749 §2.2).
    pub client_id: String,
    /// The console's client secret, inline, for a confidential client.
    pub client_secret: Option<Secret>,
    /// A file holding the console's client secret.
    pub client_secret_file: Option<PathBuf>,
    /// The redirection endpoint, the console's `/auth/callback`
    /// (RFC 6749 §3.1.2).
    pub redirect_uri: String,
    /// Where the provider sends the operator after a sign-out.
    pub post_logout_redirect_uri: Option<String>,
    /// The scopes requested, `openid` among them.
    pub scopes: Vec<String>,
    /// Whether the sign-in asks for `offline_access` (OpenID Connect Core
    /// 1.0 §11), so the provider issues a refresh token.
    pub offline_access: bool,
    /// PEM trust roots added to the platform's for a provider behind a
    /// private certificate authority.
    pub ca_file: Option<PathBuf>,
    /// How long one call to the provider may take, in seconds.
    pub timeout_s: u64,
}

impl Default for OidcSection {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: None,
            end_session_endpoint: None,
            revocation_endpoint: None,
            client_id: String::new(),
            client_secret: None,
            client_secret_file: None,
            redirect_uri: String::new(),
            post_logout_redirect_uri: None,
            scopes: vec![String::from(OPENID)],
            offline_access: false,
            ca_file: None,
            timeout_s: 10,
        }
    }
}

/// The checked `[oidc]`.
#[derive(Clone)]
pub struct OidcSettings {
    issuer: String,
    endpoints: ServerMetadata,
    client_id: String,
    client_secret: Option<Secret>,
    redirect_uri: Url,
    post_logout_redirect_uri: Option<Url>,
    scopes: Vec<String>,
    offline_access: bool,
    roots: Option<Vec<u8>>,
    timeout: Duration,
}

impl fmt::Debug for OidcSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcSettings")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri.as_str())
            .field("scopes", &self.scopes)
            .field("offline_access", &self.offline_access)
            .finish_non_exhaustive()
    }
}

impl OidcSection {
    /// Checks the section and reads its secret and its trust roots.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Missing`] for an empty `issuer`, `client_id`
    /// or `redirect_uri`, [`ConfigError::Url`] for a value that is not a
    /// URL, [`ConfigError::UrlShape`] for a provider URL that is not `https`
    /// off loopback or a redirection endpoint that is no `http` or `https`
    /// URL with a host, no userinfo and no fragment,
    /// [`ConfigError::NoOpenId`] and [`ConfigError::OfflineAccessScope`] for
    /// `scopes` without `openid` or with `offline_access`,
    /// [`ConfigError::Zero`] for a zero `timeout_s`, and the errors of
    /// reading `client_secret` and `ca_file`.
    pub fn check(&self) -> Result<OidcSettings, ConfigError> {
        let issuer = required("oidc.issuer", &self.issuer)?;
        provider_url("oidc.issuer", issuer)?;
        let client_id = required("oidc.client_id", &self.client_id)?;
        let redirect_uri = web_url(
            "oidc.redirect_uri",
            required("oidc.redirect_uri", &self.redirect_uri)?,
        )?;
        // NOTE: RFC 6749 §3.1.2: the redirection endpoint URI MUST NOT include a fragment
        // component.
        if redirect_uri.fragment().is_some() {
            return Err(ConfigError::UrlShape {
                key: "oidc.redirect_uri",
                reason: "must not carry a fragment",
            });
        }
        // NOTE: OpenID Connect Core 1.0 §3.1.2.1: an OpenID Connect request MUST carry the
        // `openid` scope value.
        if !self.scopes.iter().any(|scope| scope == OPENID) {
            return Err(ConfigError::NoOpenId);
        }
        // NOTE: OpenID Connect Core 1.0 §11: `offline_access` goes with `prompt=consent`,
        // which the relying party sends only for `offline_access = true`.
        if self.scopes.iter().any(|scope| scope == OFFLINE_ACCESS) {
            return Err(ConfigError::OfflineAccessScope);
        }
        let endpoints = ServerMetadata {
            issuer: issuer.to_owned(),
            authorization_endpoint: endpoint(
                "oidc.authorization_endpoint",
                self.authorization_endpoint.as_deref(),
            )?,
            token_endpoint: endpoint("oidc.token_endpoint", self.token_endpoint.as_deref())?,
            jwks_uri: endpoint("oidc.jwks_uri", self.jwks_uri.as_deref())?,
            end_session_endpoint: endpoint(
                "oidc.end_session_endpoint",
                self.end_session_endpoint.as_deref(),
            )?,
            revocation_endpoint: endpoint(
                "oidc.revocation_endpoint",
                self.revocation_endpoint.as_deref(),
            )?,
            ..ServerMetadata::default()
        };
        let post_logout_redirect_uri = self
            .post_logout_redirect_uri
            .as_deref()
            .map(|value| web_url("oidc.post_logout_redirect_uri", value))
            .transpose()?;
        if self.timeout_s == 0 {
            return Err(ConfigError::Zero {
                key: "oidc.timeout_s",
            });
        }
        let client_secret = read_secret(
            "oidc.client_secret",
            self.client_secret.clone(),
            self.client_secret_file.as_deref(),
        )?;
        let roots = self.ca_file.as_deref().map(read_roots).transpose()?;
        Ok(OidcSettings {
            issuer: issuer.to_owned(),
            endpoints,
            client_id: client_id.to_owned(),
            client_secret,
            redirect_uri,
            post_logout_redirect_uri,
            scopes: self.scopes.clone(),
            offline_access: self.offline_access,
            roots,
            timeout: Duration::from_secs(self.timeout_s),
        })
    }
}

impl OidcSettings {
    /// Whether the sign-in asks for a refresh token.
    #[must_use]
    pub const fn offline_access(&self) -> bool {
        self.offline_access
    }

    /// The console's relying party at the provider, its endpoints discovered
    /// unless the section names the three the sign-in needs.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Http`] when the client cannot be built and
    /// [`ConfigError::Provider`] when discovery fails or the metadata names
    /// no authorization, token or key-set endpoint.
    pub async fn relying_party(&self) -> Result<RelyingParty, ConfigError> {
        let tls = Tls {
            root_certificates: self.roots.clone(),
            ..Tls::default()
        };
        let http = Http::with_tls(self.timeout, &tls).map_err(ConfigError::Http)?;
        let given = &self.endpoints;
        let complete = given.authorization_endpoint.is_some()
            && given.token_endpoint.is_some()
            && given.jwks_uri.is_some();
        let metadata = if complete {
            given.clone()
        } else {
            let found = http
                .discover(&self.issuer)
                .await
                .map_err(|error| ConfigError::Provider(OidcError::Discovery(error)))?;
            ServerMetadata {
                authorization_endpoint: given
                    .authorization_endpoint
                    .clone()
                    .or(found.authorization_endpoint.clone()),
                token_endpoint: given
                    .token_endpoint
                    .clone()
                    .or(found.token_endpoint.clone()),
                jwks_uri: given.jwks_uri.clone().or(found.jwks_uri.clone()),
                end_session_endpoint: given
                    .end_session_endpoint
                    .clone()
                    .or(found.end_session_endpoint.clone()),
                revocation_endpoint: given
                    .revocation_endpoint
                    .clone()
                    .or(found.revocation_endpoint.clone()),
                ..found
            }
        };
        let provider = Provider::from_metadata(&metadata).map_err(ConfigError::Provider)?;
        let mut party = RelyingParty::new(
            http,
            provider,
            self.client_id.clone(),
            self.redirect_uri.clone(),
        )
        .with_scopes(self.scopes.iter().cloned());
        if let Some(secret) = &self.client_secret {
            party = party.with_client_secret(secret.to_secret_string());
        }
        if self.offline_access {
            party = party.with_offline_access();
        }
        if let Some(redirect) = &self.post_logout_redirect_uri {
            party = party.with_post_logout_redirect_uri(redirect.clone());
        }
        Ok(party)
    }
}

/// Where a console keeps its sessions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreKind {
    /// In the console's process, bounded; the cookie carries an opaque id.
    #[default]
    Memory,
    /// In one AES-256-GCM sealed cookie, which every instance holding the
    /// key opens.
    Sealed,
}

/// `[session]`: the store and the lifetimes of the console's sessions.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionSection {
    /// Where the sessions are kept.
    pub store: StoreKind,
    /// Whether the cookies carry `Secure`, and with it the `__Host-` prefix.
    pub secure_cookie: bool,
    /// How long a pending sign-in waits for the provider's redirect back.
    pub sign_in_timeout_s: u64,
    /// How many pending sign-ins a `memory` store holds; past it the oldest
    /// is dropped.
    pub max_sign_ins: usize,
    /// How long a session lives with no request that counts as activity.
    pub idle_timeout_s: u64,
    /// How long a session lives from its sign-in, whatever the activity.
    pub absolute_timeout_s: u64,
    /// How many sessions a `memory` store holds; past it a new one is
    /// refused.
    pub max_sessions: usize,
    /// The sealing key of a `sealed` store, inline: base64 of at least 64
    /// bytes, the same on every instance.
    pub key: Option<Secret>,
    /// A file holding the sealing key.
    pub key_file: Option<PathBuf>,
}

impl Default for SessionSection {
    fn default() -> Self {
        Self {
            store: StoreKind::Memory,
            secure_cookie: true,
            sign_in_timeout_s: 300,
            max_sign_ins: 1000,
            idle_timeout_s: 1800,
            absolute_timeout_s: 43_200,
            max_sessions: 10_000,
            key: None,
            key_file: None,
        }
    }
}

/// The store a checked `[session]` names.
#[derive(Clone)]
pub(crate) enum Storage {
    /// In process, with its two bounds.
    Memory {
        /// Pending sign-ins.
        max_sign_ins: usize,
        /// Sessions.
        max_sessions: usize,
    },
    /// Sealed, with its key.
    Sealed(cookie::Key),
}

/// The checked `[session]`.
#[derive(Clone)]
pub struct SessionSettings {
    pub(crate) storage: Storage,
    pub(crate) secure_cookie: bool,
    pub(crate) sign_in_timeout: Duration,
    pub(crate) lifetimes: Lifetimes,
}

impl fmt::Debug for SessionSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let store = match self.storage {
            Storage::Memory { .. } => StoreKind::Memory,
            Storage::Sealed(_) => StoreKind::Sealed,
        };
        f.debug_struct("SessionSettings")
            .field("store", &store)
            .field("secure_cookie", &self.secure_cookie)
            .field("sign_in_timeout", &self.sign_in_timeout)
            .field("lifetimes", &self.lifetimes)
            .finish_non_exhaustive()
    }
}

impl SessionSettings {
    /// The lifetimes of every session.
    #[must_use]
    pub const fn lifetimes(&self) -> Lifetimes {
        self.lifetimes
    }

    /// Whether the cookies carry `Secure` and the `__Host-` prefix.
    #[must_use]
    pub const fn secure_cookie(&self) -> bool {
        self.secure_cookie
    }
}

impl SessionSection {
    /// Checks the section against the console's checked `[oidc]` and reads
    /// its key.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Zero`] for a zero lifetime or bound,
    /// [`ConfigError::AbsoluteBeforeIdle`] for an absolute lifetime shorter
    /// than the idle one, [`ConfigError::NoKey`], [`ConfigError::KeyBase64`]
    /// or [`ConfigError::KeyShort`] for a sealed store's missing or unusable
    /// key, [`ConfigError::KeyUnused`] for a key beside a memory store, and
    /// [`ConfigError::OfflineAccessSealed`] for a sealed store whose sign-in
    /// asks for a refresh token.
    pub fn check(&self, oidc: &OidcSettings) -> Result<SessionSettings, ConfigError> {
        self.check_with(oidc.offline_access())
    }

    /// [`Self::check`] for a console whose sign-in asks for a refresh token
    /// when `offline_access` holds, the configuration having no `[oidc]` of
    /// its own (a sign-in the console checks itself).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::check`].
    pub fn check_with(&self, offline_access: bool) -> Result<SessionSettings, ConfigError> {
        for (key, value) in [
            ("session.sign_in_timeout_s", self.sign_in_timeout_s),
            ("session.idle_timeout_s", self.idle_timeout_s),
            ("session.absolute_timeout_s", self.absolute_timeout_s),
        ] {
            if value == 0 {
                return Err(ConfigError::Zero { key });
            }
        }
        if self.absolute_timeout_s < self.idle_timeout_s {
            return Err(ConfigError::AbsoluteBeforeIdle);
        }
        let storage = match self.store {
            StoreKind::Memory => {
                if self.key.is_some() || self.key_file.is_some() {
                    return Err(ConfigError::KeyUnused);
                }
                for (key, value) in [
                    ("session.max_sign_ins", self.max_sign_ins),
                    ("session.max_sessions", self.max_sessions),
                ] {
                    if value == 0 {
                        return Err(ConfigError::Zero { key });
                    }
                }
                Storage::Memory {
                    max_sign_ins: self.max_sign_ins,
                    max_sessions: self.max_sessions,
                }
            }
            StoreKind::Sealed => {
                // NOTE: RFC 6749 §10.4: a refresh token is kept confidential, and one sealed into
                // a browser cookie outlives a sign-out that cannot reach that cookie.
                if offline_access {
                    return Err(ConfigError::OfflineAccessSealed);
                }
                let secret: Secret =
                    match require_secret("session.key", self.key.clone(), self.key_file.as_deref())
                    {
                        Ok(secret) => secret,
                        Err(SecretError::Missing { .. }) => return Err(ConfigError::NoKey),
                        Err(error) => return Err(error.into()),
                    };
                Storage::Sealed(sealing_key(&secret)?)
            }
        };
        Ok(SessionSettings {
            storage,
            secure_cookie: self.secure_cookie,
            sign_in_timeout: Duration::from_secs(self.sign_in_timeout_s),
            lifetimes: Lifetimes {
                idle: Duration::from_secs(self.idle_timeout_s),
                absolute: Duration::from_secs(self.absolute_timeout_s),
            },
        })
    }
}

/// The key `secret` decodes to.
fn sealing_key(secret: &Secret) -> Result<cookie::Key, ConfigError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(secret.expose().trim())
        .map_err(|source| ConfigError::KeyBase64 { source })?;
    cookie::Key::try_from(bytes.as_slice())
        .map_err(|_short| ConfigError::KeyShort { found: bytes.len() })
}

/// `value` of `key`, refused when empty.
fn required<'a>(key: &'static str, value: &'a str) -> Result<&'a str, ConfigError> {
    let value = value.trim();
    if value.is_empty() {
        Err(ConfigError::Missing { key })
    } else {
        Ok(value)
    }
}

/// `value` of `key` as a URL.
fn url(key: &'static str, value: &str) -> Result<Url, ConfigError> {
    Url::parse(value).map_err(|source| ConfigError::Url { key, source })
}

/// An optional provider endpoint, checked as [`provider_url`] and kept as
/// written.
fn endpoint(key: &'static str, value: Option<&str>) -> Result<Option<String>, ConfigError> {
    value
        .map(|text| provider_url(key, text).map(|_| text.to_owned()))
        .transpose()
}

/// `value` of `key` as an `http` or `https` URL with a host and no userinfo.
fn web_url(key: &'static str, value: &str) -> Result<Url, ConfigError> {
    let parsed = url(key, value)?;
    let shape = |reason| Err(ConfigError::UrlShape { key, reason });
    if !matches!(parsed.scheme(), "http" | "https") {
        return shape("must be an http or https URL");
    }
    if parsed.host().is_none() {
        return shape("must name a host");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return shape("must not carry userinfo");
    }
    Ok(parsed)
}

/// `value` of `key` as a provider URL: `https`, or `http` on a loopback host.
fn provider_url(key: &'static str, value: &str) -> Result<Url, ConfigError> {
    let parsed = web_url(key, value)?;
    // NOTE: RFC 6749 §3.1: the authorization server MUST require TLS at its authorization
    // endpoint, so plain `http` is admitted only on loopback.
    if parsed.scheme() == "https" || is_loopback(&parsed) {
        Ok(parsed)
    } else {
        Err(ConfigError::UrlShape {
            key,
            reason: "must be an https URL unless its host is loopback",
        })
    }
}

/// Whether `url` names a loopback host: `localhost`, `127.0.0.0/8` or `::1`.
fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(name)) => name == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// The PEM trust roots in `path`.
fn read_roots(path: &Path) -> Result<Vec<u8>, ConfigError> {
    std::fs::read(path).map_err(|source| ConfigError::CaFile {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ferrohealth_secret::secret::Secret;

    use ferrohealth_smart::oidc::{OFFLINE_ACCESS, OPENID};

    use super::{ConfigError, OidcSection, SessionSection, StoreKind};

    fn key(bytes: usize) -> Secret {
        let mut raw = vec![0_u8; bytes];
        aws_lc_rs::rand::fill(&mut raw).expect("the random source works");
        Secret::new(base64::engine::general_purpose::STANDARD.encode(raw))
    }

    fn sealed() -> SessionSection {
        SessionSection {
            store: StoreKind::Sealed,
            key: Some(key(64)),
            ..SessionSection::default()
        }
    }

    #[test]
    fn the_sections_refuse_an_unknown_key() {
        let refused = toml::from_str::<SessionSection>("idle_minutes = 5");
        assert!(refused.is_err(), "deny_unknown_fields");
        let refused = toml::from_str::<OidcSection>("issuer = \"x\"\nclient = \"y\"");
        assert!(refused.is_err(), "deny_unknown_fields");
    }

    #[test]
    fn the_defaults_are_a_memory_store_with_secure_cookies() {
        let section: SessionSection = toml::from_str("").expect("all defaults");
        let settings = section.check_with(false).expect("valid");
        assert!(settings.secure_cookie(), "Secure by default");
        assert_eq!(1800, settings.lifetimes().idle.as_secs(), "idle");
        assert_eq!(43_200, settings.lifetimes().absolute.as_secs(), "absolute");
    }

    #[test]
    fn an_absolute_lifetime_shorter_than_the_idle_one_is_refused() {
        let section = SessionSection {
            absolute_timeout_s: 10,
            idle_timeout_s: 20,
            ..SessionSection::default()
        };
        assert!(matches!(
            section.check_with(false),
            Err(ConfigError::AbsoluteBeforeIdle)
        ));
    }

    #[test]
    fn a_sealed_store_refuses_offline_access_when_it_loads() {
        assert!(matches!(
            sealed().check_with(true),
            Err(ConfigError::OfflineAccessSealed)
        ));
        assert!(sealed().check_with(false).is_ok(), "without offline_access");
    }

    #[test]
    fn a_sealed_store_without_a_usable_key_is_refused() {
        let none = SessionSection {
            key: None,
            ..sealed()
        };
        assert!(matches!(none.check_with(false), Err(ConfigError::NoKey)));
        let short = SessionSection {
            key: Some(key(32)),
            ..sealed()
        };
        assert!(matches!(
            short.check_with(false),
            Err(ConfigError::KeyShort { found: 32 })
        ));
        let garbled = SessionSection {
            key: Some(Secret::new("not base64 !")),
            ..sealed()
        };
        assert!(matches!(
            garbled.check_with(false),
            Err(ConfigError::KeyBase64 { .. })
        ));
    }

    #[test]
    fn a_key_beside_a_memory_store_is_refused() {
        let section = SessionSection {
            key: Some(key(64)),
            ..SessionSection::default()
        };
        assert!(matches!(
            section.check_with(false),
            Err(ConfigError::KeyUnused)
        ));
    }

    #[test]
    fn no_secret_reaches_a_debug_rendering_or_an_error() {
        let section = sealed();
        let shown = format!(
            "{section:?} {:?}",
            section.check_with(false).expect("valid")
        );
        let raw = section.key.as_ref().expect("set").expose().to_owned();
        assert!(!shown.contains(&raw), "{shown}");
        let oidc = OidcSection {
            issuer: String::from("https://idp.example.org"),
            client_id: String::from("console"),
            client_secret: Some(Secret::new("synthetic-client-secret")),
            redirect_uri: String::from("https://console.example.org/auth/callback"),
            ..OidcSection::default()
        };
        let shown = format!("{oidc:?} {:?}", oidc.check().expect("valid"));
        assert!(!shown.contains("synthetic-client-secret"), "{shown}");
    }

    fn oidc() -> OidcSection {
        OidcSection {
            issuer: String::from("https://idp.example.org"),
            client_id: String::from("console"),
            redirect_uri: String::from("https://console.example.org/auth/callback"),
            ..OidcSection::default()
        }
    }

    #[test]
    fn a_provider_url_off_loopback_must_be_https() {
        assert!(oidc().check().is_ok(), "https");
        for (key, section) in [
            (
                "oidc.issuer",
                OidcSection {
                    issuer: String::from("http://idp.example.org"),
                    ..oidc()
                },
            ),
            (
                "oidc.token_endpoint",
                OidcSection {
                    token_endpoint: Some(String::from("http://idp.example.org/token")),
                    ..oidc()
                },
            ),
            (
                "oidc.revocation_endpoint",
                OidcSection {
                    revocation_endpoint: Some(String::from("http://idp.example.org/revoke")),
                    ..oidc()
                },
            ),
        ] {
            let refused = section.check();
            assert!(
                matches!(refused, Err(ConfigError::UrlShape { key: named, .. }) if named == key),
                "{key}: {refused:?}"
            );
        }
        let loopback = OidcSection {
            issuer: String::from("http://127.0.0.1:8081/realm"),
            jwks_uri: Some(String::from("http://localhost:8081/jwks")),
            ..oidc()
        };
        assert!(loopback.check().is_ok(), "plain http on loopback");
    }

    #[test]
    fn a_redirect_with_a_fragment_or_userinfo_is_refused() {
        for redirect in [
            "https://console.example.org/auth/callback#x",
            "https://u:p@console.example.org/auth/callback",
            "ftp://console.example.org/auth/callback",
        ] {
            let refused = OidcSection {
                redirect_uri: String::from(redirect),
                ..oidc()
            }
            .check();
            assert!(
                matches!(
                    refused,
                    Err(ConfigError::UrlShape {
                        key: "oidc.redirect_uri",
                        ..
                    })
                ),
                "{redirect}: {refused:?}"
            );
        }
    }

    #[test]
    fn the_scopes_hold_openid_and_never_offline_access() {
        let refused = OidcSection {
            scopes: vec![String::from("profile")],
            ..oidc()
        }
        .check();
        assert!(matches!(refused, Err(ConfigError::NoOpenId)), "{refused:?}");
        let refused = OidcSection {
            scopes: vec![String::from(OPENID), String::from(OFFLINE_ACCESS)],
            ..oidc()
        }
        .check();
        assert!(
            matches!(refused, Err(ConfigError::OfflineAccessScope)),
            "{refused:?}"
        );
        let asked = OidcSection {
            offline_access: true,
            ..oidc()
        };
        assert!(asked.check().is_ok(), "offline_access = true asks for it");
    }

    #[test]
    fn an_oidc_section_needs_an_issuer_a_client_and_a_redirect() {
        let refused = OidcSection::default().check();
        assert!(
            matches!(refused, Err(ConfigError::Missing { key: "oidc.issuer" })),
            "{refused:?}"
        );
        let refused = OidcSection {
            issuer: String::from("https://idp.example.org"),
            client_id: String::from("console"),
            redirect_uri: String::from("not a url"),
            ..OidcSection::default()
        }
        .check();
        assert!(
            matches!(
                refused,
                Err(ConfigError::Url {
                    key: "oidc.redirect_uri",
                    ..
                })
            ),
            "{refused:?}"
        );
    }
}
