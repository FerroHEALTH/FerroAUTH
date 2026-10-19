// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The configuration sections every product embeds: `[auth]` for the
//! surface it guards, and `[<lane>.credentials]` for each upstream it
//! calls.
//!
//! Both are read with `deny_unknown_fields`, every default lives in the
//! section's `Default`, and every secret has a `_file` sibling of which
//! exactly one is set. A product's loader applies its own environment
//! overrides over these types and resolves them at load, so a section that
//! breaks a rule refuses the start (no specification governs the model: our
//! own design).

use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use jsonwebtoken::Algorithm;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::Deserialize;
use url::Url;

use crate::basic::Credential;
use crate::basic::PasswordStore;
use crate::basic::StoreError;
use crate::client::ClientAuth;
use crate::client::ClientCredentials;
use crate::client::Endpoint;
use crate::client::assertion::AssertionError;
use crate::client::assertion::AssertionKey;
use crate::metadata::DiscoveryError;
use crate::resource::ResourceError;
use crate::resource::Settings;
use crate::resource::TokenProfile;
use crate::resource::configuration::SmartOptions;
use crate::resource::configuration::is_capability;
use crate::scope::is_extension_scope;
use crate::scope::is_scope_token;

/// A section that breaks a rule, named by its key.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A key the section needs is not set, or does not parse.
    #[error("{key} is not set or does not parse")]
    Missing {
        /// The key.
        key: &'static str,
    },
    /// Both a secret and its `_file` sibling are set, or neither.
    #[error("exactly one of {key} and {key}_file must be set")]
    Secret {
        /// The key of the secret.
        key: &'static str,
    },
    /// A secret file could not be read.
    #[error("the secret file {} could not be read", path.display())]
    SecretFile {
        /// The file.
        path: PathBuf,
        /// What the file system reported.
        #[source]
        source: std::io::Error,
    },
    /// Two keys that exclude each other are both set.
    #[error("{left} and {right} exclude each other")]
    Exclusive {
        /// The one key.
        left: &'static str,
        /// The other.
        right: &'static str,
    },
    /// An issuer entry breaks a resource-server rule.
    #[error("the issuer {issuer:?} is refused")]
    Issuer {
        /// The issuer.
        issuer: String,
        /// The rule.
        #[source]
        source: Box<ResourceError>,
    },
    /// A Basic user or credential breaks a rule.
    #[error("a Basic user or credential is refused")]
    Basic {
        /// The rule.
        #[source]
        source: StoreError,
    },
    /// A scope token is outside the RFC 6749 §3.3 character set.
    #[error("the scope token {scope:?} is outside the RFC 6749 scope character set")]
    Scope {
        /// The token.
        scope: String,
    },
    /// The product scope is in neither extension form of SMART App Launch
    /// 2.2.0, Scopes and Launch Context, §Extensibility.
    #[error("the product scope {scope:?} is neither a full URI nor a string starting with __")]
    ProductScope {
        /// The scope.
        scope: String,
    },
    /// A capability is in neither the SMART App Launch 2.2.0 list nor the
    /// SMART on openEHR list, and is no full URI.
    #[error("the capability {capability:?} is not a SMART capability and not a full URI")]
    Capability {
        /// The capability.
        capability: String,
    },
    /// The issuer of the client credentials grant breaks the RFC 8414 §2
    /// URL rule.
    #[error("credentials.oauth.issuer is refused")]
    OauthIssuer {
        /// The rule.
        #[source]
        source: DiscoveryError,
    },
    /// A resource indicator carries a fragment, which RFC 8707 §2 forbids.
    #[error("{key} carries a fragment, which a resource indicator must not")]
    Fragment {
        /// The key.
        key: &'static str,
    },
    /// The assertion key could not be loaded.
    #[error("the private key of the client assertion is refused")]
    Key {
        /// Why.
        #[source]
        source: AssertionError,
    },
}

/// The `[auth]` section: the surface's issuer or issuers, the audiences,
/// the token rules and the Basic users.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthSection {
    /// Whether inbound authentication is on; a product may refuse `false`.
    pub enabled: bool,
    /// The issuer identifier, or the `[[auth.issuer]]` entries of a product
    /// that trusts several.
    pub issuer: IssuerKey,
    /// The audiences, of which a token's `aud` must contain one.
    pub audience: Vec<String>,
    /// The signature algorithms admitted.
    pub algorithms: Vec<Algorithm>,
    /// The claims a token must carry.
    pub token_profile: TokenProfile,
    /// The clock skew, at most 300.
    pub clock_skew_seconds: u64,
    /// How long a held key set is used.
    pub jwks_max_age_seconds: u64,
    /// The shortest time between two reads of the key set.
    pub jwks_refresh_interval_seconds: u64,
    /// A key set file handed over out of band, in place of the issuer's
    /// `jwks_uri`; empty for none.
    pub jwks_file: String,
    /// How long one call to the authorization server may take.
    pub timeout_ms: u64,
    /// The realm the challenges name; empty for none, which a product
    /// replaces with its own default.
    pub realm: String,
    /// The exact `sub` values granted system-wide access without a scope.
    pub scopeless_subjects: Vec<String>,
    /// The SMART capabilities the discovery document adds, each a
    /// capability SMART App Launch 2.2.0 or the SMART on openEHR draft
    /// defines, or a full URI.
    pub capabilities: Vec<String>,
    /// The scopes the discovery document lists as `scopes_supported`: only
    /// scopes the product honours, because "the server SHALL support all
    /// scopes listed here".
    pub scopes_supported: Vec<String>,
    /// The product's own scope, a full URI or a string starting with `__`;
    /// empty for none.
    pub product_scope: String,
    /// The Basic users of the surface; absent for no Basic.
    pub basic: Option<BasicSection>,
}

impl Default for AuthSection {
    fn default() -> Self {
        Self {
            enabled: true,
            issuer: IssuerKey::Flat(String::new()),
            audience: Vec::new(),
            algorithms: vec![
                Algorithm::RS256,
                Algorithm::RS384,
                Algorithm::PS256,
                Algorithm::PS384,
                Algorithm::ES256,
                Algorithm::ES384,
            ],
            token_profile: TokenProfile::Rfc9068,
            clock_skew_seconds: 60,
            jwks_max_age_seconds: 600,
            jwks_refresh_interval_seconds: 60,
            jwks_file: String::new(),
            timeout_ms: 10_000,
            realm: String::new(),
            scopeless_subjects: Vec::new(),
            capabilities: Vec::new(),
            scopes_supported: Vec::new(),
            product_scope: String::new(),
            basic: None,
        }
    }
}

/// The `issuer` key: the flat issuer identifier, or the `[[auth.issuer]]`
/// list.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum IssuerKey {
    /// One issuer, the rest of its fields on the section.
    Flat(String),
    /// Several issuers, each with its own fields; a field an entry omits is
    /// the section's.
    List(Vec<IssuerEntry>),
}

/// One `[[auth.issuer]]` entry: the fields of the flat form, each optional,
/// the section's value standing in for one left out.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IssuerEntry {
    /// The issuer identifier.
    pub issuer: String,
    /// The audiences.
    pub audience: Option<Vec<String>>,
    /// The signature algorithms admitted.
    pub algorithms: Option<Vec<Algorithm>>,
    /// The claims a token must carry.
    pub token_profile: Option<TokenProfile>,
    /// The clock skew.
    pub clock_skew_seconds: Option<u64>,
    /// How long a held key set is used.
    pub jwks_max_age_seconds: Option<u64>,
    /// The shortest time between two reads of the key set.
    pub jwks_refresh_interval_seconds: Option<u64>,
    /// A key set file in place of the issuer's `jwks_uri`.
    pub jwks_file: Option<String>,
}

/// The `[auth.basic]` table.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BasicSection {
    /// The users.
    pub users: Vec<BasicUser>,
}

/// One `[[auth.basic.users]]` entry.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BasicUser {
    /// The user-id.
    pub user: String,
    /// The Argon2id PHC string of the password.
    pub password_hash: Option<SecretString>,
    /// The file holding that PHC string.
    pub password_hash_file: Option<PathBuf>,
    /// The scopes the user is granted.
    pub scopes: Vec<String>,
}

/// What the `[auth]` section resolves to.
#[derive(Debug)]
pub struct Resolved {
    /// Whether inbound authentication is on.
    pub enabled: bool,
    /// The resource-server settings of each issuer, in the order written.
    pub issuers: Vec<Settings>,
    /// The Basic users, when the surface admits Basic.
    pub basic: Option<PasswordStore>,
    /// The realm the challenges name, when one is set.
    pub realm: Option<String>,
    /// The SMART capabilities the discovery document adds.
    pub capabilities: Vec<String>,
    /// The scopes the discovery document lists.
    pub scopes_supported: Vec<String>,
    /// The product's own scope, when one is set.
    pub product_scope: Option<String>,
}

impl Resolved {
    /// Returns the discovery document options the section names: its
    /// scopes and its capabilities.
    ///
    /// A product sets what the section cannot know on the result: whether
    /// it evaluates granular scopes, and the openEHR services of
    /// [`SmartOptions::with_openehr`].
    #[must_use]
    pub fn smart_options(&self) -> SmartOptions {
        SmartOptions {
            scopes_supported: self.scopes_supported.clone(),
            capabilities: self.capabilities.clone(),
            ..SmartOptions::default()
        }
    }
}

impl AuthSection {
    /// Returns the issuer entries the section names, the flat form as one
    /// entry.
    #[must_use]
    pub fn issuers(&self) -> Vec<IssuerEntry> {
        match &self.issuer {
            IssuerKey::Flat(issuer) => vec![IssuerEntry {
                issuer: issuer.clone(),
                ..IssuerEntry::default()
            }],
            IssuerKey::List(entries) => entries.clone(),
        }
    }

    /// Resolves the section: every rule checked, every secret read.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] naming the first rule broken: no issuer or
    /// audience, an issuer outside the URL rule, a symmetric algorithm, a
    /// skew over the bound, a Basic user with a bad hash, user-id or scope,
    /// a secret set twice or not at all, a capability SMART does not
    /// define, a listed scope outside RFC 6749 §3.3, or a product scope in
    /// no extension form.
    pub fn resolve(&self) -> Result<Resolved, ConfigError> {
        if let Some(bad) = self
            .capabilities
            .iter()
            .find(|capability| !is_capability(capability))
        {
            return Err(ConfigError::Capability {
                capability: bad.clone(),
            });
        }
        if let Some(bad) = self
            .scopes_supported
            .iter()
            .find(|scope| !is_scope_token(scope))
        {
            return Err(ConfigError::Scope { scope: bad.clone() });
        }
        if !self.product_scope.is_empty() && !is_extension_scope(&self.product_scope) {
            return Err(ConfigError::ProductScope {
                scope: self.product_scope.clone(),
            });
        }
        let mut issuers = Vec::new();
        if self.enabled {
            for entry in self.issuers() {
                if entry.issuer.is_empty() {
                    return Err(ConfigError::Missing { key: "auth.issuer" });
                }
                let settings = self.settings_of(&entry);
                settings.validate().map_err(|source| ConfigError::Issuer {
                    issuer: entry.issuer.clone(),
                    source: Box::new(source),
                })?;
                issuers.push(settings);
            }
        }
        let basic = match &self.basic {
            None => None,
            Some(section) => {
                let mut store = PasswordStore::new();
                for user in &section.users {
                    let hash = secret(
                        user.password_hash.as_ref(),
                        user.password_hash_file.as_deref(),
                        "auth.basic.users.password_hash",
                    )?;
                    store = store
                        .with_user(user.user.clone(), hash, user.scopes.join(" "))
                        .map_err(|source| ConfigError::Basic { source })?;
                }
                Some(store)
            }
        };
        Ok(Resolved {
            enabled: self.enabled,
            issuers,
            basic,
            realm: (!self.realm.is_empty()).then(|| self.realm.clone()),
            capabilities: self.capabilities.clone(),
            scopes_supported: self.scopes_supported.clone(),
            product_scope: (!self.product_scope.is_empty()).then(|| self.product_scope.clone()),
        })
    }

    /// Returns the settings of `entry`, the section standing in for a field
    /// it omits.
    fn settings_of(&self, entry: &IssuerEntry) -> Settings {
        let jwks_file = entry
            .jwks_file
            .clone()
            .unwrap_or_else(|| self.jwks_file.clone());
        Settings {
            issuer: entry.issuer.clone(),
            audience: entry
                .audience
                .clone()
                .unwrap_or_else(|| self.audience.clone()),
            algorithms: entry
                .algorithms
                .clone()
                .unwrap_or_else(|| self.algorithms.clone()),
            profile: entry.token_profile.unwrap_or(self.token_profile),
            clock_skew: Duration::from_secs(
                entry.clock_skew_seconds.unwrap_or(self.clock_skew_seconds),
            ),
            jwks_max_age: Duration::from_secs(
                entry
                    .jwks_max_age_seconds
                    .unwrap_or(self.jwks_max_age_seconds),
            ),
            jwks_refresh_interval: Duration::from_secs(
                entry
                    .jwks_refresh_interval_seconds
                    .unwrap_or(self.jwks_refresh_interval_seconds),
            ),
            jwks_file: (!jwks_file.is_empty()).then(|| PathBuf::from(jwks_file)),
            timeout: Duration::from_millis(self.timeout_ms),
            scopeless_subjects: self
                .scopeless_subjects
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
        }
    }
}

/// The `[<lane>.credentials]` table: HTTP Basic with `user` and `password`,
/// or the client credentials grant under `oauth`; the two exclude each
/// other.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CredentialsSection {
    /// The Basic user-id.
    pub user: String,
    /// The Basic password.
    pub password: Option<SecretString>,
    /// The file holding the Basic password.
    pub password_file: Option<PathBuf>,
    /// The client credentials grant.
    pub oauth: Option<OauthSection>,
}

/// The `[<lane>.credentials.oauth]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OauthSection {
    /// The issuer whose metadata names the token endpoint; exclusive with
    /// `token_endpoint`.
    pub issuer: String,
    /// The token endpoint itself; exclusive with `issuer`.
    pub token_endpoint: String,
    /// The client identifier.
    pub client_id: String,
    /// How the client authenticates.
    pub client_auth: ClientAuth,
    /// The client secret.
    pub client_secret: Option<SecretString>,
    /// The file holding the client secret.
    pub client_secret_file: Option<PathBuf>,
    /// The PEM file holding the private key of the client assertion.
    pub private_key_file: Option<PathBuf>,
    /// The `kid` the assertion names; the RFC 7638 thumbprint when empty.
    pub kid: String,
    /// The algorithm the assertion is signed with; by key type when unset.
    pub assertion_alg: Option<Algorithm>,
    /// The `scope` request parameter; empty for none.
    pub scope: String,
    /// The RFC 8707 resource indicator; empty for none.
    pub resource: String,
    /// The `audience` request parameter; empty for none.
    pub audience: String,
    /// How long before the token expires a new one is fetched.
    pub refresh_margin_ms: u64,
    /// How long one call to the authorization server may take.
    pub timeout_ms: u64,
}

impl Default for OauthSection {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            token_endpoint: String::new(),
            client_id: String::new(),
            client_auth: ClientAuth::ClientSecretBasic,
            client_secret: None,
            client_secret_file: None,
            private_key_file: None,
            kid: String::new(),
            assertion_alg: None,
            scope: String::new(),
            resource: String::new(),
            audience: String::new(),
            refresh_margin_ms: 30_000,
            timeout_ms: 10_000,
        }
    }
}

/// The outbound credential a `[<lane>.credentials]` table resolves to.
#[derive(Debug, Clone)]
pub enum Outbound {
    /// HTTP Basic.
    Basic(Credential),
    /// The client credentials grant.
    Oauth(Box<ClientCredentials>),
}

impl CredentialsSection {
    /// Resolves the table: `None` when it names no credential.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when `user` and `oauth` are both set, a
    /// secret is set twice or not at all, neither or both of `issuer` and
    /// `token_endpoint` are set, the issuer breaks the RFC 8414 §2 URL rule,
    /// the key file cannot be read, a URL does not parse, or `resource`
    /// carries a fragment (RFC 8707 §2).
    pub fn resolve(&self) -> Result<Option<Outbound>, ConfigError> {
        match (&self.user, &self.oauth) {
            (user, Some(_)) if !user.is_empty() => Err(ConfigError::Exclusive {
                left: "credentials.user",
                right: "credentials.oauth",
            }),
            (user, None) if user.is_empty() => {
                if self.password.is_some() || self.password_file.is_some() {
                    return Err(ConfigError::Missing {
                        key: "credentials.user",
                    });
                }
                Ok(None)
            }
            (user, None) => {
                let password = secret(
                    self.password.as_ref(),
                    self.password_file.as_deref(),
                    "credentials.password",
                )?;
                let credential = Credential::new(user.clone(), password)
                    .map_err(|source| ConfigError::Basic { source })?;
                Ok(Some(Outbound::Basic(credential)))
            }
            (_, Some(oauth)) => oauth
                .resolve()
                .map(|grant| Some(Outbound::Oauth(Box::new(grant)))),
        }
    }
}

impl OauthSection {
    /// Resolves the grant.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] as [`CredentialsSection::resolve`] does.
    pub fn resolve(&self) -> Result<ClientCredentials, ConfigError> {
        let endpoint = match (self.issuer.is_empty(), self.token_endpoint.is_empty()) {
            (false, false) => {
                return Err(ConfigError::Exclusive {
                    left: "credentials.oauth.issuer",
                    right: "credentials.oauth.token_endpoint",
                });
            }
            (true, true) => {
                return Err(ConfigError::Missing {
                    key: "credentials.oauth.issuer or credentials.oauth.token_endpoint",
                });
            }
            (false, true) => {
                crate::metadata::issuer_url(&self.issuer)
                    .map_err(|source| ConfigError::OauthIssuer { source })?;
                Endpoint::Issuer(self.issuer.clone())
            }
            (true, false) => Endpoint::Token(parse_url(
                &self.token_endpoint,
                "credentials.oauth.token_endpoint",
            )?),
        };
        if self.client_id.is_empty() {
            return Err(ConfigError::Missing {
                key: "credentials.oauth.client_id",
            });
        }
        let mut grant = match self.client_auth {
            ClientAuth::ClientSecretBasic | ClientAuth::ClientSecretPost => {
                let client_secret = secret(
                    self.client_secret.as_ref(),
                    self.client_secret_file.as_deref(),
                    "credentials.oauth.client_secret",
                )?;
                let mut grant =
                    ClientCredentials::new(endpoint, self.client_id.clone(), client_secret);
                grant.client_auth = self.client_auth;
                grant
            }
            ClientAuth::PrivateKeyJwt => {
                let path = self
                    .private_key_file
                    .as_deref()
                    .ok_or(ConfigError::Missing {
                        key: "credentials.oauth.private_key_file",
                    })?;
                let pem = std::fs::read(path).map_err(|source| ConfigError::SecretFile {
                    path: path.to_path_buf(),
                    source,
                })?;
                let kid = (!self.kid.is_empty()).then(|| self.kid.clone());
                let key = AssertionKey::from_pem(&pem, self.assertion_alg, kid)
                    .map_err(|source| ConfigError::Key { source })?;
                ClientCredentials::with_private_key_jwt(endpoint, self.client_id.clone(), key)
            }
        };
        if !self.scope.is_empty() {
            if let Some(bad) = self.scope.split(' ').find(|token| !is_scope_token(token)) {
                return Err(ConfigError::Scope {
                    scope: bad.to_owned(),
                });
            }
            grant.scope = Some(self.scope.clone());
        }
        if !self.resource.is_empty() {
            let resource = parse_url(&self.resource, "credentials.oauth.resource")?;
            // NOTE: RFC 8707 §2, the resource "MUST NOT include a fragment
            // component"; an absolute URI is what `Url` parses at all.
            if resource.fragment().is_some() {
                return Err(ConfigError::Fragment {
                    key: "credentials.oauth.resource",
                });
            }
            grant.resource = Some(resource);
        }
        if !self.audience.is_empty() {
            grant.audience = Some(self.audience.clone());
        }
        grant.refresh_margin = Duration::from_millis(self.refresh_margin_ms);
        grant.timeout = Duration::from_millis(self.timeout_ms);
        Ok(grant)
    }
}

/// Returns the secret of `key`: the value or the trimmed content of its
/// `_file` sibling, exactly one of which is set.
fn secret(
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
fn parse_url(text: &str, key: &'static str) -> Result<Url, ConfigError> {
    text.parse()
        .map_err(|_malformed| ConfigError::Missing { key })
}
