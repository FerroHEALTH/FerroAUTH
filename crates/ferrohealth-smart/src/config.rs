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
use serde::Serialize;
use serde::Serializer;
use url::Url;

use crate::basic::Credential;
use crate::basic::PasswordStore;
use crate::basic::StoreError;
use crate::client::AssertionAudience;
use crate::client::ClientAuth;
use crate::client::ClientCredentials;
use crate::client::Endpoint;
use crate::client::Tls;
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
    /// `mode = "introspection"` in a build without the `fetch` feature,
    /// which links no HTTP client to call the endpoint with.
    #[error("auth.mode = \"introspection\" needs the fetch feature")]
    IntrospectionUnavailable,
    /// The introspection settings break a rule.
    #[cfg(feature = "fetch")]
    #[error("the auth.introspection settings are refused")]
    Introspection {
        /// The rule.
        #[source]
        source: Box<crate::resource::introspection::IntrospectionError>,
    },
    /// The trust roots or the client certificate of the token endpoint
    /// connection are refused.
    #[error("the TLS material of credentials.oauth is refused")]
    Tls {
        /// Why.
        #[source]
        source: Box<DiscoveryError>,
    },
}

/// The `[auth]` section: the surface's issuer or issuers, the audiences,
/// the token rules and the Basic users.
#[derive(Debug, Clone, Deserialize, Serialize)]
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
    /// The claims a token's roles are read from, each a dotted path; by
    /// default `roles`, `groups` and `entitlements` (RFC 9068 §2.2.3.1).
    pub role_claims: Vec<String>,
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
    /// How a bearer token is checked: as a JWT against the issuer's key
    /// set, or by the issuer's introspection endpoint.
    pub mode: AuthMode,
    /// The introspection check, under `mode = "introspection"`.
    pub introspection: Option<IntrospectionSection>,
}

/// How a bearer token is checked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// The token is a JWT, checked against the issuer's key set (RFC 9068).
    #[default]
    Jwt,
    /// The token is posted to the issuer's introspection endpoint
    /// (RFC 7662), for a token the resource server cannot read itself.
    Introspection,
}

/// The `[auth.introspection]` table.
///
/// The product authenticates its call with exactly one of `client` (the
/// client authentication of the token endpoint, RFC 7662 §2.1) and `bearer`
/// (a token from the client credentials grant, SMART App Launch 2.2.0,
/// Token Introspection). Each takes the fields of
/// `[<lane>.credentials.oauth]`, and a refusal names those keys; `client`
/// stands in the section's issuer when it names neither `issuer` nor
/// `token_endpoint`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IntrospectionSection {
    /// The introspection endpoint; empty for the one the issuer's metadata
    /// names.
    pub endpoint: String,
    /// The longest an active response is used; 0 caches nothing.
    pub cache_max_age_seconds: u64,
    /// The most responses held at once.
    pub cache_capacity: usize,
    /// The client authentication of the introspection call.
    pub client: Option<OauthSection>,
    /// The client credentials grant whose token authorizes the call.
    pub bearer: Option<OauthSection>,
}

impl Default for IntrospectionSection {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            cache_max_age_seconds: 60,
            cache_capacity: 10_000,
            client: None,
            bearer: None,
        }
    }
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
            role_claims: crate::roles::default_claims(),
            capabilities: Vec::new(),
            scopes_supported: Vec::new(),
            product_scope: String::new(),
            basic: None,
            mode: AuthMode::Jwt,
            introspection: None,
        }
    }
}

/// The `issuer` key: the flat issuer identifier, or the `[[auth.issuer]]`
/// list.
#[derive(Debug, Clone, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
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
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BasicSection {
    /// The users.
    pub users: Vec<BasicUser>,
    /// How long a credential that verified is kept, so a repeat request
    /// skips the key derivation; 0 keeps none.
    pub cache_ttl_seconds: u64,
}

/// One `[[auth.basic.users]]` entry.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BasicUser {
    /// The user-id.
    pub user: String,
    /// The Argon2id PHC string of the password, rendered redacted.
    #[serde(serialize_with = "redact", skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<SecretString>,
    /// The file holding that PHC string.
    pub password_hash_file: Option<PathBuf>,
    /// The scopes the user is granted.
    pub scopes: Vec<String>,
    /// The roles the user is granted ([`crate::roles`]).
    pub roles: Vec<String>,
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
    /// The introspection check, under `mode = "introspection"`, in place of
    /// the issuers.
    #[cfg(feature = "fetch")]
    pub introspection: Option<crate::resource::introspection::IntrospectionSettings>,
}

impl Resolved {
    /// Returns the discovery document options the section names: its
    /// scopes and its capabilities.
    ///
    /// A product sets what the section cannot know on the result: the
    /// permission capabilities its route table enforces
    /// ([`SmartOptions::permissions`]), whether it advertises `OpenID` Connect
    /// sign-in ([`SmartOptions::openid_connect`]), and the openEHR services
    /// of [`SmartOptions::with_openehr`].
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
    /// An enabled section with Basic users and an empty flat `issuer`
    /// resolves to no issuer and the Basic store, a Basic-only surface; an
    /// enabled section that admits neither a token nor a Basic user is
    /// refused.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] naming the first rule broken: no issuer and
    /// no Basic user, no audience, an issuer outside the URL rule, a
    /// symmetric algorithm, a skew over the bound, a Basic user with a bad
    /// hash, user-id or scope, a secret set twice or not at all, a
    /// capability SMART does not define, a listed scope outside RFC 6749
    /// §3.3, a product scope in no extension form, or a cache key the
    /// random source cannot draw.
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
        self.check_role_claims()?;
        let basic_users = self
            .basic
            .as_ref()
            .is_some_and(|section| !section.users.is_empty());
        let basic_only =
            basic_users && matches!(&self.issuer, IssuerKey::Flat(issuer) if issuer.is_empty());
        if self.introspection.is_some() && self.mode == AuthMode::Jwt {
            return Err(ConfigError::Exclusive {
                left: "auth.introspection",
                right: "auth.mode = \"jwt\"",
            });
        }
        let mut issuers = Vec::new();
        #[cfg(feature = "fetch")]
        let mut introspection = None;
        if self.enabled && !basic_only && self.mode == AuthMode::Introspection {
            #[cfg(feature = "fetch")]
            {
                introspection = Some(self.introspection_settings()?);
            }
            #[cfg(not(feature = "fetch"))]
            return Err(ConfigError::IntrospectionUnavailable);
        } else if self.enabled && !basic_only {
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
        // NOTE: no specification governs the configuration model: our own
        // design, and a surface that admits no credential at all fails closed.
        #[cfg(feature = "fetch")]
        let introspects = introspection.is_some();
        #[cfg(not(feature = "fetch"))]
        let introspects = false;
        if self.enabled && issuers.is_empty() && !introspects && !basic_users {
            return Err(ConfigError::Missing { key: "auth.issuer" });
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
                        .and_then(|store| store.with_roles(&user.user, user.roles.clone()))
                        .map_err(|source| ConfigError::Basic { source })?;
                }
                store = store
                    .with_cache(Duration::from_secs(section.cache_ttl_seconds))
                    .map_err(|source| ConfigError::Basic { source })?;
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
            #[cfg(feature = "fetch")]
            introspection,
        })
    }

    /// Refuses a role claim path that is empty, has an empty step, or
    /// carries whitespace.
    fn check_role_claims(&self) -> Result<(), ConfigError> {
        let malformed = |path: &String| {
            path.split('.').any(str::is_empty) || path.contains(char::is_whitespace)
        };
        if self.role_claims.iter().any(malformed) {
            return Err(ConfigError::Missing {
                key: "auth.role_claims",
            });
        }
        Ok(())
    }

    /// Returns the introspection settings of `mode = "introspection"`: the
    /// flat issuer, the section's audiences, skew, timeout and scopeless
    /// subjects, and the `[auth.introspection]` table.
    #[cfg(feature = "fetch")]
    fn introspection_settings(
        &self,
    ) -> Result<crate::resource::introspection::IntrospectionSettings, ConfigError> {
        use crate::resource::introspection::IntrospectionAuth;
        use crate::resource::introspection::IntrospectionSettings;
        let IssuerKey::Flat(issuer) = &self.issuer else {
            return Err(ConfigError::Exclusive {
                left: "auth.mode = \"introspection\"",
                right: "[[auth.issuer]]",
            });
        };
        if issuer.is_empty() {
            return Err(ConfigError::Missing { key: "auth.issuer" });
        }
        if !self.jwks_file.is_empty() {
            return Err(ConfigError::Exclusive {
                left: "auth.mode = \"introspection\"",
                right: "auth.jwks_file",
            });
        }
        let section = self.introspection.as_ref().ok_or(ConfigError::Missing {
            key: "auth.introspection",
        })?;
        let auth = match (&section.client, &section.bearer) {
            (Some(_), Some(_)) => {
                return Err(ConfigError::Exclusive {
                    left: "auth.introspection.client",
                    right: "auth.introspection.bearer",
                });
            }
            (None, None) => {
                return Err(ConfigError::Missing {
                    key: "auth.introspection.client or auth.introspection.bearer",
                });
            }
            (Some(client), None) => {
                let mut client = client.clone();
                if client.issuer.is_empty() && client.token_endpoint.is_empty() {
                    client.issuer.clone_from(issuer);
                }
                IntrospectionAuth::Client(Box::new(client.resolve()?))
            }
            (None, Some(bearer)) => {
                let source = crate::client::cache::TokenSource::new(bearer.resolve()?).map_err(
                    |source| ConfigError::Introspection {
                        source: Box::new(
                            crate::resource::introspection::IntrospectionError::Credential {
                                source: std::sync::Arc::new(source),
                            },
                        ),
                    },
                )?;
                IntrospectionAuth::Bearer(source)
            }
        };
        let mut settings = IntrospectionSettings::new(issuer.clone(), String::new(), auth);
        settings.audience.clone_from(&self.audience);
        if !section.endpoint.is_empty() {
            settings.endpoint = Some(parse_url(&section.endpoint, "auth.introspection.endpoint")?);
        }
        settings.clock_skew = Duration::from_secs(self.clock_skew_seconds);
        settings.cache_max_age = Duration::from_secs(section.cache_max_age_seconds);
        settings.cache_capacity = section.cache_capacity;
        settings.timeout = Duration::from_millis(self.timeout_ms);
        settings.scopeless_subjects = self.scopeless_subjects.iter().cloned().collect();
        settings.role_claims.clone_from(&self.role_claims);
        settings
            .validate()
            .map_err(|source| ConfigError::Introspection {
                source: Box::new(source),
            })?;
        Ok(settings)
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
            role_claims: self.role_claims.clone(),
        }
    }
}

/// The `[<lane>.credentials]` table: HTTP Basic with `user` and `password`,
/// or the client credentials grant under `oauth`; the two exclude each
/// other.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CredentialsSection {
    /// The Basic user-id.
    pub user: String,
    /// The Basic password, rendered redacted.
    #[serde(serialize_with = "redact", skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretString>,
    /// The file holding the Basic password.
    pub password_file: Option<PathBuf>,
    /// The client credentials grant.
    pub oauth: Option<OauthSection>,
}

/// The `[<lane>.credentials.oauth]` table.
///
/// Its rendering, serialized or `Debug`, shows `issuer` and
/// `token_endpoint` with any userinfo masked and the secrets redacted, so a
/// product can render its running configuration.
#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OauthSection {
    /// The issuer whose metadata names the token endpoint; exclusive with
    /// `token_endpoint`.
    #[serde(serialize_with = "masked_url")]
    pub issuer: String,
    /// The token endpoint itself; exclusive with `issuer`.
    #[serde(serialize_with = "masked_url")]
    pub token_endpoint: String,
    /// The client identifier.
    pub client_id: String,
    /// How the client authenticates.
    pub client_auth: ClientAuth,
    /// The client secret, rendered redacted.
    #[serde(serialize_with = "redact", skip_serializing_if = "Option::is_none")]
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
    /// The `aud` of a `private_key_jwt` assertion: `token_endpoint` (the
    /// default) or `issuer`, which needs `issuer` set.
    pub assertion_audience: AssertionAudience,
    /// A PEM file of trust roots added to the built-in ones, for a token
    /// endpoint behind a private certificate authority.
    pub ca_file: Option<PathBuf>,
    /// The PEM file of the client certificate chain presented over mutual
    /// TLS (RFC 8705 §2); set with `client_key_file`.
    pub client_certificate_file: Option<PathBuf>,
    /// The PEM file of the client certificate's private key; set with
    /// `client_certificate_file`.
    pub client_key_file: Option<PathBuf>,
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
            assertion_audience: AssertionAudience::TokenEndpoint,
            ca_file: None,
            client_certificate_file: None,
            client_key_file: None,
        }
    }
}

impl std::fmt::Debug for OauthSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OauthSection")
            .field("issuer", &mask_userinfo(&self.issuer))
            .field("token_endpoint", &mask_userinfo(&self.token_endpoint))
            .field("client_id", &self.client_id)
            .field("client_auth", &self.client_auth)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_set| REDACTED),
            )
            .field("client_secret_file", &self.client_secret_file)
            .field("private_key_file", &self.private_key_file)
            .field("kid", &self.kid)
            .field("scope", &self.scope)
            .field("resource", &self.resource)
            .field("audience", &self.audience)
            .finish_non_exhaustive()
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
    /// carries a fragment (RFC 8707 §2), and as [`OauthSection::resolve`]
    /// does for the `oauth` table.
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
    /// Returns [`ConfigError`] as [`CredentialsSection::resolve`] does, and
    /// for a client certificate file without its key file or the reverse,
    /// a mutual-TLS `client_auth` without a client certificate, TLS
    /// material that is no PEM (with the `fetch` feature), and
    /// `assertion_audience = "issuer"` without `issuer`.
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
        let tls = self.tls()?;
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
            ClientAuth::TlsClientAuth | ClientAuth::SelfSignedTlsClientAuth => {
                let identity = tls.identity.clone().ok_or(ConfigError::Missing {
                    key: "credentials.oauth.client_certificate_file",
                })?;
                ClientCredentials::with_mutual_tls(
                    endpoint,
                    self.client_id.clone(),
                    identity,
                    self.client_auth == ClientAuth::SelfSignedTlsClientAuth,
                )
            }
        };
        if self.assertion_audience == AssertionAudience::Issuer && self.issuer.is_empty() {
            return Err(ConfigError::Missing {
                key: "credentials.oauth.issuer, which assertion_audience = \"issuer\" names",
            });
        }
        grant.assertion_audience = self.assertion_audience;
        grant.tls = tls;
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

    /// Returns every problem of the table without reading a file, each
    /// naming its key under `table`, the key the product embeds the table at
    /// (such as `terminology.server.oauth`): the issuer and the token
    /// endpoint, exactly one set and well formed; the client id; the
    /// credential its `client_auth` needs; the certificate and key files
    /// set together; `assertion_audience = "issuer"` with an issuer; the
    /// scope tokens; and a resource that is a URL without a fragment.
    /// [`OauthSection::resolve`] still refuses what only the files show.
    #[must_use]
    pub fn problems(&self, table: &str) -> Vec<String> {
        let mut out = Vec::new();
        match (self.issuer.is_empty(), self.token_endpoint.is_empty()) {
            (false, false) => out.push(format!(
                "{table}: set one of issuer and token_endpoint, not both"
            )),
            (true, true) => out.push(format!("{table}: set issuer or token_endpoint")),
            (false, true) => {
                if crate::metadata::issuer_url(&self.issuer).is_err() {
                    out.push(format!(
                        "{table}.issuer is not an https issuer identifier (RFC 8414 §2)"
                    ));
                }
            }
            (true, false) => {
                if self.token_endpoint.parse::<Url>().is_err() {
                    out.push(format!("{table}.token_endpoint is not a URL"));
                }
            }
        }
        if self.client_id.is_empty() {
            out.push(format!("{table}.client_id must not be empty"));
        }
        match self.client_auth {
            ClientAuth::ClientSecretBasic | ClientAuth::ClientSecretPost => {
                match (&self.client_secret, &self.client_secret_file) {
                    (Some(_), Some(_)) => out.push(format!(
                        "{table}: set one of client_secret and client_secret_file, not both"
                    )),
                    (None, None) => out.push(format!(
                        "{table} requires client_secret or client_secret_file"
                    )),
                    _ => {}
                }
            }
            ClientAuth::PrivateKeyJwt => {
                if self.private_key_file.is_none() {
                    out.push(format!(
                        "{table}.private_key_file is required by client_auth = \"private_key_jwt\""
                    ));
                }
            }
            ClientAuth::TlsClientAuth | ClientAuth::SelfSignedTlsClientAuth => {
                if self.client_certificate_file.is_none() {
                    out.push(format!(
                        "{table}.client_certificate_file is required by a mutual-TLS client_auth"
                    ));
                }
            }
        }
        match (&self.client_certificate_file, &self.client_key_file) {
            (Some(_), None) => out.push(format!(
                "{table}.client_key_file is required beside client_certificate_file"
            )),
            (None, Some(_)) => out.push(format!(
                "{table}.client_certificate_file is required beside client_key_file"
            )),
            _ => {}
        }
        if self.assertion_audience == AssertionAudience::Issuer && self.issuer.is_empty() {
            out.push(format!(
                "{table}.issuer is required by assertion_audience = \"issuer\""
            ));
        }
        if self
            .scope
            .split(' ')
            .any(|token| !token.is_empty() && !is_scope_token(token))
        {
            out.push(format!(
                "{table}.scope holds a token outside the RFC 6749 §3.3 character set"
            ));
        }
        if !self.resource.is_empty() {
            match self.resource.parse::<Url>() {
                Err(_malformed) => out.push(format!("{table}.resource is not a URL")),
                Ok(resource) if resource.fragment().is_some() => out.push(format!(
                    "{table}.resource carries a fragment, which a resource indicator must not (RFC 8707 §2)"
                )),
                Ok(_) => {}
            }
        }
        out
    }

    /// Returns the TLS material the table names, each file read and, with
    /// the `fetch` feature, parsed, so a bad file refuses the start.
    fn tls(&self) -> Result<Tls, ConfigError> {
        let read = |path: &Path| {
            std::fs::read(path).map_err(|source| ConfigError::SecretFile {
                path: path.to_path_buf(),
                source,
            })
        };
        let root_certificates = self.ca_file.as_deref().map(read).transpose()?;
        let identity = match (&self.client_certificate_file, &self.client_key_file) {
            (None, None) => None,
            (Some(_), None) => {
                return Err(ConfigError::Missing {
                    key: "credentials.oauth.client_key_file",
                });
            }
            (None, Some(_)) => {
                return Err(ConfigError::Missing {
                    key: "credentials.oauth.client_certificate_file",
                });
            }
            (Some(certificate), Some(key)) => {
                let mut pem = read(certificate)?;
                pem.push(b'\n');
                pem.extend(read(key)?);
                Some(std::sync::Arc::new(secrecy::SecretSlice::from(pem)))
            }
        };
        let tls = Tls {
            root_certificates,
            identity,
        };
        #[cfg(feature = "fetch")]
        crate::metadata::Http::with_tls(Duration::from_millis(self.timeout_ms), &tls).map_err(
            |source| ConfigError::Tls {
                source: Box::new(source),
            },
        )?;
        Ok(tls)
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

/// The text a set secret is rendered as.
const REDACTED: &str = "[redacted]";

/// Returns `text` with the userinfo of the URL it is replaced by
/// [`REDACTED`], or `text` itself when it is no URL or carries none.
fn mask_userinfo(text: &str) -> String {
    match text.parse::<Url>() {
        Ok(mut url) if !url.username().is_empty() || url.password().is_some() => {
            let masked = url.set_username(REDACTED).is_ok() && url.set_password(None).is_ok();
            if masked {
                url.to_string()
            } else {
                String::from(REDACTED)
            }
        }
        _ => text.to_owned(),
    }
}

/// Writes a URL with its userinfo masked ([`mask_userinfo`]).
#[expect(
    clippy::ptr_arg,
    reason = "serde's serialize_with hands the field over as its own type"
)]
fn masked_url<S: Serializer>(text: &String, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&mask_userinfo(text))
}

/// Writes a set secret as [`REDACTED`], never its value, so a product can
/// render its running configuration (no specification governs the
/// rendering: our own design).
#[expect(
    clippy::ref_option,
    reason = "serde's serialize_with hands the field over by reference"
)]
fn redact<S: Serializer>(secret: &Option<SecretString>, serializer: S) -> Result<S::Ok, S::Error> {
    match secret {
        Some(_) => serializer.serialize_str(REDACTED),
        None => serializer.serialize_none(),
    }
}
