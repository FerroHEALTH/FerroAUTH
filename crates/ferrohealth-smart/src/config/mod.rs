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

use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

use ferrohealth_secret::secret_url::RedactedUrl;
use jsonwebtoken::Algorithm;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;
use url::Url;

use crate::assurance::AssuranceSection;
use crate::basic::Credential;
use crate::basic::PasswordStore;
use crate::basic::StoreError;
use crate::client::AssertionAudience;
use crate::client::ClientAuth;
use crate::client::ClientCredentials;
use crate::client::assertion::AssertionError;
use crate::federation::FederationSection;
use crate::kind::IssuerKind;
use crate::metadata::DiscoveryError;
use crate::profile::Delegate;
use crate::profile::Marker;
use crate::profile::Preset;
use crate::profile::ProfileKeys;
use crate::profile::Representation;
use crate::profile::ScopeClaim;
use crate::resource::ResourceError;
use crate::resource::Settings;
use crate::sender::SenderConstraint;

mod auth;
mod credentials;

/// A section that breaks a rule, named by its key.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The `[auth.dpop]` settings break a rule.
    #[error("auth.dpop is refused")]
    Dpop {
        /// The rule.
        #[source]
        source: crate::sender::proof::ProofSettingsError,
    },
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
    /// An issuer with `mode = "introspection"` in a build without the `fetch` feature,
    /// which links no HTTP client to call the endpoint with.
    #[error("auth.issuer.mode = \"introspection\" needs the fetch feature")]
    IntrospectionUnavailable,
    /// The introspection settings break a rule.
    #[cfg(feature = "fetch")]
    #[error("the auth.issuer.introspection settings are refused")]
    Introspection {
        /// The rule.
        #[source]
        source: Box<crate::resource::introspection::IntrospectionError>,
    },
    /// The `auth.ca_file` trust roots cannot be read, are no PEM, or hold
    /// no certificate.
    #[error("auth.ca_file is refused")]
    CaFile {
        /// Why.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The trust roots or the client certificate of the token endpoint
    /// connection are refused.
    #[error("the TLS material of credentials.oauth is refused")]
    Tls {
        /// Why.
        #[source]
        source: Box<DiscoveryError>,
    },
    /// A key was removed; the error names what replaces it.
    #[error("{key} is removed: {replacement}")]
    Removed {
        /// The key.
        key: &'static str,
        /// What replaces it.
        replacement: &'static str,
    },
    /// A product role list names an issuer that is not a `persons` issuer
    /// the section trusts.
    #[error("the {key} list names the issuer {issuer:?}, which is not a trusted persons issuer")]
    RoleIssuer {
        /// The key of the product's list.
        key: &'static str,
        /// The issuer.
        issuer: String,
        /// Its kind, when the section trusts it.
        kind: Option<IssuerKind>,
    },
    /// A `federation` issuer without its one `[[auth.federation]]` table,
    /// or a table naming no trusted `federation` issuer or naming one twice.
    #[error("the federation table of {issuer:?} is refused: {reason}")]
    Federation {
        /// The issuer.
        issuer: String,
        /// Which rule.
        reason: &'static str,
    },
    /// An entry of a list read per issuer names an issuer the section does
    /// not trust.
    #[error("a {key} entry names the issuer {issuer:?}, which the section does not trust")]
    UnknownIssuer {
        /// The key of the list.
        key: &'static str,
        /// The issuer the entry names.
        issuer: String,
    },
}

/// A key that was removed, kept only so a configuration that still sets it
/// fails to load naming its replacement ([`ConfigError::Removed`]).
pub type Removed = Option<serde_json::Value>;

/// The `[auth]` section: the surface's `[[auth.issuer]]` tables, the
/// issuer-qualified allowlist, the discovery document's options and the
/// Basic users.
///
/// Every setting of an issuer lives on its own `[[auth.issuer]]` table: no
/// section-level value stands in for one an issuer leaves out.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthSection {
    /// Whether inbound authentication is on; a product may refuse `false`.
    pub enabled: bool,
    /// The `[[auth.issuer]]` tables; the flat `issuer = "…"` form is
    /// refused.
    pub issuer: IssuerKey,
    /// The subjects granted system-wide access without a scope, each
    /// `{ issuer, sub }`; only a [`CallerKind::System`] caller of a
    /// `persons` or `machines` issuer is ever admitted by an entry.
    ///
    /// [`CallerKind::System`]: crate::kind::CallerKind::System
    pub scopeless_subjects: Vec<ScopelessSubject>,
    /// The realm the challenges name; empty for none, which a product
    /// replaces with its own default.
    pub realm: String,
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
    /// The `DPoP` proof check of the surface; absent for none, so a `DPoP`
    /// request is refused as carrying no admitted credential.
    pub dpop: Option<crate::sender::proof::DpopSection>,
    /// A PEM file of trust roots added to the platform's, for an issuer
    /// behind a private certificate authority: the discovery document and
    /// the key set of every issuer are read trusting it. Read once at start.
    pub ca_file: Option<PathBuf>,
    /// The `[[auth.federation]]` tables, one per `federation` issuer.
    pub federation: Vec<FederationSection>,
    /// Removed: set `audience` on each `[[auth.issuer]]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Removed,
    /// Removed: set `algorithms` on each `[[auth.issuer]]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithms: Removed,
    /// Removed: set the profile keys on each `[[auth.issuer]]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_profile: Removed,
    /// Removed: set `clock_skew_seconds` on each `[[auth.issuer]]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clock_skew_seconds: Removed,
    /// Removed: set `jwks_max_age_seconds` on each `[[auth.issuer]]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_max_age_seconds: Removed,
    /// Removed: set `jwks_refresh_interval_seconds` on each
    /// `[[auth.issuer]]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_refresh_interval_seconds: Removed,
    /// Removed: set `jwks_file` on each `[[auth.issuer]]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_file: Removed,
    /// Removed: set `timeout_ms` on each `[[auth.issuer]]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Removed,
    /// Removed: set `role_claims` on each `[[auth.issuer]]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_claims: Removed,
    /// Removed: set `mode` on each `[[auth.issuer]]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Removed,
    /// Removed: set `introspection` on each `[[auth.issuer]]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection: Removed,
    /// Removed: the caller classification replaces it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acting_for_claim: Removed,
    /// Removed: the caller classification replaces it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_tokens: Removed,
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

/// The `[auth.issuer.introspection]` table.
///
/// The product authenticates its call with exactly one of `client` (the
/// client authentication of the token endpoint, RFC 7662 §2.1) and `bearer`
/// (a token from the client credentials grant, SMART App Launch 2.2.0,
/// Token Introspection). Each takes the fields of
/// `[<lane>.credentials.oauth]`, and a refusal names those keys; `client`
/// stands in the table's issuer when it names neither `issuer` nor
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
            issuer: IssuerKey::List(Vec::new()),
            scopeless_subjects: Vec::new(),
            realm: String::new(),
            capabilities: Vec::new(),
            scopes_supported: Vec::new(),
            product_scope: String::new(),
            basic: None,
            dpop: None,
            ca_file: None,
            federation: Vec::new(),
            audience: None,
            algorithms: None,
            token_profile: None,
            clock_skew_seconds: None,
            jwks_max_age_seconds: None,
            jwks_refresh_interval_seconds: None,
            jwks_file: None,
            timeout_ms: None,
            role_claims: None,
            mode: None,
            introspection: None,
            acting_for_claim: None,
            client_tokens: None,
        }
    }
}

/// The `issuer` key: the `[[auth.issuer]]` list, or the flat identifier,
/// which [`AuthSection::resolve`] refuses naming the table form.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum IssuerKey {
    /// The removed flat form.
    Flat(String),
    /// The issuers, each with its own settings.
    List(Vec<IssuerEntry>),
}

impl<'de> Deserialize<'de> for IssuerKey {
    // NOTE: serde's `untagged` drops each variant's own error, so the form is chosen
    // by the value's shape and an entry's refusal, naming its key, reaches the caller.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(IssuerKeyVisitor)
    }
}

/// Reads [`IssuerKey`] by the shape of the value: a string or a list.
struct IssuerKeyVisitor;

impl<'de> serde::de::Visitor<'de> for IssuerKeyVisitor {
    type Value = IssuerKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a list of issuer tables")
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<IssuerKey, E> {
        Ok(IssuerKey::Flat(value.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<IssuerKey, E> {
        Ok(IssuerKey::Flat(value))
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, seq: A) -> Result<IssuerKey, A::Error> {
        Vec::<IssuerEntry>::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
            .map(IssuerKey::List)
    }
}

/// One `scopeless_subjects` entry: `{ issuer, sub }`, or the removed string
/// form, which [`AuthSection::resolve`] refuses naming the table form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ScopelessSubject {
    /// The subject `sub` of the issuer `issuer`.
    Qualified {
        /// The issuer.
        issuer: String,
        /// The `sub`.
        sub: String,
    },
    /// The removed string form, bare or `<issuer>#<sub>`.
    Text(String),
}

impl<'de> Deserialize<'de> for ScopelessSubject {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ScopelessVisitor)
    }
}

/// The table form of a [`ScopelessSubject`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopelessTable {
    /// The issuer.
    issuer: String,
    /// The `sub`.
    sub: String,
}

/// Reads [`ScopelessSubject`] by the shape of the value: a string or a
/// table.
struct ScopelessVisitor;

impl<'de> serde::de::Visitor<'de> for ScopelessVisitor {
    type Value = ScopelessSubject;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a table { issuer, sub }")
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<ScopelessSubject, E> {
        Ok(ScopelessSubject::Text(value.to_owned()))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<ScopelessSubject, A::Error> {
        ScopelessTable::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(
            |table| ScopelessSubject::Qualified {
                issuer: table.issuer,
                sub: table.sub,
            },
        )
    }
}

/// One `[[auth.issuer]]` table: the issuer, its kind, how its tokens are
/// checked, and its profile, a [`Preset`] with any profile key set over it.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IssuerEntry {
    /// The issuer identifier.
    pub issuer: String,
    /// Whose tokens the issuer signs; required, with no default.
    pub kind: Option<IssuerKind>,
    /// The preset the profile starts from.
    pub profile: Preset,
    /// The audiences, of which a token's `aud` must contain one.
    pub audience: Vec<String>,
    /// The signature algorithms admitted.
    pub algorithms: Vec<Algorithm>,
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
    /// How the issuer's tokens are checked.
    pub mode: AuthMode,
    /// The introspection check, under `mode = "introspection"`.
    pub introspection: Option<IntrospectionSection>,
    /// The assurance level the issuer's tokens carry.
    pub assurance: Option<AssuranceSection>,
    /// Whether the issuer's tokens must be bound to a `DPoP` key or a client
    /// certificate: `none` (the default) or `required` ([`crate::sender`]).
    pub sender_constraint: SenderConstraint,
    /// The claims the issuer's roles are read from, each a dotted path; by
    /// default `roles`, `groups` and `entitlements` (RFC 9068 §2.2.3.1), and
    /// none, never settable, on a `federation` issuer.
    pub role_claims: Option<Vec<String>>,
    /// [`ProfileKeys::person_key`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub person_key: Option<String>,
    /// [`ProfileKeys::tenant_claim`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_claim: Option<String>,
    /// [`ProfileKeys::client_claims`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_claims: Option<Vec<String>>,
    /// [`ProfileKeys::app_only`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_only: Option<Vec<Marker>>,
    /// [`ProfileKeys::guest`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest: Option<Vec<Marker>>,
    /// [`ProfileKeys::impersonation_marker`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonation_marker: Option<String>,
    /// [`ProfileKeys::expect`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expect: Option<BTreeMap<String, String>>,
    /// [`ProfileKeys::user_claims`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_claims: Option<Vec<String>>,
    /// [`ProfileKeys::person_equality`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub person_equality: Option<Vec<String>>,
    /// [`ProfileKeys::unstable_claims`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unstable_claims: Option<Vec<String>>,
    /// [`ProfileKeys::first_party_clients`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_party_clients: Option<Vec<String>>,
    /// [`ProfileKeys::delegates`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegates: Option<Vec<Delegate>>,
    /// [`ProfileKeys::max_actor_chain`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_actor_chain: Option<usize>,
    /// [`ProfileKeys::representation`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representation: Option<Representation>,
    /// [`ProfileKeys::token_types`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_types: Option<Vec<String>>,
    /// [`ProfileKeys::required_claims`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_claims: Option<Vec<String>>,
    /// [`ProfileKeys::scope_claim`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_claim: Option<ScopeClaim>,
    /// [`ProfileKeys::app_only_scope_claim`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_only_scope_claim: Option<ScopeClaim>,
    /// [`ProfileKeys::adapter`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,
    /// Removed: the profile keys replace it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_profile: Removed,
    /// Removed: the caller classification replaces it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acting_for_claim: Removed,
    /// Removed: the caller classification replaces it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_tokens: Removed,
}

impl Default for IssuerEntry {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            kind: None,
            profile: Preset::Rfc9068,
            audience: Vec::new(),
            algorithms: vec![
                Algorithm::RS256,
                Algorithm::RS384,
                Algorithm::PS256,
                Algorithm::PS384,
                Algorithm::ES256,
                Algorithm::ES384,
            ],
            clock_skew_seconds: 60,
            jwks_max_age_seconds: 600,
            jwks_refresh_interval_seconds: 60,
            jwks_file: String::new(),
            timeout_ms: 10_000,
            mode: AuthMode::Jwt,
            introspection: None,
            assurance: None,
            sender_constraint: SenderConstraint::None,
            role_claims: None,
            person_key: None,
            tenant_claim: None,
            client_claims: None,
            app_only: None,
            guest: None,
            impersonation_marker: None,
            expect: None,
            user_claims: None,
            person_equality: None,
            unstable_claims: None,
            first_party_clients: None,
            delegates: None,
            max_actor_chain: None,
            representation: None,
            token_types: None,
            required_claims: None,
            scope_claim: None,
            app_only_scope_claim: None,
            adapter: None,
            token_profile: None,
            acting_for_claim: None,
            client_tokens: None,
        }
    }
}

impl IssuerEntry {
    /// Returns the profile keys this table sets over its preset.
    #[must_use]
    pub fn profile_keys(&self) -> ProfileKeys {
        ProfileKeys {
            person_key: self.person_key.clone(),
            tenant_claim: self.tenant_claim.clone(),
            client_claims: self.client_claims.clone(),
            app_only: self.app_only.clone(),
            guest: self.guest.clone(),
            impersonation_marker: self.impersonation_marker.clone(),
            expect: self.expect.clone(),
            user_claims: self.user_claims.clone(),
            person_equality: self.person_equality.clone(),
            unstable_claims: self.unstable_claims.clone(),
            first_party_clients: self.first_party_clients.clone(),
            delegates: self.delegates.clone(),
            max_actor_chain: self.max_actor_chain,
            representation: self.representation.clone(),
            token_types: self.token_types.clone(),
            required_claims: self.required_claims.clone(),
            scope_claim: self.scope_claim.clone(),
            app_only_scope_claim: self.app_only_scope_claim.clone(),
            adapter: self.adapter.clone(),
        }
    }
}

/// The `[auth.basic]` table.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BasicSection {
    /// The users.
    pub users: Vec<BasicUser>,
    /// How long a credential that verified is kept, so a repeat request
    /// skips the key derivation; 300 seconds by default, 0 keeps none.
    pub cache_ttl_seconds: u64,
}

impl Default for BasicSection {
    fn default() -> Self {
        Self {
            users: Vec::new(),
            // NOTE: no specification governs the cache: our own design, safe on
            // by default because the user list changes only at a restart.
            cache_ttl_seconds: 300,
        }
    }
}

/// One `[[auth.basic.users]]` entry: a person's credential, never a
/// machine's ([`crate::resource::Caller::basic`]).
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
    /// The resource-server settings of each JWT issuer, in the order
    /// written.
    pub issuers: Vec<Settings>,
    /// The kind of every issuer the section trusts, by identifier.
    pub kinds: BTreeMap<String, IssuerKind>,
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
    /// The `DPoP` proof settings of the surface, when `[auth.dpop]` is set; a
    /// product builds its [`crate::sender::proof::ProofCheck`] from them with
    /// its replay store.
    pub dpop: Option<crate::sender::proof::ProofSettings>,
    /// The introspection check of each `mode = "introspection"` issuer, in
    /// the order written.
    #[cfg(feature = "fetch")]
    pub introspection: Vec<crate::resource::introspection::IntrospectionSettings>,
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

/// The text a set secret, or the userinfo and the query of a URL, is
/// rendered as: the family mask of `ferrohealth-secret`, so every product
/// renders every secret of its configuration one way.
pub const REDACTED: &str = ferrohealth_secret::REDACTED;

/// Returns `text` with the userinfo and the query of the URL it holds
/// replaced by [`REDACTED`], or `text` itself when it holds no URL.
///
/// A text carrying `://` renders through
/// `ferrohealth_secret::secret_url::RedactedUrl`, the family mask: the
/// scheme, the host, the port, the path and the fragment show as written, so
/// the rendering still names the host and path an operator configured, and a
/// value no URL parser accepts, such as a password holding a character a URL
/// forbids, is masked all the same. Any other text is kept as written (no
/// specification governs the rendering: our own design).
///
/// ```
/// use ferrohealth_smart::config::mask_userinfo;
///
/// let masked = mask_userinfo("https://user:secret@idp.example:443/token");
/// assert_eq!(masked, "https://***@idp.example:443/token");
/// assert_eq!(mask_userinfo("postgres://u:p[x@db/x"), "postgres://***@db/x");
/// assert_eq!(mask_userinfo("https://host/path/@handle"), "https://host/path/@handle");
/// assert_eq!(mask_userinfo("https://host?next=a@b"), "https://host?***");
/// assert_eq!(mask_userinfo("not a url"), "not a url");
/// ```
#[must_use]
pub fn mask_userinfo(text: &str) -> String {
    if text.contains("://") {
        RedactedUrl(text).to_string()
    } else {
        text.to_owned()
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
