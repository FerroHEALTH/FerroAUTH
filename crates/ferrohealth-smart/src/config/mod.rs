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
use std::path::PathBuf;

use ferrohealth_secret::secret_url::RedactedUrl;
use jsonwebtoken::Algorithm;
use secrecy::SecretString;
use serde::Deserialize;
use serde::Serialize;

use crate::assurance::AssuranceSection;
use crate::basic::PasswordStore;
use crate::basic::StoreError;
use crate::client::assertion::AssertionError;
use crate::config::credentials::OauthSection;
use crate::federation::FederationSection;
use crate::kind::IssuerKind;
use crate::metadata::DiscoveryError;
use crate::party::config::PartyError;
use crate::party::config::PartySection;
use crate::profile::Delegate;
use crate::profile::Marker;
use crate::profile::Preset;
use crate::profile::Representation;
use crate::profile::ScopeClaim;
use crate::profile::onward::OnwardGrant;
use crate::profile::onward::OnwardIndicator;
use crate::profile::onward::PreviewVariant;
use crate::resource::ResourceError;
use crate::resource::Settings;
use crate::sender::SenderConstraint;

mod auth;
pub mod credentials;
mod issuer;
pub mod onward;
mod read;
mod shapes;

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
    /// An `[[auth.issuer]]` URL carries userinfo, which an issuer
    /// identifier never holds (OpenID Connect Core 1.0 §1.2), shown masked.
    #[error("auth.issuer {issuer} carries userinfo, which an issuer identifier never holds")]
    IssuerUserinfo {
        /// The issuer, its userinfo masked ([`mask_userinfo`]).
        issuer: String,
    },
    /// An issuer's `jwks_file` holds a symmetric key (`kty` `oct`), which
    /// a verifier of asymmetric signatures never holds (RFC 8725 §3.1).
    #[error(
        "the jwks_file of auth.issuer {issuer} holds a symmetric key at index {index} (kid {kid:?})"
    )]
    JwksSymmetricKey {
        /// The issuer whose file it is.
        issuer: String,
        /// The key's index in `keys`.
        index: usize,
        /// The key's `kid`, when it has one.
        kid: Option<String>,
    },
    /// An issuer's `jwks_file` holds private key material, which a verifier
    /// never needs (RFC 7517 Appendix A.2).
    #[error(
        "the jwks_file of auth.issuer {issuer} holds private key material ({member}) at index {index} (kid {kid:?})"
    )]
    JwksPrivateKey {
        /// The issuer whose file it is.
        issuer: String,
        /// The key's index in `keys`.
        index: usize,
        /// The key's `kid`, when it has one.
        kid: Option<String>,
        /// The first private member the key carries, never its value.
        member: &'static str,
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
    /// The `DPoP` key could not be loaded.
    #[error("the DPoP key is refused")]
    DpopKey {
        /// Why.
        #[source]
        source: crate::client::dpop::DpopKeyError,
    },
    /// The assertion keys form no ring.
    #[error("the assertion keys form no key ring")]
    KeyRing {
        /// Why.
        #[source]
        source: crate::client::keys::KeyRingError,
    },
    /// The `authorization_details` is not of RFC 9396 §2 shape.
    #[error("credentials.oauth.authorization_details is not of RFC 9396 §2 shape")]
    AuthorizationDetails {
        /// Why.
        #[source]
        source: crate::client::authorization_details::AuthorizationDetailsError,
    },
    /// A `mtls_alias_hosts` entry is no host.
    #[error("credentials.oauth.mtls_alias_hosts holds {host:?}, which is no host")]
    AliasHost {
        /// The entry.
        host: String,
    },
    /// The grant breaks a rule of its method or security profile.
    #[error("the credentials.oauth grant is refused")]
    Grant {
        /// Why.
        #[source]
        source: Box<crate::client::TokenError>,
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
    /// The `credentials.onward` table names an issuer or a target the onward
    /// client refuses.
    #[cfg(feature = "fetch")]
    #[error("credentials.onward is refused")]
    Onward {
        /// Why.
        #[source]
        source: Box<crate::client::onward::OnwardError>,
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
    /// An `[[auth.party]]` table breaks a rule.
    #[error("an [[auth.party]] table is refused")]
    Party {
        /// The rule.
        #[source]
        source: PartyError,
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
    /// The `[[auth.party]]` tables, one per `persons` issuer whose logins
    /// are bound to a party.
    pub party: Vec<PartySection>,
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
    /// [`ProfileKeys::person_key`](crate::profile::ProfileKeys::person_key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub person_key: Option<String>,
    /// [`ProfileKeys::tenant_claim`](crate::profile::ProfileKeys::tenant_claim).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_claim: Option<String>,
    /// [`ProfileKeys::client_claims`](crate::profile::ProfileKeys::client_claims).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_claims: Option<Vec<String>>,
    /// [`ProfileKeys::app_only`](crate::profile::ProfileKeys::app_only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_only: Option<Vec<Marker>>,
    /// [`ProfileKeys::guest`](crate::profile::ProfileKeys::guest).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest: Option<Vec<Marker>>,
    /// [`ProfileKeys::impersonation_marker`](crate::profile::ProfileKeys::impersonation_marker).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonation_marker: Option<String>,
    /// [`ProfileKeys::expect`](crate::profile::ProfileKeys::expect).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expect: Option<BTreeMap<String, String>>,
    /// [`ProfileKeys::user_claims`](crate::profile::ProfileKeys::user_claims).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_claims: Option<Vec<String>>,
    /// [`ProfileKeys::person_equality`](crate::profile::ProfileKeys::person_equality).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub person_equality: Option<Vec<String>>,
    /// [`ProfileKeys::unstable_claims`](crate::profile::ProfileKeys::unstable_claims).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unstable_claims: Option<Vec<String>>,
    /// [`ProfileKeys::first_party_clients`](crate::profile::ProfileKeys::first_party_clients).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_party_clients: Option<Vec<String>>,
    /// [`ProfileKeys::delegates`](crate::profile::ProfileKeys::delegates).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegates: Option<Vec<Delegate>>,
    /// [`ProfileKeys::max_actor_chain`](crate::profile::ProfileKeys::max_actor_chain).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_actor_chain: Option<usize>,
    /// [`ProfileKeys::representation`](crate::profile::ProfileKeys::representation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representation: Option<Representation>,
    /// [`ProfileKeys::token_types`](crate::profile::ProfileKeys::token_types).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_types: Option<Vec<String>>,
    /// [`ProfileKeys::required_claims`](crate::profile::ProfileKeys::required_claims).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_claims: Option<Vec<String>>,
    /// [`ProfileKeys::scope_claim`](crate::profile::ProfileKeys::scope_claim).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_claim: Option<ScopeClaim>,
    /// [`ProfileKeys::app_only_scope_claim`](crate::profile::ProfileKeys::app_only_scope_claim).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_only_scope_claim: Option<ScopeClaim>,
    /// [`ProfileKeys::adapter`](crate::profile::ProfileKeys::adapter).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,
    /// [`ProfileKeys::max_onward_lifetime`](crate::profile::ProfileKeys::max_onward_lifetime).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_onward_lifetime: Option<u64>,
    /// [`ProfileKeys::onward_grant`](crate::profile::ProfileKeys::onward_grant).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_grant: Option<OnwardGrant>,
    /// [`ProfileKeys::onward_indicator`](crate::profile::ProfileKeys::onward_indicator).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_indicator: Option<OnwardIndicator>,
    /// [`ProfileKeys::onward_parameters`](crate::profile::ProfileKeys::onward_parameters).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_parameters: Option<BTreeMap<String, String>>,
    /// [`ProfileKeys::onward_client_id`](crate::profile::ProfileKeys::onward_client_id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_client_id: Option<bool>,
    /// [`ProfileKeys::onward_subject_audience`](crate::profile::ProfileKeys::onward_subject_audience).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_subject_audience: Option<bool>,
    /// [`ProfileKeys::onward_preview`](crate::profile::ProfileKeys::onward_preview).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_preview: Option<Vec<PreviewVariant>>,
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

/// One `[[auth.basic.users]]` entry: a person's credential, never a
/// machine's ([`crate::resource::Caller::basic`]).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BasicUser {
    /// The user-id.
    pub user: String,
    /// The Argon2id PHC string of the password, rendered redacted.
    #[serde(
        serialize_with = "shapes::redact",
        skip_serializing_if = "Option::is_none"
    )]
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
    /// The `[[auth.party]]` tables, each checked against its issuer.
    pub party: Vec<PartySection>,
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
