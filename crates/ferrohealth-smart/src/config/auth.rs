// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The resolution of the `[auth]` section: every rule checked, every
//! secret read, every issuer's settings built from its own table.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use crate::basic::PasswordStore;
#[cfg(feature = "fetch")]
use crate::client::Tls;
use crate::config::AuthMode;
use crate::config::AuthSection;
use crate::config::BasicSection;
use crate::config::ConfigError;
use crate::config::IssuerEntry;
use crate::config::IssuerKey;
use crate::config::Resolved;
use crate::config::ScopelessSubject;
use crate::config::read::secret;
use crate::federation::FederationSection;
use crate::kind::IssuerKind;
use crate::profile::Profile;
use crate::resource::Settings;
use crate::resource::configuration::SmartOptions;
use crate::resource::configuration::is_capability;
use crate::scope::is_extension_scope;
use crate::scope::is_scope_token;
use crate::sender::proof::ProofSettings;

/// The replacement each removed section key names.
const ISSUER_TABLE: &str = "set it on each [[auth.issuer]] table";

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

    /// Checks a product role list, the issuers a product honours an
    /// administrator, emergency or identifier-reader role from: each must
    /// be a `persons` issuer the section trusts (no specification governs
    /// this: our own design, since only a person holds such a role).
    ///
    /// # Errors
    ///
    /// [`ConfigError::RoleIssuer`] naming `key` and the first issuer that is
    /// not a trusted `persons` issuer.
    pub fn check_role_issuers<S: AsRef<str>>(
        &self,
        key: &'static str,
        issuers: &[S],
    ) -> Result<(), ConfigError> {
        for issuer in issuers {
            let issuer = issuer.as_ref();
            let kind = self.kinds.get(issuer).copied();
            if kind != Some(IssuerKind::Persons) {
                return Err(ConfigError::RoleIssuer {
                    key,
                    issuer: issuer.to_owned(),
                    kind,
                });
            }
        }
        Ok(())
    }
}

impl AuthSection {
    /// Returns the `[[auth.issuer]]` tables the section names; none for the
    /// removed flat form, which [`AuthSection::resolve`] refuses.
    #[must_use]
    pub fn issuers(&self) -> &[IssuerEntry] {
        match &self.issuer {
            IssuerKey::Flat(_) => &[],
            IssuerKey::List(entries) => entries,
        }
    }

    /// Resolves the section: every rule checked, every secret read.
    ///
    /// An enabled section with Basic users and no issuer resolves to the
    /// Basic store alone, a Basic-only surface; an enabled section that
    /// admits neither a token nor a Basic user is refused.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] naming the first rule broken: a removed key
    /// ([`ConfigError::Removed`]), no issuer and no Basic user, an issuer
    /// without `kind`, no audience, an issuer outside the URL rule, a
    /// symmetric algorithm, a skew over the bound, a profile or a
    /// kind-bound setting refused, a `scopeless_subjects` entry naming an
    /// issuer the section does not trust, a Basic user with a bad hash,
    /// user-id or scope, a secret set twice or not at all, a capability
    /// SMART does not define, a listed scope outside RFC 6749 §3.3, a
    /// product scope in no extension form, or a cache key the random
    /// source cannot draw.
    pub fn resolve(&self) -> Result<Resolved, ConfigError> {
        self.check_removed()?;
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
        let basic_users = self
            .basic
            .as_ref()
            .is_some_and(|section| !section.users.is_empty());
        let trust_roots = self.trust_roots()?;
        let mut kinds = BTreeMap::new();
        let mut issuers = Vec::new();
        #[cfg(feature = "fetch")]
        let mut introspection = Vec::new();
        if self.enabled {
            self.check_scopeless()?;
            self.check_federation()?;
            for entry in self.issuers() {
                let kind = check_entry(entry)?;
                kinds.insert(entry.issuer.clone(), kind);
                match entry.mode {
                    AuthMode::Jwt => {
                        let mut settings = self.settings_of(entry, kind)?;
                        settings.trust_roots.clone_from(&trust_roots);
                        settings.validate().map_err(|source| ConfigError::Issuer {
                            issuer: entry.issuer.clone(),
                            source: Box::new(source),
                        })?;
                        issuers.push(settings);
                    }
                    #[cfg(feature = "fetch")]
                    AuthMode::Introspection => {
                        introspection.push(self.introspection_of(
                            entry,
                            kind,
                            trust_roots.as_deref(),
                        )?);
                    }
                    #[cfg(not(feature = "fetch"))]
                    AuthMode::Introspection => return Err(ConfigError::IntrospectionUnavailable),
                }
            }
        }
        // NOTE: no specification governs the configuration model: our own
        // design, and a surface that admits no credential at all fails closed.
        if self.enabled && kinds.is_empty() && !basic_users {
            return Err(ConfigError::Missing { key: "auth.issuer" });
        }
        if self.enabled {
            self.check_party()?;
        }
        let basic = self.basic_store()?;
        let dpop = self.dpop_settings()?;
        Ok(Resolved {
            enabled: self.enabled,
            issuers,
            kinds,
            basic,
            realm: (!self.realm.is_empty()).then(|| self.realm.clone()),
            capabilities: self.capabilities.clone(),
            scopes_supported: self.scopes_supported.clone(),
            product_scope: (!self.product_scope.is_empty()).then(|| self.product_scope.clone()),
            dpop,
            #[cfg(feature = "fetch")]
            introspection,
            party: if self.enabled {
                self.party.clone()
            } else {
                Vec::new()
            },
        })
    }

    /// Refuses every removed key the section, or one of its issuers, still
    /// sets, naming the replacement.
    fn check_removed(&self) -> Result<(), ConfigError> {
        if matches!(self.issuer, IssuerKey::Flat(_)) {
            return Err(ConfigError::Removed {
                key: "auth.issuer = \"…\"",
                replacement: "write each issuer as an [[auth.issuer]] table with its own kind",
            });
        }
        let section = [
            ("auth.audience", self.audience.is_some(), ISSUER_TABLE),
            ("auth.algorithms", self.algorithms.is_some(), ISSUER_TABLE),
            (
                "auth.clock_skew_seconds",
                self.clock_skew_seconds.is_some(),
                ISSUER_TABLE,
            ),
            (
                "auth.jwks_max_age_seconds",
                self.jwks_max_age_seconds.is_some(),
                ISSUER_TABLE,
            ),
            (
                "auth.jwks_refresh_interval_seconds",
                self.jwks_refresh_interval_seconds.is_some(),
                ISSUER_TABLE,
            ),
            ("auth.jwks_file", self.jwks_file.is_some(), ISSUER_TABLE),
            ("auth.timeout_ms", self.timeout_ms.is_some(), ISSUER_TABLE),
            ("auth.mode", self.mode.is_some(), ISSUER_TABLE),
            (
                "auth.introspection",
                self.introspection.is_some(),
                ISSUER_TABLE,
            ),
            (
                "auth.role_claims",
                self.role_claims.is_some(),
                "set role_claims on each [[auth.issuer]] table",
            ),
            (
                "auth.token_profile",
                self.token_profile.is_some(),
                TOKEN_SHAPE,
            ),
            (
                "auth.acting_for_claim",
                self.acting_for_claim.is_some(),
                DELEGATION,
            ),
            (
                "auth.client_tokens",
                self.client_tokens.is_some(),
                DELEGATION,
            ),
        ];
        if let Some((key, _, replacement)) = section.iter().find(|(_, set, _)| *set) {
            return Err(ConfigError::Removed { key, replacement });
        }
        for entry in self.issuers() {
            let removed = [
                (
                    "auth.issuer.token_profile",
                    entry.token_profile.is_some(),
                    TOKEN_SHAPE,
                ),
                (
                    "auth.issuer.acting_for_claim",
                    entry.acting_for_claim.is_some(),
                    DELEGATION,
                ),
                (
                    "auth.issuer.client_tokens",
                    entry.client_tokens.is_some(),
                    DELEGATION,
                ),
            ];
            if let Some((key, _, replacement)) = removed.iter().find(|(_, set, _)| *set) {
                return Err(ConfigError::Removed { key, replacement });
            }
        }
        if self
            .scopeless_subjects
            .iter()
            .any(|entry| matches!(entry, ScopelessSubject::Text(_)))
        {
            return Err(ConfigError::Removed {
                key: "auth.scopeless_subjects = [\"…\"]",
                replacement: "write each entry as { issuer, sub }",
            });
        }
        Ok(())
    }

    /// Refuses a `scopeless_subjects` entry that names an issuer the section
    /// does not trust (no specification governs the allowlist: our own
    /// design, since a `sub` is unique only within its issuer, RFC 7519
    /// §4.1.2).
    fn check_scopeless(&self) -> Result<(), ConfigError> {
        let trusted: BTreeSet<&str> = self
            .issuers()
            .iter()
            .map(|entry| entry.issuer.as_str())
            .collect();
        for entry in &self.scopeless_subjects {
            if let ScopelessSubject::Qualified { issuer, .. } = entry
                && !trusted.contains(issuer.as_str())
            {
                return Err(ConfigError::UnknownIssuer {
                    key: "auth.scopeless_subjects",
                    issuer: issuer.clone(),
                });
            }
        }
        Ok(())
    }

    /// Refuses a `[[auth.federation]]` table that names no trusted
    /// `federation` issuer or names one twice, and a `federation` issuer with
    /// no table (no specification governs this: our own design).
    fn check_federation(&self) -> Result<(), ConfigError> {
        let mut seen = BTreeSet::new();
        for section in &self.federation {
            let kind = self
                .issuers()
                .iter()
                .find(|entry| entry.issuer == section.issuer)
                .and_then(|entry| entry.kind);
            if kind != Some(IssuerKind::Federation) {
                return Err(ConfigError::Federation {
                    issuer: section.issuer.clone(),
                    reason: "it names no trusted federation issuer",
                });
            }
            if !seen.insert(section.issuer.as_str()) {
                return Err(ConfigError::Federation {
                    issuer: section.issuer.clone(),
                    reason: "two tables name the issuer",
                });
            }
        }
        for entry in self.issuers() {
            if entry.kind == Some(IssuerKind::Federation) && !seen.contains(entry.issuer.as_str()) {
                return Err(ConfigError::Federation {
                    issuer: entry.issuer.clone(),
                    reason: "a federation issuer needs its [[auth.federation]] table",
                });
            }
        }
        Ok(())
    }

    /// Refuses an `[[auth.party]]` table that names no trusted `persons`
    /// issuer, sets `claim`, or shares its issuer or its `identifier_issuer`
    /// with another (no specification governs this: our own design).
    fn check_party(&self) -> Result<(), ConfigError> {
        let profiles = self
            .issuers()
            .iter()
            .filter_map(|entry| Some((entry.issuer.as_str(), entry.kind?, entry)))
            .map(|(issuer, kind, entry)| Ok((issuer, kind, profile_of(entry)?)))
            .collect::<Result<Vec<_>, ConfigError>>()?;
        crate::party::config::check_tables(&self.party, |issuer| {
            profiles
                .iter()
                .find(|(named, _, _)| *named == issuer)
                .map(|(_, kind, profile)| (*kind, profile))
        })
        .map_err(|source| ConfigError::Party { source })
    }

    /// Returns the `[[auth.federation]]` table of `entry`, set over its
    /// preset's federation defaults; the defaults alone when it has no table,
    /// which an issuer of another kind then refuses.
    fn federation_of(&self, entry: &IssuerEntry) -> Result<Option<FederationSection>, ConfigError> {
        let defaults = entry
            .profile
            .federation()
            .map_err(|source| ConfigError::Issuer {
                issuer: entry.issuer.clone(),
                source: Box::new(source.into()),
            })?;
        let table = self
            .federation
            .iter()
            .find(|section| section.issuer == entry.issuer)
            .cloned();
        Ok(match (table, defaults) {
            (Some(table), Some(defaults)) => Some(table.over(defaults)),
            (table, None) => table,
            (None, Some(defaults)) => Some(FederationSection {
                issuer: entry.issuer.clone(),
                ..defaults
            }),
        })
    }

    /// Returns the subjects of `scopeless_subjects` that name `issuer`.
    fn scopeless_of(&self, issuer: &str) -> BTreeSet<String> {
        self.scopeless_subjects
            .iter()
            .filter_map(|entry| match entry {
                ScopelessSubject::Qualified { issuer: named, sub } if named == issuer => {
                    Some(sub.clone())
                }
                _ => None,
            })
            .collect()
    }

    /// Returns the `DPoP` proof settings of `[auth.dpop]`, when the section has
    /// the table.
    fn dpop_settings(&self) -> Result<Option<ProofSettings>, ConfigError> {
        let Some(section) = &self.dpop else {
            return Ok(None);
        };
        let mut settings = ProofSettings::new(crate::config::read::parse_url(
            &section.external_url,
            "auth.dpop.external_url",
        )?);
        settings.max_age = Duration::from_secs(section.max_age_seconds);
        settings.clock_skew = Duration::from_secs(section.clock_skew_seconds);
        settings.algorithms.clone_from(&section.algorithms);
        settings
            .validate()
            .map_err(|source| ConfigError::Dpop { source })?;
        Ok(Some(settings))
    }

    /// Returns the Basic store of `[auth.basic]`, when the section has one.
    fn basic_store(&self) -> Result<Option<PasswordStore>, ConfigError> {
        let Some(section) = &self.basic else {
            return Ok(None);
        };
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
        store
            .with_cache(Duration::from_secs(section.cache_ttl_seconds))
            .map(Some)
            .map_err(|source| ConfigError::Basic { source })
    }

    /// Returns the settings of the JWT issuer `entry`, an issuer of `kind`.
    fn settings_of(&self, entry: &IssuerEntry, kind: IssuerKind) -> Result<Settings, ConfigError> {
        let mut settings = Settings::new(entry.issuer.clone(), String::new(), kind);
        settings.audience.clone_from(&entry.audience);
        settings.algorithms.clone_from(&entry.algorithms);
        settings.profile = profile_of(entry)?;
        settings.clock_skew = Duration::from_secs(entry.clock_skew_seconds);
        settings.jwks_max_age = Duration::from_secs(entry.jwks_max_age_seconds);
        settings.jwks_refresh_interval = Duration::from_secs(entry.jwks_refresh_interval_seconds);
        settings.jwks_file = (!entry.jwks_file.is_empty()).then(|| PathBuf::from(&entry.jwks_file));
        settings.timeout = Duration::from_millis(entry.timeout_ms);
        settings.scopeless_subjects = self.scopeless_of(&entry.issuer);
        settings.role_claims = role_claims_of(entry, kind);
        settings.assurance.clone_from(&entry.assurance);
        settings.federation = self.federation_of(entry)?;
        settings.sender_constraint = entry.sender_constraint;
        Ok(settings)
    }

    /// Returns the introspection settings of the `mode = "introspection"`
    /// issuer `entry`, an issuer of `kind`.
    #[cfg(feature = "fetch")]
    fn introspection_of(
        &self,
        entry: &IssuerEntry,
        kind: IssuerKind,
        trust_roots: Option<&[u8]>,
    ) -> Result<crate::resource::introspection::IntrospectionSettings, ConfigError> {
        use crate::resource::introspection::IntrospectionAuth;
        use crate::resource::introspection::IntrospectionError;
        use crate::resource::introspection::IntrospectionSettings;
        if !entry.jwks_file.is_empty() {
            return Err(ConfigError::Exclusive {
                left: "auth.issuer.mode = \"introspection\"",
                right: "auth.issuer.jwks_file",
            });
        }
        let section = entry.introspection.as_ref().ok_or(ConfigError::Missing {
            key: "auth.issuer.introspection",
        })?;
        let auth = match (&section.client, &section.bearer) {
            (Some(_), Some(_)) => {
                return Err(ConfigError::Exclusive {
                    left: "auth.issuer.introspection.client",
                    right: "auth.issuer.introspection.bearer",
                });
            }
            (None, None) => {
                return Err(ConfigError::Missing {
                    key: "auth.issuer.introspection.client or auth.issuer.introspection.bearer",
                });
            }
            (Some(client), None) => {
                let mut client = client.clone();
                if client.issuer.is_empty() && client.token_endpoint.is_empty() {
                    client.issuer.clone_from(&entry.issuer);
                }
                let mut credentials = client.resolve()?;
                trust_also(&mut credentials.tls, trust_roots);
                IntrospectionAuth::Client(Box::new(credentials))
            }
            (None, Some(bearer)) => {
                let mut grant = bearer.resolve()?;
                trust_also(&mut grant.tls, trust_roots);
                let source = crate::client::cache::TokenSource::new(grant).map_err(|source| {
                    ConfigError::Introspection {
                        source: Box::new(IntrospectionError::Credential {
                            source: std::sync::Arc::new(source),
                        }),
                    }
                })?;
                IntrospectionAuth::Bearer(source)
            }
        };
        let mut settings =
            IntrospectionSettings::new(entry.issuer.clone(), String::new(), auth, kind);
        settings.audience.clone_from(&entry.audience);
        if !section.endpoint.is_empty() {
            settings.endpoint = Some(crate::config::read::parse_url(
                &section.endpoint,
                "auth.issuer.introspection.endpoint",
            )?);
        }
        settings.clock_skew = Duration::from_secs(entry.clock_skew_seconds);
        settings.cache_max_age = Duration::from_secs(section.cache_max_age_seconds);
        settings.cache_capacity = section.cache_capacity;
        settings.timeout = Duration::from_millis(entry.timeout_ms);
        settings.scopeless_subjects = self.scopeless_of(&entry.issuer);
        settings.role_claims = role_claims_of(entry, kind);
        settings.profile = profile_of(entry)?;
        settings.assurance.clone_from(&entry.assurance);
        settings.federation = self.federation_of(entry)?;
        settings.sender_constraint = entry.sender_constraint;
        settings
            .validate()
            .map_err(|source| ConfigError::Introspection {
                source: Box::new(source),
            })?;
        Ok(settings)
    }

    /// Returns the PEM trust roots of `ca_file`, read and, with the `fetch`
    /// feature, parsed, so a bad file refuses the start.
    fn trust_roots(&self) -> Result<Option<Vec<u8>>, ConfigError> {
        let Some(path) = &self.ca_file else {
            return Ok(None);
        };
        let pem = std::fs::read(path).map_err(|source| ConfigError::CaFile {
            source: Box::new(source),
        })?;
        #[cfg(feature = "fetch")]
        crate::metadata::Http::with_tls(
            Duration::from_secs(10),
            &Tls {
                root_certificates: Some(pem.clone()),
                identity: None,
            },
        )
        .map_err(|source| ConfigError::CaFile {
            source: Box::new(source),
        })?;
        Ok(Some(pem))
    }
}

/// The replacement of the removed token shape key.
const TOKEN_SHAPE: &str =
    "set token_types, required_claims and scope_claim, or a profile, on each [[auth.issuer]]";

/// The replacement of the removed delegation keys.
const DELEGATION: &str = "issue the client a delegated token whose subject is the person, \
     classified by the issuer's delegates and first_party_clients";

/// Checks the issuer-level rules of `entry` and returns its kind: an
/// identifier, a kind, and no `federation` issuer in this build.
fn check_entry(entry: &IssuerEntry) -> Result<IssuerKind, ConfigError> {
    if entry.issuer.is_empty() {
        return Err(ConfigError::Missing { key: "auth.issuer" });
    }
    // NOTE: OpenID Connect Core 1.0 §1.2: an issuer identifier holds scheme, host, port and
    // path; userinfo is refused before any later error could quote the URL.
    if let Ok(url) = url::Url::parse(entry.issuer.trim())
        && (!url.username().is_empty() || url.password().is_some())
    {
        return Err(ConfigError::IssuerUserinfo {
            issuer: crate::config::mask_userinfo(&entry.issuer),
        });
    }
    if !entry.jwks_file.is_empty() {
        check_jwks_file(entry)?;
    }
    let kind = entry.kind.ok_or(ConfigError::Missing {
        key: "auth.issuer.kind",
    })?;
    if entry.mode == AuthMode::Jwt && entry.introspection.is_some() {
        return Err(ConfigError::Exclusive {
            left: "auth.issuer.introspection",
            right: "auth.issuer.mode = \"jwt\"",
        });
    }
    if !entry
        .role_claims
        .iter()
        .flatten()
        .all(|path| crate::roles::well_formed(path))
    {
        return Err(ConfigError::Missing {
            key: "auth.issuer.role_claims",
        });
    }
    Ok(kind)
}

/// The JWK members that carry private or symmetric key material, as the
/// example private and symmetric keys of RFC 7517 Appendix A.2 and A.3 show.
const SECRET_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Refuses a `jwks_file` that holds a symmetric key or private key
/// material, which a verifier never holds (RFC 7517 §5; RFC 8725 §3.1).
/// A file that cannot be read or parsed is left to the read of the key
/// set, which refuses it; no key value is ever quoted.
fn check_jwks_file(entry: &IssuerEntry) -> Result<(), ConfigError> {
    let Ok(text) = std::fs::read_to_string(&entry.jwks_file) else {
        return Ok(());
    };
    // NOTE: a file that is no JSON is legitimately left to the key set read, which refuses it.
    let Ok(set) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Ok(());
    };
    let keys = set
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    for (index, key) in keys.iter().enumerate() {
        let kid = key
            .get("kid")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        if key.get("kty").and_then(serde_json::Value::as_str) == Some("oct") {
            return Err(ConfigError::JwksSymmetricKey {
                issuer: entry.issuer.clone(),
                index,
                kid,
            });
        }
        if let Some(member) = SECRET_MEMBERS
            .iter()
            .find(|member| key.get(**member).is_some())
        {
            return Err(ConfigError::JwksPrivateKey {
                issuer: entry.issuer.clone(),
                index,
                kid,
                member,
            });
        }
    }
    Ok(())
}

/// Returns the profile of `entry`: its preset with its own keys over it.
fn profile_of(entry: &IssuerEntry) -> Result<Profile, ConfigError> {
    Profile::resolve(entry.profile, &entry.profile_keys()).map_err(|source| ConfigError::Issuer {
        issuer: entry.issuer.clone(),
        source: Box::new(source.into()),
    })
}

/// Returns the role claims of `entry`: its own, or the RFC 9068 §2.2.3.1
/// defaults; none for a `federation` issuer.
fn role_claims_of(entry: &IssuerEntry, kind: IssuerKind) -> Vec<String> {
    match (&entry.role_claims, kind) {
        (Some(claims), _) => claims.clone(),
        (None, IssuerKind::Federation) => Vec::new(),
        (None, _) => crate::roles::default_claims(),
    }
}

/// Adds the `auth.ca_file` roots to the roots of an introspection grant, so
/// the metadata, introspection and token calls trust both (no specification
/// governs trust configuration: our own design).
#[cfg(feature = "fetch")]
fn trust_also(tls: &mut Tls, roots: Option<&[u8]>) {
    let Some(roots) = roots else {
        return;
    };
    let mut merged = tls.root_certificates.take().unwrap_or_default();
    if !merged.is_empty() && !merged.ends_with(b"\n") {
        merged.push(b'\n');
    }
    merged.extend_from_slice(roots);
    tls.root_certificates = Some(merged);
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
            party: Vec::new(),
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
