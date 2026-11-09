// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The resolution of the `[auth]` section: every rule checked, every
//! secret read, every issuer's settings built from its own table.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::basic::PasswordStore;
#[cfg(feature = "fetch")]
use ferrohealth_config::removed::{Removals, Removed};
use ferrohealth_config::tls::TlsClientSection;

use crate::client::Tls;
use crate::config::AuthMode;
use crate::config::AuthSection;
use crate::config::BasicSection;
use crate::config::ConfigError;
use crate::config::IssuerEntry;
use crate::config::IssuerKey;
use crate::config::Resolved;
use crate::config::ScopelessSubject;
use crate::config::TlsBuilder;
use crate::config::build_tls;
use crate::config::issuer::check_entry;
use crate::config::read::secret;
use crate::federation::FederationSection;
use crate::federation::person::AttributesSection;
use crate::kind::IssuerKind;
use crate::profile::Profile;
use crate::resource::Settings;
use crate::resource::configuration::SmartOptions;
use crate::resource::configuration::is_capability;
use crate::scope::is_extension_scope;
use crate::scope::is_scope_token;
use crate::sender::proof::ProofSettings;

/// The replacement each removed section key names.
const ISSUER_TABLE: &str = "the same key on each [[auth.issuer]] table";

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
        self.resolve_over(None)
    }

    /// Resolves the section as [`AuthSection::resolve`] does, every `tls`
    /// table it holds (`auth.tls` and the `tls` of each introspection grant)
    /// built by `tls`, the product's reader of TLS material.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] as [`AuthSection::resolve`] does, and
    /// [`ConfigError::TlsBuild`] when `tls` refuses a table.
    pub fn resolve_with_tls(&self, tls: &dyn TlsBuilder) -> Result<Resolved, ConfigError> {
        self.resolve_over(Some(tls))
    }

    /// Resolves the section, over the product's TLS builder when one is
    /// handed.
    fn resolve_over(&self, builder: Option<&dyn TlsBuilder>) -> Result<Resolved, ConfigError> {
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
        let tls = Tls {
            presented: match builder {
                Some(builder) => Some(build_tls(builder, "auth.tls", &self.tls)?),
                None if self.tls.names_material() => {
                    return Err(ConfigError::TlsNotBuilt { key: "auth.tls" });
                }
                None => None,
            },
            min_version: self.tls.min_version,
        };
        let mut kinds = BTreeMap::new();
        let mut issuers = Vec::new();
        #[cfg(feature = "fetch")]
        let mut introspection = Vec::new();
        if self.enabled {
            self.check_scopeless()?;
            self.check_federation()?;
            self.check_attributes()?;
            for entry in self.issuers() {
                let kind = check_entry(entry)?;
                kinds.insert(entry.issuer.clone(), kind);
                match entry.mode {
                    AuthMode::Jwt => {
                        let mut settings = self.settings_of(entry, kind)?;
                        settings.tls = tls.clone();
                        settings.validate().map_err(|source| ConfigError::Issuer {
                            issuer: entry.issuer.clone(),
                            source: Box::new(source),
                        })?;
                        issuers.push(settings);
                    }
                    #[cfg(feature = "fetch")]
                    AuthMode::Introspection => {
                        introspection.push(self.introspection_of(entry, kind, builder)?);
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
    /// sets, naming the replacement of each, all at once.
    fn check_removed(&self) -> Result<(), ConfigError> {
        if matches!(self.issuer, IssuerKey::Flat(_)) {
            return Err(ConfigError::Removed {
                key: "auth.issuer = \"…\"",
                replacement: "write each issuer as an [[auth.issuer]] table with its own kind",
            });
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
        let mut removals = Removals::new();
        for (removed, key, replacement) in [
            (self.audience, "auth.audience", ISSUER_TABLE),
            (self.algorithms, "auth.algorithms", ISSUER_TABLE),
            (
                self.clock_skew_seconds,
                "auth.clock_skew_seconds",
                "clock_skew on each [[auth.issuer]] table, a duration such as `60s`",
            ),
            (
                self.jwks_max_age_seconds,
                "auth.jwks_max_age_seconds",
                "jwks_max_age on each [[auth.issuer]] table, a duration such as `1h`",
            ),
            (
                self.jwks_refresh_interval_seconds,
                "auth.jwks_refresh_interval_seconds",
                "jwks_refresh_interval on each [[auth.issuer]] table, a duration such as `5min`",
            ),
            (self.jwks_file, "auth.jwks_file", ISSUER_TABLE),
            (
                self.timeout_ms,
                "auth.timeout_ms",
                "timeout on each [[auth.issuer]] table, a duration such as `10s`",
            ),
            (self.mode, "auth.mode", ISSUER_TABLE),
            (self.introspection, "auth.introspection", ISSUER_TABLE),
            (
                self.role_claims,
                "auth.role_claims",
                "role_claims on each [[auth.issuer]] table",
            ),
            (self.token_profile, "auth.token_profile", TOKEN_SHAPE),
            (
                self.ca_file,
                "auth.ca_file",
                "auth.tls.trust_roots_file, read with the product's TLS reader",
            ),
        ] {
            removals.replaced(removed, key, replacement);
        }
        removals.retired(self.acting_for_claim, "auth.acting_for_claim", DELEGATION);
        removals.retired(self.client_tokens, "auth.client_tokens", DELEGATION);
        for (index, entry) in self.issuers().iter().enumerate() {
            let at = |key: &str| format!("auth.issuer[{index}].{key}");
            for (removed, key, replacement) in [
                (entry.token_profile, "token_profile", TOKEN_SHAPE),
                (
                    entry.clock_skew_seconds,
                    "clock_skew_seconds",
                    "clock_skew, a duration such as `60s`",
                ),
                (
                    entry.jwks_max_age_seconds,
                    "jwks_max_age_seconds",
                    "jwks_max_age, a duration such as `1h`",
                ),
                (
                    entry.jwks_refresh_interval_seconds,
                    "jwks_refresh_interval_seconds",
                    "jwks_refresh_interval, a duration such as `5min`",
                ),
                (
                    entry.timeout_ms,
                    "timeout_ms",
                    "timeout, a duration such as `10s`",
                ),
            ] {
                removals.replaced(removed, at(key), replacement);
            }
            removals.retired(entry.acting_for_claim, at("acting_for_claim"), DELEGATION);
            removals.retired(entry.client_tokens, at("client_tokens"), DELEGATION);
            if let Some(introspection) = &entry.introspection {
                removals.replaced(
                    introspection.cache_max_age_seconds,
                    at("introspection.cache_max_age_seconds"),
                    "cache_max_age, a duration such as `5min`",
                );
                for (name, oauth) in [
                    ("client", &introspection.client),
                    ("bearer", &introspection.bearer),
                ] {
                    if let Some(oauth) = oauth {
                        removals.extend(oauth.removals(&at(&format!("introspection.{name}"))));
                    }
                }
            }
        }
        if let Some(basic) = &self.basic {
            removals.replaced(
                basic.cache_ttl_seconds,
                "auth.basic.cache_ttl_seconds",
                "auth.basic.cache_ttl, a duration such as `5min`",
            );
        }
        if let Some(dpop) = &self.dpop {
            removals.extend(dpop.removals("auth.dpop"));
        }
        removals.finish()?;
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

    /// Refuses an `[[auth.attributes]]` table that names no trusted
    /// `persons` issuer or names one twice (no specification governs this:
    /// our own design).
    fn check_attributes(&self) -> Result<(), ConfigError> {
        let mut seen = BTreeSet::new();
        for section in &self.attributes {
            let kind = self
                .issuers()
                .iter()
                .find(|entry| entry.issuer == section.issuer)
                .and_then(|entry| entry.kind);
            if kind != Some(IssuerKind::Persons) {
                return Err(ConfigError::Attributes {
                    issuer: section.issuer.clone(),
                    reason: "it names no trusted persons issuer",
                });
            }
            if !seen.insert(section.issuer.as_str()) {
                return Err(ConfigError::Attributes {
                    issuer: section.issuer.clone(),
                    reason: "two tables name the issuer",
                });
            }
        }
        Ok(())
    }

    /// Returns the `[[auth.attributes]]` table of `entry`, when it has one.
    fn attributes_of(&self, entry: &IssuerEntry) -> Option<AttributesSection> {
        self.attributes
            .iter()
            .find(|section| section.issuer == entry.issuer)
            .cloned()
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
        settings.max_age = section.max_age.get();
        settings.clock_skew = section.clock_skew.get();
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
            .with_cache(section.cache_ttl.get())
            .map(Some)
            .map_err(|source| ConfigError::Basic { source })
    }

    /// Returns the settings of the JWT issuer `entry`, an issuer of `kind`.
    fn settings_of(&self, entry: &IssuerEntry, kind: IssuerKind) -> Result<Settings, ConfigError> {
        let mut settings = Settings::new(entry.issuer.clone(), String::new(), kind);
        settings.audience.clone_from(&entry.audience);
        settings.algorithms.clone_from(&entry.algorithms);
        settings.profile = profile_of(entry)?;
        settings.clock_skew = entry.clock_skew.get();
        settings.jwks_max_age = entry.jwks_max_age.get();
        settings.jwks_refresh_interval = entry.jwks_refresh_interval.get();
        settings.jwks_file = (!entry.jwks_file.is_empty()).then(|| PathBuf::from(&entry.jwks_file));
        settings.timeout = entry.timeout.get();
        settings.scopeless_subjects = self.scopeless_of(&entry.issuer);
        settings.role_claims = role_claims_of(entry, kind);
        settings.assurance.clone_from(&entry.assurance);
        settings.federation = self.federation_of(entry)?;
        settings.attributes = self.attributes_of(entry);
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
        builder: Option<&dyn TlsBuilder>,
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
                let credentials = match builder {
                    Some(builder) => client.resolve_with_tls(builder)?,
                    None => client.resolve()?,
                };
                IntrospectionAuth::Client(Box::new(credentials))
            }
            (None, Some(bearer)) => {
                let grant = match builder {
                    Some(builder) => bearer.resolve_with_tls(builder)?,
                    None => bearer.resolve()?,
                };
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
        settings.clock_skew = entry.clock_skew.get();
        settings.cache_max_age = section.cache_max_age.get();
        settings.cache_capacity = section.cache_capacity;
        settings.timeout = entry.timeout.get();
        settings.scopeless_subjects = self.scopeless_of(&entry.issuer);
        settings.role_claims = role_claims_of(entry, kind);
        settings.profile = profile_of(entry)?;
        settings.assurance.clone_from(&entry.assurance);
        settings.federation = self.federation_of(entry)?;
        settings.attributes = self.attributes_of(entry);
        settings.sender_constraint = entry.sender_constraint;
        settings
            .validate()
            .map_err(|source| ConfigError::Introspection {
                source: Box::new(source),
            })?;
        Ok(settings)
    }
}

/// The replacement of the removed token shape key.
const TOKEN_SHAPE: &str =
    "token_types, required_claims and scope_claim, or a profile, on each [[auth.issuer]]";

/// The replacement of the removed delegation keys.
const DELEGATION: &str = "issue the client a delegated token whose subject is the person, \
     classified by the issuer's delegates and first_party_clients";

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
            tls: TlsClientSection::default(),
            federation: Vec::new(),
            attributes: Vec::new(),
            party: Vec::new(),
            audience: Removed::default(),
            algorithms: Removed::default(),
            token_profile: Removed::default(),
            clock_skew_seconds: Removed::default(),
            jwks_max_age_seconds: Removed::default(),
            jwks_refresh_interval_seconds: Removed::default(),
            jwks_file: Removed::default(),
            timeout_ms: Removed::default(),
            role_claims: Removed::default(),
            mode: Removed::default(),
            introspection: Removed::default(),
            acting_for_claim: Removed::default(),
            client_tokens: Removed::default(),
            ca_file: Removed::default(),
        }
    }
}

impl Default for BasicSection {
    fn default() -> Self {
        Self {
            users: Vec::new(),
            // NOTE: no specification governs the cache: our own design, safe on
            // by default because the user list changes only at a restart.
            cache_ttl: ferrohealth_config::units::Duration::from_mins(5),
            cache_ttl_seconds: Removed::default(),
        }
    }
}
