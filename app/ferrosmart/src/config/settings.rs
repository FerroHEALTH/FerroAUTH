// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The checked settings the server runs on, resolved from [`Config`].

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ferrohealth_secret::file::require_secret;
use ferrohealth_server::section::ServerSection;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrohealth_smart::client::keys::KeyRing;
use ferrohealth_smart::client::outbound::OutboundClient;
use ferrohealth_smart::config::ServerTls;
use ihe_atna::atna::feed::FeedRepository;
use ihe_atna::balp::{NetworkAddress, Observer, SOURCE_SECURITY_SERVER};
use jsonwebtoken::Algorithm;
use secrecy::SecretString;
use url::Url;

use crate::clients::Client;
use crate::upstream::{Authentication, PrivateKeyJwtSection, Upstream, UpstreamSection};

use crate::config::error::Error;
use crate::config::{AuditSection, BrandingSection, Config, KeysSection};

/// The settings the server runs on.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The `[server]` section.
    pub server: ServerSection,
    /// The issuer identifier exactly as configured, which every document
    /// repeats, since a client holds the `issuer` it reads "identical" to
    /// the one it was configured with (RFC 8414 §3.3).
    pub issuer: String,
    /// The issuer identifier as a URL, for its path.
    pub issuer_url: Url,
    /// How long an access token lives.
    pub access_token_lifetime: Duration,
    /// How long an `offline_access` refresh token lasts unused.
    pub refresh_idle: Duration,
    /// How long an `online_access` refresh token lasts unused.
    pub online_idle: Duration,
    /// The keys that sign every token.
    pub keys: Arc<KeyRing>,
    /// The connection URL of the database.
    pub database_url: SecretString,
    /// The most connections one replica holds.
    pub max_connections: u32,
    /// The clients the configuration registers.
    pub clients: Vec<Client>,
    /// The base URLs of the resource servers, each as configured.
    pub resources: Vec<String>,
    /// The base URLs among them that serve openEHR.
    pub openehr_resources: Vec<String>,
    /// The subject namespace of each openEHR base that names one.
    pub subject_namespaces: BTreeMap<String, String>,
    /// The FHIR base each openEHR base that names one is paired with.
    pub pairings: BTreeMap<String, Pairing>,
    /// The upstream provider, when people log in.
    pub upstream: Option<Upstream>,
    /// The scopes each role may be granted.
    pub roles: BTreeMap<String, Vec<String>>,
    /// The deployment's name and words on the pages.
    pub branding: BrandingSection,
    /// Where every login and token is recorded.
    pub audit: AuditSettings,
}

/// The audit lane, resolved from `[ferrosmart.audit]`.
#[derive(Debug, Clone)]
pub struct AuditSettings {
    /// The Audit Record Repository's FHIR Feed, when the records are
    /// forwarded.
    pub feed: Option<FeedRepository>,
    /// FerroSMART as the recording system.
    pub observer: Observer,
}

impl Settings {
    /// Returns the absolute URL of the endpoint at `route` under the issuer,
    /// as the metadata names it (SMART App Launch 2.2.0, Conformance: "All
    /// endpoint URLs in the response document SHALL be absolute URLs").
    #[must_use]
    pub fn endpoint(&self, route: &str) -> String {
        format!("{}{route}", self.issuer.trim_end_matches('/'))
    }

    /// Returns [`Settings::endpoint`] as a URL.
    #[must_use]
    pub fn endpoint_url(&self, route: &str) -> Url {
        let mut url = self.issuer_url.clone();
        let path = format!("{}{route}", self.issuer_url.path().trim_end_matches('/'));
        url.set_path(&path);
        url
    }

    /// Returns the path of the RFC 8414 §3 metadata: the well-known suffix
    /// inserted between the host and the issuer's path.
    #[must_use]
    pub fn metadata_path(&self) -> String {
        format!(
            "/.well-known/oauth-authorization-server{}",
            self.issuer_url.path().trim_end_matches('/')
        )
    }
}

impl Config {
    /// Resolves the tree into the [`Settings`] the server runs on, reading
    /// the key files.
    ///
    /// # Errors
    /// Returns [`Error`] naming the first key the server cannot run with.
    pub fn resolve(&self) -> Result<Settings, Error> {
        let section = &self.ferrosmart;
        if section.issuer.is_empty() {
            return Err(Error::Missing {
                key: "ferrosmart.issuer",
            });
        }
        let issuer = ferrohealth_smart::metadata::issuer_url(&section.issuer)
            .map_err(|source| Error::Issuer { source })?;
        // NOTE: RFC 8414 §3, the metadata of an issuer with a path sits beside that
        // path, so the issuer's path is the one the routes are served under.
        if issuer.path().trim_end_matches('/') != self.server.base_path.as_str() {
            return Err(Error::IssuerPath);
        }
        if section.access_token_lifetime.is_zero() {
            return Err(Error::Zero {
                key: "ferrosmart.access_token_lifetime",
            });
        }
        // NOTE: SMART App Launch 2.2.0, App Launch, Response, access tokens SHOULD
        // have a valid lifetime no greater than one hour.
        if section.access_token_lifetime.get() > Duration::from_secs(3600) {
            return Err(Error::LongLifetime);
        }
        if section.refresh_idle.is_zero() {
            return Err(Error::Zero {
                key: "ferrosmart.refresh_idle",
            });
        }
        if section.online_idle.is_zero() {
            return Err(Error::Zero {
                key: "ferrosmart.online_idle",
            });
        }
        if section.database.max_connections == 0 {
            return Err(Error::Zero {
                key: "ferrosmart.database.max_connections",
            });
        }
        let database_url: SecretString = require_secret(
            "ferrosmart.database.url",
            section
                .database
                .url
                .as_ref()
                .map(ferrohealth_secret::secret::Secret::to_secret_string),
            section.database.url_file.as_deref(),
        )?;
        let keys = Arc::new(key_ring(&section.keys, &TOKEN_KEYS, Algorithm::RS256)?);
        Ok(Settings {
            server: self.server.clone(),
            issuer: section.issuer.clone(),
            issuer_url: issuer.clone(),
            access_token_lifetime: section.access_token_lifetime.get(),
            refresh_idle: section.refresh_idle.get(),
            online_idle: section.online_idle.get(),
            keys: Arc::clone(&keys),
            database_url,
            max_connections: section.database.max_connections,
            clients: crate::clients::resolve(&section.client)?,
            resources: resources(&section.resource)?,
            openehr_resources: section
                .resource
                .iter()
                .filter(|resource| resource.kind == crate::config::ResourceKind::Openehr)
                .map(|resource| resource.base.clone())
                .collect(),
            subject_namespaces: subject_namespaces(&section.resource)?,
            pairings: pairings(&section.resource)?,
            upstream: section
                .upstream
                .as_ref()
                .map(|upstream_section| upstream(upstream_section, &keys))
                .transpose()?,
            roles: roles(&section.role)?,
            branding: branding(&section.branding)?,
            audit: audit(&section.audit, &issuer)?,
        })
    }
}

/// Returns the audit lane `section` describes for the server at `issuer`.
fn audit(section: &AuditSection, issuer: &Url) -> Result<AuditSettings, Error> {
    let feed = section
        .feed
        .as_ref()
        .map(|endpoint| {
            let client = OutboundClient::build(endpoint, "ferrosmart.audit.feed", &ServerTls)
                .map_err(|source| Error::AuditFeed { source })?;
            let base = client.url().clone();
            let between_rounds = Duration::from(client.retry().max_backoff);
            FeedRepository::new(
                &base,
                Arc::new(crate::audit_feed::OutboundFeed(client)),
                between_rounds,
            )
            .map_err(|source| Error::AuditBase { source })
        })
        .transpose()?;
    let host = issuer.host_str().unwrap_or_default().to_owned();
    let source_id = if section.source_id.is_empty() {
        host.clone()
    } else {
        section.source_id.clone()
    };
    Ok(AuditSettings {
        feed,
        // NOTE: FHIR R4 security-source-type, 6 "Security Server": the system
        // that authenticates people and issues tokens.
        observer: Observer {
            source_id,
            site: section.site.clone(),
            host: NetworkAddress::host(&host),
            source_types: vec![SOURCE_SECURITY_SERVER],
        },
    })
}

/// Returns `section` once its style URL holds: empty, or an https URL.
fn branding(section: &BrandingSection) -> Result<BrandingSection, Error> {
    let style = &section.smart_style_url;
    // NOTE: SMART App Launch 2.2.0, App Launch, Styling: the app downloads the
    // document `smart_style_url` names, so it is an absolute https URL.
    if !style.is_empty() && Url::parse(style).map_or(true, |url| url.scheme() != "https") {
        return Err(Error::StyleUrl);
    }
    Ok(section.clone())
}

/// The configuration keys of one ring's three files, for its errors.
struct RingNames {
    /// The current key's file.
    current: &'static str,
    /// The previous key's file.
    previous: &'static str,
    /// The next key's file.
    next: &'static str,
}

/// The names of `[ferrosmart.keys]`, the ring that signs tokens.
const TOKEN_KEYS: RingNames = RingNames {
    current: "ferrosmart.keys.private_key_file",
    previous: "ferrosmart.keys.previous_private_key_file",
    next: "ferrosmart.keys.next_private_key_file",
};

/// The names of `[ferrosmart.upstream.private_key_jwt.keys]`, the ring that
/// signs client assertions to the upstream provider.
const ASSERTION_KEYS: RingNames = RingNames {
    current: "ferrosmart.upstream.private_key_jwt.keys.private_key_file",
    previous: "ferrosmart.upstream.private_key_jwt.keys.previous_private_key_file",
    next: "ferrosmart.upstream.private_key_jwt.keys.next_private_key_file",
};

/// Returns the ring `keys` names: the current key, the previous one for its
/// overlap and the next one, each read to sign with `algorithm`.
fn key_ring(keys: &KeysSection, names: &RingNames, algorithm: Algorithm) -> Result<KeyRing, Error> {
    let path = keys
        .private_key_file
        .as_deref()
        .ok_or(Error::Missing { key: names.current })?;
    let kid = (!keys.kid.is_empty()).then(|| keys.kid.clone());
    let mut ring = KeyRing::new(read_key(names.current, path, kid, algorithm)?);
    if let Some(path) = keys.previous_private_key_file.as_deref() {
        let previous = read_key(names.previous, path, None, algorithm)?;
        ring = if keys.previous_key_overlap.is_zero() {
            ring.with_previous_until_removed(previous)
        } else {
            ring.with_previous_for(previous, keys.previous_key_overlap.get())
        }
        .map_err(|source| Error::KeyRing { source })?;
    }
    if let Some(path) = keys.next_private_key_file.as_deref() {
        let next = read_key(names.next, path, None, algorithm)?;
        ring = ring
            .with_next(next)
            .map_err(|source| Error::KeyRing { source })?;
    }
    Ok(ring)
}

/// Reads the key at `path`, which `key` names, to sign with `algorithm`.
fn read_key(
    key: &'static str,
    path: &Path,
    kid: Option<String>,
    algorithm: Algorithm,
) -> Result<AssertionKey, Error> {
    let pem = std::fs::read(path).map_err(|source| Error::KeyFile {
        key,
        path: path.to_owned(),
        source,
    })?;
    AssertionKey::from_pem(&pem, Some(algorithm), kid).map_err(|source| Error::Key { key, source })
}

/// Returns the base URLs `sections` configure: at least one, each an
/// absolute `https` URL (a loopback host may be `http`) with no query and
/// no fragment, none twice.
fn resources(sections: &[crate::config::ResourceSection]) -> Result<Vec<String>, Error> {
    if sections.is_empty() {
        return Err(Error::Resource {
            rule: "at least one resource server is configured",
        });
    }
    let mut bases: Vec<String> = Vec::with_capacity(sections.len());
    for section in sections {
        // NOTE: SMART App Launch 2.2.0, the `aud` is the "URL of the EHR resource
        // server"; the loopback exception is the one `issuer_url` makes.
        ferrohealth_smart::metadata::issuer_url(&section.base)
            .map_err(|source| Error::ResourceBase { source })?;
        if bases.contains(&section.base) {
            return Err(Error::Resource {
                rule: "a base is configured twice",
            });
        }
        bases.push(section.base.clone());
    }
    Ok(bases)
}

/// Returns the subject namespace of each openEHR base in `sections` that
/// names one.
fn subject_namespaces(
    sections: &[crate::config::ResourceSection],
) -> Result<BTreeMap<String, String>, Error> {
    let mut namespaces = BTreeMap::new();
    for section in sections {
        let Some(namespace) = &section.subject_namespace else {
            continue;
        };
        // NOTE: openEHR ITS-REST 1.1.0, ehr_get_by_subject, the namespace is matched
        // against `EHR_STATUS.subject`, which only an openEHR server holds.
        if section.kind != crate::config::ResourceKind::Openehr {
            return Err(Error::Resource {
                rule: "a `subject_namespace` is for an openEHR base",
            });
        }
        if namespace.trim().is_empty() {
            return Err(Error::Resource {
                rule: "a `subject_namespace` is not empty",
            });
        }
        namespaces.insert(section.base.clone(), namespace.clone());
    }
    Ok(namespaces)
}

/// The FHIR server an openEHR base is paired with, and how one of its
/// patients names their EHR's subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    /// The FHIR base, one of the configured FHIR resource servers.
    pub fhir_base: String,
    /// The `system` of the `Patient.identifier` that carries the subject id.
    pub subject_system: String,
}

/// Returns the pairing of each openEHR base in `sections` that names a
/// `fhir_base`.
fn pairings(
    sections: &[crate::config::ResourceSection],
) -> Result<BTreeMap<String, Pairing>, Error> {
    let refuse = |rule| Err(Error::Resource { rule });
    let mut pairings = BTreeMap::new();
    for section in sections {
        let (fhir_base, subject_system) = match (&section.fhir_base, &section.subject_system) {
            (None, None) => continue,
            (Some(fhir_base), Some(subject_system)) => (fhir_base, subject_system),
            _ => return refuse("`fhir_base` and `subject_system` are set together"),
        };
        // NOTE: SMART on openEHR draft, Service Discovery, `org.fhir.rest` is the FHIR
        // API of a platform whose required service is `org.openehr.rest`.
        if section.kind != crate::config::ResourceKind::Openehr {
            return refuse("a `fhir_base` is for an openEHR base");
        }
        // NOTE: openEHR ITS-REST 1.1.0, ehr_get_by_subject, the EHR is looked up by
        // a subject id and its namespace, so a paired base names the namespace.
        if section.subject_namespace.is_none() {
            return refuse("a base with a `fhir_base` names its `subject_namespace`");
        }
        let fhir = sections.iter().any(|other| {
            other.kind == crate::config::ResourceKind::Fhir && &other.base == fhir_base
        });
        if !fhir {
            return refuse("a `fhir_base` is a configured FHIR `ferrosmart.resource` base");
        }
        if subject_system.trim().is_empty() {
            return refuse("a `subject_system` is not empty");
        }
        pairings.insert(
            section.base.clone(),
            Pairing {
                fhir_base: fhir_base.clone(),
                subject_system: subject_system.clone(),
            },
        );
    }
    Ok(pairings)
}

/// Returns the upstream provider `section` names, authenticating with
/// `keys`' current key under `private_key_jwt`.
fn upstream(section: &UpstreamSection, keys: &KeyRing) -> Result<Upstream, Error> {
    if section.issuer.is_empty() || section.client_id.is_empty() {
        return Err(Error::Upstream {
            rule: "`issuer` and `client_id` are set",
        });
    }
    let Some(jwt) = &section.private_key_jwt else {
        return Err(Error::Upstream {
            rule: "`[ferrosmart.upstream.private_key_jwt]` is set: FerroSMART authenticates to the provider by `private_key_jwt` alone",
        });
    };
    let authentication = assertion_keys(jwt, keys)?;
    let named = |claim: &String| !claim.is_empty();
    Ok(Upstream {
        issuer: section.issuer.clone(),
        client_id: section.client_id.clone(),
        authentication,
        scopes: section.scopes.clone(),
        fhir_user_claim: Some(section.fhir_user_claim.clone()).filter(named),
        role_claims: section
            .role_claims
            .iter()
            .filter(|claim| named(claim))
            .cloned()
            .collect(),
        trusted_audiences: section.trusted_audiences.clone(),
    })
}

/// Returns the assertion ring `section` names, signing at the algorithm of
/// the provider's registration and naming the certificate it knows the
/// current key by, once it holds none of `tokens`' keys.
fn assertion_keys(
    section: &PrivateKeyJwtSection,
    tokens: &KeyRing,
) -> Result<Authentication, Error> {
    const KEY: &str = "ferrosmart.upstream.private_key_jwt";
    let algorithm = section
        .algorithm
        .parse::<Algorithm>()
        .map_err(|_unknown| Error::Upstream {
            rule: "`private_key_jwt.algorithm` names a JWS algorithm (RFC 7518 §3.1)",
        })?;
    let ring = key_ring(&section.keys, &ASSERTION_KEYS, algorithm)?;
    // NOTE: RFC 8725 §3.12: a key that signs client assertions never signs a
    // token, so the two rings share no key.
    if shares_key(&ring.published(), &tokens.published()) {
        return Err(Error::Upstream {
            rule: "the assertion keys share no key with `[ferrosmart.keys]`",
        });
    }
    let mut key = ring.current().clone();
    if let Some(path) = section.certificate_file.as_deref() {
        let pem = std::fs::read(path).map_err(|source| Error::KeyFile {
            key: "ferrosmart.upstream.private_key_jwt.certificate_file",
            path: path.to_owned(),
            source,
        })?;
        key = key
            .with_certificate(&pem)
            .map_err(|source| Error::Key { key: KEY, source })?;
    }
    Ok(Authentication {
        signer: Box::new(key),
        ring: Arc::new(ring),
    })
}

/// Whether the JWK Sets `one` and `other` publish a key in common, compared
/// by its RFC 7638 members.
fn shares_key(one: &serde_json::Value, other: &serde_json::Value) -> bool {
    let members = |set: &serde_json::Value| -> Vec<String> {
        set.get("keys")
            .and_then(serde_json::Value::as_array)
            .map(|keys| {
                keys.iter()
                    .map(|key| {
                        ["kty", "crv", "n", "e", "x", "y"]
                            .iter()
                            .map(|name| key.get(*name).map(ToString::to_string).unwrap_or_default())
                            .collect::<Vec<_>>()
                            .join("|")
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let theirs = members(other);
    members(one).iter().any(|key| theirs.contains(key))
}

/// Returns the scopes of each role `sections` name: a role named once,
/// each scope a `user/` or `patient/` scope token (SMART App Launch 2.2.0,
/// Scopes and Launch Context), since a person's role grants a person's
/// access, never a system's.
fn roles(sections: &[crate::config::RoleSection]) -> Result<BTreeMap<String, Vec<String>>, Error> {
    let mut roles = BTreeMap::new();
    for section in sections {
        if !ferrohealth_smart::roles::is_role(&section.name) {
            return Err(Error::Role {
                rule: "a role has no name, or one with a space",
            });
        }
        let person = section.scopes.iter().all(|scope| {
            ferrohealth_smart::scope::is_scope_token(scope)
                && (scope.starts_with("user/") || scope.starts_with("patient/"))
        });
        if !person {
            return Err(Error::Role {
                rule: "a role grants a scope other than a user/ or patient/ one",
            });
        }
        if roles
            .insert(section.name.clone(), section.scopes.clone())
            .is_some()
        {
            return Err(Error::Role {
                rule: "a role is named twice",
            });
        }
    }
    Ok(roles)
}
