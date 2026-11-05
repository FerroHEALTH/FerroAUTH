// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The resource-server role: who calls, and what the caller's access token
//! permits.
//!
//! One [`ResourceServer`] validates the access tokens of one authorization
//! server. The issuer and the audiences are configured; the issuer's
//! metadata (RFC 8414 §3, with `OpenID` Connect Discovery 1.0 §4 as the
//! fallback location) names the key set (RFC 7517) every token signature is
//! checked against, or a key set file handed over out of band does. A token
//! is an RFC 7519 JWT, read under the RFC 9068 access token profile unless
//! the deployment says otherwise. A product that trusts several issuers
//! holds them in an [`IssuerSet`]. [`ResourceServer::lazy`] defers the
//! metadata and key set read to the first token, for a product that answers
//! an unreachable issuer with `503` rather than refusing to start. A product
//! that checks a token another
//! way (RFC 7662 introspection, a signed edge assertion) implements
//! [`Verifier`] beside them. A product never forwards a caller's token
//! upstream: an access token names the resource server it is for (RFC 9068
//! §4), and an upstream is reached with the product's own credential
//! ([`crate::client`]).

mod caller;
pub mod configuration;
#[cfg(feature = "fetch")]
pub mod introspection;
mod jwks;
mod set;
mod token;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use http::Extensions;
use http::StatusCode;
use jsonwebtoken::Algorithm;
use url::Url;

use crate::assurance::Assessment;
use crate::assurance::AssuranceError;
use crate::assurance::AssuranceSection;
use crate::kind::CallerKind;
use crate::kind::IssuerKind;
use crate::kind::Unclassified;
use crate::metadata::DiscoveryError;
#[cfg(feature = "fetch")]
use crate::metadata::Http;
use crate::metadata::ServerMetadata;
use crate::profile::Profile;
use crate::profile::ProfileError;
use crate::refusal::Reason;
use crate::resource::jwks::KeySet;
use crate::resource::jwks::KeySource;
use crate::scope::Scopes;

/// The longest clock skew a deployment may configure: RFC 7519 §4.1.4
/// allows "some small leeway, usually no more than a few minutes".
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(300);

/// What one deployment configured its resource server with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// The issuer identifier every token's `iss` must equal (RFC 8414 §2).
    pub issuer: String,
    /// The audiences, of which every token's `aud` must contain one
    /// (RFC 9068 §4); at least one.
    pub audience: Vec<String>,
    /// The signature algorithms a token may use; asymmetric only (RFC 8725
    /// §3.1, §3.2), which [`Settings::validate`] checks.
    pub algorithms: Vec<Algorithm>,
    /// Whose tokens the issuer signs.
    pub kind: IssuerKind,
    /// What the issuer's tokens look like and how their callers are
    /// classified.
    pub profile: Profile,
    /// The clock skew `exp`, `nbf` and `iat` are checked with, at most
    /// [`MAX_CLOCK_SKEW`].
    pub clock_skew: Duration,
    /// How long a held key set is used before it is read again.
    pub jwks_max_age: Duration,
    /// The shortest time between two reads of the key set an unknown `kid`
    /// or a failed read triggers.
    pub jwks_refresh_interval: Duration,
    /// A JWK Set file handed over out of band, read in place of the
    /// issuer's `jwks_uri`; the issuer's metadata is then not read.
    pub jwks_file: Option<PathBuf>,
    /// How long one call to the authorization server may take.
    pub timeout: Duration,
    /// The subjects a token with no clinical scope is granted system-wide
    /// access for (a product's allowlist; no specification governs it: our
    /// own design).
    pub scopeless_subjects: BTreeSet<String>,
    /// The claims a token's roles are read from, each a dotted path
    /// (RFC 9068 §2.2.3.1; [`crate::roles`]).
    pub role_claims: Vec<String>,
    /// The assurance level the issuer's tokens carry, when the deployment
    /// maps its authentication context values.
    pub assurance: Option<AssuranceSection>,
    /// PEM trust roots added to the platform's for the discovery document
    /// and the key set, for an issuer behind a private certificate
    /// authority; none trusts the platform roots alone.
    pub trust_roots: Option<Vec<u8>>,
}

impl Settings {
    /// Returns settings for tokens of `issuer`, an issuer of `kind`,
    /// addressed to `audience`.
    ///
    /// RS256, RS384, PS256, PS384, ES256 and ES384 are accepted under the
    /// `rfc9068` profile, the clock skew is 60 seconds, the key set is used
    /// for 600 seconds and read again at most once a minute, a call to the
    /// authorization server may take 10 seconds, and no subject is granted
    /// scopeless access.
    #[must_use]
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>, kind: IssuerKind) -> Self {
        Self {
            issuer: issuer.into(),
            audience: vec![audience.into()],
            algorithms: vec![
                Algorithm::RS256,
                Algorithm::RS384,
                Algorithm::PS256,
                Algorithm::PS384,
                Algorithm::ES256,
                Algorithm::ES384,
            ],
            kind,
            profile: Profile::default(),
            clock_skew: Duration::from_secs(60),
            jwks_max_age: Duration::from_secs(600),
            jwks_refresh_interval: Duration::from_secs(60),
            jwks_file: None,
            timeout: Duration::from_secs(10),
            scopeless_subjects: BTreeSet::new(),
            // NOTE: no specification governs this: our own design; another party's
            // issuer asserts no role of this deployment.
            role_claims: if kind == IssuerKind::Federation {
                Vec::new()
            } else {
                crate::roles::default_claims()
            },
            assurance: None,
            trust_roots: None,
        }
    }

    /// Checks the settings: the issuer URL rule, at least one audience, at
    /// least one algorithm and none symmetric, and the clock skew bound.
    ///
    /// # Errors
    ///
    /// Returns the [`ResourceError`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), ResourceError> {
        crate::metadata::issuer_url(&self.issuer)?;
        if self.audience.iter().all(String::is_empty) {
            return Err(ResourceError::NoAudience);
        }
        if self.algorithms.is_empty() {
            return Err(ResourceError::NoAlgorithm);
        }
        if let Some(algorithm) = self.algorithms.iter().find(|algorithm| {
            matches!(
                algorithm,
                Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
            )
        }) {
            return Err(ResourceError::SymmetricAlgorithm {
                algorithm: *algorithm,
            });
        }
        if self.clock_skew > MAX_CLOCK_SKEW {
            return Err(ResourceError::ClockSkew {
                skew: self.clock_skew,
            });
        }
        check_issuer_rules(
            self.kind,
            &self.profile,
            self.assurance.as_ref(),
            &self.scopeless_subjects,
            &self.role_claims,
        )
    }
}

/// Checks what an issuer of `kind` is configured with beside its keys: its
/// profile, its assurance mapping, and the settings its kind refuses.
fn check_issuer_rules(
    kind: IssuerKind,
    profile: &Profile,
    assurance: Option<&AssuranceSection>,
    scopeless_subjects: &BTreeSet<String>,
    role_claims: &[String],
) -> Result<(), ResourceError> {
    profile.validate(kind)?;
    if let Some(assurance) = assurance {
        assurance.validate()?;
    }
    // NOTE: no specification governs the allowlist: our own design; a patient
    // or another party is never granted system-wide access.
    if !scopeless_subjects.is_empty()
        && matches!(kind, IssuerKind::Patients | IssuerKind::Federation)
    {
        return Err(ResourceError::Kind {
            key: "scopeless_subjects",
            kind,
        });
    }
    // NOTE: no specification governs this: our own design; another party's
    // issuer asserts no role of this deployment.
    if !role_claims.is_empty() && kind == IssuerKind::Federation {
        return Err(ResourceError::Kind {
            key: "role_claims",
            kind,
        });
    }
    Ok(())
}

/// A failure to reach or read the authorization server, or settings that
/// break a rule.
///
/// No variant carries a token.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResourceError {
    /// The metadata could not be read, or the issuer is outside the URL
    /// rule.
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    /// The settings admit a symmetric algorithm, which RFC 8725 §3.1 and
    /// §3.2 have a verifier refuse: a key of the issuer's set would then
    /// sign a token.
    #[error("the settings admit the symmetric algorithm {algorithm:?}")]
    SymmetricAlgorithm {
        /// The algorithm admitted.
        algorithm: Algorithm,
    },
    /// The settings admit no algorithm at all.
    #[error("the settings admit no signature algorithm")]
    NoAlgorithm,
    /// The settings name no audience (RFC 8725 §3.9 has a token without a
    /// recognized audience refused, so one must be expected).
    #[error("the settings name no audience")]
    NoAudience,
    /// The clock skew is longer than [`MAX_CLOCK_SKEW`].
    #[error("the clock skew of {skew:?} is longer than {MAX_CLOCK_SKEW:?}")]
    ClockSkew {
        /// The skew configured.
        skew: Duration,
    },
    /// The issuer's profile breaks a rule.
    #[error(transparent)]
    Profile(#[from] ProfileError),
    /// The issuer's assurance mapping breaks a rule.
    #[error(transparent)]
    Assurance(#[from] AssuranceError),
    /// A setting is refused on an issuer of this kind.
    #[error("{key} is refused on a {kind} issuer")]
    Kind {
        /// The setting.
        key: &'static str,
        /// The issuer's kind.
        kind: IssuerKind,
    },
    /// The metadata names no member the resource server needs.
    #[error("the authorization server metadata names no {member}")]
    MissingMember {
        /// The member it lacks.
        member: &'static str,
    },
    /// The metadata names a `jwks_uri` that is not a URL.
    #[error("the authorization server metadata names a jwks_uri that is not a URL")]
    JwksUrl {
        /// What the URL parser reported.
        #[source]
        source: url::ParseError,
    },
    /// The key set location answered anything other than `200`.
    #[error("the key set at {url} answered {status}")]
    KeySetStatus {
        /// The location.
        url: Url,
        /// The status it answered.
        status: StatusCode,
        /// The body it answered, as received.
        body: String,
    },
    /// The key set file could not be read.
    #[error("the key set file {} could not be read", path.display())]
    KeySetFile {
        /// The file.
        path: PathBuf,
        /// What the file system reported.
        #[source]
        source: std::io::Error,
    },
    /// The key set is not the JSON object RFC 7517 §5 describes.
    #[error("the key set at {origin} is not a JWK Set")]
    KeySet {
        /// Where it was read from.
        origin: KeySource,
        /// What the JSON reader reported.
        #[source]
        error: serde_json::Error,
    },
    /// An object of the key set repeats a member name, whose meaning
    /// RFC 8259 §4 leaves to each parser.
    #[error("the key set at {origin} repeats a member name")]
    KeySetRepeatedName {
        /// Where it was read from.
        origin: KeySource,
        /// What the JSON reader reported, with the position.
        #[source]
        error: serde_json::Error,
    },
    /// The settings name no `jwks_file`, and the crate is built without the
    /// `fetch` feature that reads the issuer's metadata and its `jwks_uri`.
    #[error("the settings name no jwks_file, and this build reads no key set over HTTP")]
    KeySetFileRequired,
    /// The key set was not read again, because a read failed within the
    /// refresh interval.
    #[error("the key set at {origin} failed to read within the refresh interval")]
    KeySetBackoff {
        /// Where it is read from.
        origin: KeySource,
    },
    /// Operator-supplied metadata was offered to a resource server that read
    /// its metadata from the issuer, whose own document stands.
    #[error("the metadata of this issuer was read from the issuer and is not replaced")]
    MetadataFetched,
    /// Operator-supplied metadata names another issuer than the configured
    /// one (RFC 8414 §3.3).
    #[error("the supplied metadata names the issuer {found:?}, not the configured one")]
    MetadataIssuer {
        /// The issuer the metadata names.
        found: String,
    },
    /// Operator-supplied metadata names a location that is not a URL.
    #[error("the supplied metadata names a {member} that is not a URL")]
    MetadataUrl {
        /// The member.
        member: &'static str,
        /// What the URL parser reported.
        #[source]
        source: url::ParseError,
    },
}

/// The resource types a clinical scope may name, when a product holds a
/// table.
type ResourceTypes = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// The resource server: the configured authorization server, its metadata
/// and its key set.
pub struct ResourceServer {
    /// What the deployment configured.
    settings: Settings,
    /// The authorization server's metadata, read at boot; only the issuer
    /// when the key set comes from a file.
    metadata: ServerMetadata,
    /// The signing keys.
    keys: KeySet,
    /// The resource types a clinical scope may name, when the product holds
    /// a table; the lexical rule of [`Scopes::parse`] otherwise.
    resource_types: Option<ResourceTypes>,
    /// The product's values copied onto every caller this server admits.
    extensions: Extensions,
}

impl std::fmt::Debug for ResourceServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceServer")
            .field("settings", &self.settings)
            .field("metadata", &self.metadata)
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

impl ResourceServer {
    /// Reads the metadata and the key set of the authorization server
    /// `settings` names.
    ///
    /// Both are read once here, so an authorization server that cannot be
    /// reached refuses the start rather than the first request. With a
    /// `jwks_file`, the file is read and the metadata is not; without the
    /// `fetch` feature, a `jwks_file` is the one key source.
    ///
    /// # Errors
    ///
    /// Returns every [`ResourceError`]: the settings break a rule, the
    /// metadata or the key set could not be read, the metadata names
    /// another issuer, no `jwks_uri` or an insecure one, or, without the
    /// `fetch` feature, the settings name no `jwks_file`.
    pub async fn discover(settings: Settings) -> Result<Self, ResourceError> {
        settings.validate()?;
        #[cfg(feature = "fetch")]
        let http = match &settings.trust_roots {
            Some(roots) => Http::with_tls(
                settings.timeout,
                &crate::client::Tls {
                    root_certificates: Some(roots.clone()),
                    identity: None,
                },
            )?,
            None => Http::new(settings.timeout)?,
        };
        let (metadata, source) = if let Some(path) = &settings.jwks_file {
            let metadata = ServerMetadata {
                issuer: settings.issuer.clone(),
                ..ServerMetadata::default()
            };
            (metadata, KeySource::File(path.clone()))
        } else {
            #[cfg(feature = "fetch")]
            {
                let metadata = http.discover(&settings.issuer).await?;
                let jwks_uri = metadata
                    .jwks_uri
                    .as_deref()
                    .ok_or(ResourceError::MissingMember { member: "jwks_uri" })?
                    .parse::<Url>()
                    .map_err(|source| ResourceError::JwksUrl { source })?;
                crate::metadata::secure(&jwks_uri, "the jwks_uri")?;
                (metadata, KeySource::Uri(jwks_uri))
            }
            #[cfg(not(feature = "fetch"))]
            return Err(ResourceError::KeySetFileRequired);
        };
        let keys = KeySet::load(
            #[cfg(feature = "fetch")]
            http,
            source,
            settings.jwks_max_age,
            settings.jwks_refresh_interval,
        )
        .await?;
        // NOTE: no specification governs this: our own design; the count is read
        // before the log line, so no formatting argument is held across an await
        // and the future stays `Send`.
        let count = keys.len().await;
        tracing::info!(
            issuer = %settings.issuer,
            keys = count,
            source = %keys.source(),
            "validating access tokens of this issuer"
        );
        Ok(Self {
            settings,
            metadata,
            keys,
            resource_types: None,
            extensions: Extensions::new(),
        })
    }

    /// Returns a resource server for `settings` that reads the metadata and
    /// the key set when the first token needs them.
    ///
    /// The settings are checked here, so a broken rule still refuses the
    /// start. A read that fails answers that token, and every token inside
    /// `jwks_refresh_interval`, with [`Rejection::Unavailable`] (`503`), and
    /// the next token after the interval reads again. No specification
    /// governs when the key set is first read: our own design.
    ///
    /// # Errors
    ///
    /// Returns the [`ResourceError`] of [`Settings::validate`], or, without
    /// the `fetch` feature, [`ResourceError::KeySetFileRequired`] when the
    /// settings name no `jwks_file`.
    pub fn lazy(settings: Settings) -> Result<LazyResourceServer, ResourceError> {
        settings.validate()?;
        #[cfg(not(feature = "fetch"))]
        if settings.jwks_file.is_none() {
            return Err(ResourceError::KeySetFileRequired);
        }
        Ok(LazyResourceServer {
            settings,
            resource_types: None,
            extensions: Extensions::new(),
            server: tokio::sync::OnceCell::new(),
            failed: Mutex::new(None),
        })
    }

    /// Returns this resource server copying `value` onto every caller it
    /// admits, which a handler reads with [`Caller::extension`].
    ///
    /// This is how a product attaches its own per-issuer policy to the
    /// callers of that issuer; the crate reads one extension, the
    /// [`PatientClaim`] (no specification governs this: our own design).
    #[must_use]
    pub fn with_extension<T: Clone + Send + Sync + 'static>(mut self, value: T) -> Self {
        self.extensions.insert(value);
        self
    }

    /// Returns this resource server reading a clinical scope's resource type
    /// against `known`, in place of the lexical rule.
    #[must_use]
    pub fn with_resource_types(
        mut self,
        known: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.resource_types = Some(Arc::new(known));
        self
    }

    /// Returns this resource server with `metadata`, supplied by the
    /// operator, as its authorization server's, for a key set read from a
    /// `jwks_file`, whose issuer metadata is otherwise unknown.
    ///
    /// The SMART discovery document is built from it, so a `jwks_file`
    /// issuer can name the `token_endpoint` SMART App Launch 2.2.0
    /// (Conformance, Metadata) requires. The metadata must name the
    /// configured issuer, as RFC 8414 §3.3 holds a fetched document to, and
    /// every location it names, each member of [`ServerMetadata::endpoints`]
    /// with the mutual-TLS token alias, is held to the `https` rule of
    /// RFC 8414 §2.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceError::MetadataFetched`] when the metadata was read
    /// from the issuer, [`ResourceError::MetadataIssuer`] for another
    /// issuer, [`ResourceError::MetadataUrl`] for a location that is not a
    /// URL, and [`ResourceError::Discovery`] for one outside the `https`
    /// rule.
    pub fn with_metadata(mut self, metadata: ServerMetadata) -> Result<Self, ResourceError> {
        if self.settings.jwks_file.is_none() {
            return Err(ResourceError::MetadataFetched);
        }
        if crate::metadata::check_issuer(&self.settings.issuer, &metadata.issuer).is_err() {
            return Err(ResourceError::MetadataIssuer {
                found: metadata.issuer,
            });
        }
        for (member, location) in metadata.endpoints() {
            let url = location
                .parse::<Url>()
                .map_err(|source| ResourceError::MetadataUrl { member, source })?;
            crate::metadata::secure(&url, member)?;
        }
        self.metadata = metadata;
        Ok(self)
    }

    /// Returns what the deployment configured.
    #[must_use]
    pub const fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Returns the authorization server's metadata as read at boot.
    #[must_use]
    pub const fn metadata(&self) -> &ServerMetadata {
        &self.metadata
    }

    /// Returns the caller `token` authenticates.
    ///
    /// # Errors
    ///
    /// Returns [`Rejection::Invalid`] for a token whose signature, issuer,
    /// audience, lifetime or claims do not hold, and
    /// [`Rejection::Unavailable`] when the key set could not be read again.
    pub async fn authenticate(&self, token: &str) -> Result<Caller, Rejection> {
        token::validate(self, token).await
    }

    /// Returns the SMART discovery document of this resource server under
    /// `options`.
    #[must_use]
    pub fn smart_configuration(&self, options: &configuration::SmartOptions) -> serde_json::Value {
        configuration::document(&self.metadata, options)
    }
}

/// How a bearer token is checked.
///
/// [`ResourceServer`] checks a JWT against the issuer's key set; a product
/// that checks a token another way (RFC 7662 introspection for a token that
/// is no JWS, a signed assertion of a trusted edge) implements this beside
/// it, so the gate, the [`Access`] and the audit line are shared and only
/// the check differs.
pub trait Verifier: Send + Sync + 'static {
    /// Returns the caller `token` authenticates, or why it does not.
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>>;
}

impl Verifier for ResourceServer {
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>> {
        Box::pin(self.authenticate(token))
    }
}

/// A resource server whose metadata and key set are read when the first
/// token needs them ([`ResourceServer::lazy`]).
pub struct LazyResourceServer {
    /// What the deployment configured.
    settings: Settings,
    /// The resource types a clinical scope may name, when the product holds
    /// a table.
    resource_types: Option<ResourceTypes>,
    /// The product's values copied onto every caller this server admits.
    extensions: Extensions,
    /// The resource server, once a read succeeded.
    server: tokio::sync::OnceCell<Arc<ResourceServer>>,
    /// When the last read failed and why, so the next is not made inside
    /// the refresh interval.
    failed: Mutex<Option<(Instant, Arc<ResourceError>)>>,
}

impl std::fmt::Debug for LazyResourceServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyResourceServer")
            .field("settings", &self.settings)
            .field("server", &self.server.get())
            .finish_non_exhaustive()
    }
}

/// The resource servers of several trusted issuers, each token routed to
/// the one its `iss` names.
///
/// The `iss` is read from the payload before the signature is checked, as
/// RFC 7519 §7.2 lets a recipient do to select the key; the server it
/// names then checks everything, the issuer included.
#[derive(Debug, Default)]
pub struct IssuerSet {
    /// The servers, by issuer identifier.
    servers: BTreeMap<String, set::Trusted>,
}

/// Why a request carries no usable identity.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Rejection {
    /// No bearer token arrived.
    #[error("the request carries no bearer token")]
    Missing,
    /// The token does not hold.
    #[error("the access token is not valid: {reason}")]
    Invalid {
        /// Which check failed, for the log; never a claim value.
        reason: Reason,
    },
    /// The token is valid and matches no step of the caller classification
    /// for its issuer's kind ([`crate::kind`]); answered as an invalid token.
    #[error("the access token names no caller this issuer may: {reason}")]
    Unclassified {
        /// Which step refused it, for the log; never a claim value.
        reason: Unclassified,
    },
    /// The key set could not be read to check the token.
    #[error("the authorization server's key set could not be read")]
    Unavailable {
        /// What failed.
        #[source]
        source: Arc<ResourceError>,
    },
    /// An upstream a product's own [`Verifier`] calls (an RFC 7662
    /// introspection endpoint) could not be reached or read, so the token
    /// was not checked. It answers `503`, as [`Rejection::Unavailable`]
    /// does.
    #[error("the {upstream} could not be reached to check the access token")]
    Upstream {
        /// What could not be reached, for the log.
        upstream: &'static str,
        /// What failed, the product's own error.
        #[source]
        source: Arc<dyn std::error::Error + Send + Sync + 'static>,
    },
}

impl Rejection {
    /// Returns the rejection of a token a product's own verifier could not
    /// check, because `upstream` failed with `source`.
    #[must_use]
    pub fn upstream(
        upstream: &'static str,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Upstream {
            upstream,
            source: Arc::new(source),
        }
    }
}

/// What a product honours for a caller beyond a `user/` grant under the
/// SMART on openEHR grammar, read from its issuer or client lists.
///
/// No specification governs these: our own design, FerroFED's, over the
/// draft's own notes (`master08 §Resource Scopes` on `system/aql-*`,
/// `master07 §Context Selection` on the `ehrId`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Honoured {
    /// The caller is a backend client the product lists, so a
    /// `system/aql-*` grant counts.
    pub backend: bool,
    /// The caller's issuer is bound to the product's own EHR space, so a
    /// `patient/` grant counts on an EHR's data, confined to the `ehrId` of
    /// the launch context.
    pub patient: bool,
}

/// The scheme a credential arrived with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// A bearer token (RFC 6750).
    Bearer,
    /// A Basic credential (RFC 7617).
    Basic,
}

impl Via {
    /// Returns the name the audit line records.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::Basic => "basic",
        }
    }
}

/// The identity one valid credential carries.
///
/// Two callers are equal when everything but their extensions is.
#[derive(Debug, Clone)]
pub struct Caller {
    /// The token's `sub`, or the Basic user-id.
    subject: String,
    /// The client the issuer profile's client claims name, when the token
    /// names one.
    client_id: Option<String>,
    /// Who stands behind the credential.
    kind: CallerKind,
    /// The value of the issuer profile's person key and tenant claim, when
    /// the token carries them.
    person_key: (Option<String>, Option<String>),
    /// What the token says about the authentication behind it, under the
    /// issuer's assurance mapping.
    assurance: Assessment,
    /// Every token of the `scope` claim, as granted.
    scope: Vec<String>,
    /// The clinical scopes among them.
    scopes: Scopes,
    /// The `patient` launch context the token carries.
    patient: Option<String>,
    /// Whether the subject is granted system-wide access without a clinical
    /// scope.
    scopeless: bool,
    /// The scheme the credential arrived with.
    via: Via,
    /// The issuer that signed the token, when one did.
    issuer: Option<String>,
    /// Every claim of the token, for the product's own reading.
    claims: serde_json::Map<String, serde_json::Value>,
    /// The roles the token's claims or the Basic user's configuration grant.
    roles: Vec<String>,
    /// Whether a Basic credential was admitted from the verified-credential
    /// cache, without the key derivation.
    cached: bool,
    /// The product's own values, attached by its resource server or its
    /// verifier.
    extensions: Extensions,
}

impl PartialEq for Caller {
    fn eq(&self, other: &Self) -> bool {
        self.subject == other.subject
            && self.client_id == other.client_id
            && self.kind == other.kind
            && self.person_key == other.person_key
            && self.assurance == other.assurance
            && self.scope == other.scope
            && self.scopes == other.scopes
            && self.patient == other.patient
            && self.scopeless == other.scopeless
            && self.via == other.via
            && self.issuer == other.issuer
            && self.claims == other.claims
            && self.roles == other.roles
            && self.cached == other.cached
    }
}

impl Eq for Caller {}

/// Which resources one permission reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compartment {
    /// Every resource of the type.
    Any,
    /// Only the compartment of the patient with this id, the `patient`
    /// launch context of the token.
    Patient(String),
}

/// The patient a request of the person's own access is bound to, as its
/// token names it ([`Caller::person`]).
///
/// Each field is what one source names, `None` when the token carries no
/// such value; a product reads the one its own identifiers live in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PersonContext<'a> {
    /// The `patient` launch context (SMART App Launch 2.2.0, Scopes and
    /// Launch Context, §Launch context arrives with your `access_token`).
    pub patient: Option<&'a str>,
    /// The `ehrId` of the SMART on openEHR launch context (`master07
    /// §Context Selection`).
    pub ehr_id: Option<&'a str>,
    /// The value of the deployment's [`PatientClaim`].
    pub claim: Option<&'a str>,
}

/// The claim a deployment names the patient of a person's own token in, a
/// dotted path such as `patient_id` or `person.patient_id`.
///
/// A product attaches it to its resource server with `with_extension`, so
/// every caller that server admits carries it, and
/// [`Caller::person`] reads it. No specification names such a
/// claim: our own design, FerroEHR's ABAC patient claim moved here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatientClaim(String);

/// A [`PatientClaim`] path that is blank, has an empty step, or carries
/// whitespace.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the patient claim path is blank, has an empty step or carries whitespace")]
pub struct PatientClaimError;

impl PatientClaim {
    /// Returns the claim at the dotted `path`.
    ///
    /// # Errors
    ///
    /// [`PatientClaimError`] when `path` is blank, has an empty step, or
    /// carries whitespace, which would name no claim.
    pub fn new(path: impl Into<String>) -> Result<Self, PatientClaimError> {
        let path = path.into();
        if path.split('.').any(str::is_empty) || path.contains(char::is_whitespace) {
            return Err(PatientClaimError);
        }
        Ok(Self(path))
    }

    /// Returns the dotted path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.0
    }
}

/// What a request may do, as the gate established it.
///
/// Every request through the gate carries one as an extension, so a handler
/// that finds none is outside the gate, which fails the request.
#[derive(Debug, Clone)]
pub enum Access {
    /// Inbound authentication is off: the surface is open.
    Open,
    /// A caller with a valid credential.
    Caller(Arc<Caller>),
}

#[cfg(test)]
mod tests {
    use super::{MAX_CLOCK_SKEW, ResourceError, Settings};
    use crate::kind::IssuerKind;
    use std::time::Duration;

    #[test]
    fn the_settings_rules_refuse_the_start() {
        let mut settings = Settings::new("https://as.example.org", "aud", IssuerKind::Persons);
        assert!(settings.validate().is_ok());
        settings.clock_skew = MAX_CLOCK_SKEW + Duration::from_secs(1);
        assert!(matches!(
            settings.validate(),
            Err(ResourceError::ClockSkew { .. })
        ));
        let mut settings = Settings::new("https://as.example.org", "", IssuerKind::Persons);
        assert!(matches!(
            settings.validate(),
            Err(ResourceError::NoAudience)
        ));
        settings.audience = vec![String::from("aud")];
        settings.issuer = String::from("http://as.example.org");
        assert!(matches!(
            settings.validate(),
            Err(ResourceError::Discovery(_))
        ));
    }
}
