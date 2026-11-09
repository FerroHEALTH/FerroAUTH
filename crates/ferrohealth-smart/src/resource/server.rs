// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The behaviour of [`ResourceServer`]: reading the issuer's metadata and
//! key set, the product's extensions, and the check of a token, also as
//! the crate's own [`Verifier`].

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use http::Extensions;
use url::Url;

#[cfg(feature = "fetch")]
use crate::metadata::Http;
use crate::metadata::ServerMetadata;
use crate::resource::Caller;
use crate::resource::LazyResourceServer;
use crate::resource::Rejection;
use crate::resource::ResourceError;
use crate::resource::ResourceServer;
use crate::resource::Settings;
use crate::resource::Verifier;
use crate::resource::configuration;
use crate::resource::jwks::KeySet;
use crate::resource::jwks::KeySource;
use crate::resource::token;
use crate::sender::Binding;

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
                    presented: None,
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
    /// [`PatientClaim`](crate::resource::PatientClaim) (no specification governs
    /// this: our own design).
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
        token::validate(self, token, &Binding::bearer()).await
    }

    /// Returns the caller `token` authenticates, its `cnf` held to what
    /// `binding` proves and to the issuer's sender constraint
    /// ([`crate::sender`]).
    ///
    /// # Errors
    ///
    /// Returns every [`Rejection`] of [`ResourceServer::authenticate`], and
    /// [`Rejection::Invalid`] naming the [`Check`](crate::sender::Check) for a
    /// token whose binding does not hold.
    pub async fn authenticate_bound(
        &self,
        token: &str,
        binding: &Binding,
    ) -> Result<Caller, Rejection> {
        token::validate(self, token, binding).await
    }

    /// Returns the SMART discovery document of this resource server under
    /// `options`.
    #[must_use]
    pub fn smart_configuration(&self, options: &configuration::SmartOptions) -> serde_json::Value {
        configuration::document(&self.metadata, options)
    }
}

impl Verifier for ResourceServer {
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>> {
        Box::pin(self.authenticate(token))
    }

    fn verify_bound<'a>(
        &'a self,
        token: &'a str,
        binding: &'a Binding,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>> {
        Box::pin(self.authenticate_bound(token, binding))
    }
}
