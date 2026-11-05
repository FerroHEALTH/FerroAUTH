// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The behaviour of [`LazyResourceServer`] and [`IssuerSet`]: a server read
//! on its first token, and the routing of each token to its issuer.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::PoisonError;
use std::time::Instant;

use base64::Engine as _;

use crate::refusal::Reason;
use crate::resource::Caller;
use crate::resource::IssuerSet;
use crate::resource::LazyResourceServer;
use crate::resource::Rejection;
use crate::resource::ResourceError;
use crate::resource::ResourceServer;
use crate::resource::Settings;
use crate::resource::Verifier;

impl LazyResourceServer {
    /// Returns this server reading a clinical scope's resource type against
    /// `known`, as [`ResourceServer::with_resource_types`] does.
    #[must_use]
    pub fn with_resource_types(
        mut self,
        known: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.resource_types = Some(Arc::new(known));
        self
    }

    /// Returns this server copying `value` onto every caller it admits, as
    /// [`ResourceServer::with_extension`] does.
    #[must_use]
    pub fn with_extension<T: Clone + Send + Sync + 'static>(mut self, value: T) -> Self {
        self.extensions.insert(value);
        self
    }

    /// Returns what the deployment configured.
    #[must_use]
    pub const fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Returns the resource server, when a read has succeeded.
    #[must_use]
    pub fn get(&self) -> Option<&Arc<ResourceServer>> {
        self.server.get()
    }

    /// Returns the resource server, reading the issuer's metadata and key
    /// set when no read has succeeded yet.
    ///
    /// Concurrent first tokens share one read.
    ///
    /// # Errors
    ///
    /// Returns [`Rejection::Unavailable`] when the read fails, or failed
    /// within the refresh interval.
    pub async fn server(&self) -> Result<&Arc<ResourceServer>, Rejection> {
        if let Some(server) = self.server.get() {
            return Ok(server);
        }
        let interval = self.settings.jwks_refresh_interval;
        let recent = self
            .failed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|(at, _)| at.elapsed() < interval)
            .map(|(_, source)| Arc::clone(source));
        if let Some(source) = recent {
            return Err(Rejection::Unavailable { source });
        }
        self.server
            .get_or_try_init(|| async {
                let mut server = ResourceServer::discover(self.settings.clone()).await?;
                server.resource_types.clone_from(&self.resource_types);
                server.extensions = self.extensions.clone();
                Ok(Arc::new(server))
            })
            .await
            .map_err(|source: ResourceError| {
                let source = Arc::new(source);
                tracing::warn!(
                    issuer = %self.settings.issuer,
                    error = %source,
                    "the issuer's metadata or key set could not be read; its tokens answer 503"
                );
                *self.failed.lock().unwrap_or_else(PoisonError::into_inner) =
                    Some((Instant::now(), Arc::clone(&source)));
                Rejection::Unavailable { source }
            })
    }

    /// Returns the caller `token` authenticates, reading the issuer first
    /// when no read has succeeded yet.
    ///
    /// # Errors
    ///
    /// Returns the [`Rejection`] of [`ResourceServer::authenticate`], and
    /// [`Rejection::Unavailable`] when the issuer cannot be read.
    pub async fn authenticate(&self, token: &str) -> Result<Caller, Rejection> {
        self.server().await?.authenticate(token).await
    }
}

impl Verifier for LazyResourceServer {
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>> {
        Box::pin(self.authenticate(token))
    }
}

/// One issuer of an [`IssuerSet`].
#[derive(Debug)]
pub(super) enum Trusted {
    /// A resource server that read its issuer at boot.
    Ready(Arc<ResourceServer>),
    /// A resource server that reads its issuer on the first token.
    Lazy(Arc<LazyResourceServer>),
    /// An issuer whose tokens are introspected (RFC 7662).
    #[cfg(feature = "fetch")]
    Introspected(Arc<crate::resource::introspection::Introspector>),
}

impl Trusted {
    /// Returns whether the issuer's tokens are introspected.
    const fn introspected(&self) -> bool {
        match self {
            Self::Ready(_) | Self::Lazy(_) => false,
            #[cfg(feature = "fetch")]
            Self::Introspected(_) => true,
        }
    }
}

impl IssuerSet {
    /// Returns an empty set, which admits no token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns this set trusting `server`'s issuer.
    #[must_use]
    pub fn with(mut self, server: Arc<ResourceServer>) -> Self {
        self.servers
            .insert(server.settings().issuer.clone(), Trusted::Ready(server));
        self
    }

    /// Returns this set trusting the issuer of `server`, read on its first
    /// token.
    #[must_use]
    pub fn with_lazy(mut self, server: Arc<LazyResourceServer>) -> Self {
        self.servers
            .insert(server.settings().issuer.clone(), Trusted::Lazy(server));
        self
    }

    /// Returns this set trusting the issuer of `introspector`, whose tokens
    /// it introspects: a token naming that issuer in a readable `iss`, and a
    /// token that is no JWS when this is the set's one introspected issuer.
    #[cfg(feature = "fetch")]
    #[must_use]
    pub fn with_introspector(
        mut self,
        introspector: Arc<crate::resource::introspection::Introspector>,
    ) -> Self {
        self.servers.insert(
            introspector.settings().issuer.clone(),
            Trusted::Introspected(introspector),
        );
        self
    }

    /// Returns the server of `issuer`, when the set trusts it and its
    /// metadata and key set have been read.
    #[must_use]
    pub fn server(&self, issuer: &str) -> Option<&Arc<ResourceServer>> {
        match self.servers.get(issuer)? {
            Trusted::Ready(server) => Some(server),
            Trusted::Lazy(lazy) => lazy.get(),
            #[cfg(feature = "fetch")]
            Trusted::Introspected(_) => None,
        }
    }

    /// Returns how many issuers the set trusts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    /// Returns whether the set trusts no issuer.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }
}

impl IssuerSet {
    /// Returns the issuer a token with no readable `iss` goes to: the one
    /// introspected issuer, when the set holds exactly one (no specification
    /// governs the routing: our own design, since an opaque token names no
    /// issuer).
    fn opaque(&self) -> Option<&Trusted> {
        let mut introspected = self
            .servers
            .values()
            .filter(|trusted| trusted.introspected());
        let first = introspected.next();
        introspected.next().is_none().then_some(first).flatten()
    }
}

impl Verifier for IssuerSet {
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>> {
        Box::pin(async move {
            let server = match unverified_issuer(token) {
                Some(issuer) => self.servers.get(&issuer).ok_or(Rejection::Invalid {
                    reason: Reason::UntrustedIssuer,
                })?,
                None => self.opaque().ok_or(Rejection::Invalid {
                    reason: Reason::Malformed,
                })?,
            };
            match server {
                Trusted::Ready(server) => server.authenticate(token).await,
                Trusted::Lazy(lazy) => lazy.authenticate(token).await,
                #[cfg(feature = "fetch")]
                Trusted::Introspected(introspector) => introspector.authenticate(token).await,
            }
        })
    }
}

/// Returns the `iss` claim of `token` without checking anything.
fn unverified_issuer(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&bytes).ok()?;
    claims
        .get("iss")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}
