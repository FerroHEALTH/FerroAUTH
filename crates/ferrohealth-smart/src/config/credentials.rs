// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The resolution of the `[<lane>.credentials]` tables: HTTP Basic or the
//! client credentials grant, every rule checked and every secret read.

use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use jsonwebtoken::Algorithm;
use secrecy::SecretString;
use serde::Deserialize;
use serde::Serialize;
use url::Url;

use crate::basic::Credential;
use crate::client::AssertionAudience;
use crate::client::ClientAuth;
use crate::client::ClientCredentials;
use crate::client::Endpoint;
use crate::client::Tls;
use crate::client::assertion::AssertionKey;
use crate::client::authorization_details::AuthorizationDetails;
use crate::client::dpop::DpopKey;
use crate::client::fapi2::AliasHost;
use crate::client::fapi2::Fapi2;
use crate::client::fapi2::ProfileKind;
use crate::client::fapi2::SecurityProfile;
use crate::client::keys::KeyRing;
use crate::config::ConfigError;
use crate::config::REDACTED;
use crate::config::mask_userinfo;
use crate::config::onward;
use crate::config::read::parse_url;
use crate::config::read::secret;
use crate::config::shapes;
use crate::scope::is_scope_token;

/// The `[<lane>.credentials]` table: HTTP Basic with `user` and `password`,
/// or the client credentials grant under `oauth`; the two exclude each
/// other.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CredentialsSection {
    /// The Basic user-id.
    pub user: String,
    /// The Basic password, rendered redacted.
    #[serde(
        serialize_with = "shapes::redact",
        skip_serializing_if = "Option::is_none"
    )]
    pub password: Option<SecretString>,
    /// The file holding the Basic password.
    pub password_file: Option<PathBuf>,
    /// The client credentials grant.
    pub oauth: Option<OauthSection>,
    /// The onward target the lane reaches on a caller's behalf, authenticating
    /// with `oauth`.
    pub onward: Option<onward::OnwardSection>,
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
    #[serde(serialize_with = "shapes::masked_url")]
    pub issuer: String,
    /// The token endpoint itself; exclusive with `issuer`.
    #[serde(serialize_with = "shapes::masked_url")]
    pub token_endpoint: String,
    /// The client identifier.
    pub client_id: String,
    /// How the client authenticates.
    pub client_auth: ClientAuth,
    /// The client secret, rendered redacted.
    #[serde(
        serialize_with = "shapes::redact",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_secret: Option<SecretString>,
    /// The file holding the client secret.
    pub client_secret_file: Option<PathBuf>,
    /// The PEM file holding the private key of the client assertion.
    pub private_key_file: Option<PathBuf>,
    /// The `kid` the assertion names; the RFC 7638 thumbprint when empty.
    pub kid: String,
    /// The algorithm the assertion is signed with; when unset, by key type,
    /// an EC key by its curve (P-256 ES256, P-384 ES384).
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
    /// The PEM file of the `DPoP` key the tokens are bound to (RFC 9449).
    pub dpop_key_file: Option<PathBuf>,
    /// Whether the tokens are bound to the client certificate (RFC 8705 §3).
    pub certificate_bound: bool,
    /// The security profile: `oauth2` (the default) or `fapi2`.
    pub security_profile: ProfileKind,
    /// The hosts a FAPI 2.0 mutual-TLS alias may be on (RFC 8705 §5).
    pub mtls_alias_hosts: Vec<String>,
    /// The PEM file of the previous assertion key, published, never signing.
    pub previous_private_key_file: Option<PathBuf>,
    /// How long the previous key stays published; 0 for as long as it is set.
    pub previous_key_overlap_ms: u64,
    /// The PEM file of the next assertion key, published and never signing.
    pub next_private_key_file: Option<PathBuf>,
    /// The RFC 9396 `authorization_details` JSON text; empty for none.
    pub authorization_details: String,
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
            ClientAuth::PrivateKeyJwt => self.private_key_jwt(endpoint)?,
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
        self.finish(self.bind(grant)?)
    }

    /// Returns the `private_key_jwt` grant at `endpoint`, signing with the
    /// key ring of `private_key_file` and its previous and next keys.
    fn private_key_jwt(&self, endpoint: Endpoint) -> Result<ClientCredentials, ConfigError> {
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
        Ok(ClientCredentials::with_key_ring(
            endpoint,
            self.client_id.clone(),
            std::sync::Arc::new(self.ring(key)?),
        ))
    }

    /// Returns `grant` with the table's `authorization_details` and security
    /// profile, checked as [`ClientCredentials::validate`] checks it.
    fn finish(&self, mut grant: ClientCredentials) -> Result<ClientCredentials, ConfigError> {
        if !self.authorization_details.is_empty() {
            grant.authorization_details = Some(
                AuthorizationDetails::parse(&self.authorization_details)
                    .map_err(|source| ConfigError::AuthorizationDetails { source })?,
            );
        }
        grant.profile = self.profile()?;
        grant.validate().map_err(|source| ConfigError::Grant {
            source: Box::new(source),
        })?;
        Ok(grant)
    }

    /// Returns the key ring `current` signs in, with the previous and next
    /// keys the table names published beside it.
    fn ring(&self, current: AssertionKey) -> Result<KeyRing, ConfigError> {
        let read = |path: &Path| -> Result<AssertionKey, ConfigError> {
            let pem = std::fs::read(path).map_err(|source| ConfigError::SecretFile {
                path: path.to_path_buf(),
                source,
            })?;
            AssertionKey::from_pem(&pem, self.assertion_alg, None)
                .map_err(|source| ConfigError::Key { source })
        };
        let mut ring = KeyRing::new(current);
        if let Some(path) = &self.previous_private_key_file {
            let previous = read(path)?;
            ring = match self.previous_key_overlap_ms {
                0 => ring.with_previous_until_removed(previous),
                ms => ring.with_previous_for(previous, Duration::from_millis(ms)),
            }
            .map_err(|source| ConfigError::KeyRing { source })?;
        }
        if let Some(path) = &self.next_private_key_file {
            ring = ring
                .with_next(read(path)?)
                .map_err(|source| ConfigError::KeyRing { source })?;
        }
        Ok(ring)
    }

    /// Returns the security profile the table names, with its alias hosts.
    fn profile(&self) -> Result<SecurityProfile, ConfigError> {
        match self.security_profile {
            ProfileKind::OAuth2 if self.mtls_alias_hosts.is_empty() => Ok(SecurityProfile::OAuth2),
            ProfileKind::OAuth2 => Err(ConfigError::Missing {
                key: "credentials.oauth.security_profile = \"fapi2\", which mtls_alias_hosts needs",
            }),
            ProfileKind::Fapi2 => {
                let mut profile = Fapi2::new();
                for host in &self.mtls_alias_hosts {
                    let host = AliasHost::parse(host)
                        .map_err(|_invalid| ConfigError::AliasHost { host: host.clone() })?;
                    profile = profile.with_alias_host(host);
                }
                Ok(SecurityProfile::Fapi2(profile))
            }
        }
    }

    /// Returns `grant` with the token binding the table names: a `DPoP` key
    /// (RFC 9449) or the client certificate (RFC 8705 §3), never both.
    fn bind(&self, grant: ClientCredentials) -> Result<ClientCredentials, ConfigError> {
        match (&self.dpop_key_file, self.certificate_bound) {
            (Some(_), true) => Err(ConfigError::Exclusive {
                left: "credentials.oauth.dpop_key_file",
                right: "credentials.oauth.certificate_bound",
            }),
            (Some(path), false) => {
                let pem = std::fs::read(path).map_err(|source| ConfigError::SecretFile {
                    path: path.clone(),
                    source,
                })?;
                let key =
                    DpopKey::from_pem(&pem).map_err(|source| ConfigError::DpopKey { source })?;
                Ok(grant.with_dpop(std::sync::Arc::new(key)))
            }
            (None, true) if grant.tls.identity.is_none() => Err(ConfigError::Missing {
                key: "credentials.oauth.client_certificate_file, which certificate_bound names",
            }),
            (None, true) => Ok(grant.with_certificate_binding()),
            (None, false) => Ok(grant),
        }
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
        self.binding_problems(table, &mut out);
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

    /// Adds to `out` the problems of the keys this table adds beside the
    /// grant's credential: the token binding, the key ring, the security
    /// profile and `authorization_details`.
    fn binding_problems(&self, table: &str, out: &mut Vec<String>) {
        if self.dpop_key_file.is_some() && self.certificate_bound {
            out.push(format!(
                "{table}: set one of dpop_key_file and certificate_bound, not both"
            ));
        }
        if self.client_auth != ClientAuth::PrivateKeyJwt
            && (self.previous_private_key_file.is_some() || self.next_private_key_file.is_some())
        {
            out.push(format!(
                "{table}: previous_private_key_file and next_private_key_file need client_auth = \"private_key_jwt\""
            ));
        }
        if self.security_profile != ProfileKind::Fapi2 && !self.mtls_alias_hosts.is_empty() {
            out.push(format!(
                "{table}.mtls_alias_hosts needs security_profile = \"fapi2\""
            ));
        }
        if !self.authorization_details.is_empty()
            && AuthorizationDetails::parse(&self.authorization_details).is_err()
        {
            out.push(format!(
                "{table}.authorization_details is not of RFC 9396 §2 shape"
            ));
        }
        if self.certificate_bound && self.client_certificate_file.is_none() {
            out.push(format!(
                "{table}.client_certificate_file is required by certificate_bound"
            ));
        }
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
            dpop_key_file: None,
            certificate_bound: false,
            security_profile: ProfileKind::OAuth2,
            mtls_alias_hosts: Vec::new(),
            previous_private_key_file: None,
            previous_key_overlap_ms: 0,
            next_private_key_file: None,
            authorization_details: String::new(),
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
            .field("dpop_key_file", &self.dpop_key_file)
            .field("certificate_bound", &self.certificate_bound)
            .field("security_profile", &self.security_profile)
            .field("mtls_alias_hosts", &self.mtls_alias_hosts)
            .field("previous_private_key_file", &self.previous_private_key_file)
            .field("next_private_key_file", &self.next_private_key_file)
            .finish_non_exhaustive()
    }
}
