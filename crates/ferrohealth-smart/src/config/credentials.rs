// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The resolution of the `[<lane>.credentials]` tables: HTTP Basic or the
//! client credentials grant, every rule checked and every secret read.

use std::path::Path;
use std::time::Duration;

use url::Url;

use crate::basic::Credential;
use crate::client::AssertionAudience;
use crate::client::ClientAuth;
use crate::client::ClientCredentials;
use crate::client::Endpoint;
use crate::client::Tls;
use crate::client::assertion::AssertionKey;
use crate::config::ConfigError;
use crate::config::CredentialsSection;
use crate::config::OauthSection;
use crate::config::Outbound;
use crate::config::REDACTED;
use crate::config::mask_userinfo;
use crate::config::parse_url;
use crate::config::secret;
use crate::scope::is_scope_token;

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
