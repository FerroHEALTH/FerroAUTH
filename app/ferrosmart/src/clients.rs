// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The client registry: who may ask FerroSMART for a token, and how.
//!
//! SMART specifies no registration protocol ("SMART does not specify a
//! standards-based registration process", SMART App Launch 2.2.0, Register
//! App with EHR), so the registry is content: each `[[ferrosmart.client]]`
//! table names one client, checked here against what SMART requires of a
//! registration, and the store keeps them (`docs/architecture.md` §13.9).

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

/// How a client authenticates at the token endpoint (SMART App Launch
/// 2.2.0, Conformance, Client Types).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    /// No client authentication (`client-public`).
    #[default]
    Public,
    /// A JWT assertion signed with a key of its registered JWK Set
    /// (`client-confidential-asymmetric`).
    ConfidentialAsymmetric,
}

impl ClientKind {
    /// Returns the kind as the store writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::ConfidentialAsymmetric => "confidential_asymmetric",
        }
    }
}

/// A grant type a client may use at the token endpoint (RFC 6749 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    /// The authorization code grant (RFC 6749 §4.1).
    AuthorizationCode,
    /// The client credentials grant (RFC 6749 §4.4), SMART Backend Services.
    ClientCredentials,
    /// The refresh token grant (RFC 6749 §6).
    RefreshToken,
}

impl GrantType {
    /// Returns the `grant_type` value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::ClientCredentials => "client_credentials",
            Self::RefreshToken => "refresh_token",
        }
    }
}

/// One `[[ferrosmart.client]]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientSection {
    /// The `client_id` the client is assigned ("Upon registration, the
    /// client SHALL be assigned a `client_id`", SMART App Launch 2.2.0,
    /// Client Authentication: Asymmetric).
    pub client_id: String,
    /// The name shown to the person who approves the client.
    pub name: String,
    /// How the client authenticates.
    pub kind: ClientKind,
    /// The URL of the client's JWK Set; exclusive with `jwks_file`.
    pub jwks_uri: String,
    /// A file holding the client's JWK Set; exclusive with `jwks_uri`.
    pub jwks_file: Option<PathBuf>,
    /// The client's complete redirect URIs.
    pub redirect_uris: Vec<String>,
    /// The scopes the client may be granted at most.
    pub scopes: Vec<String>,
    /// The grant types the client may use.
    pub grant_types: Vec<GrantType>,
}

/// A registered client, checked.
#[expect(
    clippy::struct_field_names,
    reason = "`client_id` is the parameter's name in RFC 6749 §2.2"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    /// The `client_id`.
    pub client_id: String,
    /// The name.
    pub name: String,
    /// How it authenticates.
    pub kind: ClientKind,
    /// Its JWK Set, by URL or by value.
    pub keys: Option<ClientKeys>,
    /// Its redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Its scope ceiling.
    pub scopes: Vec<String>,
    /// Its grant types, sorted and without repetition.
    pub grant_types: Vec<GrantType>,
}

/// Where a confidential asymmetric client's public keys are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientKeys {
    /// The URL of its JWK Set, "strongly preferred" (SMART App Launch 2.2.0,
    /// Client Authentication: Asymmetric, Registering a client).
    Uri(Url),
    /// Its JWK Set by value, which the server "SHALL protect ... from
    /// corruption" (same section).
    Set(Value),
}

/// Why a client table was refused, naming the client and the key.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// A client has no `client_id`.
    #[error("a `[[ferrosmart.client]]` table has no `client_id`")]
    NoClientId,
    /// Two tables name one `client_id`.
    #[error("the client `{client_id}` is registered twice")]
    Repeated {
        /// The client.
        client_id: String,
    },
    /// A key the client's kind or grants need is missing, or one they
    /// forbid is set.
    #[error("the client `{client_id}`: {rule}")]
    Rule {
        /// The client.
        client_id: String,
        /// The rule broken.
        rule: &'static str,
    },
    /// The JWK Set URL is no `https` URL.
    #[error("the client `{client_id}`: `jwks_uri` is not an https URL")]
    JwksUri {
        /// The client.
        client_id: String,
    },
    /// The JWK Set file cannot be read or is no JSON.
    #[error("the client `{client_id}`: `jwks_file` cannot be read as JSON")]
    JwksFile {
        /// The client.
        client_id: String,
        /// Why.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// A JWK of the set breaks SMART's rule for a registered key.
    #[error("the client `{client_id}`: key {index} of its JWK Set {rule}")]
    Jwk {
        /// The client.
        client_id: String,
        /// The key's place in the set.
        index: usize,
        /// The rule broken.
        rule: &'static str,
    },
    /// A redirect URI is no absolute URL, or carries a fragment.
    #[error("the client `{client_id}`: a redirect URI is not an absolute URL without a fragment")]
    RedirectUri {
        /// The client.
        client_id: String,
    },
    /// A scope is outside the RFC 6749 §3.3 character set.
    #[error("the client `{client_id}`: a scope is outside the RFC 6749 §3.3 character set")]
    Scope {
        /// The client.
        client_id: String,
    },
}

/// Returns the clients `sections` register, each checked.
///
/// # Errors
/// Returns [`ClientError`] for the first table that breaks a rule.
pub fn resolve(sections: &[ClientSection]) -> Result<Vec<Client>, ClientError> {
    let mut seen = BTreeSet::new();
    let mut clients = Vec::with_capacity(sections.len());
    for section in sections {
        let client = resolve_one(section)?;
        if !seen.insert(client.client_id.clone()) {
            return Err(ClientError::Repeated {
                client_id: client.client_id,
            });
        }
        clients.push(client);
    }
    Ok(clients)
}

/// Returns the client `section` registers, checked.
fn resolve_one(section: &ClientSection) -> Result<Client, ClientError> {
    if section.client_id.is_empty() {
        return Err(ClientError::NoClientId);
    }
    let id = || section.client_id.clone();
    let rule = |rule| ClientError::Rule {
        client_id: id(),
        rule,
    };
    let grant_types: Vec<GrantType> = section
        .grant_types
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if grant_types.is_empty() {
        return Err(rule("no `grant_types`"));
    }
    let keys = match section.kind {
        ClientKind::Public => {
            if !section.jwks_uri.is_empty() || section.jwks_file.is_some() {
                return Err(rule("a public client registers no JWK Set"));
            }
            // NOTE: SMART App Launch 2.2.0, Backend Services, the client
            // credentials grant authenticates with an asymmetric key.
            if grant_types.contains(&GrantType::ClientCredentials) {
                return Err(rule("a public client cannot use `client_credentials`"));
            }
            None
        }
        ClientKind::ConfidentialAsymmetric => Some(keys(section)?),
    };
    // NOTE: SMART App Launch 2.2.0, Backend Services, refresh tokens SHOULD NOT be
    // issued there; a refresh token continues an authorization code grant.
    if grant_types.contains(&GrantType::RefreshToken)
        && !grant_types.contains(&GrantType::AuthorizationCode)
    {
        return Err(rule("`refresh_token` needs `authorization_code`"));
    }
    if grant_types.contains(&GrantType::AuthorizationCode) && section.redirect_uris.is_empty() {
        return Err(rule("`authorization_code` needs `redirect_uris`"));
    }
    for uri in &section.redirect_uris {
        // NOTE: RFC 6749 §3.1.2, "The redirection endpoint URI MUST be an
        // absolute URI" and "MUST NOT include a fragment component".
        let absolute = Url::parse(uri).is_ok_and(|url| url.fragment().is_none());
        if !absolute {
            return Err(ClientError::RedirectUri { client_id: id() });
        }
    }
    if !section
        .scopes
        .iter()
        .all(|scope| ferrohealth_smart::scope::is_scope_token(scope))
    {
        return Err(ClientError::Scope { client_id: id() });
    }
    Ok(Client {
        client_id: section.client_id.clone(),
        name: if section.name.is_empty() {
            section.client_id.clone()
        } else {
            section.name.clone()
        },
        kind: section.kind,
        keys,
        redirect_uris: section.redirect_uris.clone(),
        scopes: section.scopes.clone(),
        grant_types,
    })
}

/// Returns the JWK Set a confidential asymmetric client registers: by URL
/// or by value, exactly one ("FHIR authorization servers SHALL support
/// registration of client JWKs using both of the following techniques",
/// SMART App Launch 2.2.0, Client Authentication: Asymmetric, Registering a
/// client).
fn keys(section: &ClientSection) -> Result<ClientKeys, ClientError> {
    let id = || section.client_id.clone();
    match (section.jwks_uri.is_empty(), &section.jwks_file) {
        (false, None) => {
            // NOTE: SMART App Launch 2.2.0, Registering a client, the JWK Set URL
            // is a "TLS-protected endpoint"; a loopback host is the test exception.
            let url = Url::parse(&section.jwks_uri)
                .ok()
                .filter(|url| url.scheme() == "https" || is_loopback(url))
                .ok_or(ClientError::JwksUri { client_id: id() })?;
            Ok(ClientKeys::Uri(url))
        }
        (true, Some(path)) => {
            let set = std::fs::read(path)
                .map_err(|source| ClientError::JwksFile {
                    client_id: id(),
                    source: Box::new(source),
                })
                .and_then(|bytes| {
                    serde_json::from_slice::<Value>(&bytes).map_err(|source| {
                        ClientError::JwksFile {
                            client_id: id(),
                            source: Box::new(source),
                        }
                    })
                })?;
            check_set(&section.client_id, &set)?;
            Ok(ClientKeys::Set(set))
        }
        _ => Err(ClientError::Rule {
            client_id: id(),
            rule: "a confidential asymmetric client registers exactly one of `jwks_uri` and `jwks_file`",
        }),
    }
}

/// Returns whether `url` names a loopback host over plain `http`, which a
/// test's JWK Set server is. No specification governs the exception: our
/// own design, the one `ferrohealth_smart::metadata::issuer_url` makes.
fn is_loopback(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

/// Checks the JWK Set `set` of `client_id` against SMART's rule for a
/// registered key: "each JWK SHALL represent an asymmetric key by including
/// `kty` and `kid` properties, with content conveyed using 'bare key'
/// properties", `n` and `e` for RSA and `crv`, `x` and `y` for EC (SMART
/// App Launch 2.2.0, Client Authentication: Asymmetric, Registering a
/// client). A private member (`d`, RFC 7518 §6.2.2.1 and §6.3.2.1) is
/// refused: a public key set never carries one.
fn check_set(client_id: &str, set: &Value) -> Result<(), ClientError> {
    let keys = set
        .get("keys")
        .and_then(Value::as_array)
        .filter(|keys| !keys.is_empty())
        .ok_or(ClientError::Rule {
            client_id: client_id.to_owned(),
            rule: "its JWK Set has no `keys`",
        })?;
    for (index, key) in keys.iter().enumerate() {
        let fault = |rule| ClientError::Jwk {
            client_id: client_id.to_owned(),
            index,
            rule,
        };
        let text = |member: &str| key.get(member).and_then(Value::as_str);
        if text("kid").is_none_or(str::is_empty) {
            return Err(fault("has no `kid`"));
        }
        let bare = match text("kty") {
            Some("RSA") => ["n", "e"].iter().all(|member| text(member).is_some()),
            Some("EC") => ["crv", "x", "y"]
                .iter()
                .all(|member| text(member).is_some()),
            _ => return Err(fault("is no RSA or EC key")),
        };
        if !bare {
            return Err(fault("lacks a bare key member"));
        }
        if key.get("d").is_some() {
            return Err(fault("carries a private member"));
        }
    }
    Ok(())
}
