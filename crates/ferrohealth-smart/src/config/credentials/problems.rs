// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The problems of an `oauth` table, read without opening a file.

use url::Url;

use crate::client::AssertionAudience;
use crate::client::ClientAuth;
use crate::client::PresentedTls;
use crate::client::authorization_details::AuthorizationDetails;
use crate::client::fapi2::ProfileKind;
use crate::config::credentials::OauthSection;
use crate::scope::is_scope_token;

impl OauthSection {
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
        self.problems_presenting(table, None)
    }

    /// Returns every problem of the table as [`OauthSection::problems`]
    /// does, for a grant [`OauthSection::resolve_with_tls`] resolves over
    /// `tls`: the client certificate a mutual-TLS `client_auth` or
    /// `certificate_bound` needs is the one `tls` presents, and the table
    /// names no certificate, key or roots file beside it.
    #[must_use]
    pub fn problems_with_tls(&self, table: &str, tls: &PresentedTls) -> Vec<String> {
        self.problems_presenting(table, Some(tls))
    }

    /// Returns every problem of the table, over the product's built TLS
    /// configuration when `presented` carries one.
    fn problems_presenting(&self, table: &str, presented: Option<&PresentedTls>) -> Vec<String> {
        let mut out = Vec::new();
        let certificate = match presented {
            Some(tls) => tls.certificate().is_some(),
            None => self.tls.client_identity.is_some() || self.tls.client_identity_file.is_some(),
        };
        match (self.issuer.is_empty(), self.token_endpoint.is_empty()) {
            (false, false) => out.push(format!(
                "{table}: set one of issuer and token_endpoint, not both"
            )),
            (true, true) => out.push(format!("{table}: set issuer or token_endpoint")),
            (false, true) => {
                if crate::metadata::issuer_url(self.issuer.expose()).is_err() {
                    out.push(format!(
                        "{table}.issuer is not an https issuer identifier (RFC 8414 §2)"
                    ));
                }
            }
            (true, false) => match self.token_endpoint.expose().parse::<Url>() {
                Err(_malformed) => out.push(format!("{table}.token_endpoint is not a URL")),
                Ok(url) => {
                    if let Some(part) = crate::client::forbidden_part(&url) {
                        out.push(format!(
                            "{table}.token_endpoint carries {part}, which a token endpoint must not (RFC 6749 §3.2, RFC 9110 §4.2.4)"
                        ));
                    }
                }
            },
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
                if !certificate {
                    out.push(certificate_missing(
                        table,
                        presented.is_some(),
                        "a mutual-TLS client_auth",
                    ));
                }
            }
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
        self.binding_problems(table, certificate, presented.is_some(), &mut out);
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
    fn binding_problems(
        &self,
        table: &str,
        certificate: bool,
        presented: bool,
        out: &mut Vec<String>,
    ) {
        if self.dpop_key_file.is_some() && self.certificate_bound {
            out.push(format!(
                "{table}: set one of dpop_key_file and certificate_bound, not both"
            ));
        }
        if self.private_key_file.is_none()
            && (self.previous_private_key_file.is_some() || self.next_private_key_file.is_some())
        {
            out.push(format!(
                "{table}: previous_private_key_file and next_private_key_file need private_key_file"
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
        if self.certificate_bound && !certificate {
            out.push(certificate_missing(table, presented, "certificate_bound"));
        }
    }
}

/// The problem of a table whose `what` needs a client certificate it has
/// none of: from `client_certificate_file`, or from the product's built TLS
/// configuration when `presented`.
fn certificate_missing(table: &str, presented: bool, what: &str) -> String {
    if presented {
        format!(
            "{table}: {what} needs a client certificate the product's TLS configuration presents"
        )
    } else {
        format!("{table}.tls.client_identity_file is required by {what}")
    }
}
