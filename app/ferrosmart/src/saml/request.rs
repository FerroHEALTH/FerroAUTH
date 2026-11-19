// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! FerroSMART's `AuthnRequest`, always signed, and its two encodings.
//!
//! The request follows saml-core-2.0-os §3.4.1 and saml-profiles-2.0-os
//! §4.1.4.1; the encodings are
//! the HTTP-Redirect binding's signed query string (saml-bindings-2.0-os
//! §3.4.4.1) and the HTTP-POST binding's form value with an enveloped
//! signature (§3.5.4).

use std::fmt::Write as _;
use std::io::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use jiff::Timestamp;
use url::Url;
use url::form_urlencoded::byte_serialize;

use crate::saml::ASSERTION;
use crate::saml::Escaped;
use crate::saml::PROTOCOL;
use crate::saml::VERSION;
use crate::saml::dsig;
use crate::saml::dsig::SignError;
use crate::saml::keys::SigningKey;
use crate::saml::xml;

/// The longest `RelayState` a binding carries (saml-bindings-2.0-os
/// §3.4.3, §3.5.3, §3.6.3.1).
pub const MAX_RELAY_STATE: usize = 80;

/// One authentication request.
#[derive(Debug, Clone, Copy)]
pub struct AuthnRequest<'a> {
    /// The request's `ID`, which the response's `InResponseTo` names.
    pub id: &'a str,
    /// When the request is issued.
    pub issue_instant: Timestamp,
    /// The identity provider's single sign-on location, the `Destination`.
    pub destination: &'a str,
    /// FerroSMART's entity ID, the `Issuer`.
    pub entity_id: &'a str,
    /// The assertion consumer service URL the response is delivered to.
    pub acs_url: &'a str,
    /// The binding the identity provider answers with: HTTP-POST or
    /// HTTP-Artifact.
    pub protocol_binding: &'a str,
    /// Whether the identity provider must authenticate the person afresh
    /// (§3.4.1, `ForceAuthn`).
    pub force_authn: bool,
    /// The name identifier format asked for, when the provider names one.
    pub name_id_format: Option<&'a str>,
    /// The authentication context classes the provider accepts, of which
    /// the response must be an exact match (§3.3.2.2.1); empty asks for
    /// none.
    pub authn_contexts: &'a [String],
}

impl AuthnRequest<'_> {
    /// Writes the request, unsigned.
    #[must_use]
    pub fn xml(&self) -> String {
        let mut out = String::new();
        // Writing to a String cannot fail, so the results are discarded.
        let _written: std::fmt::Result = write!(
            out,
            concat!(
                "<samlp:AuthnRequest xmlns:samlp=\"{protocol}\" xmlns:saml=\"{assertion}\" ",
                "ID=\"{id}\" Version=\"{version}\" IssueInstant=\"{instant}\" ",
                "Destination=\"{destination}\" AssertionConsumerServiceURL=\"{acs}\" ",
                "ProtocolBinding=\"{binding}\"{force}>",
                "<saml:Issuer>{issuer}</saml:Issuer>"
            ),
            protocol = PROTOCOL,
            assertion = ASSERTION,
            id = Escaped(self.id),
            version = VERSION,
            instant = xml::format_instant(self.issue_instant),
            destination = Escaped(self.destination),
            acs = Escaped(self.acs_url),
            binding = Escaped(self.protocol_binding),
            force = if self.force_authn {
                " ForceAuthn=\"true\""
            } else {
                ""
            },
            issuer = Escaped(self.entity_id),
        );
        if let Some(format) = self.name_id_format {
            let _written: std::fmt::Result = write!(
                out,
                "<samlp:NameIDPolicy Format=\"{}\" AllowCreate=\"true\"/>",
                Escaped(format)
            );
        }
        if !self.authn_contexts.is_empty() {
            out.push_str("<samlp:RequestedAuthnContext Comparison=\"exact\">");
            for class in self.authn_contexts {
                let _written: std::fmt::Result = write!(
                    out,
                    "<saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef>",
                    Escaped(class)
                );
            }
            out.push_str("</samlp:RequestedAuthnContext>");
        }
        out.push_str("</samlp:AuthnRequest>");
        out
    }

    /// Returns the HTTP-Redirect URL that carries the request to the
    /// identity provider, signed by `key`, with `relay_state`
    /// (saml-bindings-2.0-os §3.4.4.1).
    ///
    /// # Errors
    ///
    /// [`SignError::Shape`] when the destination is not a URL or the relay
    /// state is longer than 80 bytes, and [`SignError::Key`] when signing
    /// fails.
    pub fn redirect(&self, key: &SigningKey, relay_state: &str) -> Result<Url, SignError> {
        if relay_state.len() > MAX_RELAY_STATE {
            return Err(SignError::Shape);
        }
        let mut deflate = DeflateEncoder::new(Vec::new(), Compression::default());
        deflate
            .write_all(self.xml().as_bytes())
            .map_err(|_io| SignError::Shape)?;
        let deflated = deflate.finish().map_err(|_io| SignError::Shape)?;
        let mut query = String::from("SAMLRequest=");
        query.extend(byte_serialize(STANDARD.encode(deflated).as_bytes()));
        if !relay_state.is_empty() {
            query.push_str("&RelayState=");
            query.extend(byte_serialize(relay_state.as_bytes()));
        }
        query.push_str("&SigAlg=");
        query.extend(byte_serialize(key.algorithm().as_bytes()));
        let signature = dsig::sign_octets(query.as_bytes(), key)?;
        query.push_str("&Signature=");
        query.extend(byte_serialize(signature.as_bytes()));
        let mut url = Url::parse(self.destination).map_err(|_invalid| SignError::Shape)?;
        let joined = match url.query() {
            Some(existing) if !existing.is_empty() => format!("{existing}&{query}"),
            _ => query,
        };
        url.set_query(Some(&joined));
        Ok(url)
    }

    /// Returns the base64 `SAMLRequest` form value of the HTTP-POST
    /// binding, the request carrying an enveloped signature by `key`
    /// (saml-bindings-2.0-os §3.5.4).
    ///
    /// # Errors
    ///
    /// [`SignError`] when signing fails.
    pub fn post(&self, key: &SigningKey) -> Result<String, SignError> {
        let signed = dsig::sign(&self.xml(), key)?;
        Ok(STANDARD.encode(signed))
    }
}
