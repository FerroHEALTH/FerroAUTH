// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The HTTP-Artifact binding (saml-bindings-2.0-os §3.6).
//!
//! It holds the type 0x0004
//! artifact (§3.6.4), the `ArtifactResolve` FerroSMART sends over the SOAP
//! binding (§3.2; saml-core-2.0-os §3.5.1), signed, and the check of the
//! `ArtifactResponse` that carries the identity provider's `Response`
//! (saml-core-2.0-os §3.5.2).
//!
//! The exchange itself runs over TLS with FerroSMART's client certificate,
//! which saml-profiles-2.0-os §4.1.4.4 requires to be mutually
//! authenticated; the transport is the caller's.

use std::fmt::Write as _;

use aws_lc_rs::digest;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jiff::Timestamp;
use roxmltree::Node;

use crate::saml::ASSERTION;
use crate::saml::Escaped;
use crate::saml::PROTOCOL;
use crate::saml::Refusal;
use crate::saml::SOAP11;
use crate::saml::VERSION;
use crate::saml::dsig;
use crate::saml::dsig::SignError;
use crate::saml::keys::SigningKey;
use crate::saml::response;
use crate::saml::response::Delivery;
use crate::saml::response::Expectations;
use crate::saml::response::Login;
use crate::saml::xml;
use crate::saml::xml::Children;

/// The `SOAPAction` header value of a SAML SOAP request
/// (saml-bindings-2.0-os §3.2.3.1).
pub const SOAP_ACTION: &str = "http://www.oasis-open.org/committees/security";

/// A type 0x0004 artifact (saml-bindings-2.0-os §3.6.4.2).
#[derive(Clone, PartialEq, Eq)]
pub struct Artifact {
    /// The artifact as received, base64.
    encoded: String,
    /// The index of the artifact resolution endpoint to ask.
    endpoint_index: u16,
    /// The SHA-1 of the issuer's entity ID.
    source_id: [u8; 20],
}

impl std::fmt::Debug for Artifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Artifact")
            .field("endpoint_index", &self.endpoint_index)
            .finish_non_exhaustive()
    }
}

impl Artifact {
    /// Reads the `SAMLart` value `encoded`.
    ///
    /// # Errors
    ///
    /// [`Refusal::Encoding`] when it is not the base64 of a type 0x0004
    /// artifact of 44 bytes.
    pub fn parse(encoded: &str) -> Result<Self, Refusal> {
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_invalid| Refusal::Encoding)?;
        let Ok::<[u8; 44], _>(bytes) = bytes.try_into() else {
            return Err(Refusal::Encoding);
        };
        let [0x00, 0x04, high, low, rest @ ..] = bytes else {
            return Err(Refusal::Encoding);
        };
        let mut source_id = [0_u8; 20];
        source_id.copy_from_slice(rest.get(..20).ok_or(Refusal::Encoding)?);
        Ok(Self {
            encoded: encoded.to_owned(),
            endpoint_index: u16::from_be_bytes([high, low]),
            source_id,
        })
    }

    /// The index of the artifact resolution endpoint to ask.
    #[must_use]
    pub fn endpoint_index(&self) -> u16 {
        self.endpoint_index
    }

    /// Whether the artifact names `entity_id` as its issuer: its
    /// `SourceID` is the SHA-1 of the entity ID (saml-bindings-2.0-os
    /// §3.6.4), an identifier, which no security property rests on.
    #[must_use]
    pub fn issued_by(&self, entity_id: &str) -> bool {
        digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, entity_id.as_bytes()).as_ref()
            == self.source_id.as_slice()
    }

    /// The artifact as received.
    #[must_use]
    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

/// One `ArtifactResolve` (saml-core-2.0-os §3.5.1).
#[derive(Debug, Clone, Copy)]
pub struct ArtifactResolve<'a> {
    /// The request's `ID`, which the `ArtifactResponse` answers.
    pub id: &'a str,
    /// When the request is issued.
    pub issue_instant: Timestamp,
    /// The artifact resolution location, the `Destination`.
    pub destination: &'a str,
    /// FerroSMART's entity ID, the `Issuer`.
    pub entity_id: &'a str,
    /// The artifact to resolve.
    pub artifact: &'a Artifact,
}

impl ArtifactResolve<'_> {
    /// Returns the SOAP 1.1 envelope that carries the request, signed by
    /// `key` (saml-bindings-2.0-os §3.2.3).
    ///
    /// # Errors
    ///
    /// [`SignError`] when signing fails.
    pub fn envelope(&self, key: &SigningKey) -> Result<String, SignError> {
        let mut request = String::new();
        // Writing to a String cannot fail, so the result is discarded.
        let _written: std::fmt::Result = write!(
            request,
            concat!(
                "<samlp:ArtifactResolve xmlns:samlp=\"{protocol}\" xmlns:saml=\"{assertion}\" ",
                "ID=\"{id}\" Version=\"{version}\" IssueInstant=\"{instant}\" ",
                "Destination=\"{destination}\"><saml:Issuer>{issuer}</saml:Issuer>",
                "<samlp:Artifact>{artifact}</samlp:Artifact></samlp:ArtifactResolve>"
            ),
            protocol = PROTOCOL,
            assertion = ASSERTION,
            id = Escaped(self.id),
            version = VERSION,
            instant = xml::format_instant(self.issue_instant),
            destination = Escaped(self.destination),
            issuer = Escaped(self.entity_id),
            artifact = Escaped(self.artifact.encoded()),
        );
        let signed = dsig::sign(&request, key)?;
        Ok(format!(
            "<soap11:Envelope xmlns:soap11=\"{SOAP11}\"><soap11:Body>{signed}</soap11:Body></soap11:Envelope>"
        ))
    }
}

/// Checks the SOAP response to the `ArtifactResolve` whose `ID` is
/// `resolve_id`, and the `Response` it carries, as [`response`] checks
/// one.
///
/// # Errors
///
/// The [`Refusal`] of the first check that fails.
pub fn check_response(
    soap: &str,
    resolve_id: &str,
    expect: &Expectations<'_>,
) -> Result<Login, Refusal> {
    let prepared = xml::prepare(soap)?;
    let document = xml::parse(&prepared)?;
    let envelope = document.root_element();
    if !xml::is(envelope, SOAP11, "Envelope") {
        return Err(Refusal::Structure("soap11:Envelope"));
    }
    let mut parts = Children::of(envelope, "soap11:Envelope")?;
    parts.optional(SOAP11, "Header");
    let body = parts.required(SOAP11, "Body", "soap11:Body")?;
    parts.end()?;
    let mut contents = Children::of(body, "soap11:Body")?;
    let artifact_response =
        contents.required(PROTOCOL, "ArtifactResponse", "samlp:ArtifactResponse")?;
    contents.end()?;
    let (inner, signed) = check_artifact_response(artifact_response, resolve_id, expect)?;
    response::check(
        inner,
        Delivery::Artifact { signed },
        &[artifact_response.id()],
        expect,
    )
}

/// Checks the `ArtifactResponse` (saml-core-2.0-os §3.5.2) and returns the
/// `Response` it carries, with whether its verified signature covers it.
fn check_artifact_response<'a, 'input>(
    artifact_response: Node<'a, 'input>,
    resolve_id: &str,
    expect: &Expectations<'_>,
) -> Result<(Node<'a, 'input>, bool), Refusal> {
    let (mut parts, signed, status) = response::status_response(
        artifact_response,
        "samlp:ArtifactResponse",
        resolve_id,
        expect,
    )?;
    let inner = parts.required(PROTOCOL, "Response", "samlp:Response")?;
    parts.end()?;
    response::check_status(status)?;
    Ok((inner, signed))
}
