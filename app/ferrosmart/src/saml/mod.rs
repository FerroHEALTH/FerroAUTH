// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The SAML 2.0 service provider of FerroSMART's upstream login.
//!
//! A person logs in at an upstream identity provider that speaks the OASIS
//! SAML 2.0 Web Browser SSO profile (saml-profiles-2.0-os §4.1) rather than
//! OpenID Connect (`docs/architecture.md` §13.25).
//!
//! The module is protocol machinery with no configuration and no I/O:
//!
//! - [`request`] writes the `AuthnRequest` and encodes it for the
//!   HTTP-Redirect or HTTP-POST binding, signed;
//! - [`response`] checks a `Response` delivered by HTTP-POST, or resolved
//!   from an artifact, against what the request expected, and returns the
//!   [`response::Login`] it asserts;
//! - [`artifact`] reads a SAML 2.0 artifact and writes and reads the SOAP
//!   `ArtifactResolve` exchange of the HTTP-Artifact binding;
//! - [`metadata`] reads the identity provider's metadata and writes
//!   FerroSMART's own (saml-metadata-2.0-os);
//! - [`keys`] holds FerroSMART's signing and decryption keys and the
//!   identity provider's trusted signing keys;
//! - [`dsig`] and `xenc` are the XML Signature and XML Encryption checks
//!   every message goes through, and [`dsig::sign`] the signature
//!   FerroSMART writes.
//!
//! Every refusal is a [`Refusal`] variant, which the login records name.

use std::fmt;

pub mod artifact;
pub mod dsig;
pub mod keys;
pub mod metadata;
pub mod request;
pub mod response;
mod xenc;
mod xml;

/// The SAML 2.0 protocol namespace (saml-core-2.0-os §2.1, §3.1).
const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
/// The SAML 2.0 assertion namespace (saml-core-2.0-os §2.1).
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
/// The SAML 2.0 metadata namespace (saml-metadata-2.0-os §2.1).
const METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
/// The XML Signature namespace (xmldsig-core1 §1.3).
const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
/// The XML Encryption namespace (xmlenc-core1 §1.3).
const XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
/// The XML Encryption 1.1 namespace (xmlenc-core1 §1.3).
const XENC11: &str = "http://www.w3.org/2009/xmlenc11#";
/// The SOAP 1.1 envelope namespace the SAML SOAP binding uses
/// (saml-bindings-2.0-os §3.2.1).
const SOAP11: &str = "http://schemas.xmlsoap.org/soap/envelope/";
/// The SAML protocol version every message carries (saml-core-2.0-os §4.1).
const VERSION: &str = "2.0";
/// The entity name identifier format, the one an `Issuer` may name besides
/// none (saml-profiles-2.0-os §4.1.4.1, §4.1.4.2).
const ENTITY: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
/// The top-level status of a successful response (saml-core-2.0-os
/// §3.2.2.2).
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

/// The HTTP-Redirect binding (saml-bindings-2.0-os §3.4).
pub const HTTP_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
/// The HTTP-POST binding (saml-bindings-2.0-os §3.5).
pub const HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
/// The HTTP-Artifact binding (saml-bindings-2.0-os §3.6).
pub const HTTP_ARTIFACT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
/// The SOAP binding the artifact is resolved over (saml-bindings-2.0-os
/// §3.2).
pub const SOAP: &str = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";

/// Why a SAML message is refused. Each variant names one check, so a login
/// record says which one failed; none carries a value from the message
/// beyond a status code URI.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// The message is not well formed, is past a size cap, or carries a
    /// document type declaration.
    #[error("the SAML message is not well-formed XML within the caps, or carries a DTD")]
    Xml,
    /// The message is not base64, or not the encoding its binding names.
    #[error("the SAML message is not encoded as its binding requires")]
    Encoding,
    /// An element or attribute is missing, repeated, out of its schema
    /// order, or not the one its place requires; the payload names it.
    #[error("the SAML message has no valid {0}")]
    Structure(&'static str),
    /// An `ID` value is carried by more than one attribute of the document.
    #[error("an ID value is carried more than once")]
    DuplicateId,
    /// A signature does not reference the element it is a child of, or
    /// sits where no signature belongs: the signature wrapping shapes.
    #[error("a signature is placed or referenced where the SAML profile admits none")]
    Wrapped,
    /// An algorithm is not one FerroSMART accepts; the payload names its
    /// role.
    #[error("the {0} algorithm is not one FerroSMART accepts")]
    Algorithm(&'static str),
    /// The digest of the signed element does not match its reference.
    #[error("the digest of the signed element does not match")]
    Digest,
    /// No trusted key of the identity provider verifies the signature.
    #[error("no trusted key verifies the signature")]
    BadSignature,
    /// The assertion is covered by no verified signature.
    #[error("the assertion is protected by no verified signature")]
    Unprotected,
    /// An encrypted element cannot be decrypted with FerroSMART's keys, or
    /// its plaintext is not the element it must be.
    #[error("an encrypted element cannot be decrypted")]
    Decryption,
    /// An element encrypted in CBC mode is covered by no verified signature
    /// (saml-core-2.0-os §6.2 as errata E93 replaces it).
    #[error("an element encrypted in CBC mode is protected by no verified signature")]
    UnprotectedCbc,
    /// The message or assertion names a SAML version other than 2.0.
    #[error("the SAML version is not 2.0")]
    Version,
    /// An issuer is missing, or names another entity or format.
    #[error("the issuer is not the identity provider")]
    Issuer,
    /// The response names a destination other than where it arrived.
    #[error("the response is addressed to another destination")]
    Destination,
    /// The identity provider answered with a status other than success;
    /// the payload is its top-level status code URI.
    #[error("the identity provider answered with status {0}")]
    Status(String),
    /// The response answers no request FerroSMART sent, or another one.
    #[error("the response answers another request")]
    InResponseTo,
    /// An instant is not a UTC `xs:dateTime`, or is in the future beyond
    /// the clock skew.
    #[error("an instant is malformed or in the future")]
    Instant,
    /// The assertion's conditions start after now.
    #[error("the assertion is not valid yet")]
    NotYetValid,
    /// The assertion's conditions or its session ended.
    #[error("the assertion has expired")]
    Expired,
    /// An audience restriction does not name FerroSMART.
    #[error("an audience restriction does not name FerroSMART")]
    Audience,
    /// The conditions carry one FerroSMART does not understand
    /// (saml-core-2.0-os §2.5.1.1).
    #[error("the assertion carries a condition FerroSMART does not understand")]
    Condition,
    /// No bearer subject confirmation names FerroSMART's assertion
    /// consumer service, the request, and a window that has not passed.
    #[error("no bearer subject confirmation is satisfied")]
    SubjectConfirmation,
    /// The authentication context is missing or below the provider's
    /// minimum.
    #[error("the authentication context is below the provider's minimum")]
    AuthnContext,
    /// The response carries more than one assertion.
    #[error("the response carries more than one assertion")]
    MultipleAssertions,
}

/// Writes `value` with the five characters XML 1.0 §2.4 and §3.1 reserve in
/// text and in a double-quoted attribute escaped.
struct Escaped<'a>(&'a str);

impl fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.0.chars() {
            match c {
                '&' => f.write_str("&amp;")?,
                '<' => f.write_str("&lt;")?,
                '>' => f.write_str("&gt;")?,
                '"' => f.write_str("&quot;")?,
                '\'' => f.write_str("&apos;")?,
                _ => fmt::Write::write_char(f, c)?,
            }
        }
        Ok(())
    }
}

/// Returns a fresh `xs:ID` value with 160 random bits (saml-core-2.0-os
/// §1.3.4 asks for at least 128), behind the `_` that makes it an `NCName`.
///
/// # Errors
///
/// [`aws_lc_rs::error::Unspecified`] when the system random source fails.
pub fn new_id() -> Result<String, aws_lc_rs::error::Unspecified> {
    let mut bytes = [0_u8; 20];
    aws_lc_rs::rand::fill(&mut bytes)?;
    let mut id = String::with_capacity(41);
    id.push('_');
    for byte in bytes {
        let _written: fmt::Result = fmt::Write::write_fmt(&mut id, format_args!("{byte:02x}"));
    }
    Ok(id)
}
