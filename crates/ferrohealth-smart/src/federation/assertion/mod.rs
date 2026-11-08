// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The eHDSI HP Identity Assertion and Treatment Relationship Confirmation
//! check, for an authorization server acting for a MyHealth@EU contact
//! point (behind `ehdsi-assertion`).
//!
//! NCPeH-B hands NCPeH-A both SAML 2.0 assertions, sender-vouches; an
//! authorization server that exchanges them for this node's `federation`
//! token checks them here: the enveloped signature by a trusted signer at
//! or above the SOG-IS ACM 1.3 floor (eHDSI Cryptographic Algorithms 9.0.0
//! §2, §4.1), the issuer, the audience, the window with its 60 s drift, the
//! subject confirmation and the attributes (SAML Profile 10.0.0 §2, §4), and
//! the TRC's link to the identity assertion. Each refusal carries its MyHealth@EU
//! Requirements Catalogue 10.0.0 §1.25 code name ([`AssertionError::code`]).
//!
//! The input is bounded before it is parsed: at most 64 KiB, nested at most
//! 32 elements deep, with at most 128 namespace declarations, then parsed
//! into at most 4096 nodes with no DTD. No specification governs these caps:
//! they are our own design, set well above what an eHDSI assertion uses, so
//! an unauthenticated input costs bounded work before any check runs.

use std::collections::BTreeMap;
use std::fmt;

use jiff::Timestamp;
use roxmltree::Document;
use roxmltree::Node;
use roxmltree::ParsingOptions;

use crate::federation::contact::EhdsiCode;

mod bounds;
mod c14n;
mod dsig;
pub mod identity;
pub mod signer;
pub mod treatment;

use crate::federation::assertion::identity::IdentityAssertion;
use crate::federation::assertion::signer::TrustedSigner;
use crate::federation::assertion::treatment::TreatmentAssertion;

/// The SAML 2.0 assertion namespace.
const SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
/// The HL7 v3 namespace of the `Role` and `PurposeOfUse` values (SAML
/// Profile 10.0.0 §2.3).
const HL7: &str = "urn:hl7-org:v3";
/// The `subject-id` attribute: the HP's name in the identity assertion, the patient's
/// identifier in the TRC (SAML Profile 10.0.0 §2.3, §4.3).
const SUBJECT: &str = "urn:oasis:names:tc:xspa:1.0:subject:subject-id";
/// The purpose of use attribute (SAML Profile 10.0.0 §2.3, §4.3).
const PURPOSE: &str = "urn:oasis:names:tc:xspa:1.0:subject:purposeofuse";
/// The only subject confirmation method (SAML Profile 10.0.0 §2.1, §4.1).
const SENDER_VOUCHES: &str = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";
/// The clock drift admitted at each window boundary: "within 60 seconds of
/// the validity window boundaries" (SAML Profile 10.0.0 §2.1, §4.1).
const DRIFT: i64 = 60;
/// The largest assertion read, in bytes (no specification governs the cap:
/// our own design). The element depth and namespace declaration caps beside
/// it are held before parsing ([`bounds`]).
const MAX_BYTES: usize = 64 * 1024;
/// The most nodes an assertion is parsed into (our own design).
const MAX_NODES: u32 = 4096;

/// Why an assertion's integrity cannot be established: its form, its
/// signature, its signer, its window, its audience or its confirmation.
///
/// Every one answers `ERROR_SEC_DATA_INTEGRITY_NOT_ENSURED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Integrity {
    /// The input is not well-formed XML, carries a DTD, or exceeds the size,
    /// node, depth or namespace declaration cap.
    #[error("the assertion is not well-formed XML within the caps")]
    Malformed,
    /// The document element is not a `saml:Assertion`.
    #[error("the document element is not a SAML assertion")]
    NotAssertion,
    /// `@Version` is not `2.0`.
    #[error("the assertion's Version is not 2.0")]
    Version,
    /// `@ID` is not a UUID.
    #[error("the assertion's ID is not a UUID")]
    Id,
    /// A required element or attribute is missing, repeated or malformed,
    /// named.
    #[error("the assertion's {0} is missing or malformed")]
    Structure(&'static str),
    /// No `ds:Signature` is present.
    #[error("the assertion is unsigned")]
    Unsigned,
    /// The signature does not cover the document element alone: a second
    /// signature, a signature elsewhere, a nested assertion, a reference to
    /// another element, or a repeated `ID`.
    #[error("the assertion's signature is wrapped")]
    Wrapped,
    /// A canonicalization other than exclusive XML canonicalization, or an
    /// inclusive prefix outside the SAML Profile's.
    #[error("the assertion's canonicalization is not the eHDSI one")]
    Canonicalization,
    /// An algorithm below the SOG-IS ACM 1.3 floor.
    #[error("the assertion's signature is below the SOG-IS ACM 1.3 floor: {0}")]
    Floor(Floor),
    /// No trusted signer is configured for the issuer, or `ds:KeyInfo`
    /// names another certificate.
    #[error("the assertion's signer is not trusted for its issuer")]
    Untrusted,
    /// The signer certificate is outside its validity.
    #[error("the assertion's signer certificate is outside its validity")]
    SignerExpired,
    /// The digest of the signed element does not match.
    #[error("the assertion's digest does not match")]
    Digest,
    /// The signature value does not verify.
    #[error("the assertion's signature does not verify")]
    BadSignature,
    /// `NotBefore` lies more than 60 s ahead.
    #[error("the assertion is not yet valid")]
    NotYetValid,
    /// `NotOnOrAfter` lies more than 60 s behind.
    #[error("the assertion has expired")]
    Expired,
    /// The window is empty or longer than the profile allows (4 h for the
    /// identity assertion, 2 h for the TRC).
    #[error("the assertion's window is longer than the profile allows")]
    Window,
    /// No `Audience` is one this node accepts.
    #[error("the assertion is not addressed to this audience")]
    Audience,
    /// The subject confirmation is not sender-vouches, or the identity assertion carries a
    /// `SubjectConfirmationData` (SAML Profile 10.0.0 §2.1).
    #[error("the assertion's subject confirmation is not sender-vouches alone")]
    Confirmation,
    /// The TRC does not name the identity assertion in `AssertionIDRef`, or names another
    /// professional (SAML Profile 10.0.0 §4.1).
    #[error("the treatment confirmation is not linked to the identity assertion")]
    Link,
}

/// The kind of algorithm below the floor of eHDSI Cryptographic Algorithms
/// 9.0.0 §2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Floor {
    /// A hash below SHA-256 (SOG-IS ACM 1.3 §3.1).
    Hash,
    /// An elliptic-curve signature, allowed only "if agreed by all
    /// countries" (Cryptographic Algorithms 9.0.0 §2).
    EllipticCurve,
    /// Any other method the floor does not agree.
    Algorithm,
}

impl fmt::Display for Floor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Hash => "a hash below SHA-256",
            Self::EllipticCurve => "an elliptic curve not agreed by all countries",
            Self::Algorithm => "an algorithm not agreed",
        })
    }
}

/// A refused assertion.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AssertionError {
    /// The assertion's integrity cannot be established.
    #[error(transparent)]
    Integrity(#[from] Integrity),
    /// A mandatory attribute is missing or not one the profile allows, the
    /// fields named as [`crate::federation::Field::as_str`] spells them.
    #[error("the assertion is refused {code}: {missing:?}")]
    Attributes {
        /// The §1.25 code.
        code: EhdsiCode,
        /// The missing fields.
        missing: Vec<&'static str>,
    },
}

impl AssertionError {
    /// Returns the MyHealth@EU Requirements Catalogue 10.0.0 §1.25 code
    /// name a contact point answers the refusal with.
    #[must_use]
    pub fn code(&self) -> EhdsiCode {
        match self {
            Self::Integrity(_) => EhdsiCode::SecDataIntegrityNotEnsured,
            Self::Attributes { code, .. } => *code,
        }
    }
}

/// The check of the assertions a contact point hands over.
#[derive(Debug, Clone)]
pub struct Validator {
    /// The trusted signers.
    signers: Vec<TrustedSigner>,
    /// The audiences this node accepts.
    audiences: Vec<String>,
}

impl Validator {
    /// Returns a validator that trusts `signers` and accepts an assertion
    /// addressed to one of `audiences`, such as
    /// `urn:ehdsi:assertions.audience:x-border` (SAML Profile 10.0.0 §2.1).
    #[must_use]
    pub fn new(signers: Vec<TrustedSigner>, audiences: Vec<String>) -> Self {
        Self { signers, audiences }
    }

    /// Checks the HP Identity Assertion `xml` at `now`.
    ///
    /// # Errors
    ///
    /// An [`AssertionError`] naming the first check it fails, in the order
    /// of the module documentation.
    pub fn identity(&self, xml: &str, now: Timestamp) -> Result<IdentityAssertion, AssertionError> {
        self.read(xml, identity::WINDOW, now, identity::read)
    }

    /// Checks the Treatment Relationship Confirmation `xml` at `now`, linked
    /// to `identity`.
    ///
    /// # Errors
    ///
    /// An [`AssertionError`] naming the first check it fails.
    pub fn treatment(
        &self,
        xml: &str,
        identity: &IdentityAssertion,
        now: Timestamp,
    ) -> Result<TreatmentAssertion, AssertionError> {
        self.read(xml, treatment::WINDOW, now, |envelope| {
            treatment::read(envelope, identity)
        })
    }

    /// Parses `xml`, checks what both assertions share, and hands the
    /// envelope to `read`.
    fn read<T>(
        &self,
        xml: &str,
        window: i64,
        now: Timestamp,
        read: impl FnOnce(&Envelope<'_, '_>) -> Result<T, AssertionError>,
    ) -> Result<T, AssertionError> {
        if xml.len() > MAX_BYTES {
            return Err(Integrity::Malformed.into());
        }
        bounds::check(xml).map_err(|_out_of_bounds| Integrity::Malformed)?;
        let options = ParsingOptions {
            allow_dtd: false,
            nodes_limit: MAX_NODES,
            ..ParsingOptions::default()
        };
        let document = Document::parse_with_options(xml, options)
            .map_err(|_malformed| Integrity::Malformed)?;
        let envelope = Envelope::open(&document, self, window, now)?;
        read(&envelope)
    }
}

/// What both assertions share, read from the signed document element.
pub(crate) struct Envelope<'a, 'input> {
    /// `@ID`.
    id: String,
    /// `saml:Issuer`.
    issuer: String,
    /// `Conditions/@NotBefore`.
    not_before: Timestamp,
    /// `Conditions/@NotOnOrAfter`.
    not_on_or_after: Timestamp,
    /// `Subject`.
    subject: Node<'a, 'input>,
    /// `Advice`, when present.
    advice: Option<Node<'a, 'input>>,
    /// `AuthnContextClassRef`, when present.
    authentication_class: Option<String>,
    /// The attribute values, by `Name`.
    attributes: BTreeMap<&'a str, Vec<Node<'a, 'input>>>,
}

impl<'a, 'input> Envelope<'a, 'input> {
    /// Checks the shared structure, the signature, the window, the audience
    /// and the confirmation of `document`.
    fn open(
        document: &'a Document<'input>,
        validator: &Validator,
        window: i64,
        now: Timestamp,
    ) -> Result<Self, AssertionError> {
        let root = document.root_element();
        if !is(root, SAML, "Assertion") {
            return Err(Integrity::NotAssertion.into());
        }
        if root
            .descendants()
            .skip(1)
            .any(|node| is(node, SAML, "Assertion"))
        {
            return Err(Integrity::Wrapped.into());
        }
        if root.attribute("Version") != Some("2.0") {
            return Err(Integrity::Version.into());
        }
        let id = root.attribute("ID").ok_or(Integrity::Id)?;
        if !uuid(id) {
            return Err(Integrity::Id.into());
        }
        let issuer = required(root, "Issuer").and_then(|node| text(node, "saml:Issuer"))?;
        let signers: Vec<&TrustedSigner> = validator
            .signers
            .iter()
            .filter(|signer| signer.issuer() == issuer)
            .collect();
        if signers.is_empty() {
            return Err(Integrity::Untrusted.into());
        }
        dsig::verify(root, &signers, now)?;
        time(root.attribute("IssueInstant"), "@IssueInstant")?;
        let conditions = required(root, "Conditions")?;
        let not_before = time(conditions.attribute("NotBefore"), "@NotBefore")?;
        let not_on_or_after = time(conditions.attribute("NotOnOrAfter"), "@NotOnOrAfter")?;
        let span = not_on_or_after
            .as_second()
            .saturating_sub(not_before.as_second());
        if span <= 0 || span > window {
            return Err(Integrity::Window.into());
        }
        if now.as_second() < not_before.as_second().saturating_sub(DRIFT) {
            return Err(Integrity::NotYetValid.into());
        }
        if now.as_second() >= not_on_or_after.as_second().saturating_add(DRIFT) {
            return Err(Integrity::Expired.into());
        }
        let restriction = required(conditions, "AudienceRestriction")?;
        let addressed = elements(restriction, SAML, "Audience")
            .filter_map(|audience| text(audience, "saml:Audience").ok())
            .any(|audience| validator.audiences.contains(&audience));
        if !addressed {
            return Err(Integrity::Audience.into());
        }
        let subject = required(root, "Subject")?;
        let confirmation = required(subject, "SubjectConfirmation")?;
        if confirmation.attribute("Method") != Some(SENDER_VOUCHES) {
            return Err(Integrity::Confirmation.into());
        }
        let authn = required(root, "AuthnStatement")?;
        time(authn.attribute("AuthnInstant"), "@AuthnInstant")?;
        let authentication_class =
            optional(required(authn, "AuthnContext")?, "AuthnContextClassRef")?
                .and_then(|node| text(node, "saml:AuthnContextClassRef").ok());
        let mut attributes: BTreeMap<&str, Vec<Node<'_, '_>>> = BTreeMap::new();
        for attribute in elements(required(root, "AttributeStatement")?, SAML, "Attribute") {
            let name = attribute
                .attribute("Name")
                .ok_or(Integrity::Structure("saml:Attribute"))?;
            let values = elements(attribute, SAML, "AttributeValue").collect();
            if attributes.insert(name, values).is_some() {
                return Err(Integrity::Structure("saml:Attribute").into());
            }
        }
        Ok(Self {
            id: id.to_owned(),
            issuer,
            not_before,
            not_on_or_after,
            subject,
            advice: optional(root, "Advice")?,
            authentication_class,
            attributes,
        })
    }

    /// Returns the `NameID` text and its `@Format`, when present.
    fn name_id(&self) -> Result<Option<(String, Option<&'a str>)>, AssertionError> {
        Ok(match optional(self.subject, "NameID")? {
            Some(node) => text(node, "saml:NameID")
                .ok()
                .map(|value| (value, node.attribute("Format"))),
            None => None,
        })
    }

    /// Returns `Advice`, refusing an assertion without one.
    fn advice(&self) -> Result<Node<'a, 'input>, AssertionError> {
        self.advice
            .ok_or_else(|| Integrity::Structure("saml:Advice").into())
    }

    /// Returns the values of the attribute `name`.
    fn values(&self, name: &str) -> &[Node<'a, 'input>] {
        self.attributes.get(name).map_or(&[], Vec::as_slice)
    }

    /// Returns the one text value of the attribute `name`, or nothing when
    /// it is absent or empty.
    ///
    /// # Errors
    ///
    /// [`Integrity::Structure`] when the attribute carries more than one
    /// value.
    fn single(&self, name: &str) -> Result<Option<String>, AssertionError> {
        match self.values(name) {
            [] => Ok(None),
            [value] => Ok(text(*value, "saml:AttributeValue").ok()),
            _ => Err(Integrity::Structure("saml:AttributeValue").into()),
        }
    }
}

/// Whether `node` is the element `name` of `namespace`.
fn is(node: Node<'_, '_>, namespace: &str, name: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(namespace)
        && node.tag_name().name() == name
}

/// Returns the child elements `name` of `namespace`.
fn elements<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &'static str,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'input>> {
    node.children()
        .filter(move |child| is(*child, namespace, name))
}

/// Returns the one SAML child element `name`, refusing a repeated one.
fn optional<'a, 'input>(
    node: Node<'a, 'input>,
    name: &'static str,
) -> Result<Option<Node<'a, 'input>>, AssertionError> {
    let mut found = elements(node, SAML, name);
    let first = found.next();
    if found.next().is_some() {
        return Err(Integrity::Structure(name).into());
    }
    Ok(first)
}

/// Returns the one SAML child element `name`, refusing a missing or
/// repeated one.
fn required<'a, 'input>(
    node: Node<'a, 'input>,
    name: &'static str,
) -> Result<Node<'a, 'input>, AssertionError> {
    optional(node, name)?.ok_or_else(|| Integrity::Structure(name).into())
}

/// Returns the text content of an element without element children,
/// refusing an empty one.
fn text(node: Node<'_, '_>, what: &'static str) -> Result<String, AssertionError> {
    if node.children().any(|child| child.is_element()) {
        return Err(Integrity::Structure(what).into());
    }
    let value: String = node
        .children()
        .filter_map(|child| child.is_text().then(|| child.text()).flatten())
        .collect();
    if value.is_empty() {
        Err(Integrity::Structure(what).into())
    } else {
        Ok(value)
    }
}

/// Reads a SAML time: an `xs:dateTime` in UTC, ending in `Z` (SAML 2.0
/// Core §1.3.3).
fn time(value: Option<&str>, what: &'static str) -> Result<Timestamp, AssertionError> {
    value
        .filter(|value| value.ends_with('Z'))
        .and_then(|value| value.parse::<Timestamp>().ok())
        .ok_or_else(|| Integrity::Structure(what).into())
}

/// Whether `id` is a UUID: URN-encoded as SAML Profile 10.0.0 §2.1 writes
/// it, or behind the `_` that makes it the `xs:ID` SAML 2.0 Core §2.3.3
/// types `@ID` as.
fn uuid(id: &str) -> bool {
    let Some(bare) = id
        .strip_prefix("urn:uuid:")
        .or_else(|| id.strip_prefix('_'))
    else {
        return false;
    };
    let groups: Vec<&str> = bare.split('-').collect();
    let lengths: Vec<usize> = groups.iter().map(|group| group.len()).collect();
    lengths == [8, 4, 4, 4, 12]
        && groups
            .iter()
            .all(|group| group.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::uuid;

    #[test]
    fn an_id_is_a_urn_or_underscore_uuid() {
        assert!(uuid("urn:uuid:0f8fad5b-d9cb-469f-a165-70867728950e"));
        assert!(uuid("_0f8fad5b-d9cb-469f-a165-70867728950e"));
        assert!(!uuid("0f8fad5b-d9cb-469f-a165-70867728950e"));
        assert!(!uuid("urn:uuid:ida-1"));
        assert!(!uuid("urn:uuid:0f8fad5b-d9cb-469f-a165-70867728950"));
    }
}
