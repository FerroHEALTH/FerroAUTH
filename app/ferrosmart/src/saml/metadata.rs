// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The identity provider's metadata, read, and FerroSMART's own, written
//! (saml-metadata-2.0-os).
//!
//! The identity provider is read from its `md:EntityDescriptor`, alone or
//! inside `md:EntitiesDescriptor` aggregates: the signing keys of its
//! `md:IDPSSODescriptor` (§2.4.1.1, §2.4.3), its single sign-on and
//! artifact resolution endpoints (§2.2.2, §2.2.3), whether it wants signed
//! requests, and the end of the metadata's validity (§2.2.1, §4.3). When
//! the deployment names the keys the metadata is signed with, the entity's
//! descriptor or an aggregate above it carries a signature one of them
//! verifies (§3), checked as every SAML signature is.

use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jiff::Timestamp;
use roxmltree::Node;

use crate::saml::DSIG;
use crate::saml::HTTP_ARTIFACT;
use crate::saml::HTTP_POST;
use crate::saml::METADATA;
use crate::saml::PROTOCOL;
use crate::saml::Refusal;
use crate::saml::SOAP;
use crate::saml::dsig;
use crate::saml::keys::DecryptionKey;
use crate::saml::keys::SigningKey;
use crate::saml::keys::TrustedKey;
use crate::saml::xml;
use crate::saml::xml::Children;

/// Why an identity provider's metadata cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MetadataError {
    /// The document is not metadata FerroSMART can read; the refusal says
    /// which check failed.
    #[error("the metadata is refused: {0}")]
    Refused(#[source] Refusal),
    /// No `md:EntityDescriptor` with the configured `entityID` is present.
    #[error("the metadata describes no entity with the configured entityID")]
    NoEntity,
    /// The entity has no `md:IDPSSODescriptor` supporting SAML 2.0, or more
    /// than one.
    #[error("the entity has no single SAML 2.0 identity provider descriptor")]
    NoIdentityProvider,
    /// The descriptor publishes no signing key FerroSMART can verify with.
    #[error("the identity provider publishes no usable signing key")]
    NoSigningKey,
    /// A `validUntil` of the descriptor or above it has passed (§2.2.1).
    #[error("the metadata is no longer valid")]
    Expired,
    /// The metadata carries no signature, where the deployment requires
    /// one.
    #[error("the metadata is not signed")]
    Unsigned,
    /// An endpoint location is not an absolute `https` URL.
    #[error("an endpoint location is not an absolute https URL")]
    Location,
}

impl From<Refusal> for MetadataError {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

/// One endpoint of the identity provider (saml-metadata-2.0-os §2.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// The binding URI.
    pub binding: String,
    /// The location.
    pub location: url::Url,
    /// The index, for an indexed endpoint (§2.2.3).
    pub index: Option<u16>,
}

/// The identity provider, as its metadata describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityProvider {
    /// Its entity ID.
    entity_id: String,
    /// The keys that verify its signatures.
    signing_keys: Vec<TrustedKey>,
    /// Its `SingleSignOnService` endpoints.
    single_sign_on: Vec<Endpoint>,
    /// Its `ArtifactResolutionService` endpoints.
    artifact_resolution: Vec<Endpoint>,
    /// Whether it wants signed authentication requests.
    want_authn_requests_signed: bool,
    /// The earliest `validUntil` of the descriptor and the elements above
    /// it, when any names one.
    valid_until: Option<Timestamp>,
}

impl IdentityProvider {
    /// Reads the identity provider `entity_id` from the metadata `xml` at
    /// `now`; with `metadata_keys`, a signature one of them verifies must
    /// cover its descriptor.
    ///
    /// # Errors
    ///
    /// A [`MetadataError`] naming the check that failed.
    pub fn from_metadata(
        xml: &str,
        entity_id: &str,
        now: Timestamp,
        metadata_keys: Option<&[TrustedKey]>,
    ) -> Result<Self, MetadataError> {
        let prepared = xml::prepare(xml)?;
        let document = xml::parse(&prepared)?;
        let root = document.root_element();
        let entity = document
            .descendants()
            .find(|node| {
                xml::is(*node, METADATA, "EntityDescriptor")
                    && node.attribute("entityID") == Some(entity_id)
            })
            .ok_or(MetadataError::NoEntity)?;
        let mut chain = Vec::new();
        let mut at = Some(entity);
        while let Some(node) = at.filter(Node::is_element) {
            if !(xml::is(node, METADATA, "EntityDescriptor")
                || xml::is(node, METADATA, "EntitiesDescriptor"))
            {
                return Err(MetadataError::NoEntity);
            }
            chain.push(node);
            at = node.parent();
        }
        if chain.last() != Some(&root) {
            return Err(MetadataError::NoEntity);
        }
        if let Some(keys) = metadata_keys {
            let signed = chain
                .iter()
                .find(|node| {
                    node.children()
                        .any(|child| xml::is(child, DSIG, "Signature"))
                })
                .ok_or(MetadataError::Unsigned)?;
            dsig::verify(*signed, keys)?;
        }
        let descriptors: Vec<Node<'_, '_>> = entity
            .children()
            .filter(|child| {
                xml::is(*child, METADATA, "IDPSSODescriptor")
                    && child
                        .attribute("protocolSupportEnumeration")
                        .is_some_and(|protocols| {
                            protocols
                                .split_ascii_whitespace()
                                .any(|uri| uri == PROTOCOL)
                        })
            })
            .collect();
        let [descriptor] = descriptors[..] else {
            return Err(MetadataError::NoIdentityProvider);
        };
        chain.insert(0, descriptor);
        let mut valid_until: Option<Timestamp> = None;
        for node in &chain {
            if let Some(until) = xml::instant(*node, "validUntil")? {
                valid_until = Some(valid_until.map_or(until, |earliest| earliest.min(until)));
            }
        }
        if valid_until.is_some_and(|until| until <= now) {
            return Err(MetadataError::Expired);
        }
        let mut signing_keys = Vec::new();
        let mut single_sign_on = Vec::new();
        let mut artifact_resolution = Vec::new();
        for child in Children::of(descriptor, "md:IDPSSODescriptor")?.rest() {
            if xml::is(child, METADATA, "KeyDescriptor") {
                if child
                    .attribute("use")
                    .is_none_or(|usage| usage == "signing")
                {
                    signing_keys.extend(trusted_keys(child)?);
                }
            } else if xml::is(child, METADATA, "SingleSignOnService") {
                single_sign_on.push(endpoint(child, false)?);
            } else if xml::is(child, METADATA, "ArtifactResolutionService") {
                artifact_resolution.push(endpoint(child, true)?);
            }
        }
        if signing_keys.is_empty() {
            return Err(MetadataError::NoSigningKey);
        }
        Ok(Self {
            entity_id: entity_id.to_owned(),
            signing_keys,
            single_sign_on,
            artifact_resolution,
            want_authn_requests_signed: descriptor.attribute("WantAuthnRequestsSigned")
                == Some("true")
                || descriptor.attribute("WantAuthnRequestsSigned") == Some("1"),
            valid_until,
        })
    }

    /// Its entity ID.
    #[must_use]
    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    /// The keys that verify its signatures.
    #[must_use]
    pub fn signing_keys(&self) -> &[TrustedKey] {
        &self.signing_keys
    }

    /// The single sign-on location for `binding`, the first one listed.
    #[must_use]
    pub fn single_sign_on(&self, binding: &str) -> Option<&url::Url> {
        self.single_sign_on
            .iter()
            .find(|endpoint| endpoint.binding == binding)
            .map(|endpoint| &endpoint.location)
    }

    /// The SOAP artifact resolution location with `index`
    /// (saml-bindings-2.0-os §3.6.4).
    #[must_use]
    pub fn artifact_resolution(&self, index: u16) -> Option<&url::Url> {
        self.artifact_resolution
            .iter()
            .find(|endpoint| endpoint.binding == SOAP && endpoint.index == Some(index))
            .map(|endpoint| &endpoint.location)
    }

    /// Whether it wants signed authentication requests (§2.4.3).
    #[must_use]
    pub fn want_authn_requests_signed(&self) -> bool {
        self.want_authn_requests_signed
    }

    /// The earliest `validUntil` above and on its descriptor.
    #[must_use]
    pub fn valid_until(&self) -> Option<Timestamp> {
        self.valid_until
    }
}

/// Returns the keys of the `ds:X509Certificate` elements of a key
/// descriptor; a key of a kind FerroSMART cannot verify with is not one it
/// trusts, so it is left out (our own design).
fn trusted_keys(descriptor: Node<'_, '_>) -> Result<Vec<TrustedKey>, Refusal> {
    let mut keys = Vec::new();
    for certificate in descriptor
        .descendants()
        .filter(|node| xml::is(*node, DSIG, "X509Certificate"))
    {
        let der = dsig::base64(certificate, "ds:X509Certificate")?;
        if let Ok(key) = TrustedKey::from_certificate_der(&der) {
            keys.push(key);
        }
    }
    Ok(keys)
}

/// Reads one endpoint, its location an absolute `https` URL.
fn endpoint(node: Node<'_, '_>, indexed: bool) -> Result<Endpoint, MetadataError> {
    let binding = node
        .attribute("Binding")
        .ok_or(Refusal::Structure("md:Endpoint"))?;
    let location = node
        .attribute("Location")
        .and_then(|location| url::Url::parse(location).ok())
        .filter(|location| location.scheme() == "https")
        .ok_or(MetadataError::Location)?;
    let index = if indexed {
        Some(
            node.attribute("index")
                .and_then(|index| index.parse::<u16>().ok())
                .ok_or(Refusal::Structure("md:IndexedEndpoint"))?,
        )
    } else {
        None
    };
    Ok(Endpoint {
        binding: binding.to_owned(),
        location,
        index,
    })
}

/// FerroSMART's service provider metadata (saml-metadata-2.0-os §2.4.4).
#[derive(Debug)]
pub struct ServiceProvider<'a> {
    /// FerroSMART's entity ID.
    pub entity_id: &'a str,
    /// The assertion consumer service location, where the HTTP-POST and
    /// the HTTP-Artifact bindings deliver.
    pub acs_url: &'a str,
    /// The key that signs FerroSMART's requests.
    pub signing_key: &'a SigningKey,
    /// The keys an identity provider encrypts for.
    pub decryption_keys: &'a [DecryptionKey],
    /// The name identifier formats FerroSMART asks for, in order.
    pub name_id_formats: &'a [String],
}

impl ServiceProvider<'_> {
    /// Writes the `md:EntityDescriptor`.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        let entity = crate::saml::Escaped(self.entity_id);
        let acs = crate::saml::Escaped(self.acs_url);
        // Writing to a String cannot fail, so the results are discarded.
        let _written: std::fmt::Result = write!(
            out,
            concat!(
                "<md:EntityDescriptor xmlns:md=\"{md}\" xmlns:ds=\"{ds}\" entityID=\"{entity}\">",
                "<md:SPSSODescriptor protocolSupportEnumeration=\"{protocol}\" ",
                "AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">"
            ),
            md = METADATA,
            ds = DSIG,
            entity = entity,
            protocol = PROTOCOL,
        );
        key_descriptor(&mut out, "signing", self.signing_key.certificate_der(), &[]);
        for key in self.decryption_keys {
            key_descriptor(
                &mut out,
                "encryption",
                key.certificate_der(),
                ENCRYPTION_METHODS,
            );
        }
        for format in self.name_id_formats {
            let _written: std::fmt::Result = write!(
                out,
                "<md:NameIDFormat>{}</md:NameIDFormat>",
                crate::saml::Escaped(format)
            );
        }
        for (index, binding) in [HTTP_POST, HTTP_ARTIFACT].into_iter().enumerate() {
            let _written: std::fmt::Result = write!(
                out,
                concat!(
                    "<md:AssertionConsumerService index=\"{index}\" isDefault=\"{default}\" ",
                    "Binding=\"{binding}\" Location=\"{acs}\"/>"
                ),
                index = index,
                default = index == 0,
                binding = binding,
                acs = acs,
            );
        }
        out.push_str("</md:SPSSODescriptor></md:EntityDescriptor>");
        out
    }
}

/// The algorithms FerroSMART decrypts with, which an encryption key
/// descriptor names in order of preference (saml-metadata-2.0-os
/// §2.4.1.1).
const ENCRYPTION_METHODS: &[&str] = &[
    "http://www.w3.org/2009/xmlenc11#aes256-gcm",
    "http://www.w3.org/2009/xmlenc11#aes128-gcm",
    "http://www.w3.org/2009/xmlenc11#rsa-oaep",
    "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
];

/// Writes one `md:KeyDescriptor` for `certificate`.
fn key_descriptor(out: &mut String, usage: &str, certificate: &[u8], methods: &[&str]) {
    let _written: std::fmt::Result = write!(
        out,
        concat!(
            "<md:KeyDescriptor use=\"{usage}\"><ds:KeyInfo><ds:X509Data>",
            "<ds:X509Certificate>{certificate}</ds:X509Certificate>",
            "</ds:X509Data></ds:KeyInfo>"
        ),
        usage = usage,
        certificate = STANDARD.encode(certificate),
    );
    for method in methods {
        let _written: std::fmt::Result =
            write!(out, "<md:EncryptionMethod Algorithm=\"{method}\"/>");
    }
    out.push_str("</md:KeyDescriptor>");
}
