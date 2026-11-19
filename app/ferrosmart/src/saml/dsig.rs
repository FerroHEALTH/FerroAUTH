// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The enveloped XML Signature of a SAML message or assertion.
//!
//! It follows saml-core-2.0-os §5.4 and xmldsig-core1, checked in the one shape that
//! leaves signature wrapping nothing to work with, and written in that
//! same shape.
//!
//! The check is handed the element the caller will read, never an ID to
//! look up: the signature must be that element's child, its one reference
//! must name that element's `ID` (§5.4.2), and the digest is taken over
//! that element as parsed, so what is verified is what is read.
//!
//! What is accepted (our own design within xmldsig-core1 §6.1 and
//! saml-core-2.0-os §5.4.3 to §5.4.5, recorded in `docs/architecture.md`
//! §13.25): exclusive canonicalization without comments, the enveloped
//! transform then exclusive canonicalization and nothing else, digests
//! SHA-256, SHA-384 and SHA-512, signatures RSASSA-PKCS1-v1_5 with those
//! digests on keys of 2048 bits or more and ECDSA on P-256, P-384 and
//! P-521 with the digest of its curve. SHA-1, DSA, HMAC and any
//! `ds:Object` are refused; `ds:KeyInfo` is never read, since the keys come
//! from the identity provider's metadata.

use std::fmt::Write as _;

use aws_lc_rs::digest;
use aws_lc_rs::signature;
use aws_lc_rs::signature::UnparsedPublicKey;
use aws_lc_rs::signature::VerificationAlgorithm;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ferrohealth_smart::xml::c14n;
use roxmltree::Node;

use crate::saml::DSIG;
use crate::saml::Refusal;
use crate::saml::keys::KeyKind;
use crate::saml::keys::SigningKey;
use crate::saml::keys::TrustedKey;
use crate::saml::xml;
use crate::saml::xml::Children;

/// Exclusive canonicalization without comments (Exc-C14N §1.1), the one
/// canonicalization accepted, and the namespace of its
/// `InclusiveNamespaces` parameter.
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
/// The enveloped signature transform (xmldsig-core1 §6.6.4).
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
/// SHA-256 (xmldsig-core1 §6.2.2), the digest FerroSMART signs with.
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// Checks the enveloped signature that is a child of `apex`, by one of
/// `keys`. The caller has placed the signature: it is the one
/// `ds:Signature` child of `apex`.
pub(super) fn verify(apex: Node<'_, '_>, keys: &[TrustedKey]) -> Result<(), Refusal> {
    let id = apex.attribute("ID").ok_or(Refusal::Structure("ID"))?;
    let mut signatures = apex
        .children()
        .filter(|child| xml::is(*child, DSIG, "Signature"));
    let signature = signatures.next().ok_or(Refusal::Unprotected)?;
    if signatures.next().is_some() {
        return Err(Refusal::Wrapped);
    }
    let mut parts = Children::of(signature, "ds:Signature")?;
    let signed_info = parts.required(DSIG, "SignedInfo", "ds:SignedInfo")?;
    let signature_value = parts.required(DSIG, "SignatureValue", "ds:SignatureValue")?;
    // NOTE: saml-core-2.0-os §5.4.5 as errata E91 adds it: a `ds:Object` can carry unsigned
    // data, so a verifier should reject it; `parts.end()` refuses it with any other child.
    parts.optional(DSIG, "KeyInfo");
    parts.end()?;

    let mut info = Children::of(signed_info, "ds:SignedInfo")?;
    let method = info.required(DSIG, "CanonicalizationMethod", "ds:CanonicalizationMethod")?;
    let signature_method = info.required(DSIG, "SignatureMethod", "ds:SignatureMethod")?;
    let reference = info.required(DSIG, "Reference", "ds:Reference")?;
    info.end().map_err(|_more| Refusal::Wrapped)?;
    let info_prefixes = canonicalization(method)?;
    if !xml::empty(signature_method) {
        return Err(Refusal::Algorithm("signature"));
    }
    let algorithm = algorithm_of(signature_method)?;

    // NOTE: saml-core-2.0-os §5.4.2: the one reference names the ID of the signed element,
    // which is this signature's parent; anything else is the wrapping shape.
    if reference
        .attribute("URI")
        .and_then(|uri| uri.strip_prefix('#'))
        != Some(id)
    {
        return Err(Refusal::Wrapped);
    }
    let mut steps = Children::of(reference, "ds:Reference")?;
    let transforms = steps.required(DSIG, "Transforms", "ds:Transforms")?;
    let digest_method = steps.required(DSIG, "DigestMethod", "ds:DigestMethod")?;
    let digest_value = steps.required(DSIG, "DigestValue", "ds:DigestValue")?;
    steps.end()?;
    let mut transform = Children::of(transforms, "ds:Transforms")?;
    let enveloped = transform.required(DSIG, "Transform", "ds:Transform")?;
    let exclusive = transform.required(DSIG, "Transform", "ds:Transform")?;
    transform
        .end()
        .map_err(|_more| Refusal::Algorithm("transform"))?;
    if enveloped.attribute("Algorithm") != Some(ENVELOPED) || !xml::empty(enveloped) {
        return Err(Refusal::Algorithm("transform"));
    }
    let reference_prefixes = canonicalization(exclusive)?;
    let digest_algorithm = digest_algorithm(digest_method)?;

    let expected = base64(digest_value, "ds:DigestValue")?;
    let covered = c14n::canonicalize(apex, Some(signature.id()), &reference_prefixes)
        .map_err(|_unrepresentable| Refusal::Structure("canonical form"))?;
    if digest::digest(digest_algorithm, &covered).as_ref() != expected.as_slice() {
        return Err(Refusal::Digest);
    }
    let octets = c14n::canonicalize(signed_info, None, &info_prefixes)
        .map_err(|_unrepresentable| Refusal::Structure("canonical form"))?;
    let value = base64(signature_value, "ds:SignatureValue")?;
    let verified = keys.iter().any(|key| {
        verifier(algorithm, key.kind()).is_some_and(|verifier| {
            UnparsedPublicKey::new(verifier, key.public())
                .verify(&octets, &value)
                .is_ok()
        })
    });
    if verified {
        Ok(())
    } else {
        Err(Refusal::BadSignature)
    }
}

/// The signature algorithms accepted, by URI (xmldsig-core1 §6.4; RFC 6931
/// §2.3.2, §2.3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaSha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RsaSha384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RsaSha512,
    /// ECDSA with SHA-256.
    EcdsaSha256,
    /// ECDSA with SHA-384.
    EcdsaSha384,
    /// ECDSA with SHA-512.
    EcdsaSha512,
}

/// Returns the accepted signature algorithm `node` names.
fn algorithm_of(node: Node<'_, '_>) -> Result<Algorithm, Refusal> {
    Ok(match node.attribute("Algorithm") {
        Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") => Algorithm::RsaSha256,
        Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384") => Algorithm::RsaSha384,
        Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512") => Algorithm::RsaSha512,
        Some("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256") => Algorithm::EcdsaSha256,
        Some("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384") => Algorithm::EcdsaSha384,
        Some("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512") => Algorithm::EcdsaSha512,
        _ => return Err(Refusal::Algorithm("signature")),
    })
}

/// Returns the verifier of `algorithm` for a key of `kind`, when the two
/// belong together: an RSA method for an RSA key, an ECDSA method for the
/// curve whose size its digest matches.
fn verifier(algorithm: Algorithm, kind: KeyKind) -> Option<&'static dyn VerificationAlgorithm> {
    Some(match (algorithm, kind) {
        (Algorithm::RsaSha256, KeyKind::Rsa) => &signature::RSA_PKCS1_2048_8192_SHA256,
        (Algorithm::RsaSha384, KeyKind::Rsa) => &signature::RSA_PKCS1_2048_8192_SHA384,
        (Algorithm::RsaSha512, KeyKind::Rsa) => &signature::RSA_PKCS1_2048_8192_SHA512,
        (Algorithm::EcdsaSha256, KeyKind::P256) => &signature::ECDSA_P256_SHA256_FIXED,
        (Algorithm::EcdsaSha384, KeyKind::P384) => &signature::ECDSA_P384_SHA384_FIXED,
        (Algorithm::EcdsaSha512, KeyKind::P521) => &signature::ECDSA_P521_SHA512_FIXED,
        _ => return None,
    })
}

/// Returns the digest `node` names: SHA-256, SHA-384 or SHA-512
/// (xmldsig-core1 §6.2).
fn digest_algorithm(node: Node<'_, '_>) -> Result<&'static digest::Algorithm, Refusal> {
    if !xml::empty(node) {
        return Err(Refusal::Algorithm("digest"));
    }
    Ok(match node.attribute("Algorithm") {
        Some(SHA256) => &digest::SHA256,
        Some("http://www.w3.org/2001/04/xmldsig-more#sha384") => &digest::SHA384,
        Some("http://www.w3.org/2001/04/xmlenc#sha512") => &digest::SHA512,
        _ => return Err(Refusal::Algorithm("digest")),
    })
}

/// Returns the inclusive prefixes of an exclusive canonicalization method
/// or transform, refusing every other canonicalization (Exc-C14N §3).
fn canonicalization<'a>(node: Node<'a, '_>) -> Result<Vec<&'a str>, Refusal> {
    if node.attribute("Algorithm") != Some(EXC_C14N) {
        return Err(Refusal::Algorithm("canonicalization"));
    }
    let mut parameters = Children::of(node, "canonicalization")?;
    let prefixes = parameters
        .optional(EXC_C14N, "InclusiveNamespaces")
        .map(|list| {
            list.attribute("PrefixList")
                .unwrap_or_default()
                .split_ascii_whitespace()
                .collect()
        })
        .unwrap_or_default();
    parameters
        .end()
        .map_err(|_more| Refusal::Algorithm("canonicalization"))?;
    Ok(prefixes)
}

/// Decodes the base64 content of `node`, white space dropped
/// (xmldsig-core1 §4.5, `base64Binary`).
pub(super) fn base64(node: Node<'_, '_>, what: &'static str) -> Result<Vec<u8>, Refusal> {
    let text: String = xml::text(node, what)?
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    STANDARD
        .decode(text)
        .map_err(|_invalid| Refusal::Structure(what))
}

/// A message FerroSMART cannot sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// The message is not the shape FerroSMART writes: well formed, its
    /// root carrying an `ID` and a `saml:Issuer` first child.
    #[error("the message to sign is not of the shape FerroSMART writes")]
    Shape,
    /// The signing key or the random source failed.
    #[error("the signing key failed")]
    Key,
}

/// Returns `message` with an enveloped signature by `key` inserted after
/// its root's `saml:Issuer` (saml-core-2.0-os §3.2.1, §5.4), or first in
/// a metadata descriptor, in the one shape the check accepts.
///
/// # Errors
///
/// [`SignError::Shape`] when `message` is not of that shape, and
/// [`SignError::Key`] when signing fails.
pub fn sign(message: &str, key: &SigningKey) -> Result<String, SignError> {
    let document = roxmltree::Document::parse(message).map_err(|_malformed| SignError::Shape)?;
    let root = document.root_element();
    let id = root.attribute("ID").ok_or(SignError::Shape)?;
    // NOTE: saml-core-2.0-os §3.2.1 and §2.3.3 place the signature after the `Issuer`;
    // saml-metadata-2.0-os §2.3.2 places it first in a descriptor, which has no `Issuer`.
    let at = match root.children().find(Node::is_element) {
        Some(first) if first.tag_name().name() == "Issuer" => first.range().end,
        _ => root
            .first_child()
            .map_or(root.range().end, |child| child.range().start),
    };
    let covered =
        c14n::canonicalize(root, None, &[]).map_err(|_unrepresentable| SignError::Shape)?;
    let digest = STANDARD.encode(digest::digest(&digest::SHA256, &covered));
    let mut signed_info = String::new();
    // The element is written in its canonical form, so its octets are signed as written.
    write!(
        signed_info,
        concat!(
            "<ds:SignedInfo xmlns:ds=\"{dsig}\">",
            "<ds:CanonicalizationMethod Algorithm=\"{exc}\"></ds:CanonicalizationMethod>",
            "<ds:SignatureMethod Algorithm=\"{method}\"></ds:SignatureMethod>",
            "<ds:Reference URI=\"#{id}\"><ds:Transforms>",
            "<ds:Transform Algorithm=\"{enveloped}\"></ds:Transform>",
            "<ds:Transform Algorithm=\"{exc}\"></ds:Transform></ds:Transforms>",
            "<ds:DigestMethod Algorithm=\"{sha256}\"></ds:DigestMethod>",
            "<ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
        ),
        dsig = DSIG,
        exc = EXC_C14N,
        method = key.algorithm(),
        id = crate::saml::Escaped(id),
        enveloped = ENVELOPED,
        sha256 = SHA256,
        digest = digest,
    )
    .map_err(|_full| SignError::Shape)?;
    let value = STANDARD.encode(
        key.sign(signed_info.as_bytes())
            .map_err(|_unspecified| SignError::Key)?,
    );
    let certificate = STANDARD.encode(key.certificate_der());
    let signature = format!(
        concat!(
            "<ds:Signature xmlns:ds=\"{dsig}\">{signed_info}",
            "<ds:SignatureValue>{value}</ds:SignatureValue>",
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}",
            "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"
        ),
        dsig = DSIG,
        signed_info = signed_info,
        value = value,
        certificate = certificate,
    );
    let (head, tail) = (message.get(..at), message.get(at..));
    let (Some(head), Some(tail)) = (head, tail) else {
        return Err(SignError::Shape);
    };
    Ok(format!("{head}{signature}{tail}"))
}

/// Returns the base64 signature of `octets` by `key`, the `Signature`
/// parameter of the HTTP-Redirect binding (saml-bindings-2.0-os §3.4.4.1).
pub(super) fn sign_octets(octets: &[u8], key: &SigningKey) -> Result<String, SignError> {
    key.sign(octets)
        .map(|value| STANDARD.encode(value))
        .map_err(|_unspecified| SignError::Key)
}

#[cfg(test)]
mod tests {
    use super::{sign, verify};
    use crate::saml::Refusal;
    use crate::saml::keys::{SigningKey, TrustedKey};

    fn pair(algorithm: &'static rcgen::SignatureAlgorithm) -> (SigningKey, TrustedKey) {
        let key = rcgen::KeyPair::generate_for(algorithm).expect("a key");
        let certificate = rcgen::CertificateParams::new(vec![String::from("sp.example.org")])
            .expect("params")
            .self_signed(&key)
            .expect("a certificate");
        let signing =
            SigningKey::from_pem(key.serialize_pem().as_bytes(), certificate.pem().as_bytes())
                .expect("a signing key");
        let trusted = TrustedKey::from_certificate_der(certificate.der()).expect("a trusted key");
        (signing, trusted)
    }

    const REQUEST: &str = concat!(
        "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ",
        "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r1\" Version=\"2.0\">",
        "<saml:Issuer>https://sp.example.org</saml:Issuer><samlp:NameIDPolicy AllowCreate=\"true\"/>",
        "</samlp:AuthnRequest>"
    );

    #[test]
    fn what_ferrosmart_signs_verifies_for_each_key_kind() {
        for algorithm in [
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P384_SHA384,
        ] {
            let (signing, trusted) = pair(algorithm);
            let signed = sign(REQUEST, &signing).expect("signed");
            let document = roxmltree::Document::parse(&signed).expect("well formed");
            assert_eq!(verify(document.root_element(), &[trusted]), Ok(()));
        }
    }

    #[test]
    fn a_key_of_another_curve_does_not_verify() {
        let (signing, _) = pair(&rcgen::PKCS_ECDSA_P256_SHA256);
        let (_, other) = pair(&rcgen::PKCS_ECDSA_P384_SHA384);
        let signed = sign(REQUEST, &signing).expect("signed");
        let document = roxmltree::Document::parse(&signed).expect("well formed");
        assert_eq!(
            verify(document.root_element(), &[other]),
            Err(Refusal::BadSignature)
        );
    }
}
