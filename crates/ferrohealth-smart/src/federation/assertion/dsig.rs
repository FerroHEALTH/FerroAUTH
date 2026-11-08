// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The enveloped XML signature of an eHDSI assertion (eHDSI Cryptographic
//! Algorithms 9.0.0 §4.1; W3C XML Signature Syntax and Processing, Second
//! Edition), checked against signature wrapping.
//!
//! The signature is accepted only in one shape: the one `ds:Signature` of
//! the document, a child of the document element, with one `ds:Reference`
//! whose URI names the document element's `ID`, which no other attribute of
//! the document carries. The caller reads every value from that same
//! element, so nothing the signature does not cover is ever read.

use aws_lc_rs::digest;
use aws_lc_rs::signature;
use aws_lc_rs::signature::UnparsedPublicKey;
use aws_lc_rs::signature::VerificationAlgorithm;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jiff::Timestamp;
use roxmltree::Node;

use crate::federation::assertion::Floor;
use crate::federation::assertion::Integrity;
use crate::federation::assertion::c14n;
use crate::federation::assertion::signer::TrustedSigner;

/// The XML-DSig namespace.
pub(super) const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
/// The WS-Security extension namespace of `wsse:SecurityTokenReference`.
const WSSE: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
/// Exclusive canonicalization without comments, the one canonicalization
/// accepted (Cryptographic Algorithms 9.0.0 §4.1).
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
/// The enveloped signature transform (XML-DSig §6.6.4).
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
/// The `ValueType` of a subject key identifier reference (WS-Security X.509
/// Token Profile 1.1 §3.2).
const SKI: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier";
/// The prefixes an `InclusiveNamespaces PrefixList` may name: those of eHDSI
/// SAML Profile 10.0.0 §1.4.2 (Cryptographic Algorithms 9.0.0 §4.1: "other
/// prefixes than the ones defined in [SAML Profile] MUST NOT be used").
const INCLUSIVE: [&str; 4] = ["soapenv", "wsse", "saml", "xacml"];

/// Checks the enveloped signature of `root`, the document element, by one of
/// `signers` at `now`.
pub(super) fn verify(
    root: Node<'_, '_>,
    signers: &[&TrustedSigner],
    now: Timestamp,
) -> Result<(), Integrity> {
    let id = root.attribute("ID").ok_or(Integrity::Structure("ID"))?;
    // NOTE: XML-DSig §4.3.3.2 resolves a same-document URI by ID, so a second carrier of
    // the value (any attribute named ID, Id or id) could redirect the reference.
    let carriers = root
        .document()
        .descendants()
        .flat_map(|node| node.attributes())
        .filter(|attribute| attribute.name().eq_ignore_ascii_case("id") && attribute.value() == id)
        .count();
    if carriers != 1 {
        return Err(Integrity::Wrapped);
    }
    let signatures: Vec<Node<'_, '_>> = root
        .document()
        .descendants()
        .filter(|node| {
            node.tag_name().namespace() == Some(DSIG) && node.tag_name().name() == "Signature"
        })
        .collect();
    let signature = match signatures.as_slice() {
        [] => return Err(Integrity::Unsigned),
        [one] if one.parent() == Some(root) => *one,
        _ => return Err(Integrity::Wrapped),
    };
    let [signed_info, signature_value, key_info] = children(signature)?[..] else {
        return Err(Integrity::Structure("ds:Signature"));
    };
    expect(signed_info, "SignedInfo")?;
    expect(signature_value, "SignatureValue")?;
    expect(key_info, "KeyInfo")?;
    let [method, signature_method, reference] = children(signed_info)?[..] else {
        return Err(Integrity::Structure("ds:SignedInfo"));
    };
    expect(method, "CanonicalizationMethod")?;
    expect(signature_method, "SignatureMethod")?;
    expect(reference, "Reference")?;
    let info_prefixes = canonicalization(method)?;
    let algorithm = signature_algorithm(algorithm_of(signature_method)?)?;
    if reference.attribute("URI") != Some(format!("#{id}").as_str()) {
        return Err(Integrity::Wrapped);
    }
    let [transforms, digest_method, digest_value] = children(reference)?[..] else {
        return Err(Integrity::Structure("ds:Reference"));
    };
    expect(transforms, "Transforms")?;
    expect(digest_method, "DigestMethod")?;
    expect(digest_value, "DigestValue")?;
    let [enveloped, exclusive] = children(transforms)?[..] else {
        return Err(Integrity::Structure("ds:Transforms"));
    };
    expect(enveloped, "Transform")?;
    expect(exclusive, "Transform")?;
    if algorithm_of(enveloped)? != ENVELOPED || !children(enveloped)?.is_empty() {
        return Err(Integrity::Structure("ds:Transform"));
    }
    let reference_prefixes = canonicalization(exclusive)?;
    let digest_algorithm = digest_algorithm(algorithm_of(digest_method)?)?;
    let signer = select(key_info, signers)?;
    if !signer.valid_at(now) {
        return Err(Integrity::SignerExpired);
    }
    let expected = decode(digest_value)?;
    let covered = c14n::canonicalize(root, Some(signature.id()), &reference_prefixes)
        .map_err(|_unrepresentable| Integrity::Structure("canonical form"))?;
    if digest::digest(digest_algorithm, &covered).as_ref() != expected.as_slice() {
        return Err(Integrity::Digest);
    }
    let info = c14n::canonicalize(signed_info, None, &info_prefixes)
        .map_err(|_unrepresentable| Integrity::Structure("canonical form"))?;
    let value = decode(signature_value)?;
    UnparsedPublicKey::new(algorithm, signer.spki())
        .verify(&info, &value)
        .map_err(|_unspecified| Integrity::BadSignature)
}

/// Returns the element children of `node`, refusing any non-whitespace text.
fn children<'a, 'input>(node: Node<'a, 'input>) -> Result<Vec<Node<'a, 'input>>, Integrity> {
    let mut elements = Vec::new();
    for child in node.children() {
        if child.is_element() {
            elements.push(child);
        } else if child.is_text() && !child.text().unwrap_or_default().trim().is_empty() {
            return Err(Integrity::Structure("ds:Signature"));
        }
    }
    Ok(elements)
}

/// Refuses `node` unless it is the XML-DSig element `name`.
fn expect(node: Node<'_, '_>, name: &'static str) -> Result<(), Integrity> {
    if node.tag_name().namespace() == Some(DSIG) && node.tag_name().name() == name {
        Ok(())
    } else {
        Err(Integrity::Structure(name))
    }
}

/// Returns the `Algorithm` attribute of `node`.
fn algorithm_of<'a>(node: Node<'a, '_>) -> Result<&'a str, Integrity> {
    node.attribute("Algorithm")
        .ok_or(Integrity::Structure("Algorithm"))
}

/// Returns the inclusive prefixes of an exclusive canonicalization method or
/// transform, refusing any other method and any prefix outside the eHDSI
/// SAML Profile's.
fn canonicalization<'a>(node: Node<'a, '_>) -> Result<Vec<&'a str>, Integrity> {
    if algorithm_of(node)? != EXC_C14N {
        return Err(Integrity::Canonicalization);
    }
    match children(node)?.as_slice() {
        [] => Ok(Vec::new()),
        [list]
            if list.tag_name().namespace() == Some(EXC_C14N)
                && list.tag_name().name() == "InclusiveNamespaces" =>
        {
            let prefixes: Vec<&str> = list
                .attribute("PrefixList")
                .unwrap_or_default()
                .split_ascii_whitespace()
                .collect();
            if prefixes.iter().all(|prefix| INCLUSIVE.contains(prefix)) {
                Ok(prefixes)
            } else {
                Err(Integrity::Canonicalization)
            }
        }
        _ => Err(Integrity::Canonicalization),
    }
}

/// Returns the verifier of a signature method at or above the floor.
fn signature_algorithm(uri: &str) -> Result<&'static dyn VerificationAlgorithm, Integrity> {
    // NOTE: SOG-IS ACM 1.3 §5.2 agrees PKCS#1 v1.5 and PSS with SHA-256 and above; the
    // URIs are RFC 6931 §2.3.2 and §2.3.10's. The modulus floor is held at registration.
    Ok(match uri {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => {
            &signature::RSA_PKCS1_2048_8192_SHA256
        }
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => {
            &signature::RSA_PKCS1_2048_8192_SHA384
        }
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => {
            &signature::RSA_PKCS1_2048_8192_SHA512
        }
        "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1" => {
            &signature::RSA_PSS_2048_8192_SHA256
        }
        "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1" => {
            &signature::RSA_PSS_2048_8192_SHA384
        }
        "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1" => {
            &signature::RSA_PSS_2048_8192_SHA512
        }
        _ if uri.contains("ecdsa") => return Err(Integrity::Floor(Floor::EllipticCurve)),
        _ if weak(uri) => return Err(Integrity::Floor(Floor::Hash)),
        _ => return Err(Integrity::Floor(Floor::Algorithm)),
    })
}

/// Returns the digest of a digest method at or above the floor.
fn digest_algorithm(uri: &str) -> Result<&'static digest::Algorithm, Integrity> {
    Ok(match uri {
        "http://www.w3.org/2001/04/xmlenc#sha256" => &digest::SHA256,
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => &digest::SHA384,
        "http://www.w3.org/2001/04/xmlenc#sha512" => &digest::SHA512,
        _ if weak(uri) => return Err(Integrity::Floor(Floor::Hash)),
        _ => return Err(Integrity::Floor(Floor::Algorithm)),
    })
}

/// Whether a method names a hash below SHA-256: SHA-1 is not agreed and
/// SHA-224 is legacy only until 2025 (SOG-IS ACM 1.3 §3.1).
fn weak(uri: &str) -> bool {
    let method = uri.rsplit('#').next().unwrap_or_default();
    ["sha1", "sha224", "md5", "ripemd160"]
        .iter()
        .any(|hash| method.contains(hash))
}

/// Returns the trusted signer `ds:KeyInfo` names: by its certificate in
/// `ds:X509Data`, or by its subject key identifier in a
/// `wsse:SecurityTokenReference` (Cryptographic Algorithms 9.0.0 §4.1).
fn select<'s>(
    key_info: Node<'_, '_>,
    signers: &[&'s TrustedSigner],
) -> Result<&'s TrustedSigner, Integrity> {
    let [named] = children(key_info)?[..] else {
        return Err(Integrity::Structure("ds:KeyInfo"));
    };
    let tag = named.tag_name();
    let found = match (tag.namespace(), tag.name()) {
        (Some(DSIG), "X509Data") => {
            let [certificate] = children(named)?[..] else {
                return Err(Integrity::Structure("ds:X509Data"));
            };
            expect(certificate, "X509Certificate")?;
            let der = decode(certificate)?;
            signers.iter().find(|signer| signer.der() == der.as_slice())
        }
        (Some(WSSE), "SecurityTokenReference") => {
            let [identifier] = children(named)?[..] else {
                return Err(Integrity::Structure("wsse:SecurityTokenReference"));
            };
            let tag = identifier.tag_name();
            if tag.namespace() != Some(WSSE)
                || tag.name() != "KeyIdentifier"
                || identifier.attribute("ValueType") != Some(SKI)
            {
                return Err(Integrity::Structure("wsse:KeyIdentifier"));
            }
            let id = decode(identifier)?;
            signers
                .iter()
                .find(|signer| signer.key_identifier() == id.as_slice())
        }
        _ => return Err(Integrity::Structure("ds:KeyInfo")),
    };
    found.copied().ok_or(Integrity::Untrusted)
}

/// Decodes the base64 text of `node`, its whitespace dropped (XML-DSig
/// §4.2: `base64Binary`).
fn decode(node: Node<'_, '_>) -> Result<Vec<u8>, Integrity> {
    let text: String = node
        .children()
        .filter(Node::is_text)
        .filter_map(|text| text.text())
        .flat_map(str::chars)
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if node.children().any(|child| child.is_element()) {
        return Err(Integrity::Structure("base64Binary"));
    }
    STANDARD
        .decode(text)
        .map_err(|_invalid| Integrity::Structure("base64Binary"))
}
