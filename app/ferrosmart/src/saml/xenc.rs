// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The decryption of an `EncryptedAssertion`, `EncryptedID` or
//! `EncryptedAttribute` (saml-core-2.0-os §2.2.4, §6; xmlenc-core1).
//!
//! What is accepted (our own design within xmlenc-core1 §5.1, recorded in
//! `docs/architecture.md` §13.25): the content key transported by RSA-OAEP
//! (`rsa-oaep-mgf1p`, or `xmlenc11#rsa-oaep`, with the digest and mask
//! generation function both SHA-1, both SHA-256, both SHA-384 or both
//! SHA-512) to one of FerroSMART's keys, and the data encrypted by
//! AES-GCM, or by AES-CBC only when a verified signature covers the
//! encrypted element (saml-core-2.0-os §6.2 as errata E93 replaces it).
//! RSA-v1.5 key transport, key agreement, key wrap and Triple DES are
//! refused. Every failure past the algorithm choice is the one refusal
//! [`Refusal::Decryption`], so the outcome tells an attacker nothing about
//! which step failed.

use aws_lc_rs::aead;
use aws_lc_rs::cipher;
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rsa;
use aws_lc_rs::rsa::OaepAlgorithm;
use roxmltree::Node;

use crate::saml::DSIG;
use crate::saml::Refusal;
use crate::saml::XENC;
use crate::saml::XENC11;
use crate::saml::dsig;
use crate::saml::keys::DecryptionKey;
use crate::saml::xml;
use crate::saml::xml::Children;

/// The `Type` of encrypted data that is one element (xmlenc-core1 §3.1).
const ELEMENT: &str = "http://www.w3.org/2001/04/xmlenc#Element";
/// The `ds:RetrievalMethod` type that names an encrypted key
/// (xmlenc-core1 §3.5.1).
const ENCRYPTED_KEY: &str = "http://www.w3.org/2001/04/xmlenc#EncryptedKey";

/// A data encryption algorithm (xmlenc-core1 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Data {
    /// AES-GCM with a key of the given length, in bytes (§5.2.4).
    Gcm(usize),
    /// AES-CBC with a key of the given length, in bytes (§5.2.3).
    Cbc(usize),
}

impl Data {
    /// Returns the data algorithm `uri` names.
    fn of(uri: Option<&str>) -> Result<Self, Refusal> {
        Ok(match uri {
            Some("http://www.w3.org/2009/xmlenc11#aes128-gcm") => Self::Gcm(16),
            Some("http://www.w3.org/2009/xmlenc11#aes192-gcm") => Self::Gcm(24),
            Some("http://www.w3.org/2009/xmlenc11#aes256-gcm") => Self::Gcm(32),
            Some("http://www.w3.org/2001/04/xmlenc#aes128-cbc") => Self::Cbc(16),
            Some("http://www.w3.org/2001/04/xmlenc#aes192-cbc") => Self::Cbc(24),
            Some("http://www.w3.org/2001/04/xmlenc#aes256-cbc") => Self::Cbc(32),
            _ => return Err(Refusal::Algorithm("data encryption")),
        })
    }

    /// The length of the content key, in bytes.
    fn key_len(self) -> usize {
        match self {
            Self::Gcm(len) | Self::Cbc(len) => len,
        }
    }
}

/// Returns the plaintext of the encrypted element `element`, decrypted
/// with one of `keys`. `recipient` is FerroSMART's entity ID, which an
/// `EncryptedKey` naming a `Recipient` must name, and `covered` says
/// whether a verified signature covers `element`.
pub(super) fn decrypt(
    element: Node<'_, '_>,
    keys: &[DecryptionKey],
    recipient: &str,
    covered: bool,
) -> Result<String, Refusal> {
    let mut parts = Children::of(element, "encrypted element")?;
    let data = parts.required(XENC, "EncryptedData", "xenc:EncryptedData")?;
    let siblings = parts.many(XENC, "EncryptedKey");
    parts.end()?;
    if data.attribute("Type").is_some_and(|kind| kind != ELEMENT) {
        return Err(Refusal::Structure("xenc:EncryptedData"));
    }
    let mut fields = Children::of(data, "xenc:EncryptedData")?;
    let method = fields.required(XENC, "EncryptionMethod", "xenc:EncryptionMethod")?;
    let key_info = fields.optional(DSIG, "KeyInfo");
    let cipher_data = fields.required(XENC, "CipherData", "xenc:CipherData")?;
    fields.end()?;
    if !xml::empty(method) {
        return Err(Refusal::Algorithm("data encryption"));
    }
    let algorithm = Data::of(method.attribute("Algorithm"))?;
    if matches!(algorithm, Data::Cbc(_)) && !covered {
        return Err(Refusal::UnprotectedCbc);
    }
    let ciphertext = cipher_value(cipher_data)?;
    let candidates = encrypted_keys(key_info, &siblings)?;
    let mut transported = 0_usize;
    for encrypted_key in candidates {
        if encrypted_key
            .attribute("Recipient")
            .is_some_and(|named| named != recipient)
        {
            continue;
        }
        transported = transported.saturating_add(1);
        let transport = KeyTransport::of(encrypted_key)?;
        for key in keys {
            let Some(content_key) = transport.unwrap(key, algorithm.key_len()) else {
                continue;
            };
            if let Some(plaintext) = open(algorithm, &content_key, &ciphertext) {
                return String::from_utf8(plaintext).map_err(|_not_utf8| Refusal::Decryption);
            }
        }
    }
    if transported == 0 {
        return Err(Refusal::Structure("xenc:EncryptedKey"));
    }
    Err(Refusal::Decryption)
}

/// Returns the encrypted keys the data names: those inside its
/// `ds:KeyInfo`, the siblings a `ds:RetrievalMethod` there names by `Id`,
/// or, with neither, every sibling (saml-core-2.0-os §6.2 as errata E43
/// replaces it). A retrieval method never looks beyond the siblings.
fn encrypted_keys<'a, 'input>(
    key_info: Option<Node<'a, 'input>>,
    siblings: &[Node<'a, 'input>],
) -> Result<Vec<Node<'a, 'input>>, Refusal> {
    let Some(key_info) = key_info else {
        return Ok(siblings.to_vec());
    };
    let mut named = Vec::new();
    let mut referenced = false;
    for child in key_info.children().filter(Node::is_element) {
        if xml::is(child, XENC, "EncryptedKey") {
            named.push(child);
        } else if xml::is(child, DSIG, "RetrievalMethod") {
            referenced = true;
            if child.attribute("Type") != Some(ENCRYPTED_KEY) {
                return Err(Refusal::Structure("ds:RetrievalMethod"));
            }
            let id = child
                .attribute("URI")
                .and_then(|uri| uri.strip_prefix('#'))
                .ok_or(Refusal::Structure("ds:RetrievalMethod"))?;
            let sibling = siblings
                .iter()
                .find(|sibling| sibling.attribute("Id") == Some(id))
                .ok_or(Refusal::Structure("ds:RetrievalMethod"))?;
            named.push(*sibling);
        }
    }
    if named.is_empty() && !referenced {
        Ok(siblings.to_vec())
    } else {
        Ok(named)
    }
}

/// Returns the decoded `CipherValue` of `cipher_data`; a `CipherReference`
/// is refused, since it points outside the message (xmlenc-core1 §3.3.1).
fn cipher_value(cipher_data: Node<'_, '_>) -> Result<Vec<u8>, Refusal> {
    let mut parts = Children::of(cipher_data, "xenc:CipherData")?;
    let value = parts.required(XENC, "CipherValue", "xenc:CipherValue")?;
    parts.end()?;
    dsig::base64(value, "xenc:CipherValue")
}

/// The RSA-OAEP transport of one content key (xmlenc-core1 §5.5.2).
struct KeyTransport {
    /// The OAEP digest and mask generation function.
    algorithm: &'static OaepAlgorithm,
    /// The `OAEPparams` label, empty when absent.
    label: Vec<u8>,
    /// The encrypted content key.
    ciphertext: Vec<u8>,
}

impl KeyTransport {
    /// Reads the transport of `encrypted_key`.
    fn of(encrypted_key: Node<'_, '_>) -> Result<Self, Refusal> {
        let mut parts = Children::of(encrypted_key, "xenc:EncryptedKey")?;
        let method = parts.required(XENC, "EncryptionMethod", "xenc:EncryptionMethod")?;
        parts.optional(DSIG, "KeyInfo");
        let cipher_data = parts.required(XENC, "CipherData", "xenc:CipherData")?;
        parts.optional(XENC, "EncryptionProperties");
        parts.optional(XENC, "ReferenceList");
        parts.optional(XENC, "CarriedKeyName");
        parts.end()?;
        let generic = match method.attribute("Algorithm") {
            Some("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p") => false,
            Some("http://www.w3.org/2009/xmlenc11#rsa-oaep") => true,
            _ => return Err(Refusal::Algorithm("key transport")),
        };
        let mut digest = "http://www.w3.org/2000/09/xmldsig#sha1";
        let mut mgf = "http://www.w3.org/2009/xmlenc11#mgf1sha1";
        let mut label = Vec::new();
        let (mut seen_digest, mut seen_mgf, mut seen_label) = (false, false, false);
        for parameter in method.children().filter(Node::is_element) {
            if xml::is(parameter, DSIG, "DigestMethod") && !seen_digest {
                seen_digest = true;
                digest = parameter
                    .attribute("Algorithm")
                    .ok_or(Refusal::Algorithm("key transport"))?;
            } else if xml::is(parameter, XENC11, "MGF") && generic && !seen_mgf {
                // NOTE: xmlenc-core1 §5.5.2: `rsa-oaep-mgf1p` fixes MGF1 with SHA-1 and must not
                // carry an `xenc11:MGF`; only `xmlenc11#rsa-oaep` names its mask function.
                seen_mgf = true;
                mgf = parameter
                    .attribute("Algorithm")
                    .ok_or(Refusal::Algorithm("key transport"))?;
            } else if xml::is(parameter, XENC, "OAEPparams") && !seen_label {
                seen_label = true;
                label = dsig::base64(parameter, "xenc:OAEPparams")?;
            } else {
                return Err(Refusal::Algorithm("key transport"));
            }
        }
        let algorithm = match (digest, mgf) {
            (
                "http://www.w3.org/2000/09/xmldsig#sha1",
                "http://www.w3.org/2009/xmlenc11#mgf1sha1",
            ) => &rsa::OAEP_SHA1_MGF1SHA1,
            (
                "http://www.w3.org/2001/04/xmlenc#sha256",
                "http://www.w3.org/2009/xmlenc11#mgf1sha256",
            ) => &rsa::OAEP_SHA256_MGF1SHA256,
            (
                "http://www.w3.org/2001/04/xmldsig-more#sha384",
                "http://www.w3.org/2009/xmlenc11#mgf1sha384",
            ) => &rsa::OAEP_SHA384_MGF1SHA384,
            (
                "http://www.w3.org/2001/04/xmlenc#sha512",
                "http://www.w3.org/2009/xmlenc11#mgf1sha512",
            ) => &rsa::OAEP_SHA512_MGF1SHA512,
            _ => return Err(Refusal::Algorithm("key transport")),
        };
        let ciphertext = cipher_value(cipher_data)?;
        Ok(Self {
            algorithm,
            label,
            ciphertext,
        })
    }

    /// Returns the content key, when `key` decrypts it to `len` bytes.
    fn unwrap(&self, key: &DecryptionKey, len: usize) -> Option<Vec<u8>> {
        let oaep = key.oaep();
        let mut out = vec![0_u8; oaep.min_output_size()];
        let label = (!self.label.is_empty()).then_some(self.label.as_slice());
        // NOTE: a failure is the absence of this key's content key, not a defect: another key of
        // FerroSMART's, or another `EncryptedKey`, may hold it (our own design).
        let plain = oaep
            .decrypt(self.algorithm, &self.ciphertext, &mut out, label)
            .ok()?;
        (plain.len() == len).then(|| plain.to_vec())
    }
}

/// Returns the plaintext of `ciphertext` under `content_key`, or `None`
/// when it does not decrypt.
///
/// A failure is the absence of the plaintext under this content key, not a
/// defect: another transported key may open it, and the caller answers
/// [`Refusal::Decryption`] when none does.
fn open(algorithm: Data, content_key: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        Data::Gcm(len) => {
            // NOTE: xmlenc-core1 §5.2.4: a 96-bit IV first, then the encrypted octets, then the
            // 128-bit authentication tag, which must match.
            let aes = match len {
                16 => &aead::AES_128_GCM,
                24 => &aead::AES_192_GCM,
                _ => &aead::AES_256_GCM,
            };
            let (iv, sealed) = ciphertext.split_at_checked(aead::NONCE_LEN)?;
            let key = aead::LessSafeKey::new(aead::UnboundKey::new(aes, content_key).ok()?);
            let nonce = aead::Nonce::try_assume_unique_for_key(iv).ok()?;
            let mut in_out = sealed.to_vec();
            let plain = key
                .open_in_place(nonce, aead::Aad::empty(), &mut in_out)
                .ok()?;
            Some(plain.to_vec())
        }
        Data::Cbc(len) => {
            // NOTE: xmlenc-core1 §5.2.1 and §5.2.3: a 128-bit IV first, and the last plaintext
            // octet counts the padding octets, 1 to 16, whose other values are arbitrary.
            let aes = match len {
                16 => &cipher::AES_128,
                24 => &cipher::AES_192,
                _ => &cipher::AES_256,
            };
            let (iv, encrypted) = ciphertext.split_at_checked(16)?;
            let iv: [u8; 16] = iv.try_into().ok()?;
            if encrypted.is_empty() || encrypted.len() % 16 != 0 {
                return None;
            }
            let key =
                cipher::DecryptingKey::cbc(cipher::UnboundCipherKey::new(aes, content_key).ok()?)
                    .ok()?;
            let mut in_out = encrypted.to_vec();
            let plain = key
                .decrypt(
                    &mut in_out,
                    cipher::DecryptionContext::Iv128(FixedLength::from(iv)),
                )
                .ok()?;
            let padding = usize::from(*plain.last()?);
            if padding == 0 || padding > 16 || padding > plain.len() {
                return None;
            }
            let end = plain.len().checked_sub(padding)?;
            Some(plain.get(..end)?.to_vec())
        }
    }
}
