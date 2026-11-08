// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The signers an eHDSI assertion is trusted from: the issuer URI and the
//! seal certificate a Member State publishes for it.
//!
//! The trust anchor is the Trusted List, and the certificate the one the
//! scheme operator's signed SMP publishes (Service Location and Capability
//! Lookup Profile 10.0.0 §3.1.3, §3.1.6); a deployment hands this module
//! the certificates it bootstrapped that way, and removes a revoked one
//! (no specification governs how the set is kept: our own design).

use std::fmt;

use jiff::Timestamp;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;
use x509_parser::public_key::PublicKey;

/// The smallest RSA modulus SOG-IS Agreed Cryptographic Mechanisms 1.3
/// admits at the "Legacy valid beyond 2025" level (§4.1 and Note 27), the
/// floor of eHDSI Cryptographic Algorithms 9.0.0 §2.
pub const MIN_RSA_BITS: usize = 3000;

/// A certificate refused as an assertion signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    /// The bytes are not one DER X.509 certificate.
    #[error("the signer certificate is not a DER X.509 certificate")]
    Malformed,
    /// The key is on an elliptic curve, which eHDSI Cryptographic
    /// Algorithms 9.0.0 §2 allows only "if agreed by all countries".
    #[error("the signer key is on an elliptic curve, not agreed by all countries")]
    EllipticCurve,
    /// The key is neither RSA nor on an elliptic curve.
    #[error("the signer key is not an RSA key")]
    NotRsa,
    /// The RSA modulus is below SOG-IS ACM 1.3's 3000 bits.
    #[error("the signer key is below the SOG-IS ACM 1.3 floor of 3000 bits")]
    ShortKey {
        /// The modulus length, in bits.
        bits: usize,
    },
    /// `KeyUsage` is missing, not critical, or not exactly
    /// `digitalSignature` and `keyEncipherment` (X.509 Certificates Profile
    /// 7.0.0 §3.1, `[Seal]`).
    #[error("the signer certificate's KeyUsage is not the eHDSI seal profile's")]
    KeyUsage,
    /// `ExtendedKeyUsage` is present, which a seal certificate "MUST NOT"
    /// include (X.509 Certificates Profile 7.0.0 §3.1).
    #[error("the signer certificate carries an ExtendedKeyUsage")]
    ExtendedKeyUsage,
    /// The `BasicConstraints` the profile requires is missing, or names a
    /// certificate authority (X.509 Certificates Profile 7.0.0 §3.1).
    #[error("the signer certificate's BasicConstraints is missing or names a CA")]
    BasicConstraints,
    /// The `SubjectKeyIdentifier` the profile requires is missing (X.509
    /// Certificates Profile 7.0.0 §3.1).
    #[error("the signer certificate carries no SubjectKeyIdentifier")]
    SubjectKeyIdentifier,
}

/// One trusted assertion signer: the issuer URI an assertion names in
/// `saml:Issuer`, and the certificate that signs for it.
#[derive(Clone)]
pub struct TrustedSigner {
    /// The `saml:Issuer` this certificate signs for.
    issuer: String,
    /// The certificate, DER.
    der: Vec<u8>,
    /// Its `SubjectPublicKeyInfo`, DER.
    spki: Vec<u8>,
    /// Its `SubjectKeyIdentifier`.
    key_identifier: Vec<u8>,
    /// The start of its validity, in seconds since the epoch.
    not_before: i64,
    /// The end of its validity, in seconds since the epoch.
    not_after: i64,
}

impl fmt::Debug for TrustedSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedSigner")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl TrustedSigner {
    /// Reads the seal certificate `der` that signs the assertions of
    /// `issuer`.
    ///
    /// # Errors
    ///
    /// A [`SignerError`] when the certificate is malformed, its key is
    /// below the SOG-IS ACM 1.3 floor or not RSA, or its extensions are not
    /// the X.509 Certificates Profile 7.0.0 §3.1 seal profile's.
    pub fn from_der(issuer: impl Into<String>, der: Vec<u8>) -> Result<Self, SignerError> {
        let (rest, certificate) =
            X509Certificate::from_der(&der).map_err(|_malformed| SignerError::Malformed)?;
        if !rest.is_empty() {
            return Err(SignerError::Malformed);
        }
        match certificate.public_key().parsed() {
            Ok(PublicKey::RSA(rsa)) => {
                let bits = modulus_bits(rsa.modulus);
                if bits < MIN_RSA_BITS {
                    return Err(SignerError::ShortKey { bits });
                }
            }
            Ok(PublicKey::EC(_)) => return Err(SignerError::EllipticCurve),
            Ok(_) => return Err(SignerError::NotRsa),
            Err(_) => return Err(SignerError::Malformed),
        }
        let usage = certificate
            .key_usage()
            .map_err(|_malformed| SignerError::Malformed)?
            .ok_or(SignerError::KeyUsage)?;
        let seal = usage.value.digital_signature()
            && usage.value.key_encipherment()
            && !usage.value.non_repudiation()
            && !usage.value.data_encipherment()
            && !usage.value.key_agreement()
            && !usage.value.key_cert_sign()
            && !usage.value.crl_sign()
            && !usage.value.encipher_only()
            && !usage.value.decipher_only();
        if !usage.critical || !seal {
            return Err(SignerError::KeyUsage);
        }
        if certificate
            .extended_key_usage()
            .map_err(|_malformed| SignerError::Malformed)?
            .is_some()
        {
            return Err(SignerError::ExtendedKeyUsage);
        }
        let constraints = certificate
            .basic_constraints()
            .map_err(|_malformed| SignerError::Malformed)?
            .ok_or(SignerError::BasicConstraints)?;
        if constraints.value.ca {
            return Err(SignerError::BasicConstraints);
        }
        let key_identifier = certificate
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0.to_vec()),
                _ => None,
            })
            .ok_or(SignerError::SubjectKeyIdentifier)?;
        let spki = certificate.public_key().raw.to_vec();
        let not_before = certificate.validity().not_before.timestamp();
        let not_after = certificate.validity().not_after.timestamp();
        Ok(Self {
            issuer: issuer.into(),
            der,
            spki,
            key_identifier,
            not_before,
            not_after,
        })
    }

    /// Returns the `saml:Issuer` this certificate signs for.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the certificate, DER.
    pub(super) fn der(&self) -> &[u8] {
        &self.der
    }

    /// Returns the `SubjectPublicKeyInfo`, DER.
    pub(super) fn spki(&self) -> &[u8] {
        &self.spki
    }

    /// Returns the `SubjectKeyIdentifier`.
    pub(super) fn key_identifier(&self) -> &[u8] {
        &self.key_identifier
    }

    /// Whether `now` lies within the certificate's validity (X.509
    /// Certificates Profile 7.0.0 §2.4: "The current date MUST be within the
    /// validity range of the certificate").
    pub(super) fn valid_at(&self, now: Timestamp) -> bool {
        (self.not_before..=self.not_after).contains(&now.as_second())
    }
}

/// Returns the length in bits of a big-endian modulus, its leading zero
/// octets dropped.
fn modulus_bits(modulus: &[u8]) -> usize {
    let significant: &[u8] = match modulus.iter().position(|octet| *octet != 0) {
        Some(start) => modulus.get(start..).unwrap_or_default(),
        None => &[],
    };
    let Some(mut first) = significant.first().copied() else {
        return 0;
    };
    let mut bits = significant.len().saturating_mul(8);
    while first & 0x80 == 0 {
        bits = bits.saturating_sub(1);
        first <<= 1;
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::modulus_bits;

    #[test]
    fn the_modulus_length_counts_significant_bits() {
        assert_eq!(modulus_bits(&[0x00, 0x80, 0x00]), 16);
        assert_eq!(modulus_bits(&[0x7f, 0x00]), 15);
        assert_eq!(modulus_bits(&[0x00, 0x00]), 0);
    }
}
