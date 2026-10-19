// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The client assertion of `private_key_jwt` (RFC 7523 §2.2), the one
//! private key the library holds.
//!
//! The key signs only the product's own client assertion to the token
//! endpoint; no resource server accepts the assertion as an access token
//! (RFC 9068 §4, the `typ` and `aud` checks). The assertion is the one SMART
//! App Launch 2.2.0, Client Authentication: Asymmetric, fixes: header `alg`,
//! `kid` and `typ` of `JWT`; claims `iss` and `sub` both the client id,
//! `aud` the token endpoint, `exp` at most five minutes ahead and a unique
//! `jti`; one assertion per request (RFC 7523 §3). The product serves the
//! matching public keys as a JWK Set (RFC 7517 §5) at a route of its own.

use base64::Engine as _;
use jsonwebtoken::Algorithm;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::jwk::AlgorithmParameters;
use jsonwebtoken::jwk::Jwk;
use serde::Serialize;

/// How long a client assertion is valid: "no more than five minutes in the
/// future" (SMART App Launch 2.2.0, Client Authentication: Asymmetric).
pub const ASSERTION_LIFETIME_SECONDS: i64 = 300;

/// The `client_assertion_type` of a JWT assertion (RFC 7523 §2.2).
pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// A key that cannot sign a client assertion.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AssertionError {
    /// The PEM is no RSA, EC or Ed25519 private key `jsonwebtoken` reads.
    #[error("the private key is not an RSA, EC or Ed25519 key in PEM form")]
    Key {
        /// What the key reader reported.
        #[source]
        source: jsonwebtoken::errors::Error,
    },
    /// The algorithm is no asymmetric signature algorithm, or belongs to
    /// another key type.
    #[error("the algorithm {algorithm:?} cannot sign with this key")]
    Algorithm {
        /// The algorithm.
        algorithm: Algorithm,
    },
    /// The public half could not be derived from the key.
    #[error("the public key could not be derived from the private key")]
    Public {
        /// What the key reader reported.
        #[source]
        source: jsonwebtoken::errors::Error,
    },
    /// The random source for `jti` failed.
    #[error("the random source for the assertion id failed")]
    Random,
    /// The assertion could not be signed.
    #[error("the assertion could not be signed")]
    Sign {
        /// What the signer reported.
        #[source]
        source: jsonwebtoken::errors::Error,
    },
}

/// The key a product signs its client assertions with, and its public
/// half.
#[derive(Clone)]
pub struct AssertionKey {
    /// The private half.
    encoding: EncodingKey,
    /// The algorithm the assertion is signed with.
    algorithm: Algorithm,
    /// The `kid` the public half is published under.
    kid: String,
    /// The public half.
    public: Jwk,
}

impl std::fmt::Debug for AssertionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssertionKey")
            .field("algorithm", &self.algorithm)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl AssertionKey {
    /// Returns the key `pem` holds, signing with `algorithm`, published
    /// under `kid`.
    ///
    /// Without `algorithm`, an EC key signs with ES384 and an RSA key with
    /// RS384, the two SMART's asymmetric client profile has a client
    /// support, and an Ed25519 key with `EdDSA`. Without `kid`, the key is
    /// published under its RFC 7638 SHA-256 thumbprint (the default is our
    /// own design; the thumbprint is the RFC's).
    ///
    /// # Errors
    ///
    /// Returns [`AssertionError`] for a PEM that is no supported private
    /// key, an algorithm of another key type or a symmetric one, or a key
    /// whose public half cannot be derived.
    pub fn from_pem(
        pem: &[u8],
        algorithm: Option<Algorithm>,
        kid: Option<String>,
    ) -> Result<Self, AssertionError> {
        let (encoding, algorithm) = match algorithm {
            Some(algorithm) => (load(pem, algorithm)?, algorithm),
            None => {
                if let Ok(encoding) = EncodingKey::from_ec_pem(pem) {
                    (encoding, Algorithm::ES384)
                } else if let Ok(encoding) = EncodingKey::from_rsa_pem(pem) {
                    (encoding, Algorithm::RS384)
                } else {
                    (
                        EncodingKey::from_ed_pem(pem)
                            .map_err(|source| AssertionError::Key { source })?,
                        Algorithm::EdDSA,
                    )
                }
            }
        };
        let mut public = Jwk::from_encoding_key(&encoding, algorithm)
            .map_err(|source| AssertionError::Public { source })?;
        let kid = match kid {
            Some(kid) => kid,
            None => thumbprint(&public),
        };
        public.common.key_id = Some(kid.clone());
        public.common.public_key_use = Some(jsonwebtoken::jwk::PublicKeyUse::Signature);
        Ok(Self {
            encoding,
            algorithm,
            kid,
            public,
        })
    }

    /// Returns the algorithm the assertion is signed with.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the `kid` the public half is published under.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Returns the public half as the JWK the product publishes (RFC 7517
    /// §4), with its `kid`, `use` and `alg`.
    #[must_use]
    pub fn public_jwk(&self) -> serde_json::Value {
        let mut jwk = serde_json::to_value(&self.public).unwrap_or(serde_json::Value::Null);
        if let Some(members) = jwk.as_object_mut() {
            members.insert(
                String::from("alg"),
                serde_json::to_value(self.algorithm).unwrap_or(serde_json::Value::Null),
            );
        }
        jwk
    }

    /// Returns the client assertion of `client_id` for `token_endpoint`,
    /// signed now and valid for [`ASSERTION_LIFETIME_SECONDS`].
    ///
    /// # Errors
    ///
    /// Returns [`AssertionError::Random`] when no `jti` could be drawn and
    /// [`AssertionError::Sign`] when the signature failed.
    pub fn assertion(
        &self,
        client_id: &str,
        token_endpoint: &str,
    ) -> Result<String, AssertionError> {
        let now = jiff::Timestamp::now().as_second();
        let mut random = [0u8; 16];
        aws_lc_rs::rand::fill(&mut random).map_err(|_unspecified| AssertionError::Random)?;
        let claims = Claims {
            iss: client_id,
            sub: client_id,
            aud: token_endpoint,
            exp: now.saturating_add(ASSERTION_LIFETIME_SECONDS),
            iat: now,
            jti: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random),
        };
        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.kid.clone());
        header.typ = Some(String::from("JWT"));
        jsonwebtoken::encode(&header, &claims, &self.encoding)
            .map_err(|source| AssertionError::Sign { source })
    }
}

/// The claims of a client assertion (RFC 7523 §3; SMART App Launch 2.2.0,
/// Client Authentication: Asymmetric).
#[derive(Serialize)]
struct Claims<'a> {
    /// The client id.
    iss: &'a str,
    /// The client id.
    sub: &'a str,
    /// The token endpoint.
    aud: &'a str,
    /// The expiry.
    exp: i64,
    /// The issue time.
    iat: i64,
    /// The unique id of this assertion.
    jti: String,
}

/// Returns the JWK Set (RFC 7517 §5) of `keys`, the current and the
/// successor key during a rotation.
#[must_use]
pub fn jwk_set(keys: &[&AssertionKey]) -> serde_json::Value {
    serde_json::json!({
        "keys": keys.iter().map(|key| key.public_jwk()).collect::<Vec<_>>()
    })
}

/// Returns the RFC 7638 §3 SHA-256 thumbprint of `jwk`, base64url without
/// padding.
///
/// The required members of the key type are serialized with no whitespace
/// in lexicographic order (§3.2; RFC 8037 §2 for an Ed25519 key), which
/// the hand-built strings below are.
#[must_use]
pub fn thumbprint(jwk: &Jwk) -> String {
    let canonical = match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(ec) => format!(
            "{{\"crv\":{},\"kty\":\"EC\",\"x\":{},\"y\":{}}}",
            json_string(&ec.curve),
            json_string(&ec.x),
            json_string(&ec.y)
        ),
        AlgorithmParameters::RSA(rsa) => format!(
            "{{\"e\":{},\"kty\":\"RSA\",\"n\":{}}}",
            json_string(&rsa.e),
            json_string(&rsa.n)
        ),
        AlgorithmParameters::OctetKeyPair(okp) => format!(
            "{{\"crv\":{},\"kty\":\"OKP\",\"x\":{}}}",
            json_string(&okp.curve),
            json_string(&okp.x)
        ),
        AlgorithmParameters::OctetKey(oct) => {
            format!("{{\"k\":{},\"kty\":\"oct\"}}", json_string(&oct.value))
        }
        // NOTE: RFC 7638 §3.2 names the members per key type; a type this
        // reader does not know has no thumbprint, and no such key signs an
        // assertion here.
        _ => String::new(),
    };
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, canonical.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
}

/// Returns `value` as a JSON string literal.
fn json_string(value: &impl Serialize) -> String {
    serde_json::to_string(value).unwrap_or_else(|_never| String::from("\"\""))
}

/// Returns the encoding key `pem` holds for `algorithm`.
fn load(pem: &[u8], algorithm: Algorithm) -> Result<EncodingKey, AssertionError> {
    let loaded = match algorithm {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => EncodingKey::from_rsa_pem(pem),
        Algorithm::ES256 | Algorithm::ES384 => EncodingKey::from_ec_pem(pem),
        Algorithm::EdDSA => EncodingKey::from_ed_pem(pem),
        other => return Err(AssertionError::Algorithm { algorithm: other }),
    };
    loaded.map_err(|source| AssertionError::Key { source })
}

#[cfg(test)]
mod tests {
    use super::thumbprint;
    use jsonwebtoken::jwk::Jwk;

    #[test]
    fn the_thumbprint_is_the_rfc_7638_example() {
        // NOTE: RFC 7638 §3.1, the example key and its thumbprint
        // `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`.
        let jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        }))
        .expect("the example key parses");
        assert_eq!(
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
            thumbprint(&jwk)
        );
    }
}
