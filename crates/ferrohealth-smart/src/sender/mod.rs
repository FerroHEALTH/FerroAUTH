// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Sender-constrained access tokens: a token bound to a key its client
//! proves with a `DPoP` proof (RFC 9449), or to the client certificate of the
//! mutual-TLS connection (RFC 8705 §3).
//!
//! A token says what it is bound to in its `cnf` claim, or the `cnf` member
//! of its introspection response: `jkt`, the RFC 7638 SHA-256 thumbprint of
//! the `DPoP` key (RFC 9449 §6.1, §6.2), or `x5t#S256`, the SHA-256 of the
//! client certificate (RFC 8705 §3.1, §3.2). A request proves a key or a
//! certificate, which a [`Binding`] carries: a key only through a `DPoP` proof
//! [`proof::ProofCheck`] verified, a certificate as the product's TLS layer
//! hands it over ([`ClientCertificate`]). Every verifier of the crate holds
//! the token's `cnf` to that binding:
//!
//! - a token with `cnf` is never admitted as a plain bearer token: a `jkt`
//!   needs the `DPoP` proof of that key (RFC 9449 §7.1, §7.2), an `x5t#S256`
//!   the certificate it names (RFC 8705 §3), and a `cnf` naming any other
//!   method is refused, since nothing here can confirm it;
//! - a request that proves a key with the `DPoP` scheme carries a token
//!   bound to that key, or is refused (RFC 9449 §4.3, check 12);
//! - an issuer with [`SenderConstraint::Required`] has every token without
//!   `cnf` refused.
//!
//! Each refusal is a [`Rejection::Invalid`] whose [`Reason::Sender`] names
//! the failed [`Check`], never a token, a key or a thumbprint.
//!
//! [`Rejection::Invalid`]: crate::resource::Rejection::Invalid
//! [`Reason::Sender`]: crate::refusal::Reason::Sender

pub mod proof;
pub mod replay;

use base64::Engine as _;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Map;
use serde_json::Value;

/// Whether an issuer's tokens must be sender-constrained.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SenderConstraint {
    /// A token may be a bearer token; one that carries `cnf` is still held
    /// to it.
    #[default]
    None,
    /// Only a token bound by `DPoP` (`cnf.jkt`) or mutual TLS
    /// (`cnf."x5t#S256"`) is admitted.
    Required,
}

/// The authentication scheme an access token arrived under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `Bearer` (RFC 6750 §2.1), which a certificate-bound token also uses
    /// (RFC 8705 §3).
    Bearer,
    /// `DPoP` (RFC 9449 §7.1), with a proof in the `DPoP` header.
    Dpop,
}

/// The client certificate of the mutual-TLS connection a request arrived on.
///
/// The product's TLS layer reads it (RFC 8705 §3: the protected resource
/// "MUST obtain, from its TLS implementation layer, the client
/// certificate").
///
/// A product inserts it into the request's extensions, where the guard
/// reads it. Behind a TLS-terminating proxy, how the certificate reaches the
/// product is the deployment's (RFC 8705 §6.5). The trust chain is not
/// checked here (RFC 8705 §6.2).
#[derive(Clone, PartialEq, Eq)]
pub struct ClientCertificate {
    /// The SHA-256 of the DER encoding, base64url without padding.
    thumbprint: String,
}

impl std::fmt::Debug for ClientCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCertificate").finish_non_exhaustive()
    }
}

impl ClientCertificate {
    /// Returns the certificate whose DER encoding is `der`.
    #[must_use]
    pub fn from_der(der: &[u8]) -> Self {
        Self {
            thumbprint: sha256(der),
        }
    }

    /// Returns the certificate's SHA-256 thumbprint, the base64url encoding
    /// without padding of the SHA-256 of its DER encoding (RFC 8705 §3.1).
    #[must_use]
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }
}

/// A key a `DPoP` proof showed the client holds, named by its RFC 7638
/// SHA-256 thumbprint (RFC 9449 §6.1).
///
/// Only [`proof::ProofCheck`] returns one, after every check of RFC 9449
/// §4.3, so a binding cannot claim a key no proof proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenKey {
    /// The thumbprint.
    jkt: String,
}

impl ProvenKey {
    /// Returns the key's RFC 7638 SHA-256 thumbprint, base64url without
    /// padding.
    #[must_use]
    pub fn jkt(&self) -> &str {
        &self.jkt
    }
}

/// What one request proves beside its access token: the key of a verified
/// `DPoP` proof, the client certificate of its connection, or neither.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Binding {
    /// The key a `DPoP` proof proved, under the `DPoP` scheme.
    proven: Option<ProvenKey>,
    /// The thumbprint of the connection's client certificate.
    certificate: Option<String>,
}

impl Binding {
    /// Returns the binding of a `Bearer` request that proves nothing.
    #[must_use]
    pub fn bearer() -> Self {
        Self::default()
    }

    /// Returns the binding of a `DPoP` request whose proof proved `key`.
    #[must_use]
    pub fn dpop(key: ProvenKey) -> Self {
        Self {
            proven: Some(key),
            certificate: None,
        }
    }

    /// Returns this binding also carrying the connection's client
    /// `certificate`.
    #[must_use]
    pub fn with_certificate(mut self, certificate: &ClientCertificate) -> Self {
        self.certificate = Some(certificate.thumbprint.clone());
        self
    }

    /// Returns the scheme the token arrived under: `DPoP` when a proof
    /// proved a key.
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        if self.proven.is_some() {
            Scheme::Dpop
        } else {
            Scheme::Bearer
        }
    }

    /// Returns the key a `DPoP` proof proved, when one did.
    #[must_use]
    pub const fn proven_key(&self) -> Option<&ProvenKey> {
        self.proven.as_ref()
    }

    /// Returns the thumbprint of the connection's client certificate, when
    /// one was presented.
    #[must_use]
    pub fn certificate(&self) -> Option<&str> {
        self.certificate.as_deref()
    }
}

/// Which check of a sender-constrained token or its `DPoP` proof failed.
///
/// A check names no value of the token, the proof, the key or the
/// certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Check {
    /// A `DPoP` request carries no `DPoP` header (RFC 9449 §7.1).
    ProofMissing,
    /// More than one `DPoP` header arrived (RFC 9449 §4.3, check 1).
    ProofRepeated,
    /// The proof is no single well-formed JWT (RFC 9449 §4.3, check 2).
    ProofMalformed,
    /// A claim the proof must carry is absent or of the wrong type
    /// (RFC 9449 §4.2; §4.3, check 3).
    ProofClaim,
    /// The `jti` is longer than the store keeps (RFC 9449 §11.1).
    ProofJti,
    /// The `typ` header is not `dpop+jwt` (RFC 9449 §4.3, check 4).
    ProofType,
    /// The `alg` header is not an accepted asymmetric algorithm, or not
    /// the key's (RFC 9449 §4.3, check 5).
    ProofAlgorithm,
    /// The `jwk` header is absent, no public key of a known type, or
    /// carries a private or symmetric key (RFC 9449 §4.3, check 7).
    ProofKey,
    /// The signature does not verify with the `jwk` (RFC 9449 §4.3,
    /// check 6).
    ProofSignature,
    /// The `htm` claim is not the request's method (RFC 9449 §4.3,
    /// check 8).
    ProofMethod,
    /// The `htu` claim is not the request's URI under the external base
    /// URL (RFC 9449 §4.3, check 9).
    ProofUri,
    /// The proof's `iat` is older than the acceptable window (RFC 9449
    /// §4.3, check 11; §11.1).
    ProofStale,
    /// The proof's `iat` is later than now plus the clock skew (RFC 9449
    /// §11.1).
    ProofFuture,
    /// The `ath` claim is not the hash of the access token (RFC 9449 §4.3,
    /// check 12).
    ProofTokenHash,
    /// The proof's `jti` was seen within its window (RFC 9449 §11.1).
    ProofReplayed,
    /// The request line the proof is held to is unknown to the check.
    ProofRequestUnknown,
    /// The token's `cnf.jkt` is not the proof's key (RFC 9449 §4.3, check
    /// 12; §6).
    KeyMismatch,
    /// A `DPoP` request carries a token bound to no key (RFC 9449 §7.1).
    NotKeyBound,
    /// A token bound to a `DPoP` key arrived as a bearer token (RFC 9449
    /// §7.2).
    KeyBoundAsBearer,
    /// A certificate-bound token arrived without a client certificate
    /// (RFC 8705 §3).
    CertificateMissing,
    /// The client certificate is not the one the token is bound to
    /// (RFC 8705 §3).
    CertificateMismatch,
    /// The token's `cnf` is no object, or names a confirmation method this
    /// crate cannot confirm.
    ConfirmationUnknown,
    /// The issuer requires a sender-constrained token and the token
    /// carries no `cnf`.
    ConstraintRequired,
    /// A product's own verifier does not check a `DPoP` binding.
    Unsupported,
}

impl Check {
    /// Returns the check as the log names it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProofMissing => "dpop proof missing",
            Self::ProofRepeated => "dpop proof repeated",
            Self::ProofMalformed => "dpop proof malformed",
            Self::ProofClaim => "dpop proof claim missing",
            Self::ProofJti => "dpop proof jti too long",
            Self::ProofType => "dpop proof typ",
            Self::ProofAlgorithm => "dpop proof algorithm",
            Self::ProofKey => "dpop proof key",
            Self::ProofSignature => "dpop proof signature",
            Self::ProofMethod => "dpop proof htm",
            Self::ProofUri => "dpop proof htu",
            Self::ProofStale => "dpop proof stale",
            Self::ProofFuture => "dpop proof iat in the future",
            Self::ProofTokenHash => "dpop proof ath",
            Self::ProofReplayed => "dpop proof replayed",
            Self::ProofRequestUnknown => "dpop request line unknown",
            Self::KeyMismatch => "dpop key mismatch",
            Self::NotKeyBound => "token not bound to a dpop key",
            Self::KeyBoundAsBearer => "dpop-bound token as bearer",
            Self::CertificateMissing => "client certificate missing",
            Self::CertificateMismatch => "client certificate mismatch",
            Self::ConfirmationUnknown => "cnf names no known method",
            Self::ConstraintRequired => "sender constraint required",
            Self::Unsupported => "verifier checks no dpop binding",
        }
    }

    /// Returns whether the check is of the `DPoP` proof itself, which the
    /// `invalid_dpop_proof` error code answers (RFC 9449 §7.1).
    #[must_use]
    pub const fn is_proof(self) -> bool {
        matches!(
            self,
            Self::ProofMissing
                | Self::ProofRepeated
                | Self::ProofMalformed
                | Self::ProofClaim
                | Self::ProofJti
                | Self::ProofType
                | Self::ProofAlgorithm
                | Self::ProofKey
                | Self::ProofSignature
                | Self::ProofMethod
                | Self::ProofUri
                | Self::ProofStale
                | Self::ProofFuture
                | Self::ProofTokenHash
                | Self::ProofReplayed
                | Self::ProofRequestUnknown
        )
    }
}

impl std::fmt::Display for Check {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Checks the confirmation the token's `claims` carry against what
/// `binding` proves, under the issuer's `constraint`.
pub(crate) fn confirm(
    constraint: SenderConstraint,
    claims: &Map<String, Value>,
    binding: &Binding,
) -> Result<(), Check> {
    let Some(cnf) = claims.get("cnf") else {
        if constraint == SenderConstraint::Required {
            return Err(Check::ConstraintRequired);
        }
        // NOTE: RFC 9449 §7.1, a `DPoP` request's proof key must match the key
        // the token is bound to, which a token without `cnf` names none of.
        return match binding.proven {
            Some(_) => Err(Check::NotKeyBound),
            None => Ok(()),
        };
    };
    let Value::Object(cnf) = cnf else {
        return Err(Check::ConfirmationUnknown);
    };
    // NOTE: no specification governs a `cnf` method this crate cannot check:
    // our own design, refused rather than ignored, as is an empty `cnf`.
    if cnf.is_empty() || cnf.keys().any(|name| name != "jkt" && name != "x5t#S256") {
        return Err(Check::ConfirmationUnknown);
    }
    match (cnf.get("jkt"), &binding.proven) {
        (None, Some(_)) => return Err(Check::NotKeyBound),
        (Some(Value::String(_)), None) => return Err(Check::KeyBoundAsBearer),
        (Some(Value::String(jkt)), Some(key)) if *jkt != key.jkt => {
            return Err(Check::KeyMismatch);
        }
        (Some(Value::String(_)), Some(_)) | (None, None) => {}
        (Some(_), _) => return Err(Check::ConfirmationUnknown),
    }
    match (cnf.get("x5t#S256"), binding.certificate.as_deref()) {
        (None, _) => Ok(()),
        (Some(Value::String(_)), None) => Err(Check::CertificateMissing),
        (Some(Value::String(bound)), Some(presented)) if bound == presented => Ok(()),
        (Some(Value::String(_)), Some(_)) => Err(Check::CertificateMismatch),
        (Some(_), _) => Err(Check::ConfirmationUnknown),
    }
}

/// Returns whether an introspection response's `token_type` agrees with
/// its `cnf`: `DPoP` exactly when the response names a `jkt` (RFC 9449
/// §6.2), and otherwise absent or `Bearer` (RFC 6750).
#[cfg(feature = "fetch")]
pub(crate) fn token_type_holds(claims: &Map<String, Value>) -> bool {
    let jkt = claims
        .get("cnf")
        .and_then(Value::as_object)
        .is_some_and(|cnf| cnf.contains_key("jkt"));
    // NOTE: RFC 6749 §7.1 and RFC 9449 §6.2, a token type is compared
    // without regard to case, and a DPoP-bound response "MUST" name `DPoP`.
    match claims.get("token_type") {
        None => true,
        Some(Value::String(named)) if named.eq_ignore_ascii_case("dpop") => jkt,
        Some(Value::String(named)) if named.eq_ignore_ascii_case("bearer") => !jkt,
        Some(_) => false,
    }
}

/// Returns the base64url encoding without padding of the SHA-256 of
/// `bytes`.
pub(crate) fn sha256(bytes: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
}

#[cfg(test)]
mod tests {
    use super::{Binding, Check, ClientCertificate, ProvenKey, SenderConstraint, confirm};
    use serde_json::{Map, Value, json};

    fn claims(value: &Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap_or_default()
    }

    fn key(jkt: &str) -> Binding {
        Binding::dpop(ProvenKey {
            jkt: jkt.to_owned(),
        })
    }

    #[test]
    fn a_token_without_cnf_is_a_bearer_token_unless_the_issuer_requires_one() {
        let plain = claims(&json!({ "sub": "a" }));
        assert_eq!(
            Ok(()),
            confirm(SenderConstraint::None, &plain, &Binding::bearer())
        );
        assert_eq!(
            Err(Check::ConstraintRequired),
            confirm(SenderConstraint::Required, &plain, &Binding::bearer())
        );
        assert_eq!(
            Err(Check::NotKeyBound),
            confirm(SenderConstraint::None, &plain, &key("k")),
            "RFC 9449 §7.1: a DPoP request needs a key-bound token"
        );
    }

    #[test]
    fn a_cnf_naming_an_unknown_method_or_no_object_is_refused() {
        for cnf in [
            json!({ "cnf": "jkt" }),
            json!({ "cnf": {} }),
            json!({ "cnf": { "jwk": { "kty": "EC" } } }),
            json!({ "cnf": { "jkt": "k", "kid": "x" } }),
            json!({ "cnf": { "jkt": 7 } }),
        ] {
            assert_eq!(
                Err(Check::ConfirmationUnknown),
                confirm(SenderConstraint::None, &claims(&cnf), &key("k")),
                "{cnf}"
            );
        }
    }

    #[test]
    fn a_token_bound_to_both_needs_both() {
        let certificate = ClientCertificate::from_der(b"synthetic");
        let both = claims(&json!({ "cnf": {
            "jkt": "k",
            "x5t#S256": certificate.thumbprint(),
        }}));
        assert_eq!(
            Err(Check::CertificateMissing),
            confirm(SenderConstraint::Required, &both, &key("k"))
        );
        assert_eq!(
            Ok(()),
            confirm(
                SenderConstraint::Required,
                &both,
                &key("k").with_certificate(&certificate)
            )
        );
        assert_eq!(
            Err(Check::KeyBoundAsBearer),
            confirm(
                SenderConstraint::Required,
                &both,
                &Binding::bearer().with_certificate(&certificate)
            )
        );
    }

    #[test]
    fn a_certificate_renders_no_thumbprint_in_debug() {
        let certificate = ClientCertificate::from_der(b"synthetic");
        assert!(!format!("{certificate:?}").contains(certificate.thumbprint()));
    }
}
