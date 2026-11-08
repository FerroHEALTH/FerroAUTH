// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What a client grant binds its tokens to, and the client half of the
//! certificate-bound token check (RFC 8705 §3).
//!
//! A grant whose tokens are certificate-bound presents the client
//! certificate of its [`Tls`](crate::client::Tls) identity, and checks
//! every token it is issued against that certificate's thumbprint where the
//! token states a binding: a `cnf` member of the token response, in the
//! form RFC 8705 §3.2 gives an introspection response, or the `cnf` claim of
//! an access token that is a JWT (§3.1). A token bound to another
//! certificate, or confirmed by another method, is refused before it is
//! cached or sent. An opaque token states no binding and passes as sent.

use std::sync::Arc;

use base64::Engine as _;
use http::HeaderValue;
use http::Method;
use secrecy::ExposeSecret;
use secrecy::SecretSlice;
use secrecy::SecretString;
#[cfg(feature = "fetch")]
use serde::Deserialize;
use url::Url;

use crate::client::dpop;
use crate::client::dpop::DpopError;
use crate::client::dpop::DpopKey;
use crate::sender::ClientCertificate;

/// What a grant binds the tokens it is issued to (RFC 9449, RFC 8705 §3).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TokenBinding {
    /// A `DPoP` key: every token request and every resource request carries
    /// a proof of it, and the issued token is of type `DPoP` (RFC 9449 §5).
    Dpop(Arc<DpopKey>),
    /// The client certificate of the grant's TLS identity: every issued
    /// token whose binding is stated must name it (RFC 8705 §3).
    Certificate,
}

/// An issued token, ready to send: its `Authorization` value, the access
/// token, and the key it is bound to when it is `DPoP`-bound.
///
/// The `Debug` rendering never carries the token: the header value is
/// marked sensitive and the access token is a [`SecretString`].
#[derive(Debug, Clone)]
pub struct IssuedToken {
    /// The `Authorization` field value the token renders to.
    header: HeaderValue,
    /// The access token.
    access: SecretString,
    /// The key the token is bound to, when it is `DPoP`-bound.
    key: Option<Arc<DpopKey>>,
}

impl IssuedToken {
    /// Returns the token `access` sent as `header`, bound to `key` when one
    /// is given.
    #[cfg(feature = "fetch")]
    pub(crate) const fn new(
        header: HeaderValue,
        access: SecretString,
        key: Option<Arc<DpopKey>>,
    ) -> Self {
        Self {
            header,
            access,
            key,
        }
    }

    /// Returns the `Authorization` field value of the token: `Bearer` (RFC
    /// 6750 §2.1), or `DPoP` for a `DPoP`-bound token (RFC 9449 §7.1).
    #[must_use]
    pub const fn header(&self) -> &HeaderValue {
        &self.header
    }

    /// Returns the access token, for a product client that composes its own
    /// `Authorization` field.
    #[must_use]
    pub const fn access_token(&self) -> &SecretString {
        &self.access
    }

    /// Returns the key the token is bound to, when it is `DPoP`-bound.
    #[must_use]
    pub const fn dpop_key(&self) -> Option<&Arc<DpopKey>> {
        self.key.as_ref()
    }

    /// Returns the `DPoP` proof of a request with `method` to `url` that
    /// presents this token, with its `ath` (RFC 9449 §4.2, §7.1), or `None`
    /// for a token that is not `DPoP`-bound.
    ///
    /// # Errors
    ///
    /// Returns the [`DpopError`] of a proof that could not be signed.
    pub fn proof(&self, method: &Method, url: &Url) -> Result<Option<String>, DpopError> {
        self.key
            .as_ref()
            .map(|key| {
                key.proof(
                    method,
                    url,
                    dpop::Role::Resource,
                    Some(self.access.expose_secret()),
                )
            })
            .transpose()
    }
}

/// The certificate the PEM chain and key `identity` presents: its first
/// `CERTIFICATE` block, the end-entity certificate a TLS client sends first
/// (RFC 8446 §4.4.2), or `None` when it holds none that reads.
#[must_use]
pub fn presented_certificate(identity: &SecretSlice<u8>) -> Option<ClientCertificate> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    // NOTE: RFC 7468 §2, PEM text is ASCII; an identity that is not UTF-8 is
    // legitimately no PEM, and holds no certificate this reader can name.
    let text = std::str::from_utf8(identity.expose_secret()).ok()?;
    let start = text.find(BEGIN)?.checked_add(BEGIN.len())?;
    let rest = text.get(start..)?;
    let body = rest.get(..rest.find(END)?)?;
    let base64: String = body
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    // NOTE: RFC 7468 §2, the block body is base64; one that does not decode is
    // legitimately no certificate, and the grant is refused for holding none.
    let der = base64::engine::general_purpose::STANDARD
        .decode(base64)
        .ok()?;
    Some(ClientCertificate::from_der(&der))
}

/// A `cnf` confirmation (RFC 7800 §3.1), the member a certificate-bound
/// grant reads.
#[cfg(feature = "fetch")]
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct Confirmation {
    /// The certificate thumbprint the token is bound to (RFC 8705 §3.1).
    #[serde(rename = "x5t#S256")]
    x5t_s256: Option<String>,
}

/// How an issued token's stated binding compares with the grant's
/// certificate.
#[cfg(feature = "fetch")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bound {
    /// The token states no binding: an opaque token with no `cnf` beside it.
    Unstated,
    /// Every binding the token states names the certificate.
    Confirmed,
    /// A binding the token states names another certificate, or another
    /// confirmation method.
    Mismatch,
}

/// Compares the bindings `token` and `response`, the `cnf` member of its
/// token response, state with `expected`, the thumbprint of the certificate
/// the grant presents (RFC 8705 §3.1, §3.2).
#[cfg(feature = "fetch")]
pub(crate) fn bound(token: &str, response: Option<&Confirmation>, expected: &str) -> Bound {
    let stated: Vec<Confirmation> = response
        .cloned()
        .into_iter()
        .chain(claimed(token))
        .collect();
    if stated.is_empty() {
        return Bound::Unstated;
    }
    if stated
        .iter()
        .all(|cnf| cnf.x5t_s256.as_deref() == Some(expected))
    {
        Bound::Confirmed
    } else {
        Bound::Mismatch
    }
}

/// Returns the `cnf` claim of `token`, when it is a JWT that carries one
/// (RFC 8705 §3.1).
#[cfg(feature = "fetch")]
fn claimed(token: &str) -> Option<Confirmation> {
    // NOTE: RFC 6749 §1.4, an access token is opaque to the client; one that is
    // no JWT, or whose cnf is of another shape, legitimately states no binding.
    let claims = crate::client::onward::check::decode(token).ok()?;
    serde_json::from_value(claims.get("cnf")?.clone()).ok()
}

#[cfg(test)]
mod tests {
    use super::presented_certificate;
    #[cfg(feature = "fetch")]
    use super::{Bound, Confirmation, bound};
    #[cfg(feature = "fetch")]
    use base64::Engine as _;
    use secrecy::SecretSlice;

    /// The certificate of RFC 8705 Appendix A, Figure 6.
    const RFC_8705_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----
MIIBBjCBrAIBAjAKBggqhkjOPQQDAjAPMQ0wCwYDVQQDDARtdGxzMB4XDTE4MTAx
ODEyMzcwOVoXDTIyMDUwMjEyMzcwOVowDzENMAsGA1UEAwwEbXRsczBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABNcnyxwqV6hY8QnhxxzFQ03C7HKW9OylMbnQZjjJ
/Au08/coZwxS7LfA4vOLS9WuneIXhbGGWvsDSb0tH6IxLm8wCgYIKoZIzj0EAwID
SQAwRgIhAP0RC1E+vwJD/D1AGHGzuri+hlV/PpQEKTWUVeORWz83AiEA5x2eXZOV
bUlJSGQgjwD5vaUaKlLR50Q2DmFfQj1L+SY=
-----END CERTIFICATE-----
";

    /// The thumbprint of RFC 8705 Appendix A, Figure 5.
    const RFC_8705_THUMBPRINT: &str = "A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0";

    #[cfg(feature = "fetch")]
    fn jwt(claims: &str) -> String {
        let encode = |text: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text);
        format!("{}.{}.c2ln", encode(r#"{"alg":"ES256"}"#), encode(claims))
    }

    #[test]
    fn the_presented_certificate_is_the_rfc_8705_example() {
        let identity = format!(
            "{RFC_8705_CERTIFICATE}-----BEGIN PRIVATE KEY-----\nQz7secret\n-----END PRIVATE KEY-----\n"
        );
        let presented = presented_certificate(&SecretSlice::from(identity.into_bytes()))
            .expect("the certificate reads");
        assert_eq!(RFC_8705_THUMBPRINT, presented.thumbprint());
        let none = SecretSlice::from(
            b"-----BEGIN PRIVATE KEY-----\nQz7\n-----END PRIVATE KEY-----\n".to_vec(),
        );
        assert!(presented_certificate(&none).is_none());
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn a_jwt_claim_and_a_response_member_are_held_to_the_certificate() {
        let ours = RFC_8705_THUMBPRINT;
        let theirs = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
        let claim = |thumbprint: &str| jwt(&format!(r#"{{"cnf":{{"x5t#S256":"{thumbprint}"}}}}"#));
        let member = |thumbprint: &str| -> Confirmation {
            serde_json::from_str(&format!(r#"{{"x5t#S256":"{thumbprint}"}}"#)).expect("reads")
        };
        assert_eq!(Bound::Unstated, bound("opaque-token", None, ours));
        assert_eq!(Bound::Unstated, bound(&jwt(r#"{"sub":"x"}"#), None, ours));
        assert_eq!(Bound::Confirmed, bound(&claim(ours), None, ours));
        assert_eq!(Bound::Mismatch, bound(&claim(theirs), None, ours));
        assert_eq!(
            Bound::Mismatch,
            bound(&jwt(r#"{"cnf":{"jkt":"abc"}}"#), None, ours),
            "a token confirmed by a DPoP key is not bound to the certificate"
        );
        assert_eq!(Bound::Confirmed, bound("opaque", Some(&member(ours)), ours));
        assert_eq!(
            Bound::Mismatch,
            bound("opaque", Some(&member(theirs)), ours)
        );
        assert_eq!(
            Bound::Mismatch,
            bound(&claim(ours), Some(&member(theirs)), ours),
            "every stated binding must name the certificate"
        );
    }
}
