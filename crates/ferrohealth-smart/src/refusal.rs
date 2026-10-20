// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Why a request is refused at the gate, and the status and challenge it is
//! answered with.
//!
//! A missing credential is challenged without an error code and an invalid
//! one with `invalid_token`; a token that grants no permission for the
//! request is `403` with `insufficient_scope`; two credentials or a
//! malformed `Authorization` value is `400` with `invalid_request`
//! (RFC 6750 §3.1). The body a product sends with the status is the
//! product's own (a FHIR `OperationOutcome`, an openEHR error body); it
//! names no claim and no scope, so a refusal teaches a caller nothing about
//! what it lacks (no specification requires the omission: our own design).

use http::StatusCode;

use crate::resource::Rejection;

/// The authentication schemes a gate admits, which a missing-credential
/// challenge lists (RFC 9110 §11.6.1 allows several challenges).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Schemes {
    /// Whether a `Bearer` token is admitted (RFC 6750).
    pub bearer: bool,
    /// Whether a `Basic` credential is admitted (RFC 7617).
    pub basic: bool,
}

/// Why a request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The request carries no credential of a scheme the gate admits.
    Missing(Schemes),
    /// The request carries two credentials, or an `Authorization` value
    /// that is no credential at all (RFC 6750 §3.1, `invalid_request`).
    InvalidRequest,
    /// The bearer token does not hold (RFC 6750 §3.1, `invalid_token`).
    InvalidToken,
    /// The Basic credential does not hold.
    InvalidBasic,
    /// The credential holds, and it grants no permission for the request
    /// (RFC 6750 §3.1, `insufficient_scope`).
    Forbidden,
    /// The token could not be checked at all: the authorization server's key
    /// set could not be read.
    Unavailable,
    /// The route is one the gate cannot classify, which fails closed (no
    /// specification governs this: our own design).
    Unclassified,
}

impl Refusal {
    /// Returns the status the refusal is answered with.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::Missing(_) | Self::InvalidToken | Self::InvalidBasic => StatusCode::UNAUTHORIZED,
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::Forbidden | Self::Unclassified => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// Returns the `WWW-Authenticate` value of the refusal, `realm` named
    /// on each challenge when given, or `None` for a status that carries no
    /// challenge.
    ///
    /// The Basic challenge always names a realm and the UTF-8 charset
    /// (RFC 7617 §2, §2.1), the realm given or an empty one.
    #[must_use]
    pub fn challenge(&self, realm: Option<&str>) -> Option<String> {
        let quoted = realm.map(quote);
        // NOTE: RFC 9110 §11.3, auth-params follow the scheme after one
        // space and are comma-separated; RFC 6750 §3 puts realm before error.
        let bearer = |error: Option<&str>| {
            let mut params: Vec<String> = Vec::new();
            if let Some(realm) = &quoted {
                params.push(format!("realm={realm}"));
            }
            if let Some(error) = error {
                params.push(format!("error=\"{error}\""));
            }
            if params.is_empty() {
                String::from("Bearer")
            } else {
                format!("Bearer {}", params.join(", "))
            }
        };
        let basic = || {
            let realm = quoted.as_deref().unwrap_or("\"\"");
            format!("Basic realm={realm}, charset=\"UTF-8\"")
        };
        match self {
            Self::Missing(schemes) => {
                let mut challenges = Vec::new();
                if schemes.bearer {
                    challenges.push(bearer(None));
                }
                if schemes.basic {
                    challenges.push(basic());
                }
                if challenges.is_empty() {
                    None
                } else {
                    Some(challenges.join(", "))
                }
            }
            Self::InvalidRequest => Some(bearer(Some("invalid_request"))),
            Self::InvalidToken => Some(bearer(Some("invalid_token"))),
            Self::InvalidBasic => Some(basic()),
            Self::Forbidden => Some(bearer(Some("insufficient_scope"))),
            Self::Unavailable | Self::Unclassified => None,
        }
    }

    /// Returns the reason the debug log names, never a claim value.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Missing(_) => "missing",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidToken => "invalid_token",
            Self::InvalidBasic => "invalid_basic",
            Self::Forbidden => "insufficient_scope",
            Self::Unavailable => "unavailable",
            Self::Unclassified => "unclassified",
        }
    }
}

/// Which check refused a credential, for the product's own log.
///
/// A reason never reaches the wire: every invalid credential is the one
/// `401` of RFC 6750 §3 with no `error_description`, because a refusal
/// that names the failed check teaches a forger which claim to fix next (no
/// specification requires the omission: our own design). A reason names a
/// check and never carries a claim value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// Two `Authorization` header fields arrived (RFC 6750 §3.1).
    TwoCredentials,
    /// The `Authorization` value is not a scheme and a credential.
    MalformedHeader,
    /// The bearer token is outside the `b64token` syntax of RFC 6750 §2.1.
    NotB64Token,
    /// The token does not parse as a JWS in compact serialization.
    Malformed,
    /// The header names an algorithm outside the configured set.
    Algorithm,
    /// The `typ` header names another kind of token (RFC 9068 §4).
    Type,
    /// No key of the issuer's set verifies the token.
    UnknownKey,
    /// The signature does not verify.
    Signature,
    /// The token has expired.
    Expired,
    /// The token is not yet valid (`nbf`).
    NotYetValid,
    /// The token was issued in the future beyond the clock skew.
    IssuedInFuture,
    /// The `iss` claim is not the configured issuer.
    Issuer,
    /// The `iss` claim names no issuer the product trusts.
    UntrustedIssuer,
    /// The `aud` claim names no configured audience.
    Audience,
    /// A claim the token profile requires is absent.
    MissingClaim,
    /// The `sub` claim is not a string.
    Subject,
    /// The `sub` claim is empty or whitespace only, which identifies no
    /// principal (RFC 9068 §2.2, RFC 7519 §4.1.2).
    BlankSubject,
    /// The key set could not be read to check the token.
    KeySetUnavailable,
    /// The Basic credential is not the RFC 7617 §2 form.
    BasicMalformed,
    /// The Basic user is unknown or the password does not match.
    BasicRejected,
    /// A reason a product's own [`crate::resource::Verifier`] names.
    Other(&'static str),
}

impl Reason {
    /// Returns the reason as the log names it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TwoCredentials => "two credentials",
            Self::MalformedHeader => "malformed authorization header",
            Self::NotB64Token => "not a b64token",
            Self::Malformed => "malformed",
            Self::Algorithm => "algorithm not accepted",
            Self::Type => "typ names another kind",
            Self::UnknownKey => "no key of the set",
            Self::Signature => "signature",
            Self::Expired => "expired",
            Self::NotYetValid => "not yet valid",
            Self::IssuedInFuture => "iat is in the future",
            Self::Issuer => "issuer",
            Self::UntrustedIssuer => "issuer not trusted",
            Self::Audience => "audience",
            Self::MissingClaim => "a required claim is missing",
            Self::Subject => "sub is not a string",
            Self::BlankSubject => "sub is blank",
            Self::KeySetUnavailable => "key set unavailable",
            Self::BasicMalformed => "malformed basic credential",
            Self::BasicRejected => "basic credential rejected",
            Self::Other(reason) => reason,
        }
    }
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refusal at the gate with the reason behind it.
///
/// The product answers [`Denied::refusal`], whose status and challenge are
/// the library's, and logs [`Denied::reason`]; the reason never reaches
/// the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    /// What the request is answered with.
    refusal: Refusal,
    /// Which check refused it, when one did.
    reason: Option<Reason>,
}

impl Denied {
    /// Returns the denial answered with `refusal`, refused by `reason`.
    #[must_use]
    pub const fn new(refusal: Refusal, reason: Option<Reason>) -> Self {
        Self { refusal, reason }
    }

    /// Returns what the request is answered with.
    #[must_use]
    pub const fn refusal(&self) -> &Refusal {
        &self.refusal
    }

    /// Returns which check refused the credential, or `None` when no
    /// credential was examined (none arrived).
    #[must_use]
    pub const fn reason(&self) -> Option<Reason> {
        self.reason
    }

    /// Returns the refusal, dropping the reason.
    #[must_use]
    pub fn into_refusal(self) -> Refusal {
        self.refusal
    }
}

impl From<Refusal> for Denied {
    fn from(refusal: Refusal) -> Self {
        Self::new(refusal, None)
    }
}

impl From<Denied> for Refusal {
    fn from(denied: Denied) -> Self {
        denied.refusal
    }
}

impl From<&Rejection> for Denied {
    fn from(rejection: &Rejection) -> Self {
        let reason = match rejection {
            Rejection::Missing => None,
            Rejection::Invalid { reason } => Some(*reason),
            Rejection::Unavailable { .. } => Some(Reason::KeySetUnavailable),
        };
        Self::new(Refusal::from(rejection), reason)
    }
}

impl From<&Rejection> for Refusal {
    fn from(rejection: &Rejection) -> Self {
        match rejection {
            Rejection::Missing => Self::Missing(Schemes {
                bearer: true,
                basic: false,
            }),
            Rejection::Invalid { .. } => Self::InvalidToken,
            Rejection::Unavailable { .. } => Self::Unavailable,
        }
    }
}

/// Returns `realm` as an RFC 9110 §5.6.4 quoted string.
fn quote(realm: &str) -> String {
    let mut quoted = String::with_capacity(realm.len().saturating_add(2));
    quoted.push('"');
    for character in realm.chars() {
        if character == '"' || character == '\\' {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::{Denied, Reason, Refusal, Schemes};
    use crate::resource::Rejection;
    use http::StatusCode;

    #[test]
    fn a_denial_carries_its_reason_and_the_challenge_names_none() {
        let denied = Denied::from(&Rejection::Invalid {
            reason: Reason::Expired,
        });
        assert_eq!(&Refusal::InvalidToken, denied.refusal());
        assert_eq!(Some(Reason::Expired), denied.reason());
        assert_eq!("expired", Reason::Expired.to_string());
        assert_eq!(
            Some(String::from("Bearer error=\"invalid_token\"")),
            denied.refusal().challenge(None),
            "RFC 6750 §3.1: the reason stays off the wire"
        );
        assert_eq!(None, Denied::from(&Rejection::Missing).reason());
        assert_eq!(
            Refusal::InvalidToken,
            Refusal::from(Denied::new(Refusal::InvalidToken, None))
        );
    }

    #[test]
    fn a_missing_credential_lists_every_admitted_scheme() {
        let both = Refusal::Missing(Schemes {
            bearer: true,
            basic: true,
        });
        assert_eq!(StatusCode::UNAUTHORIZED, both.status());
        assert_eq!(
            Some(String::from(
                "Bearer realm=\"ferro\", Basic realm=\"ferro\", charset=\"UTF-8\""
            )),
            both.challenge(Some("ferro"))
        );
        assert_eq!(
            Some(String::from("Bearer, Basic realm=\"\", charset=\"UTF-8\"")),
            both.challenge(None)
        );
    }

    #[test]
    fn the_error_codes_are_rfc_6750s() {
        assert_eq!(
            Some(String::from("Bearer error=\"invalid_token\"")),
            Refusal::InvalidToken.challenge(None)
        );
        assert_eq!(
            Some(String::from(
                "Bearer realm=\"a \\\"b\\\"\", error=\"insufficient_scope\""
            )),
            Refusal::Forbidden.challenge(Some("a \"b\""))
        );
        assert_eq!(StatusCode::FORBIDDEN, Refusal::Forbidden.status());
        assert_eq!(
            Some(String::from(
                "Bearer realm=\"ferro\", error=\"invalid_request\""
            )),
            Refusal::InvalidRequest.challenge(Some("ferro"))
        );
        assert_eq!(StatusCode::BAD_REQUEST, Refusal::InvalidRequest.status());
        assert_eq!(None, Refusal::Unavailable.challenge(Some("ferro")));
        assert_eq!(
            StatusCode::SERVICE_UNAVAILABLE,
            Refusal::Unavailable.status()
        );
    }
}
