// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Why a request is refused at the gate, and the status and challenge it is
//! answered with.
//!
//! A missing credential is challenged without an error code and an invalid
//! one with `invalid_token`; a token that grants no permission for the
//! request is `403` with `insufficient_scope`; two credentials or a
//! malformed `Authorization` value is `400` with `invalid_request`
//! (RFC 6750 §3.1); a token whose authentication event falls short of what
//! the resource requires is `401` with `insufficient_user_authentication`
//! (RFC 9470 §3). The body a product sends with the status is the
//! product's own (a FHIR `OperationOutcome`, an openEHR error body); it
//! names no claim and no scope, so a refusal teaches a caller nothing about
//! what it lacks (no specification requires the omission: our own design).

use http::StatusCode;

use crate::resource::Caller;
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
    /// set, or the upstream a product's verifier calls, could not be read.
    Unavailable,
    /// The token holds, and the authentication event behind it does not
    /// meet what the resource requires (RFC 9470 §3,
    /// `insufficient_user_authentication`).
    StepUp(StepUp),
    /// The route is one the gate cannot classify, which fails closed (no
    /// specification governs this: our own design).
    Unclassified,
}

impl Refusal {
    /// Returns the status the refusal is answered with.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::Missing(_) | Self::InvalidToken | Self::InvalidBasic | Self::StepUp(_) => {
                StatusCode::UNAUTHORIZED
            }
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
        let bearer_with = |error: Option<&str>, extra: Vec<String>| {
            let mut params: Vec<String> = Vec::new();
            if let Some(realm) = &quoted {
                params.push(format!("realm={realm}"));
            }
            if let Some(error) = error {
                params.push(format!("error=\"{error}\""));
            }
            params.extend(extra);
            if params.is_empty() {
                String::from("Bearer")
            } else {
                format!("Bearer {}", params.join(", "))
            }
        };
        let bearer = |error: Option<&str>| bearer_with(error, Vec::new());
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
            // NOTE: RFC 9470 §3, the error code with `acr_values` and `max_age` as
            // auth-params; values are quoted strings, max_age a non-negative integer.
            Self::StepUp(step_up) => {
                let mut extra = Vec::new();
                if !step_up.acr_values.is_empty() {
                    extra.push(format!("acr_values=\"{}\"", step_up.acr_values.join(" ")));
                }
                if let Some(max_age) = step_up.max_age {
                    extra.push(format!("max_age=\"{max_age}\""));
                }
                Some(bearer_with(Some("insufficient_user_authentication"), extra))
            }
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
            Self::StepUp(_) => "insufficient_user_authentication",
            Self::Unclassified => "unclassified",
        }
    }
}

/// What the resource requires of the authentication event behind a token,
/// and the challenge that tells the client (RFC 9470 §3).
///
/// What a resource requires is the product's decision ("out of scope" of
/// RFC 9470 §3); the crate checks it against the token's `acr` and
/// `auth_time` claims (§6) and renders the challenge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StepUp {
    /// The authentication context class references, one of which the
    /// authentication event must carry, in order of preference; empty for
    /// no requirement.
    acr_values: Vec<String>,
    /// The longest time in seconds since the last active authentication
    /// event, when the resource requires one.
    max_age: Option<u64>,
}

/// An `acr` value that cannot travel in the challenge.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "the acr value {value:?} is empty or carries a space, a quote, a backslash or a byte outside visible ASCII"
)]
pub struct AcrValueError {
    /// The value refused.
    pub value: String,
}

impl StepUp {
    /// Returns a step-up challenge that names no requirement.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns this challenge requiring one of `values`, in order of
    /// preference.
    ///
    /// # Errors
    ///
    /// Returns [`AcrValueError`] for a value that is empty or carries a
    /// byte outside visible ASCII, a space (the list separator of RFC 9470
    /// §3), a quote or a backslash.
    pub fn with_acr_values<I, S>(mut self, values: I) -> Result<Self, AcrValueError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for value in values {
            let value = value.into();
            let travels = !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\');
            if !travels {
                return Err(AcrValueError { value });
            }
            self.acr_values.push(value);
        }
        Ok(self)
    }

    /// Returns this challenge requiring an authentication event at most
    /// `seconds` old.
    #[must_use]
    pub const fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }

    /// Returns the `acr` values one of which is required.
    #[must_use]
    pub fn acr_values(&self) -> &[String] {
        &self.acr_values
    }

    /// Returns the longest time since the authentication event, in seconds.
    #[must_use]
    pub const fn max_age(&self) -> Option<u64> {
        self.max_age
    }

    /// Returns whether `caller`'s authentication event meets the
    /// requirement: its `acr` is one of the values, when any is named, and
    /// its `auth_time` is at most `max_age` seconds ago, when one is named.
    ///
    /// A token without the claim a requirement reads does not meet it
    /// (RFC 9470 §6 conveys both in the access token).
    #[must_use]
    pub fn satisfied_by(&self, caller: &Caller) -> bool {
        let acr = self.acr_values.is_empty()
            || caller
                .acr()
                .is_some_and(|acr| self.acr_values.iter().any(|value| value == acr));
        let recent = self.max_age.is_none_or(|max_age| {
            caller.auth_time().is_some_and(|auth_time| {
                let elapsed = jiff::Timestamp::now().as_second().saturating_sub(auth_time);
                u64::try_from(elapsed).map_or(true, |elapsed| elapsed <= max_age)
            })
        });
        acr && recent
    }

    /// Returns the refusal that answers with this challenge.
    #[must_use]
    pub fn into_refusal(self) -> Refusal {
        Refusal::StepUp(self)
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
    /// An upstream a product's verifier calls could not be read to check
    /// the token.
    UpstreamUnavailable,
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
            Self::UpstreamUnavailable => "upstream unavailable",
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
            Rejection::Upstream { .. } => Some(Reason::UpstreamUnavailable),
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
            Rejection::Unavailable { .. } | Rejection::Upstream { .. } => Self::Unavailable,
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
    use super::{Denied, Reason, Refusal, Schemes, StepUp};
    use crate::resource::{Caller, Rejection};
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
    fn an_upstream_failure_of_a_product_verifier_answers_503() {
        let rejection = Rejection::upstream(
            "introspection endpoint",
            std::io::Error::other("connection refused"),
        );
        let denied = Denied::from(&rejection);
        assert_eq!(&Refusal::Unavailable, denied.refusal());
        assert_eq!(Some(Reason::UpstreamUnavailable), denied.reason());
        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, denied.refusal().status());
        assert_eq!(None, denied.refusal().challenge(Some("ferro")));
        let source = std::error::Error::source(&rejection).map(ToString::to_string);
        assert_eq!(Some(String::from("connection refused")), source);
    }

    #[test]
    fn the_step_up_challenge_is_rfc_9470s() {
        let bare = StepUp::new().into_refusal();
        assert_eq!(StatusCode::UNAUTHORIZED, bare.status());
        assert_eq!(
            Some(String::from(
                "Bearer realm=\"ferro\", error=\"insufficient_user_authentication\""
            )),
            bare.challenge(Some("ferro"))
        );
        let both = StepUp::new()
            .with_acr_values(["urn:acr:high", "myACR"])
            .expect("visible ASCII")
            .with_max_age(5)
            .into_refusal();
        assert_eq!(
            Some(String::from(
                "Bearer error=\"insufficient_user_authentication\", acr_values=\"urn:acr:high myACR\", max_age=\"5\""
            )),
            both.challenge(None)
        );
        assert_eq!("insufficient_user_authentication", both.reason());
        for bad in ["", "a b", "a\"b", "a\\b", "ä"] {
            assert!(StepUp::new().with_acr_values([bad]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_step_up_requirement_reads_acr_and_auth_time() {
        let caller = |acr: Option<&str>, auth_time: Option<i64>| {
            let mut claims = serde_json::Map::new();
            if let Some(acr) = acr {
                claims.insert(String::from("acr"), serde_json::json!(acr));
            }
            if let Some(auth_time) = auth_time {
                claims.insert(String::from("auth_time"), serde_json::json!(auth_time));
            }
            Caller::new(String::from("doc"), None, "", None, false).with_claims(claims)
        };
        let now = jiff::Timestamp::now().as_second();
        let level = StepUp::new()
            .with_acr_values(["high"])
            .expect("visible ASCII");
        assert!(level.satisfied_by(&caller(Some("high"), None)));
        assert!(
            !level.satisfied_by(&caller(Some("low"), None)),
            "another acr"
        );
        assert!(!level.satisfied_by(&caller(None, None)), "no acr");
        let recent = StepUp::new().with_max_age(300);
        assert!(recent.satisfied_by(&caller(None, Some(now - 10))));
        assert!(
            !recent.satisfied_by(&caller(None, Some(now - 3600))),
            "too old"
        );
        assert!(!recent.satisfied_by(&caller(None, None)), "no auth_time");
        assert!(
            StepUp::new().satisfied_by(&caller(None, None)),
            "no requirement"
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
