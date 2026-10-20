// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! How a [`Gate`] reads who calls: the `Authorization` header alone, a
//! bearer token held to the `b64token` syntax and checked by the verifier,
//! a Basic credential checked against the password store, and every refusal
//! a [`Denied`] whose reason the product logs and the wire never carries.

use std::sync::Arc;

use http::HeaderMap;
use http::HeaderValue;
use http::header;

use crate::basic::PasswordStore;
use crate::guard::Gate;
use crate::refusal::Denied;
use crate::refusal::Reason;
use crate::refusal::Refusal;
use crate::resource::Access;
use crate::resource::Caller;
use crate::resource::Rejection;
use crate::resource::Verifier;

impl Gate {
    /// Returns who calls with `headers`, or the denial.
    ///
    /// The token is read from the `Authorization` header alone, never from
    /// a query or a form body (RFC 9700 §4.3.2), and the scheme is compared
    /// case-insensitively (RFC 9110 §11.1); a scheme the gate does not admit
    /// is a missing credential. A bearer token outside the `b64token` syntax
    /// of RFC 6750 §2.1, and a caller whose subject is blank (RFC 9068
    /// §2.2), are refused as a token that does not hold.
    ///
    /// # Errors
    ///
    /// Returns a [`Denied`] whose refusal is [`Refusal::Missing`] for no
    /// admitted credential, [`Refusal::InvalidRequest`] for two credentials
    /// or a value that is no credential, [`Refusal::InvalidToken`] or
    /// [`Refusal::InvalidBasic`] for one that does not hold, and
    /// [`Refusal::Unavailable`] when a token could not be checked; its
    /// [`Denied::reason`] names the check for the product's log.
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<Access, Denied> {
        if self.is_open() {
            return Ok(Access::Open);
        }
        let missing = || Denied::from(Refusal::Missing(self.schemes()));
        let malformed = |reason| Denied::new(Refusal::InvalidRequest, Some(reason));
        let mut values = headers.get_all(header::AUTHORIZATION).iter();
        let value = match (values.next(), values.next()) {
            (None, _) => return Err(missing()),
            (Some(_), Some(_)) => return Err(malformed(Reason::TwoCredentials)),
            (Some(value), None) => value,
        };
        let text = value
            .to_str()
            .map_err(|_opaque| malformed(Reason::MalformedHeader))?;
        let (scheme, credential) = text
            .split_once(' ')
            .ok_or_else(|| malformed(Reason::MalformedHeader))?;
        let credential = credential.trim();
        if credential.is_empty() {
            return Err(malformed(Reason::MalformedHeader));
        }
        let caller = if scheme.eq_ignore_ascii_case("Bearer") {
            let verifier = self.bearer.as_ref().ok_or_else(missing)?;
            bearer(verifier.as_ref(), credential).await?
        } else if scheme.eq_ignore_ascii_case("Basic") {
            let store = Arc::clone(self.basic.as_ref().ok_or_else(missing)?);
            basic(store, value.clone()).await?
        } else {
            return Err(missing());
        };
        Ok(Access::Caller(Arc::new(caller)))
    }
}

/// Returns the caller `token` authenticates under `verifier`.
async fn bearer(verifier: &dyn Verifier, token: &str) -> Result<Caller, Denied> {
    // NOTE: RFC 6750 §2.1 fixes the `b64token` syntax, and §3.1 answers a
    // token that is "malformed" with `invalid_token`.
    if !is_b64token(token) {
        return Err(invalid_token(Reason::NotB64Token));
    }
    match verifier.verify(token).await {
        // NOTE: RFC 9068 §2.2 requires `sub`, held here over every verifier.
        Ok(caller) if caller.subject().trim().is_empty() => {
            Err(invalid_token(Reason::BlankSubject))
        }
        Ok(caller) => Ok(caller),
        Err(rejection) => {
            match &rejection {
                Rejection::Invalid { reason } => {
                    tracing::debug!(reason = %reason, "an access token was refused");
                }
                Rejection::Unavailable { source } => {
                    tracing::error!(
                        error = %source,
                        "the authorization server's key set could not be read"
                    );
                }
                Rejection::Missing => {}
            }
            Err(Denied::from(&rejection))
        }
    }
}

/// Returns the caller the Basic credential `value` authenticates in
/// `store`, the key derivation on a blocking thread.
async fn basic(store: Arc<PasswordStore>, value: HeaderValue) -> Result<Caller, Denied> {
    let checked = tokio::task::spawn_blocking(move || store.check(&value))
        .await
        .map_err(|_cancelled| {
            Denied::new(
                Refusal::InvalidBasic,
                Some(Reason::Other("the verification did not complete")),
            )
        })?;
    match checked {
        Ok(verified) => Ok(Caller::basic(verified.username, &verified.scope)),
        Err(reason) => {
            tracing::debug!(reason = %reason, "a Basic credential was refused");
            Err(Denied::new(Refusal::InvalidBasic, Some(reason)))
        }
    }
}

/// Returns the denial of a bearer token that does not hold for `reason`.
fn invalid_token(reason: Reason) -> Denied {
    tracing::debug!(reason = %reason, "an access token was refused");
    Denied::new(Refusal::InvalidToken, Some(reason))
}

/// Returns whether `token` is a `b64token` (RFC 6750 §2.1):
/// `1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`.
fn is_b64token(token: &str) -> bool {
    let body = token.trim_end_matches('=');
    !body.is_empty()
        && body.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use super::is_b64token;

    #[test]
    fn a_b64token_is_the_rfc_6750_alphabet_with_trailing_padding() {
        for token in [
            "abc",
            "a.b.c",
            "A-Z_0~9+/",
            "abc==",
            "eyJhbGciOiJFUzI1NiJ9.e30.c2ln",
        ] {
            assert!(is_b64token(token), "{token}");
        }
        for token in ["", "==", "a b", "a=b", "a,b", "a\"b", "ä", "a;b", "=abc"] {
            assert!(!is_b64token(token), "{token}");
        }
    }
}
