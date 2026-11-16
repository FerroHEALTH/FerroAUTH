// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The ZITADEL Actions v2 target of FerroSMART's ZITADEL example (#523).
//!
//! ZITADEL writes no plain claim from a user's attributes: its user metadata
//! reaches a token only base64-encoded under `urn:zitadel:iam:user:metadata`
//! (ZITADEL's `claims.mdx`). An Actions v2 execution on the `preuserinfo`
//! function calls this target with the user and its metadata, and the
//! target answers `append_claims` with the `fhirUser` claim SMART App Launch
//! 2.2.0 names (Scopes and Launch Context, `fhirUser`), taken from the
//! metadata key `fhir_user` (ZITADEL's `actions/usage.mdx`, `PreUserinfo`). It
//! checks the `ZITADEL-Signature` header of every call with the target's
//! signing key (`actions/usage.mdx`, Content Signing). It is deployment
//! content of the example, never FerroSMART code; no specification governs
//! it beyond those.
//!
//! `ZITADEL_FHIR_USER_LISTEN` names the address (default `127.0.0.1:8290`)
//! and `ZITADEL_FHIR_USER_SIGNING_KEY_FILE` the file holding the signing key
//! ZITADEL returned when the target was created, read on every call so the
//! service may start before the target exists.
#![expect(
    clippy::print_stderr,
    reason = "a binary: the one start-up failure is written to stderr"
)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::hmac;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::Engine as _;
use serde_json::{Value, json};

/// The header ZITADEL signs each call in.
const SIGNATURE_HEADER: &str = "zitadel-signature";
/// How old a signature may be, in seconds: ZITADEL's own default tolerance.
const TOLERANCE_SECONDS: u64 = 300;
/// The metadata key that holds the user's `fhirUser`.
const METADATA_KEY: &str = "fhir_user";
/// The claim the target appends.
const CLAIM: &str = "fhirUser";

/// What every call reads.
#[derive(Debug)]
struct Target {
    /// The file holding the target's signing key.
    signing_key_file: PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let Some(signing_key_file) = std::env::var_os("ZITADEL_FHIR_USER_SIGNING_KEY_FILE") else {
        eprintln!("zitadel-fhir-user: ZITADEL_FHIR_USER_SIGNING_KEY_FILE names no file");
        return ExitCode::FAILURE;
    };
    let listen = std::env::var("ZITADEL_FHIR_USER_LISTEN")
        .unwrap_or_else(|_| String::from("127.0.0.1:8290"));
    let Ok(address) = listen.parse::<SocketAddr>() else {
        eprintln!("zitadel-fhir-user: {listen} is no socket address");
        return ExitCode::FAILURE;
    };
    let target = Arc::new(Target {
        signing_key_file: PathBuf::from(signing_key_file),
    });
    let app = Router::new().route("/", post(answer)).with_state(target);
    let listener = match tokio::net::TcpListener::bind(address).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("zitadel-fhir-user: cannot listen on {address}: {error}");
            return ExitCode::FAILURE;
        }
    };
    match axum::serve(listener, app).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("zitadel-fhir-user: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Answers one `preuserinfo` call.
async fn answer(State(target): State<Arc<Target>>, headers: HeaderMap, body: Bytes) -> Response {
    let Ok(key) = std::fs::read(&target.signing_key_file) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let signature = headers
        .get(SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    if !verified(key.trim_ascii(), signature, &body, now) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let claims: Vec<Value> = fhir_user(&payload)
        .map(|value| json!({ "key": CLAIM, "value": value }))
        .into_iter()
        .collect();
    axum::Json(json!({ "append_claims": claims })).into_response()
}

/// Returns whether `header` signs `payload` with `key` at most
/// [`TOLERANCE_SECONDS`] before `now`: `t=<unix seconds>` and one or more
/// `v1=<hex HMAC-SHA256 of "<t>.<payload>">` (ZITADEL's
/// `pkg/actions/signing.go`).
fn verified(key: &[u8], header: &str, payload: &[u8], now: u64) -> bool {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for pair in header.split(',') {
        match pair.split_once('=') {
            Some(("t", value)) => timestamp = value.parse::<u64>().ok(),
            Some(("v1", value)) => signatures.push(value),
            _ => {}
        }
    }
    let Some(timestamp) = timestamp else {
        return false;
    };
    if now.saturating_sub(timestamp) > TOLERANCE_SECONDS {
        return false;
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut signed = timestamp.to_string().into_bytes();
    signed.push(b'.');
    signed.extend_from_slice(payload);
    signatures.into_iter().any(|signature| {
        decode_hex(signature).is_some_and(|tag| hmac::verify(&key, &signed, &tag).is_ok())
    })
}

/// Returns the bytes a lower- or upper-case hex string spells.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = char::from(*pair.first()?).to_digit(16)?;
            let low = char::from(*pair.get(1)?).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

/// Returns the user's `fhirUser`: the value of the metadata key
/// [`METADATA_KEY`], which the payload carries base64-encoded, as text.
fn fhir_user(payload: &Value) -> Option<String> {
    let encoded = payload
        .get("user_metadata")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("key").and_then(Value::as_str) == Some(METADATA_KEY))?
        .get("value")?
        .as_str()?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    String::from_utf8(bytes)
        .ok()
        .filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(key: &[u8], timestamp: u64, payload: &[u8]) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let mut signed = timestamp.to_string().into_bytes();
        signed.push(b'.');
        signed.extend_from_slice(payload);
        let tag = hmac::sign(&key, &signed);
        let hex = tag.as_ref().iter().fold(String::new(), |mut hex, byte| {
            use std::fmt::Write as _;
            write!(hex, "{byte:02x}").expect("a String takes a write");
            hex
        });
        format!("t={timestamp},v1={hex}")
    }

    #[test]
    fn a_signed_call_within_the_tolerance_is_verified() {
        let header = sign(b"key", 1_000, b"{}");
        assert!(verified(b"key", &header, b"{}", 1_000));
        assert!(verified(b"key", &header, b"{}", 1_300));
    }

    #[test]
    fn a_call_signed_otherwise_or_too_long_ago_is_refused() {
        let header = sign(b"key", 1_000, b"{}");
        assert!(!verified(b"other", &header, b"{}", 1_000), "another key");
        assert!(!verified(b"key", &header, b"{ }", 1_000), "another body");
        assert!(!verified(b"key", &header, b"{}", 1_301), "too old");
        assert!(!verified(b"key", "", b"{}", 1_000), "no header");
        assert!(!verified(b"key", "t=1000", b"{}", 1_000), "no signature");
        assert!(!verified(b"key", "t=1000,v1=zz", b"{}", 1_000), "no hex");
    }

    #[test]
    fn the_fhir_user_metadata_becomes_the_claim() {
        let payload = json!({
            "user_metadata": [
                { "key": "department", "value": "Y2FyZGlvbG9neQ==" },
                { "key": "fhir_user", "value": "aHR0cHM6Ly9laHIuZXhhbXBsZS5vcmcvZmhpci9QcmFjdGl0aW9uZXIvMQ==" }
            ]
        });
        assert_eq!(
            Some(String::from("https://ehr.example.org/fhir/Practitioner/1")),
            fhir_user(&payload)
        );
        assert_eq!(None, fhir_user(&json!({ "user_metadata": [] })));
        assert_eq!(None, fhir_user(&json!({})));
        assert_eq!(
            None,
            fhir_user(&json!({ "user_metadata": [{ "key": "fhir_user", "value": "%%" }] })),
            "a value that is no base64"
        );
    }
}
