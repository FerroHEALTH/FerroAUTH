// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The segments of a JWS in compact serialization (RFC 7515 §7.1), read
//! without checking its signature: by a caller that selects a key by the
//! payload's `iss` (RFC 7519 §7.2), reads a value an upstream verified, or
//! verifies the signature itself afterwards.

use base64::Engine as _;
use serde_json::Map;
use serde_json::Value;

/// Returns the JSON object one `segment` of a compact JWS encodes, its
/// header or its payload, each base64url without padding (RFC 7515 §2,
/// §7.1); `None` for a segment that is not base64url or not an object.
pub(crate) fn object(segment: &str) -> Option<Map<String, Value>> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::object;

    #[test]
    fn a_segment_reads_as_the_object_it_encodes() {
        // `{"iss":"https://as.example.org"}`, base64url without padding.
        let read = object("eyJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUub3JnIn0").expect("an object");
        assert_eq!(
            Some("https://as.example.org"),
            read.get("iss").and_then(serde_json::Value::as_str)
        );
    }

    #[test]
    fn a_segment_that_is_no_base64url_object_reads_as_none() {
        // `[1]` is JSON and no object; `e30=` is `{}` with the padding RFC 7515 §2 omits.
        for segment in ["WzFd", "e30=", "not base64", ""] {
            assert_eq!(None, object(segment), "{segment:?}");
        }
    }
}
