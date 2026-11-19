// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! URI syntax-based normalization (RFC 3986 §6.2.2), which the `htu` check
//! of a `DPoP` proof and FerroSMART's comparison of a registered launch URI
//! both apply before they compare two URIs.

use url::Url;

/// Returns `uri` normalized, without its query and fragment, or `None`
/// when it is no absolute `http` or `https` URI or carries user
/// information.
///
/// The URL parser lowercases the scheme and host, drops the default port,
/// resolves dot segments and gives an empty path `/`; the path's
/// percent-encodings are then normalized: an unreserved character decoded
/// and every other octet in upper-case hexadecimal (RFC 3986 §6.2.2,
/// §6.2.3, which RFC 9449 §4.3 has a server apply).
#[must_use]
pub fn normalized(uri: &str) -> Option<String> {
    let url = Url::parse(uri).ok()?;
    if !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let host = url.host_str()?;
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    Some(format!(
        "{}://{host}{port}{}",
        url.scheme(),
        normalize_percent(url.path())
    ))
}

/// Returns `path` with each percent-encoded unreserved character decoded
/// and every other percent-encoding in upper case (RFC 3986 §2.3, §6.2.2.1,
/// §6.2.2.2).
#[must_use]
pub fn normalize_percent(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut chars = path.chars();
    while let Some(character) = chars.next() {
        if character != '%' {
            out.push(character);
            continue;
        }
        let mut lookahead = chars.clone();
        let decoded = match (lookahead.next(), lookahead.next()) {
            (Some(high), Some(low)) => {
                high.to_digit(16)
                    .zip(low.to_digit(16))
                    .and_then(|(high, low)| {
                        u8::try_from(high.saturating_mul(16).saturating_add(low)).ok()
                    })
            }
            _ => None,
        };
        match decoded {
            Some(byte)
                if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') =>
            {
                out.push(char::from(byte));
                chars = lookahead;
            }
            Some(byte) => {
                out.push('%');
                out.push_str(&hex(byte));
                chars = lookahead;
            }
            None => out.push('%'),
        }
    }
    out
}

/// Returns `byte` as two upper-case hexadecimal digits.
fn hex(byte: u8) -> String {
    format!("{byte:02X}")
}

#[cfg(test)]
mod tests {
    use super::{normalize_percent, normalized};

    #[test]
    fn a_percent_encoding_keeps_a_reserved_octet_in_upper_case() {
        assert_eq!("/a%2Fb", normalize_percent("/a%2fb"));
        assert_eq!("/~x", normalize_percent("/%7Ex"));
        assert_eq!("/%", normalize_percent("/%"));
        assert_eq!("/%zz", normalize_percent("/%zz"));
    }

    #[test]
    fn the_htu_comparison_normalizes_syntax_and_scheme() {
        // NOTE: RFC 3986 §6.2.2 and §6.2.3, the normalizations RFC 9449 §4.3
        // has a server apply before it compares `htu`.
        let expected = normalized("https://resource.example.org/protectedresource");
        for same in [
            "HTTPS://Resource.Example.ORG/protectedresource",
            "https://resource.example.org:443/protectedresource",
            "https://resource.example.org/a/../protectedresource",
            "https://resource.example.org/%70rotectedresource",
            "https://resource.example.org/protectedresource?query#fragment",
        ] {
            assert_eq!(expected, normalized(same), "{same}");
        }
        for other in [
            "http://resource.example.org/protectedresource",
            "https://resource.example.org:8443/protectedresource",
            "https://resource.example.org/protectedresource/",
            "https://user@resource.example.org/protectedresource",
        ] {
            assert_ne!(expected, normalized(other), "{other}");
        }
        assert_eq!(None, normalized("urn:example:resource"));
    }
}
