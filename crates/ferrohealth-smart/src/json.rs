// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The refusal of a JSON document the crate reads from a file, the operator
//! or the network.
//!
//! A `serde_json::Error` renders the value it choked on (`invalid type:
//! string "…"`), and the document may be a key set, a token response or
//! another body that holds a secret. [`JsonError`] keeps what the reader
//! reported about the shape and the position and renders nothing of the
//! input, and it hands no source on, so no rendering of the chain can quote
//! the document. RFC 7517 §9.1 and §9.3 have private and symmetric key
//! material protected from disclosure; how a refusal renders is our own
//! design.

use std::fmt;

use serde_json::error::Category;

/// A JSON document that did not read: what was wrong with it and where,
/// never any part of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonError {
    category: Category,
    line: usize,
    column: usize,
}

impl JsonError {
    /// What was wrong: a syntax error, data of another shape, a document
    /// that ends early, or a failed read.
    #[must_use]
    pub const fn category(&self) -> Category {
        self.category
    }

    /// The line the reader stopped at, counted from 1, or 0 when it reported
    /// none.
    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }

    /// The column the reader stopped at, counted from 1, or 0 when it
    /// reported none.
    #[must_use]
    pub const fn column(&self) -> usize {
        self.column
    }
}

impl From<serde_json::Error> for JsonError {
    fn from(error: serde_json::Error) -> Self {
        Self {
            category: error.classify(),
            line: error.line(),
            column: error.column(),
        }
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.category {
            Category::Io => "the document could not be read",
            Category::Syntax => "the document is not JSON",
            Category::Data => "the document is JSON of another shape",
            Category::Eof => "the document ends before its JSON does",
        };
        write!(f, "{what} (line {}, column {})", self.line, self.column)
    }
}

impl std::error::Error for JsonError {}

/// The helpers every module's tests prove a refusal hides its input with.
#[cfg(test)]
pub(crate) mod leak {
    use std::error::Error;

    use super::JsonError;

    /// A value shaped like key material, which no refusal may render.
    pub(crate) const SECRET: &str = "c2VjcmV0LWtleS1tYXRlcmlhbA";

    /// The refusal of a key set whose `keys` member holds [`SECRET`].
    pub(crate) fn refused() -> JsonError {
        JsonError::from(quoting())
    }

    /// The reader's own error over a key set whose `keys` member holds
    /// [`SECRET`], which quotes it.
    pub(crate) fn quoting() -> serde_json::Error {
        /// A JWK Set, by its one required member (RFC 7517 §5).
        #[derive(serde::Deserialize)]
        struct Set {
            /// The keys.
            #[expect(dead_code, reason = "read only to be refused")]
            keys: Vec<serde_json::Value>,
        }
        serde_json::from_str::<Set>(&format!(r#"{{"keys":"{SECRET}"}}"#))
            .map(|_set| ())
            .expect_err("a string is no array")
    }

    /// Asserts that no `Display` or `Debug` of `error` or of any source in
    /// its chain renders [`SECRET`], and returns the rendered chain.
    pub(crate) fn hidden(error: &(dyn Error + 'static)) -> String {
        let mut shown = String::new();
        let mut link = Some(error);
        while let Some(current) = link {
            let display = current.to_string();
            let debug = format!("{current:?}");
            assert!(!display.contains(SECRET), "{display}");
            assert!(!debug.contains(SECRET), "{debug}");
            shown.push_str(&display);
            shown.push('\n');
            link = current.source();
        }
        shown
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::leak::{SECRET, hidden, quoting, refused};

    /// The reader's own error quotes the value, which is why it never enters
    /// a chain.
    #[test]
    fn the_reader_s_own_error_quotes_the_value() {
        let raw = quoting();
        assert!(raw.to_string().contains(SECRET), "{raw}");
    }

    /// A refusal keeps the shape and the position and renders no part of the
    /// document, and it hands no source on.
    #[test]
    fn a_refusal_renders_no_part_of_the_document() {
        let error = refused();
        hidden(&error);
        assert!(error.source().is_none());
        assert_eq!(error.category(), serde_json::error::Category::Data);
        assert_eq!(error.line(), 1);
        assert!(error.column() > 0);
    }

    #[test]
    fn a_metadata_refusal_hides_the_document() {
        let url: url::Url = "https://as.example.org/.well-known/oauth-authorization-server"
            .parse()
            .expect("a URL");
        let error = crate::metadata::parse_metadata(&url, &format!(r#"{{"issuer":["{SECRET}"]}}"#))
            .expect_err("an issuer is a string");
        assert!(
            matches!(error, crate::metadata::DiscoveryError::Metadata { .. }),
            "{error}"
        );
        hidden(&error);
        hidden(&crate::metadata::DiscoveryError::RepeatedName {
            url,
            source: refused(),
        });
    }

    #[test]
    fn an_introspection_refusal_hides_the_response() {
        hidden(
            &crate::resource::introspection::IntrospectionError::RepeatedName { source: refused() },
        );
        hidden(
            &crate::resource::introspection::IntrospectionError::Malformed {
                source: Some(refused()),
            },
        );
    }

    #[test]
    fn a_token_response_refusal_hides_the_token() {
        hidden(&crate::client::TokenError::Malformed { source: refused() });
    }

    #[test]
    fn an_authorization_details_refusal_hides_the_text() {
        let error = crate::client::authorization_details::AuthorizationDetails::parse(&format!(
            r#"[{{"type":"a","locations":"{SECRET}"}}]"#
        ))
        .expect_err("locations is an array");
        hidden(&error);
        hidden(
            &crate::client::authorization_details::AuthorizationDetailsError::Json {
                source: refused(),
            },
        );
        hidden(
            &crate::client::authorization_details::AuthorizationDetailsError::Shape {
                source: refused(),
            },
        );
    }

    #[cfg(feature = "oidc")]
    #[test]
    fn an_oidc_refusal_hides_the_body() {
        hidden(&crate::oidc::OidcError::Malformed { source: refused() });
        hidden(&crate::oidc::OidcError::KeySetBody { source: refused() });
    }
}
