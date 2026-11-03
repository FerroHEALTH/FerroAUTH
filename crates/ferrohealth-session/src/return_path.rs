// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The console page an operator comes back to once a sign-in completes.

use std::fmt;

/// The longest return path kept, in bytes.
const LIMIT: usize = 2048;

/// A path and query on the console's own origin, checked before a sign-in
/// keeps it, so the redirect after the callback never leaves the console.
#[derive(Clone, PartialEq, Eq)]
pub struct ReturnPath(String);

impl ReturnPath {
    /// Takes `text` as a return path when it names a page of this console:
    /// one leading `/` and no `//`, no `\`, printable ASCII only, at most 2048
    /// bytes, and neither one of the sign-in routes nor the console's own
    /// sign-in page `sign_in_page`.
    #[must_use]
    pub fn parse(text: &str, sign_in_page: &str) -> Option<Self> {
        let route = text.split(['?', '#']).next().unwrap_or_default();
        // NOTE: RFC 3986 §4.2: a reference that starts with `//` names another authority, and
        // the WHATWG URL Standard reads `\` as `/`, so only one leading slash stays on this origin.
        let own = text.starts_with('/')
            && !text.starts_with("//")
            && !text.contains('\\')
            && text.len() <= LIMIT
            && text.bytes().all(|byte| byte.is_ascii_graphic())
            && !crate::paths::is_own(route)
            && route.trim_end_matches('/') != sign_in_page.trim_end_matches('/');
        own.then(|| Self(text.to_owned()))
    }

    /// A return path this crate checked and sealed itself, read back from
    /// its authenticated cookie.
    pub(crate) const fn sealed(checked: String) -> Self {
        Self(checked)
    }

    /// The path and query.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ReturnPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ReturnPath").field(&self.0).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::ReturnPath;

    const SIGN_IN: &str = "/sign-in";

    #[test]
    fn a_page_of_the_console_is_kept_with_its_query() {
        let kept = ReturnPath::parse("/sources?page=2", SIGN_IN).expect("own page");
        assert_eq!("/sources?page=2", kept.as_str(), "the query stays");
    }

    #[test]
    fn a_path_that_leaves_the_origin_or_loops_is_refused() {
        for refused in [
            "https://elsewhere.example/",
            "//elsewhere.example/",
            "/\\elsewhere.example",
            "sources",
            "/a b",
            "/login",
            "/login/?return=/x",
            "/auth/callback",
            "/logout",
            "/session",
            "/sign-in",
            "/sign-in?x=1",
        ] {
            assert!(ReturnPath::parse(refused, SIGN_IN).is_none(), "{refused}");
        }
        let long = format!("/{}", "a".repeat(2048));
        assert!(ReturnPath::parse(&long, SIGN_IN).is_none(), "too long");
    }
}
