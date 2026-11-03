// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The cookies a console sets, and the read of one from a request.
//!
//! Every cookie is `HttpOnly`, `Path=/` and `SameSite=Lax`, so a cross-site
//! subrequest does not carry it while the provider's top-level redirect back
//! does (RFC 6265bis §5.4.7), and `Secure` with the `__Host-` prefix unless
//! the configuration turns `secure_cookie` off, so no sibling host can set
//! or shadow it (RFC 6265bis §4.1.3.2).

use cookie::{Cookie, SameSite};
use http::{HeaderMap, HeaderValue};

/// The cookie name prefix that binds a cookie to the host that set it.
pub const HOST_PREFIX: &str = "__Host-";

/// The base names of a console's cookies, before the `__Host-` prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieNames {
    base: String,
}

impl CookieNames {
    /// The names of the console `base`, such as `ferrobridge_console`: its
    /// session cookie is `<base>_session`, its pending sign-in cookie
    /// `<base>_sign_in`, and a preference cookie `<base>_<name>`.
    #[must_use]
    pub fn for_console(base: impl Into<String>) -> Self {
        Self { base: base.into() }
    }

    /// The base name of the session cookie.
    #[must_use]
    pub fn session(&self) -> String {
        format!("{}_session", self.base)
    }

    /// The base name of the pending sign-in cookie.
    #[must_use]
    pub fn sign_in(&self) -> String {
        format!("{}_sign_in", self.base)
    }

    /// The base name of the preference cookie `name`.
    #[must_use]
    pub fn preference(&self, name: &str) -> String {
        format!("{}_{name}", self.base)
    }
}

/// The cookie jar of one console: its names and whether its cookies are
/// `Secure`.
#[derive(Debug, Clone)]
pub(crate) struct Jar {
    pub(crate) names: CookieNames,
    pub(crate) secure: bool,
}

impl Jar {
    /// The name `base` takes on this console.
    pub(crate) fn name(&self, base: &str) -> String {
        if self.secure {
            format!("{HOST_PREFIX}{base}")
        } else {
            base.to_owned()
        }
    }

    /// The value the request's `Cookie` header carries under `base`.
    pub(crate) fn read(&self, headers: &HeaderMap, base: &str) -> Option<String> {
        let name = self.name(base);
        // NOTE: RFC 6265 §5.4: a header or pair that does not read as a cookie is not the
        // cookie asked for, so it is skipped and never an error.
        headers
            .get_all(http::header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(Cookie::split_parse)
            .filter_map(Result::ok)
            .find(|cookie| cookie.name() == name)
            .map(|cookie| cookie.value().to_owned())
    }

    /// The cookie `base` set to `value`, for `max_age` seconds when given.
    pub(crate) fn cookie(
        &self,
        base: &str,
        value: String,
        max_age: Option<i64>,
    ) -> Cookie<'static> {
        let mut builder = Cookie::build((self.name(base), value))
            .path("/")
            .http_only(true)
            .secure(self.secure)
            .same_site(SameSite::Lax);
        if let Some(seconds) = max_age {
            builder = builder.max_age(cookie::time::Duration::seconds(seconds.max(0)));
        }
        builder.build()
    }

    /// The cookie that removes `base`.
    pub(crate) fn removal(&self, base: &str) -> Cookie<'static> {
        self.cookie(base, String::new(), Some(0))
    }
}

/// `cookie` as a `Set-Cookie` value.
pub(crate) fn header(cookie: &Cookie<'_>) -> Result<HeaderValue, crate::sessions::SessionError> {
    HeaderValue::from_str(&cookie.to_string())
        .map_err(|_invalid| crate::sessions::SessionError::Header)
}

#[cfg(test)]
mod tests {
    use http::HeaderMap;
    use http::header::COOKIE;

    use super::{CookieNames, Jar};

    fn jar(secure: bool) -> Jar {
        Jar {
            names: CookieNames::for_console("ferrobridge_console"),
            secure,
        }
    }

    #[test]
    fn a_secure_cookie_is_host_bound_http_only_and_lax() {
        let jar = jar(true);
        assert_eq!(
            "__Host-ferrobridge_console_session=abc; HttpOnly; SameSite=Lax; Secure; Path=/",
            jar.cookie(&jar.names.session(), String::from("abc"), None)
                .to_string(),
            "RFC 6265bis §4.1.3.2 and §5.4.7"
        );
        assert_eq!(
            "__Host-ferrobridge_console_sign_in=; HttpOnly; SameSite=Lax; Secure; Path=/; Max-Age=0",
            jar.removal(&jar.names.sign_in()).to_string(),
            "a removal expires at once"
        );
    }

    #[test]
    fn a_cookie_that_is_not_secure_carries_no_host_prefix() {
        let jar = jar(false);
        assert_eq!(
            "ferrobridge_console_theme=dark; HttpOnly; SameSite=Lax; Path=/; Max-Age=60",
            jar.cookie(
                &jar.names.preference("theme"),
                String::from("dark"),
                Some(60)
            )
            .to_string(),
            "a browser refuses __Host- without Secure"
        );
    }

    #[test]
    fn the_read_finds_its_own_cookie_among_others_and_skips_garbage() {
        let jar = jar(true);
        let mut headers = HeaderMap::new();
        headers.append(COOKIE, "junk; other=1".parse().expect("a header"));
        headers.append(
            COOKIE,
            "ferrobridge_console_session=plain; __Host-ferrobridge_console_session=bound"
                .parse()
                .expect("a header"),
        );
        assert_eq!(
            Some(String::from("bound")),
            jar.read(&headers, &jar.names.session()),
            "host-bound only"
        );
        assert_eq!(None, jar.read(&headers, &jar.names.sign_in()), "absent");
    }
}
