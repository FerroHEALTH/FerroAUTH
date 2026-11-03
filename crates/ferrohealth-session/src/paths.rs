// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The four routes every console serves for its sign-in, the same on every
//! console so one provider registration reads alike across the family.

/// `GET`: begins a sign-in, with the page to come back to in [`RETURN`].
pub const LOGIN: &str = "/login";

/// `GET`: the redirection endpoint the provider sends the operator back to
/// (RFC 6749 §3.1.2); the console's `redirect_uri` ends in it.
pub const CALLBACK: &str = "/auth/callback";

/// `POST`: ends the session and signs the operator out at the provider.
pub const LOGOUT: &str = "/logout";

/// `GET` and `POST`: the session watch FerroUI's `session` script asks.
pub const SESSION: &str = "/session";

/// The query parameter of [`LOGIN`] that names the page to return to.
pub const RETURN: &str = "return";

/// Whether `path` is one of the four routes.
#[must_use]
pub fn is_own(path: &str) -> bool {
    let path = path.trim_end_matches('/');
    [LOGIN, CALLBACK, LOGOUT, SESSION].contains(&path)
}
