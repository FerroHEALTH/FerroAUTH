// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The profile keys of the onward grants: how an issuer issues a token for
//! another service on a caller's behalf (`client::onward`).
//!
//! RFC 8693 §2.1 defines token exchange and RFC 7523 §2.1 the JWT bearer
//! grant; what differs between authorization servers (the grant they
//! implement, whether they read `resource` or `audience`, the extra
//! parameters they need, what they label preview) is data, read by one
//! implementation. No specification governs the keys: our own design over
//! those sources.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;

use crate::profile::ProfileError;

/// The `requested_token_type` of a refresh token (RFC 8693 §3), which a
/// profile never asks for.
pub const REFRESH_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:refresh_token";

/// The parameters the client writes itself, which `onward_parameters` may
/// not name.
///
/// They are the grants' own (RFC 8693 §2.1, RFC 7523 §2.1), the target
/// and scope (RFC 8707 §2, RFC 6749 §3.3), and the client authentication
/// (RFC 6749 §2.3.1, RFC 7523 §2.2).
pub const RESERVED_PARAMETERS: [&str; 15] = [
    "grant_type",
    "subject_token",
    "subject_token_type",
    "actor_token",
    "actor_token_type",
    "assertion",
    "scope",
    "resource",
    "audience",
    "client_id",
    "client_secret",
    "client_assertion",
    "client_assertion_type",
    "refresh_token",
    "code",
];

/// The grant an issuer issues onward tokens under.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OnwardGrant {
    /// OAuth 2.0 Token Exchange (RFC 8693 §2.1), the subject token as
    /// `subject_token`.
    #[default]
    TokenExchange,
    /// The JWT bearer grant (RFC 7523 §2.1), the subject token as
    /// `assertion`.
    JwtBearer,
}

impl OnwardGrant {
    /// Returns the `grant_type` value of the grant.
    #[must_use]
    pub const fn grant_type(self) -> &'static str {
        match self {
            Self::TokenExchange => "urn:ietf:params:oauth:grant-type:token-exchange",
            Self::JwtBearer => "urn:ietf:params:oauth:grant-type:jwt-bearer",
        }
    }

    /// Returns the configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TokenExchange => "token_exchange",
            Self::JwtBearer => "jwt_bearer",
        }
    }
}

/// The token-exchange parameter a target service is named in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OnwardIndicator {
    /// `resource`, an absolute URI (RFC 8693 §2.1, RFC 8707 §2).
    #[default]
    Resource,
    /// `audience`, a logical name both sides understand (RFC 8693 §2.1).
    Audience,
}

impl OnwardIndicator {
    /// Returns the request parameter.
    #[must_use]
    pub const fn parameter(self) -> &'static str {
        match self {
            Self::Resource => "resource",
            Self::Audience => "audience",
        }
    }
}

/// A grant variant an authorization server labels preview, which the
/// client refuses to use under that issuer's profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PreviewVariant {
    /// Delegation with an `actor_token` (RFC 8693 §2.1).
    ActorToken,
}

impl PreviewVariant {
    /// Returns the configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActorToken => "actor_token",
        }
    }
}

/// Checks the onward keys of a profile: no extra parameter the client
/// writes itself, no refresh token asked for, and a lifetime that is not 0.
pub(super) fn validate(
    parameters: &BTreeMap<String, String>,
    max_onward_lifetime: Option<u64>,
) -> Result<(), ProfileError> {
    if let Some(name) = parameters
        .keys()
        .find(|name| RESERVED_PARAMETERS.contains(&name.as_str()))
    {
        return Err(ProfileError::Reserved {
            parameter: name.clone(),
        });
    }
    // NOTE: RFC 8693 §2.2.1 lets a refresh token keep access past the subject
    // token's life, which the onward grants never ask for (our own design).
    if parameters
        .get("requested_token_type")
        .is_some_and(|value| value == REFRESH_TOKEN_TYPE)
    {
        return Err(ProfileError::RefreshToken);
    }
    if max_onward_lifetime == Some(0) {
        return Err(ProfileError::Empty {
            key: "max_onward_lifetime",
        });
    }
    Ok(())
}
