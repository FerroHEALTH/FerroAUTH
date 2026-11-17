// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The RFC 9068 access token and the OpenID Connect ID Token, signed,
//! recorded and answered.

use serde::Serialize;
use serde_json::{Map, Value};

use crate::clients::Client;
use crate::server::AppState;

use super::{Issued, Refusal, TokenResponse, server_error};

/// The claims of an RFC 9068 access token.
#[derive(Debug, Serialize)]
struct AccessClaims<'a> {
    /// The issuer.
    iss: &'a str,
    /// The subject.
    sub: &'a str,
    /// The resource server.
    aud: &'a str,
    /// The expiry.
    exp: i64,
    /// The issue time.
    iat: i64,
    /// The token's id.
    jti: &'a str,
    /// The client (RFC 8693 §4.3).
    client_id: &'a str,
    /// The scope granted.
    scope: &'a str,
    /// The person as a FHIR resource, when the grant names one.
    #[serde(rename = "fhirUser", skip_serializing_if = "Option::is_none")]
    fhir_user: Option<&'a str>,
    /// The patient of an EHR launch's context (13.6 item 2).
    #[serde(skip_serializing_if = "Option::is_none")]
    patient: Option<&'a str>,
    /// The encounter of an EHR launch's context.
    #[serde(skip_serializing_if = "Option::is_none")]
    encounter: Option<&'a str>,
    /// The openEHR EHR of an EHR launch's context.
    #[serde(rename = "ehrId", skip_serializing_if = "Option::is_none")]
    ehr_id: Option<&'a str>,
}

/// What an access token grants, and what else the token response carries.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Grant<'a> {
    /// The token's `sub`.
    pub(crate) subject: &'a str,
    /// The resource server.
    pub(crate) audience: &'a str,
    /// The scope granted.
    pub(crate) scope: &'a str,
    /// The person's `fhirUser`, written into the token and the ID Token.
    pub(crate) fhir_user: Option<&'a str>,
    /// The SHA-256 of the authorization code the token answers.
    pub(crate) code_hash: Option<&'a str>,
    /// The `token_type` the grant's profile fixes.
    pub(crate) token_type: &'static str,
    /// The longest lifetime the grant's profile allows, below
    /// `access_token_lifetime`; none when the setting alone decides.
    pub(crate) longest: Option<std::time::Duration>,
    /// The ID Token's `nonce` and `auth_time`, when `openid` is granted.
    pub(crate) identity: Option<(Option<&'a str>, i64)>,
    /// The grant the token is issued under, when a person gave one.
    pub(crate) under: Option<&'a str>,
    /// The launch context parameters the response carries.
    pub(crate) context: &'a Map<String, Value>,
}

/// Signs, records and answers an access token for `client` under `grant`.
///
/// The client credentials grant's `sub` is the client id: "the value of
/// 'sub' SHOULD correspond to an identifier the authorization server uses
/// to indicate the client application" (RFC 9068 §2.2). The registry fixes
/// every `client_id` by configuration, so a client cannot choose a person's
/// `sub` (RFC 9068 §5); a person's `sub` is pairwise per upstream issuer
/// (13.6 item 9). The person's `fhirUser` rides in the access token beside
/// the RFC 9068 set (13.6 item 2).
pub(crate) fn mint(state: &AppState, client: &Client, grant: Grant<'_>) -> Result<Issued, Refusal> {
    let settings = state.settings();
    let lifetime = grant
        .longest
        .map_or(settings.access_token_lifetime, |longest| {
            longest.min(settings.access_token_lifetime)
        })
        .as_secs();
    let issued_at = jiff::Timestamp::now().as_second();
    let expires_at = issued_at.saturating_add_unsigned(lifetime);
    let jti = random_id().map_err(|error| server_error("no token id could be drawn", &error))?;
    let claims = AccessClaims {
        iss: &settings.issuer,
        sub: grant.subject,
        aud: grant.audience,
        exp: expires_at,
        iat: issued_at,
        jti: &jti,
        client_id: &client.client_id,
        scope: grant.scope,
        fhir_user: grant.fhir_user,
        patient: grant.context.get("patient").and_then(Value::as_str),
        encounter: grant.context.get("encounter").and_then(Value::as_str),
        ehr_id: grant.context.get("ehrId").and_then(Value::as_str),
    };
    // NOTE: RFC 9068 §2.1, typ at+jwt.
    let access_token = settings
        .keys
        .current()
        .sign("at+jwt", &claims)
        .map_err(|error| server_error("the access token could not be signed", &error))?;
    let id_token = match grant.identity {
        Some((nonce, auth_time)) => {
            let claims = IdClaims {
                iss: &settings.issuer,
                sub: grant.subject,
                aud: &client.client_id,
                exp: expires_at,
                iat: issued_at,
                auth_time,
                nonce,
                fhir_user: grant.fhir_user,
            };
            // NOTE: SMART App Launch 2.2.0, Scopes for requesting identity data, "The
            // EHR SHALL support Signing ID Tokens with RSA SHA-256"; typ JWT.
            Some(
                settings
                    .keys
                    .current()
                    .sign("JWT", &claims)
                    .map_err(|error| server_error("the ID token could not be signed", &error))?,
            )
        }
        None => None,
    };
    Ok(Issued {
        response: TokenResponse {
            access_token,
            token_type: grant.token_type,
            expires_in: lifetime,
            scope: grant.scope.to_owned(),
            id_token,
            refresh_token: None,
            context: grant.context.clone(),
        },
        client_id: client.client_id.clone(),
        jti,
        audience: grant.audience.to_owned(),
        person: grant.under.map(|_| grant.subject.to_owned()),
        subject: grant.subject.to_owned(),
        iat: issued_at,
        exp: expires_at,
        code_hash: grant.code_hash.map(str::to_owned),
        grant_id: grant.under.map(str::to_owned),
    })
}

/// The claims of an ID Token (OpenID Connect Core 1.0 §2).
#[derive(Debug, Serialize)]
struct IdClaims<'a> {
    /// The issuer.
    iss: &'a str,
    /// The person.
    sub: &'a str,
    /// The client.
    aud: &'a str,
    /// The expiry.
    exp: i64,
    /// The issue time.
    iat: i64,
    /// When the person logged in.
    auth_time: i64,
    /// The client's `nonce`, when it sent one.
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    /// The person as a FHIR resource (SMART App Launch 2.2.0, Scopes for
    /// requesting identity data).
    #[serde(rename = "fhirUser", skip_serializing_if = "Option::is_none")]
    fhir_user: Option<&'a str>,
}

/// Returns 128 random bits, base64url without padding.
fn random_id() -> Result<String, aws_lc_rs::error::Unspecified> {
    use base64::Engine as _;
    let mut bytes = [0_u8; 16];
    aws_lc_rs::rand::fill(&mut bytes)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}
