// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The token endpoint (RFC 6749 §3.2).
//!
//! Its one grant so far is SMART Backend Services' client credentials grant
//! with a `private_key_jwt` client assertion. The request is the form of RFC 6749 §4.4.2 with the assertion of RFC 7523
//! §2.2; the client is authenticated as SMART App Launch 2.2.0, Client
//! Authentication: Asymmetric, Signature Verification, has it, with the
//! audience `docs/architecture.md` §13.6 item 1 fixes; the answer is the JSON
//! of RFC 6749 §5.1, or the error of §5.2, never cached. The token is an RFC
//! 9068 JWT.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::Jwk};
use serde::Serialize;
use serde_json::{Value, json};

use crate::clients::{Client, ClientKeys, ClientKind, GrantType};
use crate::discovery::TOKEN_ROUTE;
use crate::server::AppState;
use crate::store::IssuedToken;

/// The `client_assertion_type` of a JWT client assertion (RFC 7523 §2.2).
pub const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The longest a client assertion may live: "This time SHALL be no more than
/// five minutes in the future" (SMART App Launch 2.2.0, Client
/// Authentication: Asymmetric, Request).
pub const MAX_ASSERTION_SECONDS: u64 = 300;

/// The clock skew admitted on `exp`. No specification governs the value:
/// our own design, the one `ferrohealth-smart` admits on a token.
pub const LEEWAY_SECONDS: u64 = 30;

/// The `typ` values a client assertion may carry: `JWT`, which SMART App
/// Launch 2.2.0 fixes, and `client-authentication+jwt` of RFC 10070 §4
/// (`docs/architecture.md` §13.6 item 1).
const ASSERTION_TYPES: [&str; 2] = ["JWT", "client-authentication+jwt"];

/// A refusal of the token endpoint: an RFC 6749 §5.2 error code with a
/// description that names no secret and quotes no input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The `error` code.
    pub error: &'static str,
    /// The `error_description`, which SMART Backend Services has the server
    /// include ("SHOULD include an `error_uri` or `error_description`").
    pub description: &'static str,
}

impl Refusal {
    /// The `invalid_request` refusal.
    const fn request(description: &'static str) -> Self {
        Self {
            error: "invalid_request",
            description,
        }
    }

    /// The `invalid_client` refusal every failure of client authentication
    /// answers ("the server SHALL respond with an `invalid_client` error",
    /// SMART App Launch 2.2.0, Client Authentication: Asymmetric, Response).
    const fn client(description: &'static str) -> Self {
        Self {
            error: "invalid_client",
            description,
        }
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        // NOTE: RFC 6749 §5.2, 400 unless otherwise specified; no Authorization
        // header carried the credential, so invalid_client is 400 too.
        let body = json!({ "error": self.error, "error_description": self.description });
        no_store((StatusCode::BAD_REQUEST, Json(body)).into_response())
    }
}

/// `POST {issuer}/token`.
pub async fn token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match issue(&state, &headers, &body).await {
        Ok(answer) => {
            tracing::info!(
                target: "ferrosmart::audit",
                event = "token.issued",
                client_id = %answer.client_id,
                jti = %answer.jti,
                aud = %answer.audience,
                scope = %answer.response.scope,
                "an access token was issued"
            );
            no_store(Json(answer.response).into_response())
        }
        Err(refusal) => {
            tracing::info!(
                target: "ferrosmart::audit",
                event = "token.refused",
                error = refusal.error,
                "a token request was refused"
            );
            refusal.into_response()
        }
    }
}

/// Returns `response` with the headers every token response carries: "The
/// authorization server's response SHALL include the HTTP 'Cache-Control'
/// response header field with a value of 'no-store'" and "'Pragma' ... with
/// a value of 'no-cache'" (SMART App Launch 2.2.0, Obtain access token,
/// Response; RFC 6749 §5.1).
fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// The RFC 6749 §5.1 token response.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,
    /// `bearer` (SMART App Launch 2.2.0, Backend Services: "Fixed value:
    /// bearer").
    pub token_type: &'static str,
    /// The lifetime in seconds.
    pub expires_in: u64,
    /// The scope granted.
    pub scope: String,
}

/// An issued token with what the audit record names.
#[derive(Debug)]
struct Issued {
    /// The response.
    response: TokenResponse,
    /// The client.
    client_id: String,
    /// The token's `jti`.
    jti: String,
    /// The token's `aud`.
    audience: String,
}

/// Answers the token request `body`.
async fn issue(state: &AppState, headers: &HeaderMap, body: &[u8]) -> Result<Issued, Refusal> {
    // NOTE: RFC 6749 §3.2, the request uses application/x-www-form-urlencoded.
    let form_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| {
            media
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    if !form_type {
        return Err(Refusal::request("the request is not form-encoded"));
    }
    let form = Form::parse(body)?;
    match form.get("grant_type") {
        Some("client_credentials") => client_credentials(state, &form).await,
        Some(_) => Err(Refusal {
            error: "unsupported_grant_type",
            description: "the grant type is not supported",
        }),
        None => Err(Refusal::request("the request names no grant_type")),
    }
}

/// The parameters of a form, each named once.
#[derive(Debug)]
struct Form(Vec<(String, String)>);

impl Form {
    /// Reads `body`, refusing a parameter named twice ("Request and response
    /// parameters MUST NOT be included more than once", RFC 6749 §3.1, §3.2).
    fn parse(body: &[u8]) -> Result<Self, Refusal> {
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body).into_owned().collect();
        let mut names = BTreeSet::new();
        if pairs.iter().any(|(name, _)| !names.insert(name.as_str())) {
            return Err(Refusal::request("a parameter is repeated"));
        }
        Ok(Self(pairs))
    }

    /// Returns the value of `name`, an empty value as absent (RFC 6749 §3.1).
    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, value)| key == name && !value.is_empty())
            .map(|(_, value)| value.as_str())
    }
}

/// The client credentials grant (RFC 6749 §4.4; SMART App Launch 2.2.0,
/// Backend Services).
async fn client_credentials(state: &AppState, form: &Form) -> Result<Issued, Refusal> {
    let client = authenticate(state, form).await?;
    if !client.grant_types.contains(&GrantType::ClientCredentials) {
        return Err(Refusal {
            error: "unauthorized_client",
            description: "the client may not use this grant",
        });
    }
    let scope = granted_scope(&client, form.get("scope"))?;
    let audience = audience(state, form.get("resource"))?;
    mint(state, &client, &client.client_id, &audience, &scope).await
}

/// Returns the scope the client is granted: each requested scope its
/// registered ceiling lists, in the order requested, "to assure that the
/// scope requested is within the scope pre-authorized to the client" (SMART
/// App Launch 2.2.0, Backend Services, Evaluate Requested Access). A
/// request with no scope, or none within the ceiling, is refused
/// (`invalid_scope`, RFC 6749 §3.3, §5.2). Matching a scope against the
/// ceiling as written is our own design.
fn granted_scope(client: &Client, requested: Option<&str>) -> Result<String, Refusal> {
    let invalid = |description| Refusal {
        error: "invalid_scope",
        description,
    };
    let requested = requested.ok_or(invalid("the request names no scope"))?;
    let mut granted: Vec<&str> = Vec::new();
    for scope in requested.split(' ').filter(|scope| !scope.is_empty()) {
        if client.scopes.iter().any(|allowed| allowed == scope) && !granted.contains(&scope) {
            granted.push(scope);
        }
    }
    if granted.is_empty() {
        return Err(invalid("no requested scope is granted to the client"));
    }
    Ok(granted.join(" "))
}

/// Returns the token's audience: the resource server the request names in
/// `resource` (RFC 8707 §2), or the one configured when the deployment
/// configures one alone (RFC 9068 §3, a default audience).
fn audience(state: &AppState, resource: Option<&str>) -> Result<String, Refusal> {
    let resources = &state.settings().resources;
    let target = |description| Refusal {
        error: "invalid_target",
        description,
    };
    match (resource, resources.as_slice()) {
        (Some(named), _) => resources
            .iter()
            .find(|base| base.as_str() == named)
            .cloned()
            .ok_or(target("the resource is not served by this issuer")),
        (None, [only]) => Ok(only.clone()),
        (None, _) => Err(target("the request names no resource")),
    }
}

/// Authenticates the client of `form` by its JWT assertion.
async fn authenticate(state: &AppState, form: &Form) -> Result<Client, Refusal> {
    if form.get("client_assertion_type") != Some(JWT_BEARER) {
        return Err(Refusal::client(
            "the client_assertion_type is not jwt-bearer",
        ));
    }
    let assertion = form
        .get("client_assertion")
        .ok_or(Refusal::client("the request carries no client_assertion"))?;
    let header = jsonwebtoken::decode_header(assertion)
        .map_err(|_unread| Refusal::client("the client_assertion is no JWT"))?;
    let algorithm = header.alg;
    // NOTE: SMART App Launch 2.2.0, Client Authentication: Asymmetric, the server
    // validates RS384 or ES384, the two the metadata advertises.
    if !matches!(algorithm, Algorithm::RS384 | Algorithm::ES384) {
        return Err(Refusal::client(
            "the client_assertion's algorithm is not admitted",
        ));
    }
    if !header
        .typ
        .as_deref()
        .is_some_and(|typ| ASSERTION_TYPES.contains(&typ))
    {
        return Err(Refusal::client(
            "the client_assertion's typ is not admitted",
        ));
    }
    let kid = header
        .kid
        .as_deref()
        .ok_or(Refusal::client("the client_assertion names no kid"))?;
    // NOTE: RFC 7523 §3 item 1, the issuer names the client; the claims are read
    // unverified only to find whose key verifies them.
    let unverified: Value = jsonwebtoken::dangerous::insecure_decode_claims(assertion)
        .map_err(|_unread| Refusal::client("the client_assertion's claims are no JSON"))?;
    let issuer = unverified
        .get("iss")
        .and_then(Value::as_str)
        .ok_or(Refusal::client("the client_assertion names no iss"))?;
    let client = state
        .store()
        .client(issuer)
        .await
        .map_err(|error| server_error("the client registry cannot be read", &error))?
        .ok_or(Refusal::client("the client is not registered"))?;
    if client.kind != ClientKind::ConfidentialAsymmetric {
        return Err(Refusal::client("the client authenticates with no key"));
    }
    if let Some(jku) = header.jku.as_deref() {
        let listed = matches!(&client.keys, Some(ClientKeys::Uri(url)) if url.as_str() == jku);
        if !listed {
            return Err(Refusal::client("the jku is not the registered JWK Set URL"));
        }
    }
    let key = key_of(state, &client, kid, algorithm).await?;
    let claims = verified(state, assertion, &key, algorithm)?;
    if claims.get("sub").and_then(Value::as_str) != Some(client.client_id.as_str()) {
        return Err(Refusal::client("the client_assertion's sub is not its iss"));
    }
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|jti| !jti.is_empty())
        .ok_or(Refusal::client("the client_assertion names no jti"))?;
    let expires = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(Refusal::client("the client_assertion names no exp"))?;
    let fresh = state
        .store()
        .first_use(&client.client_id, jti, expires)
        .await
        .map_err(|error| server_error("the assertion record cannot be written", &error))?;
    if !fresh {
        return Err(Refusal::client("the client_assertion was used before"));
    }
    Ok(client)
}

/// Returns the one key of `client`'s set whose `kid` is `kid` and whose
/// `kty` fits `algorithm` (SMART App Launch 2.2.0, Client Authentication:
/// Asymmetric, Signature Verification, step 3), reading the set again once
/// when the cached set holds none.
async fn key_of(
    state: &AppState,
    client: &Client,
    kid: &str,
    algorithm: Algorithm,
) -> Result<DecodingKey, Refusal> {
    let kty = if matches!(algorithm, Algorithm::RS384) {
        "RSA"
    } else {
        "EC"
    };
    for refresh in [false, true] {
        let set = state
            .client_keys()
            .get(client, refresh)
            .await
            .map_err(|_unread| Refusal::client("the client's JWK Set cannot be read"))?;
        let candidates: Vec<&Value> = set
            .get("keys")
            .and_then(Value::as_array)
            .map(|keys| {
                keys.iter()
                    .filter(|key| {
                        key.get("kid").and_then(Value::as_str) == Some(kid)
                            && key.get("kty").and_then(Value::as_str) == Some(kty)
                    })
                    .collect()
            })
            .unwrap_or_default();
        match candidates.as_slice() {
            [key] => {
                let jwk: Jwk = serde_json::from_value((*key).clone())
                    .map_err(|_unread| Refusal::client("the client's key is no JWK"))?;
                return DecodingKey::from_jwk(&jwk)
                    .map_err(|_unread| Refusal::client("the client's key cannot verify"));
            }
            [] => {}
            _ => return Err(Refusal::client("more than one key matches the kid")),
        }
    }
    Err(Refusal::client("no key of the client matches the kid"))
}

/// Returns the claims of `assertion` once its signature, `exp`, `iss` and
/// `aud` hold (RFC 7523 §3; `docs/architecture.md` §13.6 item 1).
fn verified(
    state: &AppState,
    assertion: &str,
    key: &DecodingKey,
    algorithm: Algorithm,
) -> Result<Value, Refusal> {
    let mut validation = Validation::new(algorithm);
    validation.leeway = LEEWAY_SECONDS;
    validation.validate_aud = false;
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud", "jti"]);
    let claims: Value = jsonwebtoken::decode(assertion, key, &validation)
        .map_err(|_refused| Refusal::client("the client_assertion does not verify"))?
        .claims;
    // NOTE: RFC 10070 §4, a sole audience value; SMART App Launch 2.2.0 names the
    // token URL, and the issuer identifier is admitted beside it (13.6 item 1).
    let settings = state.settings();
    let token_url = settings.endpoint(TOKEN_ROUTE);
    let admitted = claims
        .get("aud")
        .and_then(Value::as_str)
        .is_some_and(|aud| aud == token_url || aud == settings.issuer);
    if !admitted {
        return Err(Refusal::client(
            "the client_assertion's aud is not this server",
        ));
    }
    let now = jiff::Timestamp::now().as_second();
    let latest = now.saturating_add_unsigned(MAX_ASSERTION_SECONDS + LEEWAY_SECONDS);
    if claims
        .get("exp")
        .and_then(Value::as_i64)
        .is_none_or(|exp| exp > latest)
    {
        return Err(Refusal::client(
            "the client_assertion lives longer than five minutes",
        ));
    }
    Ok(claims)
}

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
}

/// Signs, records and answers an access token for `client` about `subject`.
///
/// Its `sub` for the client credentials grant is the client id: "the value
/// of 'sub' SHOULD correspond to an identifier the authorization server
/// uses to indicate the client application" (RFC 9068 §2.2). The registry
/// fixes every `client_id` by configuration, so a client cannot choose a
/// person's `sub` (RFC 9068 §5); a person's `sub` is pairwise per upstream
/// issuer (13.6 item 9).
async fn mint(
    state: &AppState,
    client: &Client,
    subject: &str,
    audience: &str,
    scope: &str,
) -> Result<Issued, Refusal> {
    let settings = state.settings();
    let lifetime = settings.access_token_lifetime.as_secs();
    let issued_at = jiff::Timestamp::now().as_second();
    let expires_at = issued_at.saturating_add_unsigned(lifetime);
    let jti = random_id().map_err(|error| server_error("no token id could be drawn", &error))?;
    let claims = AccessClaims {
        iss: &settings.issuer,
        sub: subject,
        aud: audience,
        exp: expires_at,
        iat: issued_at,
        jti: &jti,
        client_id: &client.client_id,
        scope,
    };
    // NOTE: RFC 9068 §2.1, typ at+jwt.
    let access_token = settings
        .keys
        .current()
        .sign("at+jwt", &claims)
        .map_err(|error| server_error("the access token could not be signed", &error))?;
    state
        .store()
        .record_token(&IssuedToken {
            jti: &jti,
            client_id: &client.client_id,
            subject,
            audience,
            scope,
            issued_at,
            expires_at,
        })
        .await
        .map_err(|error| server_error("the access token could not be recorded", &error))?;
    Ok(Issued {
        response: TokenResponse {
            access_token,
            token_type: "bearer",
            expires_in: lifetime,
            scope: scope.to_owned(),
        },
        client_id: client.client_id.clone(),
        jti,
        audience: audience.to_owned(),
    })
}

/// Returns 128 random bits, base64url without padding.
fn random_id() -> Result<String, aws_lc_rs::error::Unspecified> {
    use base64::Engine as _;
    let mut bytes = [0_u8; 16];
    aws_lc_rs::rand::fill(&mut bytes)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Returns the `server_error` refusal described by `description`, after the
/// cause is logged with its whole chain and never a value of the request.
fn server_error(description: &'static str, cause: &dyn std::error::Error) -> Refusal {
    tracing::error!(error = %ferrohealth_server::run::chain(cause), "{description}");
    Refusal {
        error: "server_error",
        description,
    }
}
