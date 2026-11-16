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

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::Jwk};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::audit::{self, Connected};
use crate::clients::{Client, ClientKeys, ClientKind, GrantType};
use crate::discovery::TOKEN_ROUTE;
use crate::form::Params;
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
    pub(crate) const fn request(description: &'static str) -> Self {
        Self {
            error: "invalid_request",
            description,
        }
    }

    /// The `invalid_client` refusal every failure of client authentication
    /// answers ("the server SHALL respond with an `invalid_client` error",
    /// SMART App Launch 2.2.0, Client Authentication: Asymmetric, Response).
    pub(crate) const fn client(description: &'static str) -> Self {
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
///
/// Each request is recorded before its answer is returned: an issued token
/// and its record commit in one transaction, and a request whose record
/// could not be stored is answered `503` with no token (no specification
/// governs the refusal: our own design).
pub async fn token(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let answer = issue(&state, &headers, &body, from).await;
    // NOTE: a form that cannot be read names no client; the record then says so.
    let form = Params::parse(&body, &[]).ok();
    let endpoint = state.settings().endpoint_url(TOKEN_ROUTE);
    let request = audit::TokenRequest {
        client_id: form.as_ref().and_then(|form| form.get("client_id")),
        from,
        endpoint: &endpoint,
        content_type: headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        body: &body,
    };
    let committed = commit(&state, &answer, &request).await;
    if let Err(error) = committed {
        tracing::error!(error = %ferrohealth_server::run::chain(&error), "a token request could not be recorded");
        return unrecorded();
    }
    match answer {
        Ok(issued) => no_store(Json(issued.response).into_response()),
        Err(refusal) => refusal.into_response(),
    }
}

/// Commits the record of `request` answered `answer`: an issued token
/// together with its record, a refusal's record alone.
async fn commit(
    state: &AppState,
    answer: &Result<Issued, Refusal>,
    request: &audit::TokenRequest<'_>,
) -> Result<(), audit::RecordFailure> {
    let lane = state.audit();
    match answer {
        Ok(issued) => {
            let exchange = audit::token_request(
                request,
                Ok(audit::Token {
                    issuer: &state.settings().issuer,
                    jti: &issued.jti,
                    client_id: &issued.client_id,
                    audience: &issued.audience,
                    subject: issued.person.as_deref(),
                }),
            );
            let mut tx = state
                .store()
                .begin()
                .await
                .map_err(audit::RecordFailure::Store)?;
            tx.insert_token(&issued.record())
                .await
                .map_err(audit::RecordFailure::Store)?;
            lane.commit(
                tx,
                &exchange,
                "token",
                issued.person.as_deref(),
                Some(&issued.client_id),
            )
            .await
        }
        Err(refusal) => {
            let exchange = audit::token_request(request, Err(refusal.error));
            let row = lane.row(&exchange, "token", None, request.client_id)?;
            lane.record(state.store(), &row).await
        }
    }
}

/// The answer to a token request that could not be recorded.
fn unrecorded() -> Response {
    no_store(StatusCode::SERVICE_UNAVAILABLE.into_response())
}

/// Returns `response` with the headers every token response carries: "The
/// authorization server's response SHALL include the HTTP 'Cache-Control'
/// response header field with a value of 'no-store'" and "'Pragma' ... with
/// a value of 'no-cache'" (SMART App Launch 2.2.0, Obtain access token,
/// Response; RFC 6749 §5.1).
pub(crate) fn no_store(mut response: Response) -> Response {
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
    /// `Bearer` for an app, `bearer` for a backend service: the fixed value
    /// each of SMART App Launch 2.2.0's grants names (compared without case,
    /// RFC 6749 §5.1).
    pub token_type: &'static str,
    /// The lifetime in seconds.
    pub expires_in: u64,
    /// The scope granted.
    pub scope: String,
    /// The ID Token, when `openid` is granted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// The refresh token, when the grant carries `offline_access` or
    /// `online_access` (SMART App Launch 2.2.0, Obtain access token).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// The launch context parameters of an app's grant, each a member of the
    /// response (SMART App Launch 2.2.0, Scopes and Launch Context, Launch
    /// context arrives with your `access_token`): `smart_style_url` when
    /// `[ferrosmart.branding]` names one.
    #[serde(flatten)]
    pub context: Map<String, Value>,
}

/// An issued token with what the audit record names.
#[derive(Debug)]
pub(crate) struct Issued {
    /// The response.
    pub(crate) response: TokenResponse,
    /// The client.
    client_id: String,
    /// The token's `jti`.
    jti: String,
    /// The token's `aud`.
    audience: String,
    /// The person the token was issued for, when one logged in.
    person: Option<String>,
    /// The token's `sub`.
    subject: String,
    /// Its `iat`.
    iat: i64,
    /// Its `exp`.
    exp: i64,
    /// The SHA-256 of the code it answers, if any.
    code_hash: Option<String>,
    /// The grant it was issued under; none for a client credentials token.
    grant_id: Option<String>,
}

impl Issued {
    /// Returns the access token as the store records it.
    fn record(&self) -> IssuedToken<'_> {
        IssuedToken {
            jti: &self.jti,
            client_id: &self.client_id,
            subject: &self.subject,
            audience: &self.audience,
            scope: &self.response.scope,
            issued_at: self.iat,
            expires_at: self.exp,
            code_hash: self.code_hash.as_deref(),
            grant_id: self.grant_id.as_deref(),
        }
    }
}

/// Answers the token request `body`.
async fn issue(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
    from: std::net::IpAddr,
) -> Result<Issued, Refusal> {
    let form = read_form(headers, body)?;
    match form.get("grant_type") {
        Some("client_credentials") => client_credentials(state, &form).await,
        Some("authorization_code") => authorization_code(from, state, &form).await,
        Some("refresh_token") => crate::refresh::refresh(state, &form, from).await,
        Some(_) => Err(Refusal {
            error: "unsupported_grant_type",
            description: "the grant type is not supported",
        }),
        None => Err(Refusal::request("the request names no grant_type")),
    }
}

/// Reads the form `body`, refused unless `headers` name it form-encoded,
/// as the token (RFC 6749 §3.2), introspection (RFC 7662 §2.1) and
/// revocation (RFC 7009 §2.1) requests all are.
pub(crate) fn read_form(headers: &HeaderMap, body: &[u8]) -> Result<Params, Refusal> {
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
    Params::parse(body, &[]).map_err(|_repeated| Refusal::request("a parameter is repeated"))
}

/// The client credentials grant (RFC 6749 §4.4; SMART App Launch 2.2.0,
/// Backend Services).
async fn client_credentials(state: &AppState, form: &Params) -> Result<Issued, Refusal> {
    let client = authenticate(state, form).await?;
    if !client.grant_types.contains(&GrantType::ClientCredentials) {
        return Err(Refusal {
            error: "unauthorized_client",
            description: "the client may not use this grant",
        });
    }
    let scope = granted_scope(&client, form.get("scope"))?;
    let audience = audience(state, form.get("resource"))?;
    mint(
        state,
        &client,
        Grant {
            subject: &client.client_id,
            audience: &audience,
            scope: &scope,
            fhir_user: None,
            code_hash: None,
            token_type: "bearer",
            identity: None,
            under: None,
            context: &Map::new(),
        },
    )
}

/// The authorization code grant (RFC 6749 §4.1.3; SMART App Launch 2.2.0,
/// Obtain access token): the client authenticated by its assertion, or a
/// public client named by `client_id`; the code its own, unexpired and
/// unused, for the same redirect URI, its PKCE verifier matching (RFC 7636
/// §4.6). A second use of a code is refused and revokes the tokens the
/// first issued, once the rest of the request holds (OAuth 2.1 draft
/// §4.1.3, §7.5.3).
async fn authorization_code(
    from: std::net::IpAddr,
    state: &AppState,
    form: &Params,
) -> Result<Issued, Refusal> {
    let client = identify(state, form).await?;
    if !client.grant_types.contains(&GrantType::AuthorizationCode) {
        return Err(Refusal {
            error: "unauthorized_client",
            description: "the client may not use this grant",
        });
    }
    let invalid = |description| Refusal {
        error: "invalid_grant",
        description,
    };
    let code = form
        .get("code")
        .ok_or(Refusal::request("the request carries no code"))?;
    let verifier = form
        .get("code_verifier")
        .ok_or(Refusal::request("the request carries no code_verifier"))?;
    let hash = crate::authorize::sha256(code);
    let (grant, redeemed) = state
        .store()
        .code(&hash)
        .await
        .map_err(|error| server_error("the code cannot be read", &error))?
        .ok_or(invalid("the code is unknown or expired"))?;
    if grant.client_id != client.client_id {
        return Err(invalid("the code was issued to another client"));
    }
    // NOTE: RFC 6749 §4.1.3, the redirect URI is the one the request carried.
    if form.get("redirect_uri") != Some(grant.redirect_uri.as_str()) {
        return Err(invalid("the redirect_uri is not the request's"));
    }
    // NOTE: RFC 7636 §4.1 and §4.6, a verifier of 43 to 128 unreserved characters
    // whose S256 is the challenge.
    let well_formed = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte));
    if !well_formed || ferrohealth_smart::oidc::challenge(verifier) != grant.code_challenge {
        return Err(invalid("the code_verifier does not match"));
    }
    let first = !redeemed
        && state
            .store()
            .redeem(&hash)
            .await
            .map_err(|error| server_error("the code cannot be redeemed", &error))?;
    if !first {
        let mut tx = state
            .store()
            .begin()
            .await
            .map_err(|error| server_error("the code's tokens cannot be revoked", &error))?;
        let revoked = tx
            .revoke_code(&hash)
            .await
            .map_err(|error| server_error("the code's tokens cannot be revoked", &error))?;
        let endpoint = state.settings().endpoint_url(TOKEN_ROUTE);
        state
            .audit()
            .commit_happening(
                tx,
                &audit::Happening {
                    event: audit::Event::CodeReused,
                    issuer: &state.settings().issuer,
                    client_id: Some(&client.client_id),
                    subject: Some(&grant.subject),
                    from,
                    endpoint: &endpoint,
                    details: vec![("revoked", revoked.to_string())],
                },
            )
            .await
            .map_err(|error| server_error("the code's tokens cannot be revoked", &error))?;
        return Err(invalid("the code was used before"));
    }
    let openid = grant.scope.split(' ').any(|scope| scope == "openid");
    let fhir_user = grant
        .fhir_user
        .as_deref()
        .filter(|_| grant.scope.split(' ').any(|scope| scope == "fhirUser"));
    let launch = crate::refresh::open(state, &client, &grant).await?;
    let mut issued = mint(
        state,
        &client,
        Grant {
            subject: &grant.subject,
            audience: &grant.audience,
            scope: &grant.scope,
            fhir_user,
            code_hash: Some(&hash),
            token_type: "Bearer",
            identity: openid.then_some((grant.nonce.as_deref(), grant.auth_time)),
            under: Some(&launch.grant_id),
            context: &launch.context,
        },
    )?;
    issued.response.refresh_token = launch.refresh_token;
    Ok(issued)
}

/// Returns the client of `form`: authenticated by its assertion, or a
/// registered public client named by `client_id`, which cannot
/// authenticate (RFC 6749 §2.1, §3.2.1; SMART App Launch 2.2.0, Refresh
/// access token, Request).
pub(crate) async fn identify(state: &AppState, form: &Params) -> Result<Client, Refusal> {
    if form.get("client_assertion").is_some() || form.get("client_assertion_type").is_some() {
        return authenticate(state, form).await;
    }
    let client_id = form
        .get("client_id")
        .ok_or(Refusal::client("the request names no client"))?;
    match state.store().client(client_id).await {
        Ok(Some(client)) if client.kind == ClientKind::Public => Ok(client),
        Ok(_) => Err(Refusal::client(
            "the client is not a registered public client",
        )),
        Err(error) => Err(server_error("the client registry cannot be read", &error)),
    }
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
/// configures one alone (RFC 9068 §3, a default audience). The issuer is
/// a resource too, the introspection endpoint's (`docs/architecture.md`
/// §13.6 item 8).
fn audience(state: &AppState, resource: Option<&str>) -> Result<String, Refusal> {
    let settings = state.settings();
    let resources = &settings.resources;
    let target = |description| Refusal {
        error: "invalid_target",
        description,
    };
    match (resource, resources.as_slice()) {
        (Some(named), _) if named == settings.issuer => Ok(settings.issuer.clone()),
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
pub(crate) async fn authenticate(state: &AppState, form: &Params) -> Result<Client, Refusal> {
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
pub(crate) async fn key_of(
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
    let lifetime = settings.access_token_lifetime.as_secs();
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

/// Returns the `server_error` refusal described by `description`, after the
/// cause is logged with its whole chain and never a value of the request.
pub(crate) fn server_error(description: &'static str, cause: &dyn std::error::Error) -> Refusal {
    tracing::error!(error = %ferrohealth_server::run::chain(cause), "{description}");
    Refusal {
        error: "server_error",
        description,
    }
}
