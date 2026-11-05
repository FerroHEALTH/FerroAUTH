// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The guard in front of a router with sender-constrained tokens: a
//! `DPoP` request admitted with its proof and answered with the `DPoP`
//! challenge when refused, a certificate-bound token admitted over the
//! client certificate the product's TLS layer leaves on the request, and a
//! `cnf` token refused under the `Bearer` scheme.

use std::error::Error as StdError;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::routing::get;
use ferrohealth_smart::guard::AuthLayer;
use ferrohealth_smart::guard::Gate;
use ferrohealth_smart::guard::Requirement;
use ferrohealth_smart::guard::Target;
use ferrohealth_smart::resource::Access;
use ferrohealth_smart::sender::ClientCertificate;
use ferrohealth_smart::sender::SenderConstraint;
use ferrohealth_smart::sender::proof::DPOP;
use http::Extensions;
use http::Method;
use http::Request;
use http::StatusCode;
use http::Uri;
use http::header;
use serde_json::json;
use tower::ServiceExt as _;

use super::Bound;
use super::EXTERNAL;
use super::check;
use super::dpop_key;
use super::proof;
use super::proof_claims;

/// The path every case addresses.
const PATH: &str = "/fhir/Observation/o-1";

/// Returns the guarded router over `bound`'s issuer, admitting `DPoP`.
async fn router(bound: &Bound, constraint: SenderConstraint) -> Router {
    let server = bound.server(constraint).await;
    let gate = Gate::default()
        .with_bearer(server)
        .with_dpop(Arc::new(check()))
        .with_realm("ferro");
    let classify = |_method: &Method, _uri: &Uri, _extensions: &Extensions| {
        Some(Target::new("read", Requirement::Caller))
    };
    Router::new()
        .route(
            PATH,
            get(|access: axum::Extension<Access>| async move {
                access
                    .caller()
                    .map(|caller| caller.subject().to_owned())
                    .unwrap_or_default()
            }),
        )
        .layer(AuthLayer::new(gate, classify))
}

/// Returns the status and challenge `router` answers `request` with.
async fn send(
    router: Router,
    request: Request<Body>,
) -> Result<(StatusCode, Option<String>), Box<dyn StdError>> {
    let response = router.oneshot(request).await?;
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    Ok((response.status(), challenge))
}

/// Returns a `GET` of the case's path with `authorization` and the proofs.
fn request(authorization: &str, dpop: &[&str]) -> Request<Body> {
    let mut builder = Request::get(PATH).header(header::AUTHORIZATION, authorization);
    for proof in dpop {
        builder = builder.header(DPOP, *proof);
    }
    builder.body(Body::empty()).expect("a request")
}

#[tokio::test]
async fn a_dpop_request_with_a_valid_proof_is_admitted() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 9449 §7.1, the `DPoP` scheme with the proof in the `DPoP`
    // header, checked against the external URL plus the request path.
    let bound = Bound::start().await;
    let key = dpop_key();
    let token = bound.token(Some(json!({ "jkt": key.jkt })));
    let htu = format!("{EXTERNAL}{PATH}");
    let jwt = proof(&key, &proof_claims("GET", &htu, &token));
    let router = router(&bound, SenderConstraint::Required).await;
    let (status, _) = send(router.clone(), request(&format!("DPoP {token}"), &[&jwt])).await?;
    assert_eq!(StatusCode::OK, status);
    let (status, challenge) = send(router, request(&format!("DPoP {token}"), &[&jwt])).await?;
    assert_eq!(StatusCode::UNAUTHORIZED, status, "the replayed proof");
    assert_eq!(
        Some("DPoP realm=\"ferro\", error=\"invalid_dpop_proof\""),
        challenge.as_deref(),
        "RFC 9449 §7.1: a proof deemed invalid"
    );
    Ok(())
}

#[tokio::test]
async fn a_dpop_key_mismatch_is_challenged_as_an_invalid_dpop_token()
-> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 9449 §7.1 Figure 16, a failed key binding is `invalid_token`
    // under the `DPoP` scheme.
    let bound = Bound::start().await;
    let token = bound.token(Some(json!({ "jkt": dpop_key().jkt })));
    let other = dpop_key();
    let jwt = proof(
        &other,
        &proof_claims("GET", &format!("{EXTERNAL}{PATH}"), &token),
    );
    let router = router(&bound, SenderConstraint::None).await;
    let (status, challenge) = send(router, request(&format!("DPoP {token}"), &[&jwt])).await?;
    assert_eq!(StatusCode::UNAUTHORIZED, status);
    assert_eq!(
        Some("DPoP realm=\"ferro\", error=\"invalid_token\""),
        challenge.as_deref()
    );
    Ok(())
}

#[tokio::test]
async fn a_dpop_bound_token_under_the_bearer_scheme_is_refused() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 9449 §7.2, a DPoP-bound token "received as a bearer token" is
    // rejected, with the `Bearer` challenge of the scheme it used.
    let bound = Bound::start().await;
    let token = bound.token(Some(json!({ "jkt": dpop_key().jkt })));
    let router = router(&bound, SenderConstraint::None).await;
    let (status, challenge) = send(router, request(&format!("Bearer {token}"), &[])).await?;
    assert_eq!(StatusCode::UNAUTHORIZED, status);
    assert_eq!(
        Some("Bearer realm=\"ferro\", error=\"invalid_token\""),
        challenge.as_deref()
    );
    Ok(())
}

#[tokio::test]
async fn a_missing_credential_is_challenged_with_both_schemes() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 9449 §7.2 Figure 17, both challenges and no error code.
    let bound = Bound::start().await;
    let router = router(&bound, SenderConstraint::None).await;
    let request = Request::get(PATH).body(Body::empty())?;
    let (status, challenge) = send(router, request).await?;
    assert_eq!(StatusCode::UNAUTHORIZED, status);
    assert_eq!(
        Some("Bearer realm=\"ferro\", DPoP realm=\"ferro\""),
        challenge.as_deref()
    );
    Ok(())
}

#[tokio::test]
async fn a_certificate_bound_token_reads_the_certificate_of_the_request()
-> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 8705 §3, the resource reads the client certificate "from its
    // TLS implementation layer", which the product leaves on the request.
    let bound = Bound::start().await;
    let generated = rcgen::generate_simple_self_signed(vec![String::from("client.invalid")])?;
    let certificate = ClientCertificate::from_der(generated.cert.der());
    let token = bound.token(Some(json!({ "x5t#S256": certificate.thumbprint() })));
    let router = router(&bound, SenderConstraint::Required).await;
    let mut with = request(&format!("Bearer {token}"), &[]);
    with.extensions_mut().insert(certificate);
    let (status, _) = send(router.clone(), with).await?;
    assert_eq!(StatusCode::OK, status, "with its certificate");
    let (status, challenge) = send(router, request(&format!("Bearer {token}"), &[])).await?;
    assert_eq!(StatusCode::UNAUTHORIZED, status, "without it");
    assert_eq!(
        Some("Bearer realm=\"ferro\", error=\"invalid_token\""),
        challenge.as_deref(),
        "RFC 8705 §3: `invalid_token`"
    );
    Ok(())
}

#[tokio::test]
async fn a_gate_without_a_proof_check_admits_no_dpop_scheme() -> Result<(), Box<dyn StdError>> {
    // NOTE: no specification governs this: our own design; a surface that
    // names no proof check challenges with `Bearer` alone.
    let bound = Bound::start().await;
    let key = dpop_key();
    let token = bound.token(Some(json!({ "jkt": key.jkt })));
    let jwt = proof(
        &key,
        &proof_claims("GET", &format!("{EXTERNAL}{PATH}"), &token),
    );
    let gate = Gate::default()
        .with_bearer(bound.server(SenderConstraint::None).await)
        .with_realm("ferro");
    let classify = |_method: &Method, _uri: &Uri, _extensions: &Extensions| {
        Some(Target::new("read", Requirement::Caller))
    };
    let router = Router::new()
        .route(PATH, get(|| async { "" }))
        .layer(AuthLayer::new(gate, classify));
    let (status, challenge) = send(router, request(&format!("DPoP {token}"), &[&jwt])).await?;
    assert_eq!(StatusCode::UNAUTHORIZED, status);
    assert_eq!(Some("Bearer realm=\"ferro\""), challenge.as_deref());
    Ok(())
}
