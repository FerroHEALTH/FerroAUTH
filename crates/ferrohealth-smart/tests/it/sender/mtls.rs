// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A certificate-bound token (RFC 8705 §3), a `cnf` token presented as a
//! plain bearer token, and an issuer that requires a sender-constrained
//! token.

use std::error::Error as StdError;

use ferrohealth_smart::resource::IssuerSet;
use ferrohealth_smart::resource::Verifier;
use ferrohealth_smart::sender::Binding;
use ferrohealth_smart::sender::Check;
use ferrohealth_smart::sender::ClientCertificate;
use ferrohealth_smart::sender::SenderConstraint;
use serde_json::json;

use super::Bound;
use super::assert_refused;
use super::dpop_key;

/// Returns a fresh self-signed client certificate.
fn certificate() -> ClientCertificate {
    let generated = rcgen::generate_simple_self_signed(vec![String::from("client.invalid")])
        .expect("a certificate");
    ClientCertificate::from_der(generated.cert.der())
}

#[tokio::test]
async fn a_certificate_bound_token_is_admitted_with_its_certificate_alone()
-> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 8705 §3, the resource "MUST verify that the certificate
    // matches the certificate associated with the access token".
    let bound = Bound::start().await;
    let mine = certificate();
    let token = bound.token(Some(json!({ "x5t#S256": mine.thumbprint() })));
    let server = bound.server(SenderConstraint::None).await;
    let caller = server
        .authenticate_bound(&token, &Binding::bearer().with_certificate(&mine))
        .await?;
    assert_eq!("synthetic-client-sub", caller.subject());
    assert_refused(
        &server
            .authenticate_bound(&token, &Binding::bearer().with_certificate(&certificate()))
            .await,
        Check::CertificateMismatch,
        "another certificate",
    );
    assert_refused(
        &server.authenticate_bound(&token, &Binding::bearer()).await,
        Check::CertificateMissing,
        "no certificate",
    );
    assert_refused(
        &server.authenticate(&token).await,
        Check::CertificateMissing,
        "a plain bearer token",
    );
    Ok(())
}

#[tokio::test]
async fn a_dpop_bound_token_presented_as_bearer_is_refused() {
    // NOTE: RFC 9449 §7.2, a resource "MUST reject a DPoP-bound access token
    // received as a bearer token", whatever the issuer's setting.
    let bound = Bound::start().await;
    let token = bound.token(Some(json!({ "jkt": dpop_key().jkt })));
    for constraint in [SenderConstraint::None, SenderConstraint::Required] {
        let server = bound.server(constraint).await;
        assert_refused(
            &server.authenticate(&token).await,
            Check::KeyBoundAsBearer,
            &format!("{constraint:?}"),
        );
        let set = IssuerSet::new().with(server);
        assert_refused(
            &set.verify(&token).await,
            Check::KeyBoundAsBearer,
            "through an issuer set",
        );
    }
}

#[tokio::test]
async fn a_cnf_naming_an_unknown_method_is_refused() {
    // NOTE: no specification governs a `cnf` method this crate cannot check:
    // our own design, refused rather than ignored.
    let bound = Bound::start().await;
    let token = bound.token(Some(json!({ "jwk": { "kty": "EC" } })));
    let server = bound.server(SenderConstraint::None).await;
    assert_refused(
        &server.authenticate(&token).await,
        Check::ConfirmationUnknown,
        "cnf.jwk",
    );
}

#[tokio::test]
async fn a_required_constraint_refuses_a_token_without_cnf() -> Result<(), Box<dyn StdError>> {
    // NOTE: no specification governs this: our own design; an issuer with
    // `sender_constraint = "required"` admits a bound token alone.
    let bound = Bound::start().await;
    let required = bound.server(SenderConstraint::Required).await;
    assert_refused(
        &required.authenticate(&bound.token(None)).await,
        Check::ConstraintRequired,
        "a bearer token",
    );
    let open = bound.server(SenderConstraint::None).await;
    let bearer = bound.token(None);
    open.authenticate(&bearer).await?;
    open.authenticate(&bearer).await?;
    let mine = certificate();
    let token = bound.token(Some(json!({ "x5t#S256": mine.thumbprint() })));
    required
        .authenticate_bound(&token, &Binding::bearer().with_certificate(&mine))
        .await?;
    Ok(())
}
