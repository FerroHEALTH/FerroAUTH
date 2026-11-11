// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The assertion key read without a configured algorithm, each EC key by its
//! curve (RFC 7518 §3.4), and the JWS of a product's own claims it signs
//! under the `typ` the product names (RFC 7515 §7.1, RFC 8725 §3.11).

use std::error::Error as StdError;
use std::time::Duration;

use ferrohealth_smart::client::assertion::AssertionError;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrohealth_smart::client::keys::KeyRing;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;
use jsonwebtoken::jwk::Jwk;
use serde::Serialize;

use crate::support::ec_key;
use crate::support::ed_key;
use crate::support::p521_pem;
use crate::support::rsa_key;

/// The claims of a product's own token.
#[derive(Serialize)]
struct Own<'a> {
    iss: &'a str,
    sub: &'a str,
    exp: i64,
}

#[test]
fn an_ec_key_signs_the_algorithm_of_its_curve() -> Result<(), Box<dyn StdError>> {
    for (generated, expected) in [
        (Algorithm::ES256, Algorithm::ES256),
        (Algorithm::ES384, Algorithm::ES384),
    ] {
        let key = AssertionKey::from_pem(&ec_key("unused", generated).pem, None, None)?;
        assert_eq!(expected, key.algorithm(), "RFC 7518 §3.4");
        assert_eq!(
            serde_json::to_value(expected)?,
            key.public_jwk()["alg"],
            "the published key names its algorithm"
        );
        assert!(
            key.assertion("synthetic-client", "https://as.example.org/token")
                .is_ok()
        );
    }
    assert_eq!(
        Algorithm::RS384,
        AssertionKey::from_pem(&rsa_key("unused", Algorithm::RS256).pem, None, None)?.algorithm()
    );
    assert_eq!(
        Algorithm::EdDSA,
        AssertionKey::from_pem(&ed_key("unused").pem, None, None)?.algorithm()
    );
    Ok(())
}

#[test]
fn an_ec_key_on_another_curve_is_refused_without_an_algorithm() {
    let refused = AssertionKey::from_pem(&p521_pem(), None, None);
    assert!(
        matches!(refused, Err(AssertionError::Curve { .. })),
        "a P-521 key signs neither ES256 nor ES384: {refused:?}"
    );
}

#[test]
fn a_configured_algorithm_still_overrides_the_curve() {
    let p256 = ec_key("unused", Algorithm::ES256);
    assert!(
        AssertionKey::from_pem(&p256.pem, Some(Algorithm::ES384), None).is_err(),
        "a P-256 key cannot sign ES384"
    );
    assert!(AssertionKey::from_pem(&p256.pem, Some(Algorithm::ES256), None).is_ok());
}

#[test]
fn the_rings_current_key_signs_a_products_own_claims_under_its_type()
-> Result<(), Box<dyn StdError>> {
    let current = AssertionKey::from_pem(&ec_key("unused", Algorithm::ES256).pem, None, None)?;
    let previous = AssertionKey::from_pem(&ec_key("unused", Algorithm::ES384).pem, None, None)?;
    let ring = KeyRing::new(current).with_previous_for(previous, Duration::from_secs(60))?;
    let key = ring.current();
    let claims = Own {
        iss: "urn:example:product",
        sub: "synthetic-subject",
        exp: jiff::Timestamp::now().as_second().saturating_add(60),
    };
    let token = key.sign("example+jwt", &claims)?;

    let header = jsonwebtoken::decode_header(&token)?;
    assert_eq!(Algorithm::ES256, header.alg);
    assert_eq!(
        Some(String::from("example+jwt")),
        header.typ,
        "RFC 8725 §3.11"
    );
    assert_eq!(Some(key.kid().to_owned()), header.kid);
    let public: Jwk = serde_json::from_value(key.public_jwk())?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&["urn:example:product"]);
    validation.set_required_spec_claims(&["exp", "iss", "sub"]);
    let read = jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(
        &token,
        &DecodingKey::from_jwk(&public)?,
        &validation,
    )?
    .claims;
    assert_eq!(
        Some(&serde_json::json!("synthetic-subject")),
        read.get("sub")
    );
    let published = ring.published();
    assert!(
        published["keys"]
            .as_array()
            .ok_or("keys")?
            .iter()
            .any(|jwk| jwk["kid"] == key.kid()),
        "the published set verifies what the current key signs"
    );
    Ok(())
}

#[test]
fn a_client_assertion_lives_sixty_seconds() -> Result<(), Box<dyn StdError>> {
    let key = AssertionKey::from_pem(&ec_key("unused", Algorithm::ES256).pem, None, None)?;
    let assertion = key.assertion("synthetic-client", "https://as.example.org/token")?;

    let public: Jwk = serde_json::from_value(key.public_jwk())?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&["https://as.example.org/token"]);
    validation.set_required_spec_claims(&["exp", "iat", "aud"]);
    let claims = jsonwebtoken::decode::<serde_json::Map<String, serde_json::Value>>(
        &assertion,
        &DecodingKey::from_jwk(&public)?,
        &validation,
    )?
    .claims;
    let iat = claims
        .get("iat")
        .and_then(serde_json::Value::as_i64)
        .ok_or("iat")?;
    let exp = claims
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .ok_or("exp")?;
    assert_eq!(
        60,
        exp - iat,
        "within SMART App Launch 2.2.0's five minutes and an issuer's 120-second cap"
    );
    Ok(())
}
