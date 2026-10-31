// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Whether a request is the natural person's own access (Regulation (EU)
//! 2025/327 Art. 3, 5 and 9), read from a verified token under the
//! [`PatientClaim`] a deployment attaches to its resource server.

use std::error::Error as StdError;

use ferrohealth_smart::resource::PatientClaim;
use ferrohealth_smart::resource::ResourceServer;
use jsonwebtoken::Algorithm;

use crate::support::Issuer;
use crate::support::ec_key;
use crate::support::mint;
use crate::support::server;

#[tokio::test]
async fn the_attached_patient_claim_makes_a_token_the_persons() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server = ResourceServer::discover(issuer.settings())
        .await?
        .with_extension(PatientClaim::new("person.patient_id")?);
    let mut claims = issuer.claims("user/Observation.rs");
    claims["person"] = serde_json::json!({ "patient_id": "p-7" });
    let caller = server.authenticate(&mint(&key, &claims)).await?;
    assert!(caller.acts_for_the_person());
    assert!(
        !caller.is_the_person(),
        "the claim alone is no person's token"
    );
    assert_eq!(Some("p-7"), caller.person().and_then(|person| person.claim));
    Ok(())
}

#[tokio::test]
async fn a_lazy_server_carries_the_patient_claim_too() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server =
        ResourceServer::lazy(issuer.settings())?.with_extension(PatientClaim::new("patient_id")?);
    let mut claims = issuer.claims("openid");
    claims["patient_id"] = serde_json::json!("p-7");
    let caller = server.authenticate(&mint(&key, &claims)).await?;
    assert!(caller.acts_for_the_person());
    Ok(())
}

#[tokio::test]
async fn without_a_patient_claim_only_the_scope_counts() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server = server(issuer.settings()).await;
    let mut claims = issuer.claims("user/Observation.rs");
    claims["patient_id"] = serde_json::json!("p-7");
    let professional = server.authenticate(&mint(&key, &claims)).await?;
    assert!(!professional.acts_for_the_person());
    assert!(!professional.is_the_person());
    let person = server
        .authenticate(&mint(&key, &issuer.claims("patient/Observation.rs")))
        .await?;
    assert!(person.acts_for_the_person());
    assert!(person.is_the_person());
    Ok(())
}
