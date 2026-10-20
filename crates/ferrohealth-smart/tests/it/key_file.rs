// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The resource server over a key set file, which every build supports,
//! the one without the `fetch` feature included.

use std::error::Error as StdError;

use ferrohealth_smart::resource::ResourceError;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::Settings;
use jsonwebtoken::Algorithm;

use crate::support::ec_key;
use crate::support::mint;
use crate::support::now;
use crate::support::temp_file;

/// The issuer of the cases; nothing is ever read from it.
const ISSUER: &str = "https://as.example.org";

#[tokio::test]
async fn a_key_set_file_verifies_without_reading_the_issuer() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let set = serde_json::json!({ "keys": [key.jwk.clone()] }).to_string();
    let path = temp_file("offline-jwks.json", set.as_bytes());
    let mut settings = Settings::new(ISSUER, "https://fhir.example.org");
    settings.jwks_file = Some(path.clone());
    let server = ResourceServer::discover(settings).await?;
    let issued = now();
    let claims = serde_json::json!({
        "iss": ISSUER,
        "aud": "https://fhir.example.org",
        "sub": "synthetic-sub",
        "client_id": "synthetic-client",
        "iat": issued,
        "exp": issued + 300,
        "jti": "synthetic-jti",
        "scope": "system/Condition.r",
    });
    let caller = server.authenticate(&mint(&key, &claims)).await?;
    assert_eq!("synthetic-sub", caller.subject());
    std::fs::remove_file(path)?;
    Ok(())
}

#[cfg(not(feature = "fetch"))]
#[tokio::test]
async fn without_the_fetch_feature_a_key_set_file_is_required() {
    let settings = Settings::new(ISSUER, "https://fhir.example.org");
    assert!(
        matches!(
            ResourceServer::discover(settings).await,
            Err(ResourceError::KeySetFileRequired)
        ),
        "a build without an HTTP client refuses settings that name no jwks_file"
    );
}

#[tokio::test]
async fn a_missing_key_set_file_refuses_the_start() {
    let mut settings = Settings::new(ISSUER, "https://fhir.example.org");
    settings.jwks_file = Some(std::path::PathBuf::from("/nonexistent/ferro-offline.jwks"));
    assert!(matches!(
        ResourceServer::discover(settings).await,
        Err(ResourceError::KeySetFile { .. })
    ));
}
