// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The resource server over a key set file, which every build supports,
//! the one without the `fetch` feature included.

use std::error::Error as StdError;

use ferrohealth_smart::metadata::ServerMetadata;
use ferrohealth_smart::resource::ResourceError;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::Settings;
use ferrohealth_smart::resource::configuration::SmartOptions;
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

/// Returns the resource server of a key set file holding a fresh key.
async fn offline_server(
    name: &str,
) -> Result<(ResourceServer, std::path::PathBuf), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let set = serde_json::json!({ "keys": [key.jwk.clone()] }).to_string();
    let path = temp_file(name, set.as_bytes());
    let mut settings = Settings::new(ISSUER, "https://fhir.example.org");
    settings.jwks_file = Some(path.clone());
    Ok((ResourceServer::discover(settings).await?, path))
}

/// Returns the metadata an operator supplies for the issuer of the cases.
fn supplied() -> ServerMetadata {
    ServerMetadata {
        issuer: String::from(ISSUER),
        token_endpoint: Some(format!("{ISSUER}/token")),
        authorization_endpoint: Some(format!("{ISSUER}/authorize")),
        grant_types_supported: Some(vec![String::from("client_credentials")]),
        ..ServerMetadata::default()
    }
}

// NOTE: SMART App Launch 2.2.0, Conformance, Metadata, `token_endpoint` is
// required, and a `jwks_file` issuer has no fetched document to name it.
#[tokio::test]
async fn supplied_metadata_names_the_token_endpoint_of_a_key_set_file_issuer()
-> Result<(), Box<dyn StdError>> {
    let (server, path) = offline_server("supplied-jwks.json").await?;
    let bare = server.smart_configuration(&SmartOptions::default());
    assert!(bare.get("token_endpoint").is_none(), "nothing names it yet");
    let server = server.with_metadata(supplied())?;
    let document = server.smart_configuration(&SmartOptions::default());
    assert_eq!(
        serde_json::json!(format!("{ISSUER}/token")),
        document["token_endpoint"]
    );
    assert_eq!(
        serde_json::json!(["client_credentials"]),
        document["grant_types_supported"]
    );
    assert_eq!(
        document,
        ferrohealth_smart::resource::configuration::document(
            server.metadata(),
            &SmartOptions::default()
        ),
        "the public builder is the one the server uses"
    );
    std::fs::remove_file(path)?;
    Ok(())
}

#[tokio::test]
async fn supplied_metadata_is_held_to_the_issuer_and_the_https_rule()
-> Result<(), Box<dyn StdError>> {
    let other = ServerMetadata {
        issuer: String::from("https://other.example.org"),
        ..supplied()
    };
    let plain = ServerMetadata {
        token_endpoint: Some(String::from("http://as.example.org/token")),
        ..supplied()
    };
    let garbled = ServerMetadata {
        token_endpoint: Some(String::from("not a url")),
        ..supplied()
    };
    let (server, path) = offline_server("other-issuer-jwks.json").await?;
    assert!(
        matches!(
            server.with_metadata(other),
            Err(ResourceError::MetadataIssuer { .. })
        ),
        "RFC 8414 §3.3: the issuer must be the configured one"
    );
    std::fs::remove_file(path)?;
    let (server, path) = offline_server("plain-http-jwks.json").await?;
    assert!(
        matches!(
            server.with_metadata(plain),
            Err(ResourceError::Discovery(_))
        ),
        "RFC 8414 §2: an https location"
    );
    std::fs::remove_file(path)?;
    let (server, path) = offline_server("garbled-jwks.json").await?;
    assert!(matches!(
        server.with_metadata(garbled),
        Err(ResourceError::MetadataUrl {
            member: "token_endpoint",
            ..
        })
    ));
    std::fs::remove_file(path)?;
    Ok(())
}
