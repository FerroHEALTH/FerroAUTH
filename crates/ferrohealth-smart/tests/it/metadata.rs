// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The metadata read: the issuer compared as exact text (RFC 8414 §3.3,
//! §4), a document that repeats a member name refused (RFC 8259 §4), and the
//! opt-in check that every endpoint sits on the issuer's origin (RFC 6454
//! §4, §5).

use std::error::Error as StdError;
use std::time::Duration;

use ferrohealth_smart::metadata::DiscoveryError;
use ferrohealth_smart::metadata::Http;
use ferrohealth_smart::resource::ResourceError;
use ferrohealth_smart::resource::ResourceServer;
use url::Url;
use wiremock::Mock;
use wiremock::ResponseTemplate;
use wiremock::matchers;

use crate::support::Issuer;

const OAUTH: &str = "/.well-known/oauth-authorization-server";

/// Mounts `body`, as written, as the RFC 8414 metadata of `issuer`.
async fn mount_raw(issuer: &Issuer, body: String) {
    Mock::given(matchers::method("GET"))
        .and(matchers::path(OAUTH))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(body),
        )
        .mount(&issuer.server)
        .await;
}

fn http() -> Http {
    Http::new(Duration::from_secs(5)).expect("an engine")
}

#[tokio::test]
async fn a_metadata_document_that_repeats_a_member_name_is_refused() -> Result<(), Box<dyn StdError>>
{
    let issuer = Issuer::bare().await;
    let uri = issuer.uri();
    mount_raw(
        &issuer,
        format!(
            r#"{{"issuer": "{uri}", "jwks_uri": "{uri}/jwks", "jwks_uri": "https://attacker.invalid/jwks"}}"#
        ),
    )
    .await;
    let error = http()
        .discover(&uri)
        .await
        .err()
        .ok_or("RFC 8259 §4, a repeated name is refused")?;
    assert!(
        matches!(error, DiscoveryError::RepeatedName { ref url, .. } if url.path() == OAUTH),
        "{error:?}"
    );

    let resource = ResourceServer::discover(issuer.settings())
        .await
        .err()
        .ok_or("the resource server refuses the start")?;
    assert!(
        matches!(
            resource,
            ResourceError::Discovery(DiscoveryError::RepeatedName { .. })
        ),
        "{resource:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_repeated_name_in_a_member_the_crate_does_not_read_is_refused()
-> Result<(), Box<dyn StdError>> {
    let issuer = Issuer::bare().await;
    let uri = issuer.uri();
    mount_raw(
        &issuer,
        format!(
            r#"{{"issuer": "{uri}", "jwks_uri": "{uri}/jwks", "x_extension": [{{"a": 1, "a": 2}}]}}"#
        ),
    )
    .await;
    let error = http()
        .discover(&uri)
        .await
        .err()
        .ok_or("RFC 8259 §4, a repeated name at any depth is refused")?;
    assert!(
        matches!(error, DiscoveryError::RepeatedName { .. }),
        "{error:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_body_that_is_no_json_is_no_metadata_document() -> Result<(), Box<dyn StdError>> {
    let issuer = Issuer::bare().await;
    mount_raw(&issuer, String::from("{\"issuer\": ")).await;
    let error = http()
        .discover(&issuer.uri())
        .await
        .err()
        .ok_or("RFC 8414 §3.2, the body is a JSON object")?;
    assert!(
        matches!(error, DiscoveryError::Metadata { .. }),
        "{error:?}"
    );
    Ok(())
}

#[tokio::test]
async fn an_issuer_that_differs_by_a_terminating_slash_is_another_issuer()
-> Result<(), Box<dyn StdError>> {
    let issuer = Issuer::bare().await;
    let mut metadata = issuer.metadata();
    metadata["issuer"] = serde_json::json!(format!("{}/", issuer.uri()));
    issuer.mount_document(OAUTH, metadata).await;
    let error = http()
        .discover(&issuer.uri())
        .await
        .err()
        .ok_or("RFC 8414 §3.3 and §4 compare the issuer as exact text")?;
    assert!(
        matches!(error, DiscoveryError::IssuerMismatch { ref found, .. } if found.ends_with('/')),
        "{error:?}"
    );
    Ok(())
}

#[tokio::test]
async fn the_origin_check_admits_endpoints_on_the_issuers_origin_and_refuses_others()
-> Result<(), Box<dyn StdError>> {
    let issuer = Issuer::bare().await;
    issuer.mount_metadata(OAUTH).await;
    let base: Url = issuer.uri().parse()?;
    let metadata = http().discover(&issuer.uri()).await?;
    metadata.check_origin(&base)?;

    let elsewhere = Issuer::bare().await;
    let mut foreign = elsewhere.metadata();
    foreign["token_endpoint"] = serde_json::json!(format!("{}/token", issuer.uri()));
    elsewhere.mount_document(OAUTH, foreign).await;
    let metadata = http().discover(&elsewhere.uri()).await?;
    let error = metadata
        .check_origin(&elsewhere.uri().parse()?)
        .err()
        .ok_or("RFC 6454 §5, another port is another origin")?;
    assert!(
        matches!(
            error,
            DiscoveryError::OtherOrigin {
                member: "token_endpoint",
                ..
            }
        ),
        "{error:?}"
    );
    Ok(())
}
