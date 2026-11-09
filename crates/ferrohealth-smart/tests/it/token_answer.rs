// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The token endpoint's answer is read up to a ceiling, and a refusal keeps
//! its status and a bounded RFC 6749 §5.2 error, nothing else of the body.

use std::error::Error as StdError;

use ferrohealth_smart::client::ClientCredentials;
use ferrohealth_smart::client::Endpoint;
use ferrohealth_smart::client::MAX_ERROR_TEXT;
use ferrohealth_smart::client::TokenError;
use ferrohealth_smart::client::cache::TokenSource;
use ferrohealth_smart::metadata::DiscoveryError;
use ferrohealth_smart::metadata::MAX_DOCUMENT_BYTES;
use http::StatusCode;
use secrecy::SecretString;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;

type TestResult = Result<(), Box<dyn StdError>>;

/// A marker no refusal may render.
const MARKER: &str = "c2VjcmV0LWJvZHktbWFya2Vy";

/// Returns a source whose token endpoint on `server` answers `response`.
async fn source(
    response: ResponseTemplate,
) -> Result<(MockServer, TokenSource), Box<dyn StdError>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(response)
        .mount(&server)
        .await;
    let config = ClientCredentials::new(
        Endpoint::Token(format!("{}/oauth/token", server.uri()).parse()?),
        String::from("bridge"),
        SecretString::from("synthetic-secret"),
    );
    let source = TokenSource::new(config)?;
    Ok((server, source))
}

#[tokio::test]
async fn an_answer_past_the_ceiling_is_refused_and_quotes_nothing() -> TestResult {
    for status in [200, 400] {
        let body = format!("{MARKER}{}", "x".repeat(MAX_DOCUMENT_BYTES));
        let (_server, source) = source(ResponseTemplate::new(status).set_body_string(body)).await?;
        let error = source.token().await.expect_err("too large");
        assert!(
            matches!(
                error.as_ref(),
                TokenError::Discovery(DiscoveryError::TooLarge { .. })
            ),
            "{status}: {error:?}"
        );
        assert!(!error.to_string().contains(MARKER), "{error}");
        assert!(!format!("{error:?}").contains(MARKER));
    }
    Ok(())
}

#[tokio::test]
async fn a_refusal_keeps_a_bounded_oauth_error_and_nothing_else() -> TestResult {
    let description = "d".repeat(MAX_ERROR_TEXT * 4);
    let (_server, source) = source(ResponseTemplate::new(400).set_body_json(serde_json::json!({
        "error": "invalid_client",
        "error_description": description,
        "access_token": MARKER,
    })))
    .await?;
    let error = source.token().await.expect_err("refused");
    let TokenError::Refused {
        status,
        error: Some(oauth),
    } = error.as_ref()
    else {
        return Err(format!("{error:?}").into());
    };
    assert_eq!(StatusCode::BAD_REQUEST, *status);
    assert_eq!("invalid_client", oauth.error);
    assert_eq!(
        Some(MAX_ERROR_TEXT),
        oauth
            .error_description
            .as_ref()
            .map(|text| text.chars().count())
    );
    assert!(!error.to_string().contains(MARKER), "{error}");
    assert!(!format!("{error:?}").contains(MARKER));
    Ok(())
}
