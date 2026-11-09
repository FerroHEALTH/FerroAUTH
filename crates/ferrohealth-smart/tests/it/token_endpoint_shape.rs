// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A token endpoint carries no userinfo (RFC 9110 §4.2.4) and no fragment
//! (RFC 6749 §3.2), configured or discovered, and may carry a query (RFC
//! 6749 §3.2).

use std::error::Error as StdError;

use ferrohealth_smart::client::ClientCredentials;
use ferrohealth_smart::client::Endpoint;
use ferrohealth_smart::client::TokenError;
use ferrohealth_smart::client::cache::TokenSource;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::credentials::OauthSection;
use secrecy::SecretString;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;
use wiremock::matchers::path;

type TestResult = Result<(), Box<dyn StdError>>;

/// The token endpoint path of the cases.
const TOKEN_PATH: &str = "/oauth/token";

/// The oauth table naming `token_endpoint`.
fn table(token_endpoint: &str) -> Result<OauthSection, toml::de::Error> {
    toml::from_str(&format!(
        "token_endpoint = {token_endpoint:?}\nclient_id = \"bridge\"\nclient_secret = \"synthetic-secret\"\n"
    ))
}

#[test]
fn a_configured_token_endpoint_with_userinfo_or_a_fragment_is_refused() -> TestResult {
    for (url, part) in [
        ("https://bridge:hunter2@as.example.org/token", "userinfo"),
        ("https://bridge@as.example.org/token", "userinfo"),
        ("https://as.example.org/token#frag", "fragment"),
    ] {
        let section = table(url)?;
        let refused = section.resolve().expect_err(url);
        assert!(
            matches!(refused, ConfigError::TokenEndpoint { part: found, .. } if found.contains(part)),
            "{url}: {refused}"
        );
        assert!(!refused.to_string().contains("hunter2"), "{refused}");
        let problems = section.problems("cdr.credentials.oauth");
        assert!(
            problems.iter().any(|problem| problem.contains(part)),
            "{url}: {problems:?}"
        );
        assert!(
            problems.iter().all(|problem| !problem.contains("hunter2")),
            "{problems:?}"
        );
    }
    let with_query = table("https://as.example.org/token?tenant=a")?;
    assert_eq!(
        Vec::<String>::new(),
        with_query.problems("cdr.credentials.oauth")
    );
    with_query.resolve()?.validate()?;
    Ok(())
}

#[tokio::test]
async fn a_programmatic_token_endpoint_with_userinfo_or_a_fragment_sends_nothing() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let address = server.address();
    for url in [
        format!("http://bridge:hunter2@{address}{TOKEN_PATH}"),
        format!("http://{address}{TOKEN_PATH}#frag"),
    ] {
        let config = ClientCredentials::new(
            Endpoint::Token(url.parse()?),
            String::from("bridge"),
            SecretString::from("synthetic-secret"),
        );
        assert!(
            matches!(
                config.validate(),
                Err(TokenError::TokenEndpointShape { .. })
            ),
            "{url}"
        );
        let refused = TokenSource::new(config)?
            .token()
            .await
            .expect_err("nothing is sent");
        assert!(
            matches!(&*refused, TokenError::TokenEndpointShape { .. }),
            "{refused:?}"
        );
        assert!(!refused.to_string().contains("hunter2"), "{refused}");
    }
    Ok(())
}

#[tokio::test]
async fn a_discovered_token_endpoint_with_userinfo_or_a_fragment_is_refused() -> TestResult {
    for part in ["userinfo", "fragment"] {
        let server = MockServer::start().await;
        let issuer = format!("{}/realms/ferro", server.uri());
        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-authorization-server/realms/ferro"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": issuer,
                "token_endpoint": if part == "userinfo" {
                    server.uri().replacen("http://", "http://bridge:hunter2@", 1) + TOKEN_PATH
                } else {
                    format!("{}{TOKEN_PATH}#frag", server.uri())
                },
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let config = ClientCredentials::new(
            Endpoint::Issuer(issuer),
            String::from("bridge"),
            SecretString::from("synthetic-secret"),
        );
        let refused = TokenSource::new(config)?
            .token()
            .await
            .expect_err("nothing is sent");
        assert!(
            matches!(
                &*refused,
                TokenError::TokenEndpointShape { member: "token_endpoint", part: found }
                    if found.contains(part)
            ),
            "{refused:?}"
        );
        assert!(!refused.to_string().contains("hunter2"), "{refused}");
    }
    Ok(())
}
