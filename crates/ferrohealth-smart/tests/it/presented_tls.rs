// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A grant over the TLS configuration a product built from material it read
//! once: the token endpoint connection presents its client certificate
//! (RFC 8705 §2), and a certificate-bound grant binds its tokens to that
//! certificate (RFC 8705 §3).

use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use ferrohealth_smart::client::ClientAuth;
use ferrohealth_smart::client::ClientCredentials;
use ferrohealth_smart::client::Endpoint;
use ferrohealth_smart::client::PresentedTls;
use ferrohealth_smart::client::TokenError;
use ferrohealth_smart::client::cache::TokenSource;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::credentials::OauthSection;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject as _;
use serde_json::json;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;
use wiremock::matchers::path;

use crate::tls::MutualTls;

type TestResult = Result<(), Box<dyn StdError>>;

/// The token endpoint path of the plain HTTP cases.
const TOKEN_PATH: &str = "/oauth/token";

/// The configuration a product builds for `endpoint`: its authority as the
/// one root, and its client certificate and key as the identity when
/// `identity`, as `ferrohealth-server`'s `TlsClient::client_config` would.
fn presented(endpoint: &MutualTls, identity: bool) -> Result<PresentedTls, Box<dyn StdError>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(endpoint.ca_pem.as_bytes())?)?;
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots);
    let certificate = CertificateDer::from_pem_slice(endpoint.client_certificate_pem.as_bytes())?;
    if !identity {
        return Ok(PresentedTls::new(
            Arc::new(builder.with_no_client_auth()),
            None,
        ));
    }
    let key = PrivateKeyDer::from_pem_slice(endpoint.client_key_pem.as_bytes())?;
    let config = builder.with_client_auth_cert(vec![certificate.clone()], key)?;
    Ok(PresentedTls::new(Arc::new(config), Some(certificate)))
}

/// Returns the RFC 8705 §3.1 thumbprint of the certificate `endpoint` hands
/// the client.
fn thumbprint(endpoint: &MutualTls) -> Result<String, Box<dyn StdError>> {
    let der = CertificateDer::from_pem_slice(endpoint.client_certificate_pem.as_bytes())?;
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der.as_ref());
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref()))
}

/// RFC 8705 §2: the token endpoint that requires a client certificate takes
/// the one the product's configuration presents, with no PEM handed to the
/// crate.
#[tokio::test]
async fn the_grant_presents_the_certificate_of_the_product_s_configuration() -> TestResult {
    let endpoint = crate::tls::start("synthetic-mtls-token").await;
    let mut config = ClientCredentials::with_presented_tls(
        Endpoint::Token(endpoint.url.parse()?),
        String::from("ferrofed"),
        presented(&endpoint, true)?,
        false,
    );
    assert_eq!(ClientAuth::TlsClientAuth, config.client_auth);
    config.timeout = Duration::from_secs(5);
    config.validate()?;
    TokenSource::new(config)?
        .token()
        .await
        .map_err(|error| error.to_string())?;
    let seen = endpoint.seen();
    assert_eq!(1, seen.len());
    assert!(
        seen.first().ok_or("a request")?.certificate,
        "the handshake carried the certificate"
    );
    Ok(())
}

/// RFC 8705 §2: a configuration that presents no certificate cannot carry a
/// mutual-TLS method.
#[tokio::test]
async fn a_configuration_without_a_certificate_carries_no_mutual_tls() -> TestResult {
    let endpoint = crate::tls::start("synthetic-mtls-token").await;
    let config = ClientCredentials::with_presented_tls(
        Endpoint::Token(endpoint.url.parse()?),
        String::from("ferrofed"),
        presented(&endpoint, false)?,
        false,
    );
    assert!(matches!(
        config.validate(),
        Err(TokenError::Credential { what }) if what.contains("client certificate")
    ));
    Ok(())
}

/// RFC 8705 §3: a certificate-bound grant over the product's configuration
/// keeps a token bound to the certificate it presents and refuses one bound
/// to another.
#[tokio::test]
async fn a_bound_grant_compares_the_token_with_the_presented_certificate() -> TestResult {
    let endpoint = crate::tls::start("unused").await;
    let ours = thumbprint(&endpoint)?;
    let theirs = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
    for (bound_to, kept) in [(ours.as_str(), true), (theirs, false)] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(TOKEN_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "opaque",
                "token_type": "Bearer",
                "cnf": {"x5t#S256": bound_to},
            })))
            .mount(&server)
            .await;
        let mut config = ClientCredentials::with_presented_tls(
            Endpoint::Token(format!("{}{TOKEN_PATH}", server.uri()).parse()?),
            String::from("bridge"),
            presented(&endpoint, true)?,
            true,
        )
        .with_certificate_binding();
        config.timeout = Duration::from_secs(5);
        let outcome = TokenSource::new(config)?.token().await;
        if kept {
            assert!(outcome.is_ok(), "{outcome:?}");
        } else {
            assert!(
                matches!(
                    outcome.as_ref().map_err(AsRef::as_ref),
                    Err(TokenError::CertificateMismatch)
                ),
                "{outcome:?}"
            );
        }
    }
    Ok(())
}

/// The oauth table resolves over the product's configuration in place of
/// `client_certificate_file`, refuses a TLS file beside it, and asks it for
/// the certificate a mutual-TLS method or `certificate_bound` needs.
#[tokio::test]
async fn the_oauth_table_resolves_over_the_product_s_configuration() -> TestResult {
    let endpoint = crate::tls::start("unused").await;
    let section = |text: &str| -> Result<OauthSection, toml::de::Error> { toml::from_str(text) };
    let base = "token_endpoint = \"https://as.example.org/token\"\nclient_id = \"ferrofed\"\n";
    let mutual = section(&format!(
        "{base}client_auth = \"tls_client_auth\"\ncertificate_bound = true\n"
    ))?;
    assert!(
        mutual
            .problems_with_tls("credentials.oauth", &presented(&endpoint, true)?)
            .is_empty(),
        "{:?}",
        mutual.problems_with_tls("credentials.oauth", &presented(&endpoint, true)?)
    );
    let grant = mutual.resolve_with_tls(&crate::tls::Built(presented(&endpoint, true)?))?;
    assert_eq!(ClientAuth::TlsClientAuth, grant.client_auth);
    assert_eq!(
        Some(thumbprint(&endpoint)?),
        grant
            .tls
            .presented_certificate()
            .map(|certificate| certificate.thumbprint().to_owned())
    );
    grant.validate()?;

    assert!(matches!(
        mutual.resolve_with_tls(&crate::tls::Built(presented(&endpoint, false)?)),
        Err(ConfigError::Missing { .. })
    ));
    let problems = mutual.problems_with_tls("credentials.oauth", &presented(&endpoint, false)?);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("mutual-TLS"))
            && problems
                .iter()
                .any(|problem| problem.contains("certificate_bound")),
        "{problems:?}"
    );

    let twice = section(&format!(
        "{base}client_auth = \"tls_client_auth\"\nclient_certificate_file = \"/etc/client.pem\"\nclient_key_file = \"/etc/client.key\"\n"
    ))?;
    assert!(matches!(
        twice.resolve_with_tls(&crate::tls::Built(presented(&endpoint, true)?)),
        Err(ConfigError::RemovedKeys(_))
    ));
    assert!(
        twice
            .problems_with_tls("credentials.oauth", &presented(&endpoint, true)?)
            .iter()
            .any(|problem| problem.contains("client_certificate_file"))
    );
    Ok(())
}
