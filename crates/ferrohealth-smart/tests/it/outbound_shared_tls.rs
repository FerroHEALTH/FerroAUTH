// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! An outbound client whose grant shares the connection's TLS: a grant
//! without TLS material of its own authenticates with the certificate the
//! connection presents (RFC 8705 §2) and binds its tokens to it (RFC 8705
//! §3), an `oauth.tls` that names material still wins, and
//! `OutboundClient::build` keeps the grant's TLS to its own table (#417).

use std::path::Path;

use ferrohealth_smart::client::outbound::Authorization;
use ferrohealth_smart::client::outbound::OutboundClient;
use ferrohealth_smart::client::outbound::OutboundError;
use ferrohealth_smart::client::outbound::SendError;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::endpoint::EndpointSection;
use ferrohealth_smart::sender::ClientCertificate;
use http::Method;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use url::Url;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::header;
use wiremock::matchers::method;
use wiremock::matchers::path;

use crate::support::temp_file;
use crate::tls::MutualTls;
use crate::tls::PemTls;

const KEY: &str = "fed.endpoint";

/// The `tls` keys naming the authority and the client identity of `point`,
/// written to files the test reader reads.
fn tls_keys(point: &MutualTls) -> String {
    let roots = temp_file("ca.pem", point.ca_pem.as_bytes());
    let identity = temp_file(
        "identity.pem",
        format!("{}{}", point.client_certificate_pem, point.client_key_pem).as_bytes(),
    );
    let text = |path: &Path| {
        path.to_str()
            .expect("the temporary path is UTF-8")
            .to_owned()
    };
    format!(
        "trust_roots_file = {:?}\nclient_identity_file = {:?}\n",
        text(&roots),
        text(&identity)
    )
}

/// Returns the RFC 8705 §3.1 thumbprint of the client certificate of `point`.
fn thumbprint(point: &MutualTls) -> String {
    let der = CertificateDer::from_pem_slice(point.client_certificate_pem.as_bytes())
        .expect("the certificate is PEM");
    ClientCertificate::from_der(der.as_ref())
        .thumbprint()
        .to_owned()
}

fn table(text: &str) -> EndpointSection {
    toml::from_str(text).expect("the table parses")
}

/// The endpoint at `url` whose connection presents the identity of
/// `connection`, its grant the `oauth` keys `oauth`.
fn endpoint(url: &str, connection: &MutualTls, oauth: &str) -> EndpointSection {
    table(&format!(
        "url = \"{url}\"\n[retry]\nmax_attempts = 1\n[tls]\n{}[credentials.oauth]\n{oauth}",
        tls_keys(connection)
    ))
}

/// RFC 8705 §2: a `tls_client_auth` grant without TLS material of its own
/// authenticates at the token endpoint with the certificate the connection
/// presents to the integration.
#[tokio::test]
async fn a_mutual_tls_grant_presents_the_connection_s_certificate() {
    let point = crate::tls::start("Qz7-token").await;
    let oauth = format!(
        "token_endpoint = \"{}\"\nclient_id = \"Qz7-node\"\nclient_auth = \"tls_client_auth\"\n",
        point.url
    );
    let client =
        OutboundClient::build_sharing_tls(&endpoint(&point.url, &point, &oauth), KEY, &PemTls)
            .expect("a client");
    assert!(matches!(
        client.authorization(),
        Some(Authorization::Bearer(_))
    ));
    let url = Url::parse(&point.url).expect("a URL");
    let answer = client
        .send(&Method::POST, &url, |request| request.body("{}"))
        .await
        .expect("an answer");
    assert_eq!(answer.status(), 200);
    let seen = point.seen();
    assert_eq!(seen.len(), 2, "the token request and the call");
    assert!(
        seen.iter().all(|request| request.certificate),
        "both handshakes presented the connection's certificate"
    );
    let token_request = seen.first().expect("the token request");
    assert!(token_request.body.contains("client_id=Qz7-node"));
    assert!(!token_request.body.contains("client_secret"));
}

/// `OutboundClient::build` keeps the grant's TLS to its own `oauth.tls`: the
/// same table, whose grant names no certificate, is refused as before.
#[tokio::test]
async fn build_keeps_the_grant_s_tls_to_its_own_table() {
    let point = crate::tls::start("Qz7-token").await;
    let oauth = format!(
        "token_endpoint = \"{}\"\nclient_id = \"Qz7-node\"\nclient_auth = \"tls_client_auth\"\n",
        point.url
    );
    let refused = OutboundClient::build(&endpoint(&point.url, &point, &oauth), KEY, &PemTls)
        .expect_err("refused");
    assert!(
        matches!(
            &refused,
            OutboundError::Config { key: KEY, source } if matches!(**source, ConfigError::Missing { .. })
        ),
        "{refused:?}"
    );
    let bound = endpoint(
        "https://x.example.org/fhir/",
        &point,
        "token_endpoint = \"https://as.example.org/token\"\nclient_id = \"Qz7-node\"\nclient_secret = \"Qz7-secret\"\ncertificate_bound = true\n",
    );
    assert!(matches!(
        OutboundClient::build(&bound, KEY, &PemTls),
        Err(OutboundError::Config { key: KEY, .. })
    ));
}

/// Mounts a token endpoint at `/token` of `server` issuing `Qz7-bound`,
/// bound to the certificate of thumbprint `bound_to` (RFC 8705 §3.2).
async fn bound_token_endpoint(server: &MockServer, bound_to: &str) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "Qz7-bound",
            "token_type": "Bearer",
            "expires_in": 300,
            "cnf": {"x5t#S256": bound_to},
        })))
        .mount(server)
        .await;
}

/// RFC 8705 §3: a `certificate_bound` grant without TLS material of its own
/// binds its tokens to the certificate the connection presents, so a token
/// whose `cnf` names that certificate is sent to the integration.
#[tokio::test]
async fn a_bound_grant_keeps_a_token_bound_to_the_connection_s_certificate() {
    let point = crate::tls::start("Qz7-unused").await;
    let server = MockServer::start().await;
    bound_token_endpoint(&server, &thumbprint(&point)).await;
    Mock::given(method("GET"))
        .and(path("/fhir/Patient"))
        .and(header("authorization", "Bearer Qz7-bound"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let oauth = format!(
        "token_endpoint = \"{}/token\"\nclient_id = \"Qz7-node\"\nclient_secret = \"Qz7-secret\"\ncertificate_bound = true\n",
        server.uri()
    );
    let client = OutboundClient::build_sharing_tls(
        &endpoint(&format!("{}/fhir/", server.uri()), &point, &oauth),
        KEY,
        &PemTls,
    )
    .expect("a client");
    let url = client.url().join("Patient").expect("a URL");
    let answer = client
        .send(&Method::GET, &url, |request| request)
        .await
        .expect("an answer");
    assert_eq!(answer.status(), 200);
}

/// RFC 8705 §3: a token bound to another certificate than the connection's
/// is refused before it reaches the integration.
#[tokio::test]
async fn a_bound_grant_refuses_a_token_bound_to_another_certificate() {
    let point = crate::tls::start("Qz7-unused").await;
    let server = MockServer::start().await;
    bound_token_endpoint(&server, "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU").await;
    let oauth = format!(
        "token_endpoint = \"{}/token\"\nclient_id = \"Qz7-node\"\nclient_secret = \"Qz7-secret\"\ncertificate_bound = true\n",
        server.uri()
    );
    let client = OutboundClient::build_sharing_tls(
        &endpoint(&format!("{}/fhir/", server.uri()), &point, &oauth),
        KEY,
        &PemTls,
    )
    .expect("a client");
    let url = client.url().join("Patient").expect("a URL");
    assert!(matches!(
        client.send(&Method::GET, &url, |request| request).await,
        Err(SendError::Token(_))
    ));
    let seen = server.received_requests().await.expect("requests");
    assert!(
        seen.iter().all(|request| request.url.path() == "/token"),
        "no call reached the integration"
    );
}

/// An `oauth.tls` that names material wins: the grant presents its own
/// identity to a token endpoint that trusts only that identity, while the
/// connection presents another to the integration.
#[tokio::test]
async fn an_oauth_tls_that_names_material_wins() {
    let integration = crate::tls::start("Qz7-unused").await;
    let issuer = crate::tls::start("Qz7-token").await;
    let oauth = format!(
        "token_endpoint = \"{}\"\nclient_id = \"Qz7-node\"\nclient_auth = \"tls_client_auth\"\n[credentials.oauth.tls]\n{}",
        issuer.url,
        tls_keys(&issuer)
    );
    let client = OutboundClient::build_sharing_tls(
        &endpoint(&integration.url, &integration, &oauth),
        KEY,
        &PemTls,
    )
    .expect("a client");
    let url = Url::parse(&integration.url).expect("a URL");
    let answer = client
        .send(&Method::POST, &url, |request| request.body("{}"))
        .await
        .expect("an answer");
    assert_eq!(answer.status(), 200);
    assert_eq!(issuer.seen().len(), 1, "the token came from its own issuer");
    assert_eq!(
        integration.seen().len(),
        1,
        "the call reached the integration"
    );
}

/// RFC 8705 §3: a `certificate_bound` grant whose own `oauth.tls` presents
/// another certificate than the connection is refused, since the
/// integration would refuse every token it is issued.
#[tokio::test]
async fn a_bound_grant_over_another_certificate_is_refused() {
    let integration = crate::tls::start("Qz7-unused").await;
    let other = crate::tls::start("Qz7-unused").await;
    let oauth = format!(
        "token_endpoint = \"https://as.example.org/token\"\nclient_id = \"Qz7-node\"\nclient_secret = \"Qz7-secret\"\ncertificate_bound = true\n[credentials.oauth.tls]\n{}",
        tls_keys(&other)
    );
    let refused = OutboundClient::build_sharing_tls(
        &endpoint("https://x.example.org/fhir/", &integration, &oauth),
        KEY,
        &PemTls,
    )
    .expect_err("refused");
    assert!(
        matches!(refused, OutboundError::CertificateBinding { key: KEY }),
        "{refused:?}"
    );
}
