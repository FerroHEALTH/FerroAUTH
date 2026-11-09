// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! `client::Reach` on the HTTP engine: a host reached at the address an
//! override names, the client certificate presented in the handshake
//! (RFC 8705 §2), and a server below the TLS floor refused.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ferrohealth_smart::client::{Reach, Tls, TlsVersion};
use ferrohealth_smart::metadata::Http;
use jsonwebtoken::Algorithm;
use secrecy::SecretSlice;

use crate::support::ec_key;
use crate::tls::{start, start_issuer_at};

/// The time one call may take.
const TIMEOUT: Duration = Duration::from_secs(5);

/// A host name no resolver answers (RFC 6761 §6.4).
const HOST: &str = "provider.invalid";

/// The trust roots of `ca_pem`, with no client certificate.
fn trusting(ca_pem: &str) -> Tls {
    Tls {
        root_certificates: Some(ca_pem.as_bytes().to_vec()),
        identity: None,
        presented: None,
    }
}

/// The loopback address of the issuer `issuer` listens on.
fn address_of(issuer: &str) -> SocketAddr {
    let port = url::Url::parse(issuer)
        .expect("a URL")
        .port()
        .expect("a port");
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[tokio::test]
async fn an_override_reaches_the_named_host_at_its_address() {
    let key = ec_key("reach-resolve", Algorithm::ES256);
    let issuer = start_issuer_at(key.jwk.clone(), HOST, rustls::DEFAULT_VERSIONS).await;
    let tls = trusting(&issuer.ca_pem);

    let reach = Reach::default().with_resolve(HOST, address_of(&issuer.issuer));
    let metadata = Http::reaching(TIMEOUT, &tls, &reach)
        .expect("the engine builds")
        .discover(&issuer.issuer)
        .await
        .expect(
            "the metadata is read at the overridden address, its certificate checked for the host",
        );
    assert_eq!(metadata.issuer, issuer.issuer);

    let unresolved = Http::reaching(TIMEOUT, &tls, &Reach::default()).expect("the engine builds");
    assert!(
        unresolved.discover(&issuer.issuer).await.is_err(),
        "without the override the host name resolves nowhere"
    );
}

#[tokio::test]
async fn the_client_certificate_is_presented_to_the_provider() {
    let endpoint = start("unused").await;
    let tls = Tls {
        root_certificates: Some(endpoint.ca_pem.as_bytes().to_vec()),
        identity: Some(Arc::new(SecretSlice::from(endpoint.identity()))),
        presented: None,
    };
    let issuer = endpoint.url.trim_end_matches("/token").to_owned();
    let http = Http::reaching(TIMEOUT, &tls, &Reach::default()).expect("the engine builds");
    // The endpoint answers every request with a token, so discovery itself fails; what
    // the case reads is the handshake.
    drop(http.discover(&issuer).await);
    let seen = endpoint.seen();
    assert!(!seen.is_empty(), "the endpoint was reached");
    assert!(
        seen.iter().all(|request| request.certificate),
        "every request presented the client certificate"
    );
}

#[tokio::test]
async fn a_provider_below_the_tls_floor_is_refused() {
    let key = ec_key("reach-floor", Algorithm::ES256);
    let issuer = start_issuer_at(key.jwk.clone(), "localhost", &[&rustls::version::TLS12]).await;
    let tls = trusting(&issuer.ca_pem);

    let floor = Reach::default().with_min_tls_version(TlsVersion::Tls13);
    assert!(
        Http::reaching(TIMEOUT, &tls, &floor)
            .expect("the engine builds")
            .discover(&issuer.issuer)
            .await
            .is_err(),
        "a TLS 1.2 server is refused under a TLS 1.3 floor"
    );
    Http::reaching(TIMEOUT, &tls, &Reach::default())
        .expect("the engine builds")
        .discover(&issuer.issuer)
        .await
        .expect("the same server is read under the default TLS 1.2 floor");
}
