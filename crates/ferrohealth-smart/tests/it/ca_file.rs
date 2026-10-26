// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! `[auth] ca_file`: an issuer behind a private certificate authority is
//! read trusting the configured roots beside the platform's, and a file that
//! cannot serve as roots refuses the start by its key.

use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::IssuerKey;
use ferrohealth_smart::resource::ResourceServer;
use jsonwebtoken::Algorithm;

use crate::support::AUDIENCE;
use crate::support::ec_key;
use crate::support::temp_file;
use crate::tls::start_issuer;

/// An `[auth]` section trusting `issuer`, with `ca_file` when given.
fn section(issuer: &str, ca_file: Option<std::path::PathBuf>) -> AuthSection {
    AuthSection {
        issuer: IssuerKey::Flat(issuer.to_owned()),
        audience: vec![AUDIENCE.to_owned()],
        ca_file,
        ..AuthSection::default()
    }
}

#[tokio::test]
async fn an_issuer_behind_a_private_authority_is_read_with_its_ca_file() {
    let key = ec_key("ca-file", Algorithm::ES256);
    let issuer = start_issuer(key.jwk.clone()).await;
    let ca = temp_file("ca.pem", issuer.ca_pem.as_bytes());

    let trusted = section(&issuer.issuer, Some(ca))
        .resolve()
        .expect("resolves");
    let settings = trusted.issuers.into_iter().next().expect("one issuer");
    assert!(settings.trust_roots.is_some());
    ResourceServer::discover(settings)
        .await
        .expect("the metadata and the key set are read over TLS from the private authority");

    let untrusted = section(&issuer.issuer, None).resolve().expect("resolves");
    let settings = untrusted.issuers.into_iter().next().expect("one issuer");
    assert!(
        ResourceServer::discover(settings).await.is_err(),
        "without ca_file the private authority is not trusted"
    );
}

#[test]
fn a_ca_file_that_cannot_serve_as_roots_refuses_the_start_by_its_key() {
    let issuer = "https://idp.example";
    let missing = std::env::temp_dir().join("ferrohealth-smart-no-such-ca.pem");
    let not_pem = temp_file("not-pem.pem", b"not a certificate");
    let key_only = temp_file("key-only.pem", &ec_key("k", Algorithm::ES256).pem);
    for path in [missing, not_pem, key_only] {
        let err = section(issuer, Some(path.clone()))
            .resolve()
            .expect_err("refused");
        assert!(
            matches!(err, ConfigError::CaFile { .. }),
            "{}: {err:?}",
            path.display()
        );
        assert!(err.to_string().contains("auth.ca_file"), "{err}");
    }
}
