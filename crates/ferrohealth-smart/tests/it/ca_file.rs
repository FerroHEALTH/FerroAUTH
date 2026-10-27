// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! `[auth] ca_file`: an issuer behind a private certificate authority is
//! read trusting the configured roots beside the platform's, and a file that
//! cannot serve as roots refuses the start by its key.

use ferrohealth_smart::config::AuthMode;
use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::IntrospectionSection;
use ferrohealth_smart::config::IssuerKey;
use ferrohealth_smart::config::OauthSection;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::introspection::Introspector;
use jsonwebtoken::Algorithm;
use secrecy::SecretString;

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

/// How the introspection call authenticates in [`introspecting`].
#[derive(Clone, Copy, Debug)]
enum Credential {
    /// `auth.introspection.client`.
    Client,
    /// `auth.introspection.bearer`.
    Bearer,
}

/// An `[auth]` section introspecting tokens of `issuer` under `credential`,
/// with `ca_file` and the grant's own `grant_ca_file` when given.
fn introspecting(
    issuer: &str,
    credential: Credential,
    ca_file: Option<std::path::PathBuf>,
    grant_ca_file: Option<std::path::PathBuf>,
) -> AuthSection {
    let grant = OauthSection {
        token_endpoint: format!("{issuer}{}", crate::support::TOKEN_PATH),
        client_id: String::from("ferro-rs"),
        client_secret: Some(SecretString::from("synthetic-secret")),
        ca_file: grant_ca_file,
        ..OauthSection::default()
    };
    let (client, bearer) = match credential {
        Credential::Client => (Some(grant), None),
        Credential::Bearer => (None, Some(grant)),
    };
    AuthSection {
        mode: AuthMode::Introspection,
        introspection: Some(IntrospectionSection {
            endpoint: format!("{issuer}/introspect"),
            client,
            bearer,
            ..IntrospectionSection::default()
        }),
        ..section(issuer, ca_file)
    }
}

#[tokio::test]
async fn introspection_reads_an_issuer_behind_a_private_authority_with_its_ca_file() {
    let key = ec_key("ca-file-introspection", Algorithm::ES256);
    let issuer = start_issuer(key.jwk.clone()).await;
    let other = start_issuer(key.jwk.clone()).await;
    let ca = temp_file("introspection-ca.pem", issuer.ca_pem.as_bytes());
    let other_ca = temp_file("introspection-other-ca.pem", other.ca_pem.as_bytes());
    for credential in [Credential::Client, Credential::Bearer] {
        let read = |ca_file, grant_ca_file| {
            let resolved = introspecting(&issuer.issuer, credential, ca_file, grant_ca_file)
                .resolve()
                .expect("resolves");
            Introspector::discover(resolved.introspection.expect("introspection settings"))
        };
        read(Some(ca.clone()), None).await.unwrap_or_else(|e| {
            panic!("{credential:?}: the metadata is read trusting auth.ca_file: {e}")
        });
        read(Some(ca.clone()), Some(other_ca.clone()))
            .await
            .unwrap_or_else(|e| {
                panic!("{credential:?}: auth.ca_file is trusted beside the grant's own: {e}")
            });
        assert!(
            read(None, None).await.is_err(),
            "{credential:?}: without ca_file the private authority is not trusted"
        );
        assert!(
            read(None, Some(other_ca.clone())).await.is_err(),
            "{credential:?}: the grant's own roots name another authority"
        );
    }
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
