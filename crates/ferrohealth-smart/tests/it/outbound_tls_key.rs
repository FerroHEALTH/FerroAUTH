// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! An outbound client's TLS refusal names the key the operator wrote: the
//! endpoint table's `tls` table at `<key>.tls`, through `build`,
//! `build_sharing_tls` and the builder alike, with the family's reader of TLS
//! material (`ServerTls`). No specification governs the key path: our own
//! design (#427).

use std::path::Path;

use ferrohealth_smart::client::outbound::OutboundClient;
use ferrohealth_smart::client::outbound::OutboundError;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::ServerTls;
use ferrohealth_smart::config::endpoint::EndpointSection;

use crate::support::temp_file;

const KEY: &str = "cdr";

/// The three ways a product builds an outbound client.
#[derive(Debug, Clone, Copy)]
enum Build {
    Own,
    SharingTls,
    Builder,
}

const BUILDS: [Build; 3] = [Build::Own, Build::SharingTls, Build::Builder];

fn build(how: Build, endpoint: &EndpointSection) -> OutboundError {
    let built = match how {
        Build::Own => OutboundClient::build(endpoint, KEY, &ServerTls),
        Build::SharingTls => OutboundClient::build_sharing_tls(endpoint, KEY, &ServerTls),
        Build::Builder => OutboundClient::builder(endpoint, KEY, &ServerTls)
            .sharing_tls()
            .build(),
    };
    match built {
        Ok(_) => panic!("{how:?}: the TLS table is refused"),
        Err(err) => err,
    }
}

/// The endpoint table at [`KEY`] whose `tls` table holds `tls`.
fn endpoint(tls: &str) -> EndpointSection {
    toml::from_str(&format!("url = \"https://cdr.example/\"\n[tls]\n{tls}"))
        .expect("the table parses")
}

fn path_text(path: &Path) -> String {
    path.to_str()
        .expect("the temporary path is UTF-8")
        .to_owned()
}

/// Every message of the cause chain of `err`, joined.
fn chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut text = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// Asserts that every build refuses `tls` with a [`ConfigError::TlsBuild`]
/// at `cdr.tls` whose chain names `named`.
fn assert_named(tls: &str, named: &str) {
    let table = endpoint(tls);
    for how in BUILDS {
        let err = build(how, &table);
        let OutboundError::Config { key, source } = &err else {
            panic!("{how:?}: a configuration refusal, got {err:?}");
        };
        assert_eq!(*key, KEY, "{how:?}");
        assert!(
            matches!(source.as_ref(), ConfigError::TlsBuild { key, .. } if key == "cdr.tls"),
            "{how:?}: {source:?}"
        );
        let text = chain(&err);
        assert!(text.contains(named), "{how:?}: {text}");
        assert!(
            !text.contains("cdr.trust_roots_file") && !text.contains("cdr.client_identity"),
            "{how:?}: a key the operator never wrote: {text}"
        );
    }
}

#[test]
fn an_unreadable_roots_file_is_named_under_the_tls_table() {
    let missing = std::env::temp_dir().join("ferrohealth-smart-no-such-roots.pem");
    assert_named(
        &format!("trust_roots_file = {:?}\n", path_text(&missing)),
        "cdr.tls.trust_roots_file names",
    );
}

#[test]
fn an_empty_roots_file_is_named_under_the_tls_table() {
    let empty = temp_file("empty-roots.pem", b"");
    assert_named(
        &format!("trust_roots_file = {:?}\n", path_text(&empty)),
        "cdr.tls.trust_roots_file holds no certificate",
    );
}

#[test]
fn an_identity_without_a_certificate_is_named_under_the_tls_table() {
    let key = rcgen::KeyPair::generate().expect("a key");
    let identity = temp_file("key-only-identity.pem", key.serialize_pem().as_bytes());
    assert_named(
        &format!("client_identity_file = {:?}\n", path_text(&identity)),
        "cdr.tls.client_identity holds no certificate chain",
    );
}
