// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What the configuration refuses, each refusal its own case.

use ferrosmart::config::error::Error;

use crate::support::{Keys, config, ec_key};

#[test]
fn a_configuration_with_an_issuer_and_a_key_resolves() {
    let keys = Keys::new();
    let settings = config(
        "[ferrosmart]\nissuer = \"https://smart.example.org\"",
        &keys,
    )
    .resolve()
    .expect("resolves");
    assert_eq!("https://smart.example.org", settings.issuer);
    assert_eq!(
        300,
        settings.access_token_lifetime.as_secs(),
        "five minutes"
    );
    assert_eq!(
        "https://smart.example.org/token",
        settings.endpoint("/token")
    );
    assert_eq!(
        "/.well-known/oauth-authorization-server",
        settings.metadata_path()
    );
}

#[test]
fn an_issuer_with_a_path_serves_under_it_and_its_metadata_beside_it() {
    let keys = Keys::new();
    let settings = config(
        "[server]\nbase_path = \"/smart\"\n[ferrosmart]\nissuer = \"https://example.org/smart\"",
        &keys,
    )
    .resolve()
    .expect("resolves");
    assert_eq!("https://example.org/smart/jwks", settings.endpoint("/jwks"));
    // NOTE: RFC 8414 §3, the well-known suffix between the host and the path.
    assert_eq!(
        "/.well-known/oauth-authorization-server/smart",
        settings.metadata_path()
    );
}

#[test]
fn a_missing_issuer_is_refused() {
    let keys = Keys::new();
    assert!(matches!(
        config("", &keys).resolve(),
        Err(Error::Missing {
            key: "ferrosmart.issuer"
        })
    ));
}

#[test]
fn an_issuer_outside_rfc_8414_is_refused() {
    let keys = Keys::new();
    for issuer in [
        "http://smart.example.org",
        "https://smart.example.org/?tenant=1",
        "https://smart.example.org/#top",
        "no url",
    ] {
        assert!(
            matches!(
                config(&format!("[ferrosmart]\nissuer = {issuer:?}"), &keys).resolve(),
                Err(Error::Issuer { .. })
            ),
            "{issuer}"
        );
    }
}

#[test]
fn an_issuer_path_other_than_the_base_path_is_refused() {
    let keys = Keys::new();
    assert!(matches!(
        config(
            "[ferrosmart]\nissuer = \"https://example.org/smart\"",
            &keys
        )
        .resolve(),
        Err(Error::IssuerPath)
    ));
}

#[test]
fn a_zero_token_lifetime_is_refused() {
    let keys = Keys::new();
    assert!(matches!(
        config(
            "[ferrosmart]\nissuer = \"https://smart.example.org\"\naccess_token_lifetime = \"0s\"",
            &keys
        )
        .resolve(),
        Err(Error::Zero {
            key: "ferrosmart.access_token_lifetime"
        })
    ));
}

#[test]
fn a_missing_or_unreadable_key_is_refused() {
    let keys = Keys::new();
    let missing = format!(
        "[ferrosmart]\nissuer = \"https://smart.example.org\"\n[ferrosmart.keys]\nprivate_key_file = {:?}",
        keys.dir.path().join("absent.pem").display().to_string()
    );
    assert!(matches!(
        config(&missing, &keys).resolve(),
        Err(Error::KeyFile {
            key: "ferrosmart.keys.private_key_file",
            ..
        })
    ));
    let none = ferrosmart::config::Config::from_sources(
        Some("[ferrosmart]\nissuer = \"https://smart.example.org\""),
        &std::collections::BTreeMap::new(),
    )
    .expect("reads");
    assert!(matches!(
        none.resolve(),
        Err(Error::Missing {
            key: "ferrosmart.keys.private_key_file"
        })
    ));
}

#[test]
fn a_key_that_cannot_sign_rs256_is_refused() {
    let keys = Keys::new();
    let ec = ec_key(keys.dir.path(), "ec.pem");
    let text = format!(
        "[ferrosmart]\nissuer = \"https://smart.example.org\"\n[ferrosmart.keys]\nprivate_key_file = {:?}",
        ec.display().to_string()
    );
    assert!(matches!(
        config(&text, &keys).resolve(),
        Err(Error::Key {
            key: "ferrosmart.keys.private_key_file",
            ..
        })
    ));
}

#[test]
fn a_ring_that_names_one_key_twice_is_refused() {
    let keys = Keys::new();
    let text = format!(
        "[ferrosmart]\nissuer = \"https://smart.example.org\"\n[ferrosmart.keys]\nprivate_key_file = {current:?}\nnext_private_key_file = {current:?}",
        current = keys.current.display().to_string()
    );
    assert!(matches!(
        config(&text, &keys).resolve(),
        Err(Error::KeyRing { .. })
    ));
}

#[test]
fn an_unknown_key_is_refused_when_the_file_loads() {
    let refused = ferrosmart::config::Config::from_sources(
        Some("[ferrosmart]\nissuer = \"https://smart.example.org\"\nsigning_key = \"x\""),
        &std::collections::BTreeMap::new(),
    );
    assert!(matches!(refused, Err(Error::Load(_))));
}
