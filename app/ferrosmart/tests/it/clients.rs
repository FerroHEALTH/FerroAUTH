// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What the client registry admits and refuses, each rule its own case.

use ferrosmart::clients::{ClientError, ClientKeys, ClientKind, ClientSection, GrantType, resolve};
use serde_json::json;

/// Returns a Backend Services client with its JWK Set at a URL.
fn backend(client_id: &str) -> ClientSection {
    ClientSection {
        client_id: client_id.to_owned(),
        kind: ClientKind::ConfidentialAsymmetric,
        jwks_uri: String::from("https://export.example.org/jwks.json"),
        scopes: vec![String::from("system/Patient.rs")],
        grant_types: vec![GrantType::ClientCredentials],
        ..ClientSection::default()
    }
}

/// Writes `set` to a file and returns a client registering it by value.
fn by_value(set: &serde_json::Value) -> (tempfile::TempDir, ClientSection) {
    let dir = tempfile::tempdir().expect("a directory");
    let path = dir.path().join("jwks.json");
    std::fs::write(&path, set.to_string()).expect("written");
    let client = ClientSection {
        jwks_uri: String::new(),
        jwks_file: Some(path),
        ..backend("by-value")
    };
    (dir, client)
}

#[test]
fn a_backend_services_client_registers_its_jwk_set_by_url() {
    let clients = resolve(&[backend("export")]).expect("admitted");
    let client = &clients[0];
    assert_eq!("export", client.name, "the name defaults to the client id");
    assert!(
        matches!(&client.keys, Some(ClientKeys::Uri(url)) if url.as_str() == "https://export.example.org/jwks.json")
    );
    assert_eq!(vec![GrantType::ClientCredentials], client.grant_types);
}

#[test]
fn a_jwk_set_by_value_holds_bare_public_keys_with_kty_and_kid() {
    let set = json!({"keys": [
        {"kty": "RSA", "kid": "r1", "n": "AQAB", "e": "AQAB", "alg": "RS384"},
        {"kty": "EC", "kid": "e1", "crv": "P-384", "x": "AA", "y": "AA"}
    ]});
    let (_dir, client) = by_value(&set);
    let clients = resolve(&[client]).expect("admitted");
    assert!(matches!(&clients[0].keys, Some(ClientKeys::Set(kept)) if *kept == set));
    // NOTE: SMART App Launch 2.2.0, Client Authentication: Asymmetric,
    // Registering a client: `kty`, `kid` and the bare key members.
    for (key, rule) in [
        (
            json!({"kty": "RSA", "n": "AQAB", "e": "AQAB"}),
            "has no `kid`",
        ),
        (
            json!({"kty": "oct", "kid": "s", "k": "AA"}),
            "is no RSA or EC key",
        ),
        (
            json!({"kty": "RSA", "kid": "r", "n": "AQAB"}),
            "lacks a bare key member",
        ),
        (
            json!({"kty": "EC", "kid": "e", "crv": "P-256", "x": "AA", "y": "AA", "d": "AA"}),
            "carries a private member",
        ),
    ] {
        let (_dir, client) = by_value(&json!({"keys": [key]}));
        assert!(
            matches!(resolve(&[client]), Err(ClientError::Jwk { rule: refused, .. }) if refused == rule),
            "{rule}"
        );
    }
    let (_dir, client) = by_value(&json!({"keys": []}));
    assert!(matches!(resolve(&[client]), Err(ClientError::Rule { .. })));
}

#[test]
fn a_confidential_asymmetric_client_registers_exactly_one_jwk_set() {
    let neither = ClientSection {
        jwks_uri: String::new(),
        ..backend("neither")
    };
    assert!(matches!(resolve(&[neither]), Err(ClientError::Rule { .. })));
    let (_dir, by_value) =
        by_value(&json!({"keys": [{"kty": "RSA", "kid": "r", "n": "AQAB", "e": "AQAB"}]}));
    let both = ClientSection {
        jwks_uri: String::from("https://export.example.org/jwks.json"),
        ..by_value
    };
    assert!(matches!(resolve(&[both]), Err(ClientError::Rule { .. })));
    let plain = ClientSection {
        jwks_uri: String::from("http://export.example.org/jwks.json"),
        ..backend("plain")
    };
    assert!(matches!(
        resolve(&[plain]),
        Err(ClientError::JwksUri { .. })
    ));
}

#[test]
fn a_public_client_neither_registers_keys_nor_uses_client_credentials() {
    let keyed = ClientSection {
        kind: ClientKind::Public,
        ..backend("keyed")
    };
    assert!(matches!(resolve(&[keyed]), Err(ClientError::Rule { .. })));
    let public = ClientSection {
        client_id: String::from("app"),
        kind: ClientKind::Public,
        grant_types: vec![GrantType::ClientCredentials],
        ..ClientSection::default()
    };
    assert!(matches!(resolve(&[public]), Err(ClientError::Rule { .. })));
}

#[test]
fn an_authorization_code_client_registers_absolute_redirect_uris() {
    let app = |uris: Vec<&str>| ClientSection {
        client_id: String::from("app"),
        kind: ClientKind::Public,
        redirect_uris: uris.into_iter().map(String::from).collect(),
        grant_types: vec![GrantType::AuthorizationCode, GrantType::AuthorizationCode],
        ..ClientSection::default()
    };
    let admitted = resolve(&[app(vec!["https://app.example.org/callback"])]).expect("admitted");
    assert_eq!(
        vec![GrantType::AuthorizationCode],
        admitted[0].grant_types,
        "once"
    );
    assert!(matches!(
        resolve(&[app(vec![])]),
        Err(ClientError::Rule { .. })
    ));
    // NOTE: RFC 6749 §3.1.2, absolute and without a fragment.
    for uri in ["/callback", "https://app.example.org/callback#done"] {
        assert!(
            matches!(
                resolve(&[app(vec![uri])]),
                Err(ClientError::RedirectUri { .. })
            ),
            "{uri}"
        );
    }
}

#[test]
fn the_registry_refuses_a_repeated_or_missing_id_a_bad_scope_and_no_grant() {
    assert!(
        matches!(resolve(&[backend("x"), backend("x")]), Err(ClientError::Repeated { client_id }) if client_id == "x")
    );
    assert!(matches!(
        resolve(&[backend("")]),
        Err(ClientError::NoClientId)
    ));
    let scoped = ClientSection {
        scopes: vec![String::from("system/Patient.rs extra")],
        ..backend("scoped")
    };
    assert!(matches!(resolve(&[scoped]), Err(ClientError::Scope { .. })));
    let idle = ClientSection {
        grant_types: Vec::new(),
        ..backend("idle")
    };
    assert!(matches!(resolve(&[idle]), Err(ClientError::Rule { .. })));
}

#[test]
fn a_refresh_token_continues_an_authorization_code_grant_only() {
    // NOTE: SMART App Launch 2.2.0, Backend Services: refresh tokens SHOULD NOT be issued.
    let backend_refresh = ClientSection {
        grant_types: vec![GrantType::ClientCredentials, GrantType::RefreshToken],
        ..backend("export")
    };
    assert!(matches!(
        resolve(&[backend_refresh]),
        Err(ClientError::Rule { .. })
    ));
    let app = ClientSection {
        client_id: String::from("app"),
        kind: ClientKind::Public,
        redirect_uris: vec![String::from("https://app.example.org/callback")],
        grant_types: vec![GrantType::RefreshToken, GrantType::AuthorizationCode],
        ..ClientSection::default()
    };
    let admitted = resolve(&[app]).expect("admitted");
    assert_eq!(
        vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        admitted[0].grant_types
    );
}
