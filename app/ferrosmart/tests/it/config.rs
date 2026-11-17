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
fn a_style_url_other_than_https_is_refused() {
    let keys = Keys::new();
    for style in ["http://ehr.example.org/style.json", "style.json"] {
        let refused = config(
            &format!(
                "[ferrosmart]\nissuer = \"https://smart.example.org\"\n\
                 [ferrosmart.branding]\nsmart_style_url = {style:?}"
            ),
            &keys,
        )
        .resolve();
        assert!(matches!(refused, Err(Error::StyleUrl)), "{style}");
    }
}

#[test]
fn the_audit_feed_is_optional_and_https_only() {
    let keys = Keys::new();
    let base = "[ferrosmart]\nissuer = \"https://smart.example.org\"\n";
    let local = config(base, &keys)
        .resolve()
        .expect("resolves without a feed");
    assert!(local.audit.feed.is_none(), "the records stay in the store");
    assert_eq!(
        "smart.example.org", local.audit.observer.source_id,
        "the issuer's host"
    );
    let fed = config(
        &format!("{base}[ferrosmart.audit.feed]\nurl = \"https://audit.example.org/fhir\""),
        &keys,
    )
    .resolve()
    .expect("resolves with a feed");
    assert!(fed.audit.feed.is_some(), "the records are forwarded");
    // NOTE: ihe-atna 0.22.0 FeedRepository::new, a record names people, so the feed is https.
    let cleartext = config(
        &format!("{base}[ferrosmart.audit.feed]\nurl = \"http://audit.example.org/fhir\""),
        &keys,
    )
    .resolve();
    assert!(
        matches!(cleartext, Err(Error::AuditBase { .. })),
        "an http repository is refused"
    );
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
fn the_refresh_idle_times_default_and_refuse_zero() {
    let keys = Keys::new();
    let settings = config(
        "[ferrosmart]\nissuer = \"https://smart.example.org\"",
        &keys,
    )
    .resolve()
    .expect("resolves");
    assert_eq!(30 * 86_400, settings.refresh_idle.as_secs(), "thirty days");
    assert_eq!(8 * 3600, settings.online_idle.as_secs(), "eight hours");
    for key in ["refresh_idle", "online_idle"] {
        let text = format!("[ferrosmart]\nissuer = \"https://smart.example.org\"\n{key} = \"0s\"");
        let refused = config(&text, &keys).resolve();
        assert!(
            matches!(&refused, Err(Error::Zero { key: named }) if named.ends_with(key)),
            "{key}"
        );
    }
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
        Some(&format!(
            "[ferrosmart]\nissuer = \"https://smart.example.org\"\n[ferrosmart.database]\nurl = {:?}",
            crate::support::UNREACHED_DATABASE
        )),
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

#[test]
fn a_missing_database_url_is_refused() {
    let keys = Keys::new();
    let text = format!(
        "[ferrosmart]\nissuer = \"https://smart.example.org\"\n[ferrosmart.database]\nmax_connections = 4\n[ferrosmart.keys]\nprivate_key_file = {:?}",
        keys.current.display().to_string()
    );
    assert!(matches!(
        config(&text, &keys).resolve(),
        Err(Error::Secret(_))
    ));
}

// NOTE: openEHR ITS-REST 1.1.0, ehr_get_by_subject, the namespace an EHR is looked
// up by is matched against `EHR_STATUS.subject`, which only an openEHR server holds.
#[test]
fn a_subject_namespace_belongs_to_an_openehr_base_and_is_never_empty() {
    let keys = Keys::new();
    let with = |kind: &str, namespace: &str| {
        config(
            &format!(
                "[ferrosmart]\nissuer = \"https://smart.example.org\"\n\
                 [[ferrosmart.resource]]\nbase = \"https://ehr.example.org/openehr/v1\"\n\
                 kind = {kind:?}\nsubject_namespace = {namespace:?}"
            ),
            &keys,
        )
        .resolve()
        .map_err(Box::new)
    };
    let settings = with("openehr", "examples").expect("resolves");
    assert_eq!(
        Some("examples"),
        settings
            .subject_namespaces
            .get("https://ehr.example.org/openehr/v1")
            .map(String::as_str)
    );
    for (kind, namespace) in [("fhir", "examples"), ("openehr", " ")] {
        let refused = with(kind, namespace).map(|_| ()).map_err(|error| *error);
        assert!(
            matches!(refused, Err(Error::Resource { .. })),
            "{kind} {namespace:?}"
        );
    }
}

/// The upstream table with `extra` under it, the issuer of every case, and
/// `keys`' current key as the token key.
fn upstream(keys: &Keys, extra: &str) -> String {
    let current = keys.current.display().to_string();
    format!(
        "[ferrosmart]\nissuer = \"https://smart.example.org\"\n\
         [ferrosmart.keys]\nprivate_key_file = {current:?}\n\
         [ferrosmart.upstream]\nissuer = \"https://idp.example.org\"\nclient_id = \"ferrosmart\"\n{extra}"
    )
}

/// The `[ferrosmart.upstream.private_key_jwt]` table with `extra` in it and
/// a fresh assertion key under `keys`.
fn private_key_jwt(keys: &Keys, extra: &str) -> String {
    let key = crate::support::rsa_key(keys.dir.path(), "assertion.pem");
    upstream(
        keys,
        &format!(
            "[ferrosmart.upstream.private_key_jwt]\n{extra}\n\
             [ferrosmart.upstream.private_key_jwt.keys]\nprivate_key_file = {:?}\n",
            key.display().to_string()
        ),
    )
}

// NOTE: OpenID Connect Core 1.0 §9: a client authenticates by one method.
#[test]
fn private_key_jwt_and_a_client_secret_together_are_refused() {
    let keys = Keys::new();
    let text = private_key_jwt(&keys, "").replace(
        "client_id = \"ferrosmart\"\n",
        "client_id = \"ferrosmart\"\nclient_secret = \"synthetic\"\n",
    );
    assert!(matches!(
        config(&text, &keys).resolve(),
        Err(Error::Upstream { .. })
    ));
}

// NOTE: RFC 7518 §3.1: the ring holds RSA keys, which sign RS* and PS* alone.
#[test]
fn a_private_key_jwt_algorithm_the_key_cannot_sign_is_refused() {
    let keys = Keys::new();
    for (algorithm, refused) in [
        ("PS256", false),
        ("RS512", false),
        ("ES256", true),
        ("none", true),
    ] {
        let text = private_key_jwt(&keys, &format!("algorithm = \"{algorithm}\""));
        assert_eq!(
            refused,
            config(&text, &keys).resolve().is_err(),
            "{algorithm}"
        );
    }
}

// NOTE: RFC 7515 §4.1.8: the certificate named by x5t#S256 is the signing key's.
#[test]
fn a_certificate_of_another_key_is_refused() {
    let keys = Keys::new();
    let other = rcgen::KeyPair::generate().expect("a key");
    let certificate = rcgen::CertificateParams::new(vec![String::from("other.example.org")])
        .expect("parameters")
        .self_signed(&other)
        .expect("a certificate");
    let path = keys.dir.path().join("other.crt");
    std::fs::write(&path, certificate.pem()).expect("written");
    let text = private_key_jwt(
        &keys,
        &format!("certificate_file = {:?}", path.display().to_string()),
    );
    assert!(matches!(
        config(&text, &keys).resolve(),
        Err(Error::Key { .. })
    ));
}

// NOTE: RFC 8725 §3.12: a key that signs client assertions never signs a token.
#[test]
fn an_assertion_ring_holding_a_token_key_or_none_is_refused() {
    let keys = Keys::new();
    let text = upstream(
        &keys,
        &format!(
            "[ferrosmart.upstream.private_key_jwt]\n[ferrosmart.upstream.private_key_jwt.keys]\n\
         next_private_key_file = {:?}\nprivate_key_file = {:?}\n",
            crate::support::rsa_key(keys.dir.path(), "next.pem")
                .display()
                .to_string(),
            keys.current.display().to_string()
        ),
    );
    assert!(matches!(
        config(&text, &keys).resolve(),
        Err(Error::Upstream { .. })
    ));
    let text = upstream(&keys, "[ferrosmart.upstream.private_key_jwt]\n");
    assert!(matches!(
        config(&text, &keys).resolve(),
        Err(Error::Missing {
            key: "ferrosmart.upstream.private_key_jwt.keys.private_key_file"
        })
    ));
}
