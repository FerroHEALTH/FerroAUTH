// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The configuration sections: what each resolves to, and every rule that
//! refuses the start.

use std::time::Duration;

use ferrohealth_smart::basic::PasswordStore;
use ferrohealth_smart::basic::StoreError;
use ferrohealth_smart::client::ClientAuth;
use ferrohealth_smart::client::Endpoint;
use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::BasicSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::credentials::CredentialsSection;
use ferrohealth_smart::config::credentials::Outbound;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::resource::Settings;

/// Returns a section of `top` keys and one `persons` issuer table.
fn one_issuer(top: &str) -> AuthSection {
    toml::from_str(&format!(
        "{top}\n[[issuer]]\nissuer = \"https://as.example.org\"\nkind = \"persons\"\naudience = [\"a\"]\n"
    ))
    .expect("the section parses")
}

#[test]
fn each_issuer_table_carries_its_own_settings() {
    let section: AuthSection = toml::from_str(
        r#"
        realm = "ferrobridge"

        [[issuer]]
        issuer = "https://one.example.org"
        kind = "persons"
        audience = ["https://bridge.example.org/fhir"]

        [[issuer]]
        issuer = "https://two.example.org"
        kind = "machines"
        audience = ["https://other.example.org"]
        clock_skew = "10s"
        jwks_file = "/etc/ferro/two.jwks"
        role_claims = []
        "#,
    )
    .expect("the section parses");
    assert_eq!(2, section.issuer.len(), "two issuer tables");
    let resolved = section.resolve().expect("the section resolves");
    assert_eq!(2, resolved.issuers.len());
    let one = &resolved.issuers[0];
    assert_eq!(IssuerKind::Persons, one.kind);
    assert_eq!(
        vec![String::from("https://bridge.example.org/fhir")],
        one.audience
    );
    assert_eq!(
        Duration::from_secs(60),
        one.clock_skew,
        "the table's default"
    );
    assert_eq!(Duration::from_secs(600), one.jwks_max_age);
    assert_eq!(3, one.role_claims.len(), "RFC 9068 §2.2.3.1 defaults");
    let two = &resolved.issuers[1];
    assert_eq!(IssuerKind::Machines, two.kind);
    assert_eq!(Duration::from_secs(10), two.clock_skew);
    assert_eq!(
        Some(std::path::PathBuf::from("/etc/ferro/two.jwks")),
        two.jwks_file
    );
    assert_eq!(Vec::<String>::new(), two.role_claims);
    assert_eq!(Some(String::from("ferrobridge")), resolved.realm);
    assert_eq!(
        Some(&IssuerKind::Machines),
        resolved.kinds.get("https://two.example.org")
    );
    assert!(resolved.basic.is_none());
}

#[test]
fn a_section_that_breaks_a_rule_refuses_the_start() {
    let unknown = toml::from_str::<AuthSection>("jwks_refresh_interval_ms = 1000");
    assert!(unknown.is_err(), "deny_unknown_fields");
    let none = AuthSection::default();
    assert!(matches!(
        none.resolve(),
        Err(ConfigError::Missing { key: "auth.issuer" })
    ));
    let table = |extra: &str| -> AuthSection {
        toml::from_str(&format!(
            "[[issuer]]\nissuer = \"https://as.example.org\"\nkind = \"persons\"\naudience = [\"a\"]\n{extra}"
        ))
        .expect("parses")
    };
    assert!(matches!(
        table("clock_skew = \"301s\"").resolve(),
        Err(ConfigError::Issuer { .. })
    ));
    assert!(matches!(
        table("algorithms = [\"HS256\"]").resolve(),
        Err(ConfigError::Issuer { .. })
    ));
    let off: AuthSection = toml::from_str("enabled = false").expect("parses");
    assert_eq!(
        off.resolve().expect("resolves").issuers,
        Vec::<Settings>::new()
    );
    let both: AuthSection = toml::from_str(
        r#"
        [[issuer]]
        issuer = "https://as.example.org"
        kind = "persons"
        audience = ["a"]
        [[basic.users]]
        user = "etl"
        password_hash = "$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljLXNhbHQtMTY$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        password_hash_file = "/run/secrets/etl.phc"
        "#,
    )
    .expect("parses");
    assert!(matches!(both.resolve(), Err(ConfigError::Secret { .. })));
}

#[test]
fn the_credentials_table_is_basic_or_oauth_and_never_both() {
    let basic: CredentialsSection =
        toml::from_str("user = \"bridge\"\npassword = \"synthetic\"").expect("parses");
    assert!(matches!(basic.resolve(), Ok(Some(Outbound::Basic(_)))));
    let empty: CredentialsSection = toml::from_str("").expect("parses");
    assert!(matches!(empty.resolve(), Ok(None)));
    let both: CredentialsSection = toml::from_str(
        "user = \"bridge\"\npassword = \"x\"\n[oauth]\nissuer = \"https://as.example.org\"\nclient_id = \"c\"\nclient_secret = \"s\"",
    )
    .expect("parses");
    assert!(matches!(both.resolve(), Err(ConfigError::Exclusive { .. })));
    let oauth: CredentialsSection = toml::from_str(
        r#"
        [oauth]
        token_endpoint = "https://as.example.org/token"
        client_id = "ferrobridge"
        client_auth = "client_secret_post"
        client_secret = "synthetic"
        scope = "system/CodeSystem.rs"
        resource = "https://term.example.org/fhir"
        refresh_margin = "5s"
        "#,
    )
    .expect("parses");
    let Ok(Some(Outbound::Oauth(grant))) = oauth.resolve() else {
        panic!("the grant resolves");
    };
    assert_eq!(ClientAuth::ClientSecretPost, grant.client_auth);
    assert!(matches!(grant.endpoint, Endpoint::Token(_)));
    assert_eq!(Some(String::from("system/CodeSystem.rs")), grant.scope);
    assert_eq!(Duration::from_millis(5000), grant.refresh_margin);
    let keyless: CredentialsSection = toml::from_str(
        "[oauth]\nissuer = \"https://as.example.org\"\nclient_id = \"c\"\nclient_auth = \"private_key_jwt\"",
    )
    .expect("parses");
    assert!(matches!(
        keyless.resolve(),
        Err(ConfigError::Missing {
            key: "credentials.oauth.private_key_file"
        })
    ));
    let two: CredentialsSection = toml::from_str(
        "[oauth]\nissuer = \"https://as.example.org\"\ntoken_endpoint = \"https://as.example.org/token\"\nclient_id = \"c\"\nclient_secret = \"s\"",
    )
    .expect("parses");
    assert!(matches!(two.resolve(), Err(ConfigError::Exclusive { .. })));
}

#[test]
fn a_capability_is_one_smart_defines_or_a_full_uri() {
    let section = one_issuer(
        r#"capabilities = ["launch-ehr", "context-openehr-episode", "https://example.org/capability/x"]"#,
    );
    let resolved = section.resolve().expect("every capability is defined");
    assert_eq!(3, resolved.capabilities.len());
    for capability in ["launch-anything", "permission-v3", "x:y", "two words", ""] {
        let section = AuthSection {
            capabilities: vec![String::from(capability)],
            ..AuthSection::default()
        };
        assert!(
            matches!(section.resolve(), Err(ConfigError::Capability { .. })),
            "SMART App Launch 2.2.0, Conformance, Capabilities reserves {capability:?}"
        );
    }
}

#[test]
fn the_product_scope_is_an_extension_scope() {
    let section = one_issuer("product_scope = \"__ferro.operator\"");
    assert_eq!(
        Some(String::from("__ferro.operator")),
        section.resolve().expect("resolves").product_scope
    );
    let none = one_issuer("");
    assert_eq!(None, none.resolve().expect("resolves").product_scope);
    for scope in ["ferro.operator", "system/*.rs", "__", "__two words"] {
        let section = AuthSection {
            product_scope: String::from(scope),
            ..AuthSection::default()
        };
        assert!(
            matches!(section.resolve(), Err(ConfigError::ProductScope { .. })),
            "SMART App Launch 2.2.0, Scopes and Launch Context, Extensibility refuses {scope:?}"
        );
    }
}

#[test]
fn the_listed_scopes_reach_the_discovery_options() {
    let section = one_issuer(
        "capabilities = [\"launch-ehr\"]\nscopes_supported = [\"system/Condition.rs\", \"openid\"]",
    );
    let options = section.resolve().expect("resolves").smart_options();
    assert_eq!(
        vec![String::from("system/Condition.rs"), String::from("openid")],
        options.scopes_supported
    );
    assert_eq!(vec![String::from("launch-ehr")], options.capabilities);
    assert!(
        options.permissions.is_empty(),
        "the product declares the permission capabilities its routes enforce"
    );
    let bad = AuthSection {
        scopes_supported: vec![String::from("two words")],
        ..AuthSection::default()
    };
    assert!(matches!(bad.resolve(), Err(ConfigError::Scope { .. })));
}

#[test]
fn the_grant_checks_its_issuer_and_resource_at_load() {
    let grant = |extra: &str| -> Result<Option<Outbound>, ConfigError> {
        let section: CredentialsSection = toml::from_str(&format!(
            "[oauth]\nclient_id = \"c\"\nclient_secret = \"s\"\n{extra}"
        ))
        .expect("parses");
        section.resolve()
    };
    assert!(matches!(
        grant("issuer = \"https://as.example.org/realms/ferro\""),
        Ok(Some(Outbound::Oauth(_)))
    ));
    for issuer in [
        "http://as.example.org",
        "https://as.example.org/?realm=ferro",
        "https://as.example.org/#ferro",
        "not a url",
    ] {
        assert!(
            matches!(
                grant(&format!("issuer = \"{issuer}\"")),
                Err(ConfigError::OauthIssuer { .. })
            ),
            "RFC 8414 §2 refuses {issuer:?}"
        );
    }
    let endpoint = "token_endpoint = \"https://as.example.org/token\"";
    assert!(matches!(
        grant(&format!(
            "{endpoint}\nresource = \"https://term.example.org/fhir\""
        )),
        Ok(Some(Outbound::Oauth(_)))
    ));
    assert!(
        matches!(
            grant(&format!(
                "{endpoint}\nresource = \"https://term.example.org/fhir#x\""
            )),
            Err(ConfigError::Fragment {
                key: "credentials.oauth.resource"
            })
        ),
        "RFC 8707 §2: the URI MUST NOT include a fragment component"
    );
}

/// A synthetic Argon2id PHC string, which verifies no password.
const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljLXNhbHQtMTY$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn an_enabled_section_with_basic_users_and_no_issuer_is_basic_only() {
    let section: AuthSection = toml::from_str(&format!(
        r#"
        enabled = true
        [basic]
        cache_ttl = "30s"
        [[basic.users]]
        user = "etl"
        password_hash = "{PHC}"
        scopes = ["user/*.rs"]
        "#
    ))
    .expect("the section parses");
    let resolved = section.resolve().expect("a Basic-only section resolves");
    assert!(resolved.enabled);
    assert!(resolved.issuers.is_empty(), "no issuer");
    assert_eq!(1, resolved.basic.as_ref().map_or(0, PasswordStore::len));
}

#[test]
fn an_enabled_section_that_admits_no_credential_fails_closed() {
    for text in [
        "enabled = true",
        "enabled = true\n[basic]\nusers = []",
        "enabled = true\nissuer = []",
        "enabled = true\nissuer = []\n[basic]\nusers = []",
    ] {
        let section: AuthSection = toml::from_str(text).expect("parses");
        assert!(
            matches!(
                section.resolve(),
                Err(ConfigError::Missing { key: "auth.issuer" })
            ),
            "{text}"
        );
    }
}

#[test]
fn a_rendered_section_carries_every_key_and_no_secret() {
    let auth: AuthSection = toml::from_str(&format!(
        r#"
        scopeless_subjects = [{{ issuer = "https://as.example.org", sub = "svc" }}]
        [[issuer]]
        issuer = "https://as.example.org"
        kind = "persons"
        audience = ["https://fhir.example.org"]
        [[basic.users]]
        user = "etl"
        password_hash = "{PHC}"
        [[basic.users]]
        user = "ops"
        password_hash_file = "/run/secrets/ops.phc"
        "#
    ))
    .expect("parses");
    let credentials: CredentialsSection = toml::from_str(
        r#"
        user = "bridge"
        password = "synthetic-basic-password"
        "#,
    )
    .expect("parses");
    let oauth: CredentialsSection = toml::from_str(
        r#"
        [oauth]
        token_endpoint = "https://as.example.org/token"
        client_id = "ferro"
        client_secret = "synthetic-client-secret"
        "#,
    )
    .expect("parses");
    let rendered = [
        serde_json::to_string(&auth).expect("serializes"),
        serde_json::to_string(&credentials).expect("serializes"),
        serde_json::to_string(&oauth).expect("serializes"),
        toml::to_string(&auth).expect("renders as TOML"),
        toml::to_string(&oauth).expect("renders as TOML"),
    ];
    for text in &rendered {
        for secret in [PHC, "synthetic-basic-password", "synthetic-client-secret"] {
            assert!(!text.contains(secret), "a secret is rendered: {text}");
        }
    }
    let auth_json = serde_json::to_value(&auth).expect("serializes");
    assert_eq!(
        serde_json::json!("***"),
        auth_json["basic"]["users"][0]["password_hash"]
    );
    assert_eq!(
        serde_json::json!("/run/secrets/ops.phc"),
        auth_json["basic"]["users"][1]["password_hash_file"],
        "a path is no secret"
    );
    assert!(
        auth_json["basic"]["users"][1]
            .get("password_hash")
            .is_none()
    );
    assert_eq!(
        serde_json::json!([{ "issuer": "https://as.example.org", "sub": "svc" }]),
        auth_json["scopeless_subjects"]
    );
    let oauth_json = serde_json::to_value(&oauth).expect("serializes");
    assert_eq!(
        serde_json::json!("***"),
        oauth_json["oauth"]["client_secret"]
    );
    assert_eq!(serde_json::json!("ferro"), oauth_json["oauth"]["client_id"]);
    let read_back: AuthSection =
        toml::from_str(&rendered[3]).expect("the rendering reads back as a section");
    assert_eq!(
        Some("https://as.example.org"),
        read_back.issuer.first().map(|entry| entry.issuer.as_str()),
        "the issuer reads back"
    );
}

/// The userinfo of a token endpoint or an issuer never reaches a rendering
/// of the section, serialized or `Debug`.
#[test]
fn the_grant_masks_the_userinfo_of_its_urls() {
    let oauth = ferrohealth_smart::config::credentials::OauthSection {
        token_endpoint: String::from("https://u:URL_PW_SENTINEL@idp.example.org/token"),
        client_id: String::from("svc"),
        ..ferrohealth_smart::config::credentials::OauthSection::default()
    };
    let rendered = toml::to_string(&oauth).expect("renders");
    let debug = format!("{oauth:?}");
    for shown in [&rendered, &debug] {
        assert!(!shown.contains("URL_PW_SENTINEL"), "{shown}");
        assert!(shown.contains("idp.example.org/token"), "{shown}");
    }
    let issuer = ferrohealth_smart::config::credentials::OauthSection {
        issuer: String::from("https://a:ISSUER_PW_SENTINEL@as.example.org"),
        ..ferrohealth_smart::config::credentials::OauthSection::default()
    };
    assert!(
        !toml::to_string(&issuer)
            .expect("renders")
            .contains("ISSUER_PW_SENTINEL")
    );
}

/// Every problem of a grant is named under the product's own table, at once.
#[test]
fn the_grant_names_every_problem_under_the_products_table() {
    let empty = ferrohealth_smart::config::credentials::OauthSection::default();
    let problems = empty.problems("terminology.server.oauth");
    let joined = problems.join("\n");
    for key in [
        "terminology.server.oauth: set issuer or token_endpoint",
        "terminology.server.oauth.client_id",
        "terminology.server.oauth requires client_secret or client_secret_file",
    ] {
        assert!(joined.contains(key), "{key} unnamed in {joined}");
    }
    assert!(!joined.contains("credentials.oauth"), "{joined}");
    let both = ferrohealth_smart::config::credentials::OauthSection {
        issuer: String::from("https://as.example.org"),
        token_endpoint: String::from("https://as.example.org/token"),
        client_id: String::from("svc"),
        client_secret: Some(secrecy::SecretString::from("s")),
        client_secret_file: Some(std::path::PathBuf::from("/run/secret")),
        resource: String::from("https://rs.example.org/#frag"),
        ..ferrohealth_smart::config::credentials::OauthSection::default()
    };
    let problems = both.problems("audit.fhir_feed.oauth").join("\n");
    for key in [
        "set one of issuer and token_endpoint",
        "set one of client_secret and client_secret_file",
        "audit.fhir_feed.oauth.resource carries a fragment",
    ] {
        assert!(problems.contains(key), "{key} unnamed in {problems}");
    }
    let mutual = ferrohealth_smart::config::credentials::OauthSection {
        token_endpoint: String::from("https://as.example.org/token"),
        client_id: String::from("svc"),
        client_auth: ClientAuth::TlsClientAuth,
        ..ferrohealth_smart::config::credentials::OauthSection::default()
    };
    let problems = mutual.problems("audit.fhir_feed.oauth").join("\n");
    assert!(
        problems.contains(
            "audit.fhir_feed.oauth.tls.client_identity_file is required by a mutual-TLS client_auth"
        ),
        "{problems}"
    );
    let sound = ferrohealth_smart::config::credentials::OauthSection {
        token_endpoint: String::from("https://as.example.org/token"),
        client_id: String::from("svc"),
        client_secret: Some(secrecy::SecretString::from("s")),
        ..ferrohealth_smart::config::credentials::OauthSection::default()
    };
    assert_eq!(sound.problems("x"), Vec::<String>::new());
}

#[test]
fn the_basic_cache_keeps_a_verified_credential_for_five_minutes_unless_set_to_zero() {
    let five = ferrohealth_config::units::Duration::from_mins(5);
    let defaulted: BasicSection = toml::from_str("users = []").expect("the section parses");
    assert_eq!(five, defaulted.cache_ttl);
    assert_eq!(five, BasicSection::default().cache_ttl);
    let off: BasicSection =
        toml::from_str("users = []\ncache_ttl = \"0s\"").expect("the section parses");
    assert!(off.cache_ttl.is_zero());
}

#[test]
fn a_misspelt_key_in_an_issuer_entry_is_refused_by_its_name() {
    let refused = toml::from_str::<AuthSection>(
        r#"
        [[issuer]]
        issuer = "https://one.example.org"
        kind = "persons"
        jwks_fiel = "/etc/ferro/one.jwks"
        "#,
    )
    .expect_err("an unknown key in an issuer entry is refused");
    assert!(
        refused.to_string().contains("jwks_fiel"),
        "the refusal names the key: {refused}"
    );
}

#[test]
fn an_issuer_that_is_neither_a_string_nor_a_list_is_refused() {
    let refused = toml::from_str::<AuthSection>("issuer = 7\n").expect_err("a number is no issuer");
    assert!(
        refused.to_string().contains("expected a sequence"),
        "the refusal says what the key takes: {refused}"
    );
}

// NOTE: a Basic credential is a person's (owner ruling on #215); a `system/` scope is a backend
// service's (SMART App Launch 2.2.0, Scopes and Launch Context), so the section refuses it (#274).
#[test]
fn a_basic_user_with_a_system_scope_fails_to_load_naming_the_user_and_the_scope() {
    let section: AuthSection = toml::from_str(&format!(
        r#"
        enabled = true
        [[basic.users]]
        user = "batch-loader"
        password_hash = "{PHC}"
        scopes = ["user/CodeSystem.r", "system/CodeSystem.cud"]
        "#
    ))
    .expect("the section parses");
    let refused = section.resolve();
    let Err(ConfigError::Basic { source }) = &refused else {
        panic!("a Basic refusal, not {refused:?}");
    };
    let StoreError::SystemScope { username, scope } = source else {
        panic!("a system scope, not {source:?}");
    };
    assert_eq!("batch-loader", username);
    assert_eq!("system/CodeSystem.cud", scope);
    let message = source.to_string();
    assert!(
        message.contains("batch-loader") && message.contains("system/CodeSystem.cud"),
        "{message}"
    );
}

/// Returns an enabled section with one `persons` issuer at `issuer`, its
/// key set read from `jwks_file` when one is given.
fn issuer_at(issuer: &str, jwks_file: Option<&std::path::Path>) -> AuthSection {
    let file = jwks_file.map_or_else(String::new, |path| {
        format!("jwks_file = {:?}\n", path.display().to_string())
    });
    toml::from_str(&format!(
        "enabled = true\n[[issuer]]\nissuer = \"{issuer}\"\nkind = \"persons\"\naudience = [\"a\"]\n{file}"
    ))
    .expect("the section parses")
}

#[test]
fn an_issuer_with_userinfo_is_refused_masked() {
    for issuer in [
        "https://user:hunter2@as.example.org",
        "https://user@as.example.org/realms/x",
    ] {
        let refused = issuer_at(issuer, None).resolve();
        let Err(ConfigError::IssuerUserinfo { issuer: shown }) = &refused else {
            panic!("{issuer} is refused for its userinfo, got {refused:?}");
        };
        assert!(
            !shown.contains("hunter2") && !shown.contains("user@"),
            "{shown}"
        );
        let message = refused.map(|_| ()).unwrap_err().to_string();
        assert!(!message.contains("hunter2"), "{message}");
    }
}

#[test]
fn a_jwks_file_with_a_symmetric_key_is_refused_naming_the_key() {
    let file = crate::support::temp_file(
        "symmetric.jwks",
        br#"{"keys":[{"kty":"RSA","kid":"rsa","n":"AQAB","e":"AQAB"},{"kty":"oct","kid":"shared","k":"c2VjcmV0"}]}"#,
    );
    let refused = issuer_at("https://as.example.org", Some(&file)).resolve();
    assert!(
        matches!(
            &refused,
            Err(ConfigError::JwksSymmetricKey { index: 1, kid: Some(kid), .. }) if kid == "shared"
        ),
        "{refused:?}"
    );
    assert!(!format!("{refused:?}").contains("c2VjcmV0"));
}

#[test]
fn a_jwks_file_with_private_key_material_is_refused_naming_the_member() {
    let file = crate::support::temp_file(
        "private.jwks",
        br#"{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA","d":"cHJpdmF0ZQ"}]}"#,
    );
    let refused = issuer_at("https://as.example.org", Some(&file)).resolve();
    assert!(
        matches!(
            &refused,
            Err(ConfigError::JwksPrivateKey {
                index: 0,
                kid: None,
                member: "d",
                ..
            })
        ),
        "{refused:?}"
    );
    assert!(
        !refused
            .map(|_| ())
            .unwrap_err()
            .to_string()
            .contains("cHJpdmF0ZQ")
    );
}

#[test]
fn a_basic_hash_below_the_owasp_floor_is_refused_naming_the_user_and_the_floor() {
    for weak in ["m=8,t=1,p=1", "m=19456,t=1,p=1", "m=19455,t=2,p=1"] {
        let phc = PHC.replace("m=19456,t=2,p=1", weak);
        let section: AuthSection = toml::from_str(&format!(
            "enabled = true\n[[basic.users]]\nuser = \"etl\"\npassword_hash = \"{phc}\"\n"
        ))
        .expect("the section parses");
        let refused = section.resolve();
        let Err(ConfigError::Basic {
            source: source @ StoreError::Weak { username, .. },
        }) = &refused
        else {
            panic!("{weak} is refused as weak, got {refused:?}");
        };
        assert_eq!(username, "etl");
        assert!(source.to_string().contains("m=19456,t=2,p=1"), "{source}");
    }
}
