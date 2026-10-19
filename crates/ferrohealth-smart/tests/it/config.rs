// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The configuration sections: what each resolves to, and every rule that
//! refuses the start.

use std::time::Duration;

use ferrohealth_smart::client::ClientAuth;
use ferrohealth_smart::client::Endpoint;
use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::CredentialsSection;
use ferrohealth_smart::config::IssuerKey;
use ferrohealth_smart::config::Outbound;
use ferrohealth_smart::resource::TokenProfile;

#[test]
fn the_flat_form_is_one_issuer_with_the_sections_fields() {
    let section: AuthSection = toml::from_str(
        r#"
        issuer = "https://as.example.org/realms/ferro"
        audience = ["https://bridge.example.org/fhir"]
        token_profile = "jwt"
        clock_skew_seconds = 120
        realm = "ferrobridge"
        "#,
    )
    .expect("the section parses");
    let resolved = section.resolve().expect("the section resolves");
    assert_eq!(1, resolved.issuers.len());
    let settings = &resolved.issuers[0];
    assert_eq!("https://as.example.org/realms/ferro", settings.issuer);
    assert_eq!(
        vec![String::from("https://bridge.example.org/fhir")],
        settings.audience
    );
    assert_eq!(TokenProfile::Jwt, settings.profile);
    assert_eq!(Duration::from_secs(120), settings.clock_skew);
    assert_eq!(Duration::from_secs(600), settings.jwks_max_age);
    assert_eq!(Some(String::from("ferrobridge")), resolved.realm);
    assert!(resolved.basic.is_none());
}

#[test]
fn the_list_form_reads_each_entry_over_the_sections_defaults() {
    let section: AuthSection = toml::from_str(
        r#"
        audience = ["https://fed.example.org"]
        clock_skew_seconds = 30

        [[issuer]]
        issuer = "https://one.example.org"

        [[issuer]]
        issuer = "https://two.example.org"
        audience = ["https://other.example.org"]
        clock_skew_seconds = 10
        jwks_file = "/etc/ferro/two.jwks"
        "#,
    )
    .expect("the section parses");
    assert!(matches!(section.issuer, IssuerKey::List(ref entries) if entries.len() == 2));
    let resolved = section.resolve().expect("the section resolves");
    assert_eq!(2, resolved.issuers.len());
    assert_eq!(
        vec![String::from("https://fed.example.org")],
        resolved.issuers[0].audience
    );
    assert_eq!(Duration::from_secs(30), resolved.issuers[0].clock_skew);
    assert_eq!(
        vec![String::from("https://other.example.org")],
        resolved.issuers[1].audience
    );
    assert_eq!(Duration::from_secs(10), resolved.issuers[1].clock_skew);
    assert_eq!(
        Some(std::path::PathBuf::from("/etc/ferro/two.jwks")),
        resolved.issuers[1].jwks_file
    );
}

#[test]
fn a_section_that_breaks_a_rule_refuses_the_start() {
    let unknown = toml::from_str::<AuthSection>("jwks_refresh_interval_ms = 1000");
    assert!(unknown.is_err(), "deny_unknown_fields");
    let none: AuthSection = toml::from_str("audience = [\"a\"]").expect("parses");
    assert!(matches!(
        none.resolve(),
        Err(ConfigError::Missing { key: "auth.issuer" })
    ));
    let skew: AuthSection = toml::from_str(
        "issuer = \"https://as.example.org\"\naudience = [\"a\"]\nclock_skew_seconds = 301",
    )
    .expect("parses");
    assert!(matches!(skew.resolve(), Err(ConfigError::Issuer { .. })));
    let hmac: AuthSection = toml::from_str(
        "issuer = \"https://as.example.org\"\naudience = [\"a\"]\nalgorithms = [\"HS256\"]",
    )
    .expect("parses");
    assert!(matches!(hmac.resolve(), Err(ConfigError::Issuer { .. })));
    let off: AuthSection = toml::from_str("enabled = false").expect("parses");
    assert!(off.resolve().expect("resolves").issuers.is_empty());
    let both: AuthSection = toml::from_str(
        r#"
        issuer = "https://as.example.org"
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
        refresh_margin_ms = 5000
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
    let section: AuthSection = toml::from_str(
        r#"
        issuer = "https://as.example.org"
        audience = ["a"]
        capabilities = ["launch-ehr", "context-openehr-episode", "https://example.org/capability/x"]
        "#,
    )
    .expect("parses");
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
    let section: AuthSection = toml::from_str(
        "issuer = \"https://as.example.org\"\naudience = [\"a\"]\nproduct_scope = \"__ferro.operator\"",
    )
    .expect("parses");
    assert_eq!(
        Some(String::from("__ferro.operator")),
        section.resolve().expect("resolves").product_scope
    );
    let none: AuthSection =
        toml::from_str("issuer = \"https://as.example.org\"\naudience = [\"a\"]").expect("parses");
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
    let section: AuthSection = toml::from_str(
        r#"
        issuer = "https://as.example.org"
        audience = ["a"]
        capabilities = ["launch-ehr"]
        scopes_supported = ["system/Condition.rs", "openid"]
        "#,
    )
    .expect("parses");
    let options = section.resolve().expect("resolves").smart_options();
    assert_eq!(
        vec![String::from("system/Condition.rs"), String::from("openid")],
        options.scopes_supported
    );
    assert_eq!(vec![String::from("launch-ehr")], options.capabilities);
    assert!(
        !options.granular,
        "the product says whether it evaluates granular scopes"
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
