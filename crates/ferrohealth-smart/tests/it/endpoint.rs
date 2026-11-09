// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The shared outbound endpoint table and the family configuration types:
//! the keys it reads, its defaults, its refusals, and the durations of the
//! other tables, with every retired key refused naming its replacement.

use ferrohealth_config::units::Duration;
use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::endpoint::EndpointSection;

#[test]
fn the_endpoint_table_reads_its_keys_and_keeps_its_defaults() {
    let table: EndpointSection = toml::from_str(
        "url = \"https://term.example.org/fhir\"\nconnect_timeout = \"2s\"\n\
         [retry]\nmax_attempts = 5\n[tls]\nmin_version = \"1.2\"\n\
         [credentials.oauth]\ntoken_endpoint = \"https://as.example.org/token\"\nclient_id = \"ehr\"\nclient_secret = \"synthetic\"\n",
    )
    .expect("the table parses");
    let url = table.validate().expect("the table is sound");
    assert_eq!("term.example.org", url.host_str().unwrap_or_default());
    assert_eq!(Duration::from_secs(10), table.timeout);
    assert_eq!(Some(Duration::from_secs(2)), table.connect_timeout);
    assert_eq!(5, table.retry.max_attempts);
    assert_eq!(Duration::from_millis(200), table.retry.initial_backoff);
    assert_eq!(Duration::from_secs(5), table.retry.max_backoff);
    assert!(
        table
            .credentials
            .resolve()
            .expect("the credential resolves")
            .is_some()
    );
}

#[test]
fn an_endpoint_table_that_breaks_a_rule_is_refused() {
    for text in [
        "",
        "url = \"not a url\"",
        "url = \"https://x.example.org\"\ntimeout = \"0s\"",
        "url = \"https://x.example.org\"\nconnect_timeout = \"0s\"",
        "url = \"https://x.example.org\"\n[retry]\nmax_attempts = 0",
        "url = \"https://x.example.org\"\n[retry]\ninitial_backoff = \"10s\"\nmax_backoff = \"1s\"",
    ] {
        let table: EndpointSection = toml::from_str(text).expect("the table parses");
        assert!(table.validate().is_err(), "{text:?} was accepted");
    }
    assert!(toml::from_str::<EndpointSection>("url = \"https://x\"\ntimeout = 30").is_err());
    assert!(toml::from_str::<EndpointSection>("base_url = \"https://x\"").is_err());
}

#[test]
fn the_issuer_durations_read_with_their_units_and_the_old_keys_are_refused() {
    let issuer =
        "[[issuer]]\nissuer = \"https://idp.example\"\nkind = \"persons\"\naudience = [\"a\"]\n";
    let section: AuthSection = toml::from_str(&format!(
        "{issuer}clock_skew = \"30s\"\njwks_max_age = \"1h\"\njwks_refresh_interval = \"5min\"\ntimeout = \"3s\"\n"
    ))
    .expect("the section parses");
    let entry = section.issuers().first().expect("one issuer");
    assert_eq!(Duration::from_secs(30), entry.clock_skew);
    assert_eq!(Duration::from_hours(1), entry.jwks_max_age);
    assert_eq!(Duration::from_mins(5), entry.jwks_refresh_interval);
    assert_eq!(Duration::from_secs(3), entry.timeout);
    let retired: AuthSection = toml::from_str(&format!(
        "{issuer}clock_skew_seconds = 30\ntimeout_ms = 500\n\n[basic]\ncache_ttl_seconds = 1\n"
    ))
    .expect("the section parses");
    let err = retired.resolve().expect_err("the old keys are refused");
    assert!(matches!(err, ConfigError::RemovedKeys(_)), "{err:?}");
    let shown = err.to_string();
    for line in [
        "auth.issuer[0].clock_skew_seconds was replaced by clock_skew",
        "auth.issuer[0].timeout_ms was replaced by timeout",
        "auth.basic.cache_ttl_seconds was replaced by auth.basic.cache_ttl",
    ] {
        assert!(shown.contains(line), "{line} in {shown}");
    }
    assert!(
        toml::from_str::<AuthSection>(&format!("{issuer}timeout = 500\n")).is_err(),
        "a bare number is no duration"
    );
}

#[cfg(feature = "schema")]
#[test]
fn the_schema_names_the_new_keys() {
    let auth = serde_json::to_value(schemars::schema_for!(AuthSection)).expect("the schema");
    let text = auth.to_string();
    for key in ["\"tls\"", "\"clock_skew\"", "\"cache_ttl\""] {
        assert!(text.contains(key), "{key} in the schema");
    }
    let endpoint =
        serde_json::to_value(schemars::schema_for!(EndpointSection)).expect("the schema");
    for key in [
        "url",
        "timeout",
        "connect_timeout",
        "retry",
        "tls",
        "credentials",
    ] {
        assert!(
            endpoint["properties"].get(key).is_some(),
            "{key} in {endpoint}"
        );
    }
}
