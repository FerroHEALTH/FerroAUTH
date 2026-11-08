// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `[<lane>.credentials.onward]` table: one onward target per lane,
//! loaded under the `rfc9068`, `entra` and `keycloak` presets and a
//! `federation` issuer, authenticating with the lane's `oauth` grant, and
//! every incomplete table refused at load naming its key.

use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::credentials::CredentialsSection;
use ferrohealth_smart::config::onward::OnwardLane;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::profile::onward::OnwardGrant;
use ferrohealth_smart::profile::onward::OnwardIndicator;
use ferrohealth_smart::resource::ResourceError;
use wiremock::MockServer;
use wiremock::ResponseTemplate;

use super::ClientKey;
use super::answer;
use super::harness::ENTRA_CLIENT;
use super::harness::ENTRA_TARGET;
use super::harness::Flavor;
use super::param;
use super::received;
use super::sign;
use super::subject_of;
use crate::support::ec_key;
use crate::support::now;
use crate::support::temp_file;

/// Returns the lane table of `oauth` and `onward`, each the body of its
/// table.
fn lane(oauth: &str, onward: &str) -> CredentialsSection {
    toml::from_str(&format!("[oauth]\n{oauth}\n[onward]\n{onward}\n")).expect("the lane parses")
}

/// Returns the `oauth` body of a `private_key_jwt` client `client_id` whose
/// key is `client`'s.
fn private_key_jwt(client: &ClientKey, client_id: &str) -> String {
    let path = temp_file("onward-client.pem", &client.key.pem);
    format!(
        "issuer = \"https://as.example.org\"\nclient_id = \"{client_id}\"\nclient_auth = \"private_key_jwt\"\nprivate_key_file = \"{}\"\nkid = \"{}\"\nassertion_alg = \"ES384\"",
        path.display(),
        client.key.kid
    )
}

/// Returns the `oauth` body of a `client_secret_basic` client whose secret
/// is in a file.
fn secret_file(client_id: &str) -> String {
    let path = temp_file("onward-secret", b"password\n");
    format!(
        "issuer = \"https://as.example.org\"\nclient_id = \"{client_id}\"\nclient_secret_file = \"{}\"",
        path.display()
    )
}

/// Returns the lane resolved, or the refusal.
fn resolved(section: &CredentialsSection) -> Result<OnwardLane, ConfigError> {
    section
        .onward()
        .and_then(|lane| lane.ok_or(ConfigError::Missing { key: "onward" }))
}

#[tokio::test]
async fn a_standards_only_lane_loads_and_exchanges_at_its_token_endpoint() {
    let server = MockServer::start().await;
    let client = ClientKey::new();
    let section = lane(
        &private_key_jwt(&client, "bridge"),
        &format!(
            "issuer = \"https://as.example.org\"\nkind = \"persons\"\ntoken_endpoint = \"{}/token\"\n\
             audiences = [\"https://ehr.example.org\"]\nindicators = [\"https://ehr.example.org/api\"]\n\
             [onward.keys]\nmax_onward_lifetime = 3600\nfirst_party_clients = [\"portal\"]",
            server.uri()
        ),
    );
    let lane = resolved(&section).expect("the lane loads");
    assert_eq!(
        &["https://ehr.example.org".to_owned()],
        lane.target.audiences()
    );
    let key = ec_key("as-2026", jsonwebtoken::Algorithm::ES256);
    let claims = Flavor::Generic.subject_claims(now());
    let issued = Flavor::Generic.issued_claims(&claims, now());
    answer(
        &server,
        "/token",
        ResponseTemplate::new(200).set_body_json(Flavor::Generic.response(&sign(&key, &issued))),
    )
    .await;
    let subject = subject_of(&sign(&key, &claims), &claims, CallerKind::Person);
    lane.onward
        .token(&subject, None, &lane.target)
        .await
        .expect("the exchange succeeds");
    let sent = received(&server).await;
    let form = sent.first().expect("one request");
    assert_eq!(
        Some(OnwardGrant::TokenExchange.grant_type()),
        param(form, "grant_type")
    );
    assert_eq!(Some("https://ehr.example.org/api"), param(form, "resource"));
    client.verify(form, "bridge", &format!("{}/token", server.uri()));
}

/// Returns how many token requests two calls of a standards-only lane whose
/// onward table ends in `extra` send to its token endpoint.
async fn exchanges_for_two_calls(extra: &str) -> (bool, usize) {
    let server = MockServer::start().await;
    let section = lane(
        &private_key_jwt(&ClientKey::new(), "bridge"),
        &format!(
            "issuer = \"https://as.example.org\"\nkind = \"persons\"\ntoken_endpoint = \"{}/token\"\n\
             audiences = [\"https://ehr.example.org\"]\nindicators = [\"https://ehr.example.org/api\"]\n{extra}\n\
             [onward.keys]\nmax_onward_lifetime = 3600\nfirst_party_clients = [\"portal\"]",
            server.uri()
        ),
    );
    let lane = resolved(&section).expect("the lane loads");
    let key = ec_key("as-2026", jsonwebtoken::Algorithm::ES256);
    let claims = Flavor::Generic.subject_claims(now());
    let issued = Flavor::Generic.issued_claims(&claims, now());
    answer(
        &server,
        "/token",
        ResponseTemplate::new(200).set_body_json(Flavor::Generic.response(&sign(&key, &issued))),
    )
    .await;
    let subject = subject_of(&sign(&key, &claims), &claims, CallerKind::Person);
    for _ in 0..2 {
        lane.onward
            .token(&subject, None, &lane.target)
            .await
            .expect("the exchange succeeds");
    }
    (lane.onward.caches(), received(&server).await.len())
}

#[tokio::test]
async fn a_lane_with_the_cache_off_exchanges_on_every_call() {
    assert_eq!((false, 2), exchanges_for_two_calls("cache = false").await);
}

#[tokio::test]
async fn a_lane_holds_its_token_by_default() {
    assert_eq!((true, 1), exchanges_for_two_calls("").await);
    assert_eq!((true, 1), exchanges_for_two_calls("cache = true").await);
}

#[test]
fn an_entra_lane_loads_the_on_behalf_of_flow() {
    let section = lane(
        &private_key_jwt(&ClientKey::new(), ENTRA_CLIENT),
        &format!(
            "issuer = \"{}\"\nkind = \"persons\"\nprofile = \"entra\"\n\
             token_endpoint = \"https://login.microsoftonline.com/{}/oauth2/v2.0/token\"\n\
             audiences = [\"{ENTRA_TARGET}\"]\nscope = \"api://{ENTRA_TARGET}/.default\"\n\
             [onward.keys]\nmax_onward_lifetime = 5400",
            Flavor::Entra.issuer(),
            super::harness::TENANT
        ),
    );
    let lane = resolved(&section).expect("the lane loads");
    assert_eq!(
        Some(format!("api://{ENTRA_TARGET}/.default").as_str()),
        lane.target.scope()
    );
}

#[test]
fn a_keycloak_lane_loads_the_standard_exchange_with_a_secret_file() {
    let section = lane(
        &secret_file("requester-client"),
        "issuer = \"https://kc.example.org/realms/test\"\nkind = \"persons\"\nprofile = \"keycloak\"\n\
         token_endpoint = \"https://kc.example.org/realms/test/protocol/openid-connect/token\"\n\
         audiences = [\"target-client2\"]\nindicators = [\"target-client2\"]\nscope = \"optional-scope2\"\n\
         [onward.keys]\nmax_onward_lifetime = 300\napp_only = [{ subjects = [\"service-account-bridge\"] }]",
    );
    let lane = resolved(&section).expect("the lane loads");
    assert_eq!(&["target-client2".to_owned()], lane.target.indicators());
}

#[test]
fn a_federation_lane_loads_its_table_over_the_preset() {
    let section = lane(
        &private_key_jwt(&ClientKey::new(), "bridge"),
        "issuer = \"https://sts.partner.example.org\"\nkind = \"federation\"\n\
         audiences = [\"https://ehr.partner.example.org/openehr\"]\ncorrelation_claim = \"txn\"\n\
         [onward.keys]\nmax_onward_lifetime = 300\n\
         [onward.federation]\ncontact_point = false\nmapping = \"iua\"\ncountries = [\"NL\"]\n\
         issuing_authorities = [\"CIBG\"]\nprovider_identifier_prefixes = [\"urn:oid:2.16.528.1.1007.3.3.\"]\n\
         exchanges_from = [\"https://as.example.org\"]\nperson_mapping = \"hp_identifier\"\n\
         fields = { \"professional.country_code\" = [{ constant = \"NL\" }], \"professional.issuing_authority_name\" = [{ constant = \"CIBG\" }] }",
    );
    let lane = resolved(&section).expect("the lane loads");
    assert_eq!(Some("txn"), lane.target.correlation_claim());
}

#[test]
fn a_lane_without_an_onward_table_resolves_to_none() {
    let section: CredentialsSection =
        toml::from_str(&format!("[oauth]\n{}", secret_file("bridge"))).expect("the lane parses");
    assert!(matches!(section.onward(), Ok(None)));
}

#[test]
fn an_unknown_key_fails_to_parse() {
    let parsed: Result<CredentialsSection, _> =
        toml::from_str("[onward]\nissuer = \"https://as.example.org\"\ngrant = \"on_behalf_of\"");
    assert!(parsed.is_err(), "deny_unknown_fields");
}

/// A complete `persons` onward body, for the refusals to break.
const COMPLETE: &str = "issuer = \"https://as.example.org\"\nkind = \"persons\"\n\
    audiences = [\"https://ehr.example.org\"]\n[onward.keys]\nmax_onward_lifetime = 3600";

#[test]
fn an_incomplete_table_fails_to_load_naming_its_key() {
    for (key, body) in [
        (
            "credentials.onward.issuer",
            COMPLETE.replacen("issuer = \"https://as.example.org\"\n", "", 1),
        ),
        (
            "credentials.onward.kind",
            COMPLETE.replacen("kind = \"persons\"\n", "", 1),
        ),
        (
            "credentials.onward.audiences",
            COMPLETE.replacen("audiences = [\"https://ehr.example.org\"]\n", "", 1),
        ),
    ] {
        let refused = resolved(&lane(&secret_file("bridge"), &body));
        assert!(
            matches!(&refused, Err(ConfigError::Missing { key: missing }) if *missing == key),
            "{key}: {refused:?}"
        );
    }
}

#[test]
fn an_onward_table_without_the_lanes_oauth_fails_to_load() {
    let section: CredentialsSection =
        toml::from_str(&format!("[onward]\n{COMPLETE}")).expect("the lane parses");
    assert!(matches!(
        section.onward(),
        Err(ConfigError::Missing { key }) if key.starts_with("credentials.oauth")
    ));
    let basic: CredentialsSection = toml::from_str(&format!(
        "user = \"bridge\"\npassword = \"synthetic-pw\"\n[onward]\n{COMPLETE}"
    ))
    .expect("the lane parses");
    assert!(matches!(
        basic.onward(),
        Err(ConfigError::Exclusive {
            right: "credentials.onward",
            ..
        })
    ));
}

#[test]
fn an_issuer_the_onward_client_refuses_fails_to_load() {
    let cases = [
        (
            "no max_onward_lifetime",
            COMPLETE.replacen("max_onward_lifetime = 3600", "", 1),
        ),
        (
            "a machines issuer",
            COMPLETE.replacen("kind = \"persons\"", "kind = \"machines\"", 1),
        ),
        (
            "a federation table without exchanges_from",
            "issuer = \"https://sts.partner.example.org\"\nkind = \"federation\"\naudiences = [\"a\"]\n\
             [onward.keys]\nmax_onward_lifetime = 300\n[onward.federation]\ncontact_point = false\n\
             countries = [\"NL\"]\nissuing_authorities = [\"CIBG\"]\nprovider_identifier_prefixes = [\"urn:\"]\n\
             person_mapping = \"hp_identifier\""
                .to_owned(),
        ),
    ];
    for (case, body) in cases {
        let refused = resolved(&lane(&secret_file("bridge"), &body));
        assert!(
            matches!(&refused, Err(ConfigError::Onward { .. })),
            "{case}: {refused:?}"
        );
    }
}

#[test]
fn a_target_the_grant_cannot_ask_for_fails_to_load() {
    let cases = [
        (
            "offline_access",
            format!("{COMPLETE}\n").replacen(
                "audiences",
                "scope = \"read offline_access\"\naudiences",
                1,
            ),
            "OfflineAccess",
        ),
        (
            "a relative resource",
            COMPLETE.replacen("audiences", "indicators = [\"/api\"]\naudiences", 1),
            "Resource",
        ),
        (
            "the JWT bearer grant without a scope",
            format!("{COMPLETE}\nonward_grant = \"jwt_bearer\""),
            "NoScope",
        ),
    ];
    for (case, body, expected) in cases {
        let refused = resolved(&lane(&secret_file("bridge"), &body));
        let named = match &refused {
            Err(ConfigError::Onward { source }) => match **source {
                OnwardError::OfflineAccess => "OfflineAccess",
                OnwardError::Resource => "Resource",
                OnwardError::NoScope => "NoScope",
                _ => "another",
            },
            _ => "not refused by the onward client",
        };
        assert_eq!(expected, named, "{case}: {refused:?}");
    }
}

#[test]
fn a_profile_key_the_rules_refuse_fails_to_load_naming_the_issuer() {
    let refused = resolved(&lane(
        &secret_file("bridge"),
        &format!("{COMPLETE}\nonward_parameters = {{ scope = \"x\" }}"),
    ));
    assert!(
        matches!(&refused, Err(ConfigError::Issuer { issuer, source })
            if issuer == "https://as.example.org" && matches!(**source, ResourceError::Profile(_))),
        "{refused:?}"
    );
}

#[test]
fn the_presets_set_the_lanes_grant() {
    let entra = lane(
        &private_key_jwt(&ClientKey::new(), ENTRA_CLIENT),
        &format!(
            "issuer = \"{}\"\nkind = \"persons\"\nprofile = \"entra\"\naudiences = [\"{ENTRA_TARGET}\"]\n\
             [onward.keys]\nmax_onward_lifetime = 5400",
            Flavor::Entra.issuer()
        ),
    );
    let refused = resolved(&entra);
    assert!(
        matches!(&refused, Err(ConfigError::Onward { source }) if matches!(**source, OnwardError::NoScope)),
        "the entra preset is the JWT bearer grant, which needs a scope: {refused:?}"
    );
    let keycloak = lane(
        &secret_file("requester-client"),
        "issuer = \"https://kc.example.org/realms/test\"\nkind = \"persons\"\nprofile = \"keycloak\"\n\
         audiences = [\"target-client2\"]\nindicators = [\"target-client2\"]\n\
         [onward.keys]\nmax_onward_lifetime = 300\napp_only = [{ subjects = [\"service-account-bridge\"] }]",
    );
    assert!(
        resolved(&keycloak).is_ok(),
        "under keycloak an indicator is an audience, never a URI: {:?}",
        OnwardIndicator::Audience
    );
}
