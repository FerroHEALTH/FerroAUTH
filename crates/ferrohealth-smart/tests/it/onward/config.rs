// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The profile keys of the onward grants on `[[auth.issuer]]`, their
//! preset values, and the issuers an onward client refuses to build for.

use std::collections::BTreeMap;

use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::client::onward::exchange::Onward;
use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::profile::Preset;
use ferrohealth_smart::profile::Profile;
use ferrohealth_smart::profile::ProfileError;
use ferrohealth_smart::profile::ProfileKeys;
use ferrohealth_smart::profile::onward::OnwardGrant;
use ferrohealth_smart::profile::onward::OnwardIndicator;
use ferrohealth_smart::profile::onward::PreviewVariant;
use ferrohealth_smart::resource::ResourceError;
use ferrohealth_smart::resource::Settings;
use wiremock::MockServer;

use super::ClientKey;
use super::endpoint;

/// Returns the `[auth]` section of one `persons` issuer with `extra` keys.
fn section(extra: &str) -> AuthSection {
    toml::from_str(&format!(
        "[[issuer]]\nissuer = \"https://as.example.org\"\nkind = \"persons\"\naudience = [\"a\"]\n{extra}\n"
    ))
    .expect("the section parses")
}

#[test]
fn the_onward_keys_on_an_issuer_table_set_its_profile() {
    let resolved = section(
        "max_onward_lifetime = 900\nonward_grant = \"jwt_bearer\"\nonward_indicator = \"audience\"\n\
         onward_parameters = { requested_token_use = \"on_behalf_of\" }\n\
         onward_client_id = true\nonward_subject_audience = true\nonward_preview = [\"actor_token\"]",
    )
    .resolve()
    .expect("the section resolves");
    let profile = &resolved.issuers.first().expect("one issuer").profile;
    assert_eq!(Some(900), profile.max_onward_lifetime);
    assert_eq!(OnwardGrant::JwtBearer, profile.onward_grant);
    assert_eq!(OnwardIndicator::Audience, profile.onward_indicator);
    assert_eq!(
        BTreeMap::from([(
            String::from("requested_token_use"),
            String::from("on_behalf_of")
        )]),
        profile.onward_parameters
    );
    assert!(profile.onward_client_id && profile.onward_subject_audience);
    assert_eq!(vec![PreviewVariant::ActorToken], profile.onward_preview);
}

#[test]
fn a_parameter_the_client_writes_itself_fails_to_load() {
    for parameter in [
        "grant_type",
        "subject_token",
        "assertion",
        "scope",
        "client_id",
    ] {
        let refused = section(&format!("onward_parameters = {{ {parameter} = \"x\" }}")).resolve();
        assert!(
            matches!(&refused, Err(ConfigError::Issuer { source, .. }) if matches!(&**source, ResourceError::Profile(ProfileError::Reserved { parameter: named }) if named == parameter)),
            "{parameter}: {refused:?}"
        );
    }
}

#[test]
fn a_refresh_token_asked_for_fails_to_load() {
    let refused = section(
        "onward_parameters = { requested_token_type = \"urn:ietf:params:oauth:token-type:refresh_token\" }",
    )
    .resolve();
    assert!(
        matches!(&refused, Err(ConfigError::Issuer { source, .. })
            if matches!(**source, ResourceError::Profile(ProfileError::RefreshToken))),
        "{refused:?}"
    );
}

#[test]
fn a_zero_onward_lifetime_fails_to_load() {
    let refused = section("max_onward_lifetime = 0").resolve();
    assert!(
        matches!(&refused, Err(ConfigError::Issuer { source, .. })
            if matches!(**source, ResourceError::Profile(ProfileError::Empty { key: "max_onward_lifetime" }))),
        "{refused:?}"
    );
}

#[test]
fn the_presets_name_their_grants() -> Result<(), ProfileError> {
    let generic = Profile::resolve(Preset::Rfc9068, &ProfileKeys::default())?;
    assert_eq!(OnwardGrant::TokenExchange, generic.onward_grant);
    assert_eq!(OnwardIndicator::Resource, generic.onward_indicator);
    assert!(generic.onward_parameters.is_empty() && generic.onward_preview.is_empty());
    let entra = Profile::resolve(Preset::Entra, &ProfileKeys::default())?;
    assert_eq!(OnwardGrant::JwtBearer, entra.onward_grant);
    assert_eq!(
        Some("on_behalf_of"),
        entra
            .onward_parameters
            .get("requested_token_use")
            .map(String::as_str)
    );
    assert!(entra.onward_client_id && entra.onward_subject_audience);
    let keycloak = Profile::resolve(Preset::Keycloak, &ProfileKeys::default())?;
    assert_eq!(OnwardGrant::TokenExchange, keycloak.onward_grant);
    assert_eq!(OnwardIndicator::Audience, keycloak.onward_indicator);
    assert_eq!(vec![PreviewVariant::ActorToken], keycloak.onward_preview);
    for profile in [generic, entra, keycloak] {
        assert_eq!(
            None, profile.max_onward_lifetime,
            "no vendored source states a lifetime, so the deployment sets it"
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_issuer_without_max_onward_lifetime_refuses_to_build() {
    let server = MockServer::start().await;
    let settings = Settings::new("https://as.example.org", "bridge", IssuerKind::Persons);
    let built = Onward::new(
        settings,
        ClientKey::new().credentials(endpoint(&server, "/token"), "bridge"),
    );
    assert!(
        matches!(built, Err(OnwardError::MaxOnwardLifetime)),
        "{built:?}"
    );
}

#[tokio::test]
async fn only_a_persons_or_federation_issuer_issues_onward_tokens() {
    let server = MockServer::start().await;
    for kind in [IssuerKind::Machines, IssuerKind::Patients] {
        let mut settings = Settings::new("https://as.example.org", "bridge", kind);
        settings.profile.max_onward_lifetime = Some(600);
        let built = Onward::new(
            settings,
            ClientKey::new().credentials(endpoint(&server, "/token"), "bridge"),
        );
        assert!(
            matches!(&built, Err(OnwardError::IssuerKind { kind: refused }) if *refused == kind),
            "{kind}: {built:?}"
        );
    }
}

#[tokio::test]
async fn credentials_without_their_methods_credential_refuse_to_build() {
    let server = MockServer::start().await;
    let mut settings = Settings::new("https://as.example.org", "bridge", IssuerKind::Persons);
    settings.profile.max_onward_lifetime = Some(600);
    let mut credentials = ClientKey::new().credentials(endpoint(&server, "/token"), "bridge");
    credentials.assertion_key = None;
    let built = Onward::new(settings, credentials);
    assert!(matches!(built, Err(OnwardError::Token(_))), "{built:?}");
}
