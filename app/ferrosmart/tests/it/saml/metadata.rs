// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The identity provider's metadata, read, and FerroSMART's, written.

use ferrosmart::saml::HTTP_REDIRECT;
use ferrosmart::saml::Refusal;
use ferrosmart::saml::metadata::{IdentityProvider, MetadataError, ServiceProvider};

use super::kit::{ACS, IDP, KIT, SP, metadata, now, sign, trusted};

fn read(xml: &str) -> Result<IdentityProvider, MetadataError> {
    IdentityProvider::from_metadata(xml, IDP, now(), None)
}

#[test]
fn the_keys_endpoints_and_request_signing_are_read() {
    let provider = read(&metadata(&[&KIT.idp_der], "")).expect("read");
    assert_eq!(provider.entity_id(), IDP);
    assert_eq!(provider.signing_keys().len(), 1);
    assert!(provider.want_authn_requests_signed());
    assert_eq!(
        provider.single_sign_on(HTTP_REDIRECT).map(url::Url::as_str),
        Some("https://idp.example.org/sso")
    );
    assert_eq!(
        provider.artifact_resolution(1).map(url::Url::as_str),
        Some("https://idp.example.org/ars")
    );
    assert!(provider.artifact_resolution(2).is_none());
    assert_eq!(provider.valid_until(), None);
}

#[test]
fn an_entity_inside_an_aggregate_is_found() {
    let aggregate = format!(
        "<md:EntitiesDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">{}</md:EntitiesDescriptor>",
        metadata(&[&KIT.idp_der], "")
    );
    assert!(read(&aggregate).is_ok());
}

#[test]
fn another_entity_is_not_found() {
    assert_eq!(
        IdentityProvider::from_metadata(
            &metadata(&[&KIT.idp_der], ""),
            "https://other.example.org/saml",
            now(),
            None
        )
        .expect_err("refused"),
        MetadataError::NoEntity
    );
}

#[test]
fn expired_metadata_is_refused() {
    let expired = metadata(&[&KIT.idp_der], "")
        .replace("entityID=", "validUntil=\"2026-11-19T09:00:00Z\" entityID=");
    assert_eq!(read(&expired).expect_err("refused"), MetadataError::Expired);
}

#[test]
fn metadata_without_a_usable_signing_key_is_refused() {
    assert_eq!(
        read(&metadata(&[], "")).expect_err("refused"),
        MetadataError::NoSigningKey
    );
    let encryption_only =
        metadata(&[&KIT.idp_der], "").replace("use=\"signing\"", "use=\"encryption\"");
    assert_eq!(
        read(&encryption_only).expect_err("refused"),
        MetadataError::NoSigningKey
    );
}

#[test]
fn a_plain_http_endpoint_is_refused() {
    let plain = metadata(&[&KIT.idp_der], "")
        .replace("https://idp.example.org/sso", "http://idp.example.org/sso");
    assert_eq!(read(&plain).expect_err("refused"), MetadataError::Location);
}

#[test]
fn signed_metadata_is_verified_when_its_keys_are_configured() {
    let publisher = [trusted(&KIT.idp_der)];
    let unsigned = metadata(&[&KIT.idp_der], "");
    assert_eq!(
        IdentityProvider::from_metadata(&unsigned, IDP, now(), Some(&publisher))
            .expect_err("refused"),
        MetadataError::Unsigned
    );
    let signed = sign(&unsigned, &KIT.idp);
    assert!(IdentityProvider::from_metadata(&signed, IDP, now(), Some(&publisher)).is_ok());
    let stranger = [trusted(&super::kit::rsa_pem().der)];
    assert!(matches!(
        IdentityProvider::from_metadata(&signed, IDP, now(), Some(&stranger)),
        Err(MetadataError::Refused(Refusal::BadSignature))
    ));
    let tampered = signed.replace(
        "https://idp.example.org/sso",
        "https://attacker.example/sso",
    );
    assert!(matches!(
        IdentityProvider::from_metadata(&tampered, IDP, now(), Some(&publisher)),
        Err(MetadataError::Refused(Refusal::Digest))
    ));
}

#[test]
fn the_service_provider_metadata_names_its_keys_and_endpoints() {
    let formats = [String::from(
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    )];
    let xml = ServiceProvider {
        entity_id: SP,
        acs_url: ACS,
        signing_key: &KIT.sp,
        decryption_keys: std::slice::from_ref(&KIT.decryption),
        name_id_formats: &formats,
    }
    .render();
    let document = roxmltree::Document::parse(&xml).expect("well formed");
    assert_eq!(document.root_element().attribute("entityID"), Some(SP));
    let uses: Vec<&str> = document
        .descendants()
        .filter(|node| node.has_tag_name("KeyDescriptor"))
        .filter_map(|node| node.attribute("use"))
        .collect();
    assert_eq!(uses, ["signing", "encryption"]);
    let bindings: Vec<&str> = document
        .descendants()
        .filter(|node| node.has_tag_name("AssertionConsumerService"))
        .filter_map(|node| node.attribute("Binding"))
        .collect();
    assert_eq!(
        bindings,
        [
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
        ]
    );
}
