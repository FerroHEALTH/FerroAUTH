// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Responses FerroSMART accepts, in each shape the profile admits.

use ferrosmart::saml::response::check_post;

use super::kit::{Assertion, Data, IDP, KIT, STRONG, at, encrypt, expect, posted, response, sign};

#[test]
fn a_signed_assertion_in_an_unsigned_response_logs_the_person_in() {
    let login = check_post(
        &posted(&response(&Assertion::default().signed())),
        &expect(),
    )
    .expect("accepted");
    assert_eq!(login.issuer, IDP);
    assert_eq!(login.name_id.value, "person-17");
    assert_eq!(
        login.name_id.format.as_deref(),
        Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
    );
    assert_eq!(login.authn_context, STRONG);
    assert_eq!(login.attribute("role"), ["clinician", "nurse"]);
    assert_eq!(login.session_index.as_deref(), Some("_s1"));
    assert_eq!(login.assertion_id, "_assertion1");
    assert_eq!(login.confirmable_until.to_string(), at(300));
}

#[test]
fn an_unsigned_assertion_in_a_signed_response_is_covered_by_it() {
    let signed = sign(&response(&Assertion::default().xml()), &KIT.idp);
    let login = check_post(&posted(&signed), &expect()).expect("accepted");
    assert_eq!(login.name_id.value, "person-17");
}

#[test]
fn both_signed_is_accepted() {
    let signed = sign(&response(&Assertion::default().signed()), &KIT.idp);
    assert!(check_post(&posted(&signed), &expect()).is_ok());
}

#[test]
fn a_signed_assertion_encrypted_with_aes_gcm_is_decrypted() {
    let encrypted = encrypt(
        "EncryptedAssertion",
        &Assertion::default().signed(),
        Data::Gcm,
    );
    let login = check_post(&posted(&response(&encrypted)), &expect()).expect("accepted");
    assert_eq!(login.name_id.value, "person-17");
}

#[test]
fn an_assertion_encrypted_with_aes_cbc_in_a_signed_response_is_decrypted() {
    let encrypted = encrypt("EncryptedAssertion", &Assertion::default().xml(), Data::Cbc);
    let signed = sign(&response(&encrypted), &KIT.idp);
    assert!(check_post(&posted(&signed), &expect()).is_ok());
}

#[test]
fn an_encrypted_id_and_an_encrypted_attribute_are_decrypted() {
    let name_id = encrypt(
        "EncryptedID",
        "<saml:NameID xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" NameQualifier=\"urn:example:id\">secret-9</saml:NameID>",
        Data::Gcm,
    );
    let attribute = encrypt(
        "EncryptedAttribute",
        "<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"number\"><saml:AttributeValue>42</saml:AttributeValue></saml:Attribute>",
        Data::Gcm,
    );
    let assertion = Assertion {
        subject: name_id,
        attributes: attribute,
        ..Assertion::default()
    };
    let login = check_post(&posted(&response(&assertion.signed())), &expect()).expect("accepted");
    assert_eq!(login.name_id.value, "secret-9");
    assert_eq!(
        login.name_id.name_qualifier.as_deref(),
        Some("urn:example:id")
    );
    assert_eq!(login.attribute("number"), ["42"]);
}

#[test]
fn an_attribute_value_holding_a_name_id_gives_its_text() {
    let assertion = Assertion {
        attributes: String::from(
            "<saml:Attribute Name=\"targeted\"><saml:AttributeValue><saml:NameID>t-1</saml:NameID></saml:AttributeValue></saml:Attribute>",
        ),
        ..Assertion::default()
    };
    let login = check_post(&posted(&response(&assertion.signed())), &expect()).expect("accepted");
    assert_eq!(login.attribute("targeted"), ["t-1"]);
}

#[test]
fn a_one_time_use_condition_and_a_line_wrapped_form_value_are_accepted() {
    let assertion = Assertion {
        extra_conditions: String::from("<saml:OneTimeUse/>"),
        ..Assertion::default()
    };
    let encoded = posted(&response(&assertion.signed()));
    let mut wrapped = String::new();
    for line in encoded.as_bytes().chunks(76) {
        wrapped.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        wrapped.push_str("\r\n");
    }
    assert!(check_post(&wrapped, &expect()).is_ok());
}

#[test]
fn an_assertion_signed_with_ecdsa_by_a_published_key_is_accepted() {
    let p256 = super::kit::p256_pem();
    let key = ferrosmart::saml::keys::SigningKey::from_pem(
        p256.key.as_bytes(),
        p256.certificate.as_bytes(),
    )
    .expect("a key");
    let provider = ferrosmart::saml::metadata::IdentityProvider::from_metadata(
        &super::kit::metadata(&[&p256.der], ""),
        IDP,
        super::kit::now(),
        None,
    )
    .expect("metadata");
    let expectations = ferrosmart::saml::response::Expectations {
        idp: &provider,
        ..expect()
    };
    let signed = sign(&Assertion::default().xml(), &key);
    assert!(check_post(&posted(&response(&signed)), &expectations).is_ok());
}
