// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The attack corpus: every known shape of a forged, replayed, wrapped or
//! misdirected response, each refused with the refusal that names its
//! check. The XSW cases follow the eight signature wrapping shapes of
//! Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be"
//! (USENIX Security 2012).

use ferrosmart::saml::Refusal;
use ferrosmart::saml::response::check_post;

use super::kit::{
    Assertion, Data, KIT, REQUEST, WEAK, at, encrypt, expect, posted, response, response_with, sign,
};

/// Returns the refusal of the response `xml`.
fn refused(xml: &str) -> Refusal {
    check_post(&posted(xml), &expect()).expect_err("the response must be refused")
}

/// An assertion for the attacker's chosen subject, unsigned.
fn evil(id: &str) -> String {
    Assertion {
        id: String::from(id),
        subject: String::from("<saml:NameID>admin</saml:NameID>"),
        ..Assertion::default()
    }
    .xml()
}

/// Returns the `ds:Signature` element of `signed`.
fn signature_of(signed: &str) -> &str {
    let start = signed.find("<ds:Signature").expect("signed");
    let end = signed.find("</ds:Signature>").expect("signed") + "</ds:Signature>".len();
    signed.get(start..end).expect("on character boundaries")
}

#[test]
fn xsw1_the_signed_response_moved_into_its_own_signature_is_refused() {
    let signed = sign(&response(&Assertion::default().signed()), &KIT.idp);
    let original = signed.replace(signature_of(&signed), "");
    let object = format!("<ds:Object>{original}</ds:Object></ds:Signature>");
    let forged_signature = signature_of(&signed).replace("</ds:Signature>", &object);
    let forged = response(&evil("_evil")).replace(
        "<samlp:Status>",
        &format!("{forged_signature}<samlp:Status>"),
    );
    assert_eq!(refused(&forged), Refusal::DuplicateId);
}

#[test]
fn xsw1_with_fresh_ids_meets_the_object_refusal() {
    let signed = sign(&response(&Assertion::default().signed()), &KIT.idp);
    let object = "<ds:Object><x/></ds:Object></ds:Signature>";
    let forged = signed.replace("</ds:Signature>", object);
    assert_eq!(refused(&forged), Refusal::Structure("ds:Signature"));
}

#[test]
fn xsw2_the_signed_response_as_a_detached_sibling_is_refused() {
    let signed = sign(&response(&Assertion::default().signed()), &KIT.idp);
    let forged = response_with("_response1", REQUEST, "Success", &evil("_evil"))
        .replace("</samlp:Response>", &format!("{signed}</samlp:Response>"));
    assert_eq!(refused(&forged), Refusal::DuplicateId);
}

#[test]
fn xsw3_an_evil_assertion_before_the_signed_one_is_refused() {
    let assertions = format!("{}{}", evil("_evil"), Assertion::default().signed());
    assert_eq!(refused(&response(&assertions)), Refusal::MultipleAssertions);
}

#[test]
fn xsw4_the_signed_assertion_inside_an_evil_one_is_refused() {
    let wrapped = evil("_evil").replace(
        "</saml:Assertion>",
        &format!("{}</saml:Assertion>", Assertion::default().signed()),
    );
    assert_eq!(refused(&response(&wrapped)), Refusal::Wrapped);
}

#[test]
fn xsw5_the_signature_copied_onto_an_evil_assertion_is_refused() {
    let signed = Assertion::default().signed();
    let forged = evil("_evil").replace(
        "<saml:Subject>",
        &format!("{}<saml:Subject>", signature_of(&signed)),
    );
    assert_eq!(refused(&response(&forged)), Refusal::Wrapped);
}

#[test]
fn xsw5_with_the_original_id_meets_the_digest() {
    let signed = Assertion::default().signed();
    let forged = evil("_assertion1").replace(
        "<saml:Subject>",
        &format!("{}<saml:Subject>", signature_of(&signed)),
    );
    assert_eq!(refused(&response(&forged)), Refusal::Digest);
}

#[test]
fn xsw7_the_signed_assertion_hidden_in_extensions_is_refused() {
    let forged = response(&evil("_evil")).replace(
        "<samlp:Status>",
        &format!(
            "<samlp:Extensions>{}</samlp:Extensions><samlp:Status>",
            Assertion::default().signed()
        ),
    );
    assert_eq!(refused(&forged), Refusal::Wrapped);
}

#[test]
fn xsw8_the_signed_assertion_in_an_object_of_the_evil_ones_signature_is_refused() {
    let signed = Assertion::default().signed();
    let carrier = signature_of(&signed).replace(
        "</ds:Signature>",
        &format!("<ds:Object>{signed}</ds:Object></ds:Signature>"),
    );
    let forged = evil("_evil").replace("<saml:Subject>", &format!("{carrier}<saml:Subject>"));
    assert_eq!(refused(&response(&forged)), Refusal::Wrapped);
}

#[test]
fn an_unsigned_assertion_in_an_unsigned_response_is_refused() {
    assert_eq!(
        refused(&response(&Assertion::default().xml())),
        Refusal::Unprotected
    );
}

#[test]
fn an_unsigned_assertion_added_to_a_signed_response_is_refused() {
    let signed = sign(&response(&Assertion::default().xml()), &KIT.idp);
    let forged = signed.replace(
        "</samlp:Response>",
        &format!("{}</samlp:Response>", evil("_evil")),
    );
    assert_eq!(refused(&forged), Refusal::Digest);
}

#[test]
fn an_assertion_swapped_into_a_signed_response_is_refused() {
    let signed = sign(&response(&Assertion::default().xml()), &KIT.idp);
    let forged = signed.replace(
        "<saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">person-17",
        "<saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">admin",
    );
    assert_eq!(refused(&forged), Refusal::Digest);
}

#[test]
fn a_subject_changed_after_signing_is_refused() {
    let forged = Assertion::default().signed().replace("person-17", "admin");
    assert_eq!(refused(&response(&forged)), Refusal::Digest);
}

#[test]
fn a_signature_by_a_key_the_metadata_does_not_publish_is_refused() {
    let forged = sign(&Assertion::default().xml(), &KIT.stranger);
    assert_eq!(refused(&response(&forged)), Refusal::BadSignature);
}

#[test]
fn a_reference_to_another_id_is_refused() {
    let forged = Assertion::default()
        .signed()
        .replace("URI=\"#_assertion1\"", "URI=\"#_other\"");
    assert_eq!(refused(&response(&forged)), Refusal::Wrapped);
}

#[test]
fn a_comment_splitting_the_name_id_is_refused() {
    let signed = Assertion {
        subject: String::from("<saml:NameID>person@example.org.attacker.example</saml:NameID>"),
        ..Assertion::default()
    }
    .signed();
    let forged = signed.replace(
        "person@example.org.attacker.example",
        "person@example.org<!---->.attacker.example",
    );
    assert_eq!(
        refused(&response(&forged)),
        Refusal::Structure("saml:NameID")
    );
}

#[test]
fn a_second_signature_on_the_assertion_is_refused() {
    let signed = Assertion::default().signed();
    let forged = signed.replacen(
        "<saml:Subject>",
        &format!("{}<saml:Subject>", signature_of(&signed)),
        1,
    );
    assert_eq!(
        refused(&response(&forged)),
        Refusal::Structure("saml:Subject")
    );
}

#[test]
fn a_signature_object_is_refused() {
    let forged = Assertion::default().signed().replace(
        "</ds:Signature>",
        "<ds:Object><x/></ds:Object></ds:Signature>",
    );
    assert_eq!(
        refused(&response(&forged)),
        Refusal::Structure("ds:Signature")
    );
}

#[test]
fn sha1_rsa_and_a_sha1_digest_are_refused() {
    let signed = Assertion::default().signed();
    let sha1_signature = signed.replace(
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    );
    assert_eq!(
        refused(&response(&sha1_signature)),
        Refusal::Algorithm("signature")
    );
    let sha1_digest = signed.replace(
        "http://www.w3.org/2001/04/xmlenc#sha256",
        "http://www.w3.org/2000/09/xmldsig#sha1",
    );
    assert_eq!(
        refused(&response(&sha1_digest)),
        Refusal::Algorithm("digest")
    );
    let hmac = signed.replace(
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
    );
    assert_eq!(refused(&response(&hmac)), Refusal::Algorithm("signature"));
}

#[test]
fn canonicalization_with_comments_or_an_extra_transform_is_refused() {
    let signed = Assertion::default().signed();
    let with_comments = signed.replace(
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">",
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\">",
    );
    assert_eq!(
        refused(&response(&with_comments)),
        Refusal::Algorithm("canonicalization")
    );
    let xpath = signed.replace(
        "</ds:Transforms>",
        "<ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\"></ds:Transform></ds:Transforms>",
    );
    assert_eq!(refused(&response(&xpath)), Refusal::Algorithm("transform"));
}

#[test]
fn a_dtd_an_external_entity_and_entity_expansion_are_refused() {
    let signed = response(&Assertion::default().signed());
    for doctype in [
        "<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>",
        "<!DOCTYPE r SYSTEM \"https://attacker.example/r.dtd\">",
        "<!DOCTYPE r [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;\">]>",
    ] {
        assert_eq!(
            refused(&format!("{doctype}{signed}")),
            Refusal::Xml,
            "{doctype}"
        );
    }
}

#[test]
fn a_response_to_another_request_or_none_is_refused() {
    let assertion = Assertion::default().signed();
    assert_eq!(
        refused(&response_with("_r", "_another", "Success", &assertion)),
        Refusal::InResponseTo
    );
    let unsolicited = response(&assertion).replace(&format!(" InResponseTo=\"{REQUEST}\""), "");
    assert_eq!(refused(&unsolicited), Refusal::InResponseTo);
}

#[test]
fn a_confirmation_for_another_request_recipient_or_window_is_refused() {
    for assertion in [
        Assertion {
            in_response_to: String::from("_another"),
            ..Assertion::default()
        },
        Assertion {
            recipient: String::from("https://attacker.example/acs"),
            ..Assertion::default()
        },
        Assertion {
            confirm_until: at(-600),
            ..Assertion::default()
        },
    ] {
        assert_eq!(
            refused(&response(&assertion.signed())),
            Refusal::SubjectConfirmation
        );
    }
}

#[test]
fn a_wrong_audience_and_a_second_restriction_without_ferrosmart_are_refused() {
    let other = Assertion {
        audience: String::from("https://other.example.org/saml"),
        ..Assertion::default()
    };
    assert_eq!(refused(&response(&other.signed())), Refusal::Audience);
    let narrowed = Assertion {
        extra_conditions: String::from(
            "<saml:AudienceRestriction><saml:Audience>https://other.example.org/saml</saml:Audience></saml:AudienceRestriction>",
        ),
        ..Assertion::default()
    };
    assert_eq!(refused(&response(&narrowed.signed())), Refusal::Audience);
}

#[test]
fn an_expired_or_not_yet_valid_assertion_is_refused() {
    let expired = Assertion {
        not_on_or_after: at(-600),
        ..Assertion::default()
    };
    assert_eq!(refused(&response(&expired.signed())), Refusal::Expired);
    let early = Assertion {
        not_before: at(600),
        ..Assertion::default()
    };
    assert_eq!(refused(&response(&early.signed())), Refusal::NotYetValid);
}

#[test]
fn an_unknown_condition_is_refused() {
    let assertion = Assertion {
        extra_conditions: String::from(
            "<saml:Condition xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"x:Delegation\"/>",
        ),
        ..Assertion::default()
    };
    assert_eq!(refused(&response(&assertion.signed())), Refusal::Condition);
}

#[test]
fn another_issuer_is_refused() {
    let assertion = Assertion {
        issuer: String::from("https://attacker.example/saml"),
        ..Assertion::default()
    };
    assert_eq!(refused(&response(&assertion.signed())), Refusal::Issuer);
}

#[test]
fn another_destination_is_refused() {
    let forged = response(&Assertion::default().signed()).replace(
        "Destination=\"https://smart.example.org/saml/acs\"",
        "Destination=\"https://attacker.example/acs\"",
    );
    assert_eq!(refused(&forged), Refusal::Destination);
}

#[test]
fn a_failure_status_is_refused_with_its_code() {
    assert_eq!(
        refused(&response_with("_r", REQUEST, "Responder", "")),
        Refusal::Status(String::from("urn:oasis:names:tc:SAML:2.0:status:Responder"))
    );
}

#[test]
fn a_context_below_the_minimum_is_refused() {
    let assertion = Assertion {
        class: String::from(WEAK),
        ..Assertion::default()
    };
    assert_eq!(
        refused(&response(&assertion.signed())),
        Refusal::AuthnContext
    );
}

#[test]
fn advice_carrying_an_assertion_is_refused() {
    let forged = Assertion::default().xml().replace(
        "<saml:AuthnStatement",
        &format!(
            "<saml:Advice>{}</saml:Advice><saml:AuthnStatement",
            evil("_advice")
        ),
    );
    let forged = sign(&forged, &KIT.idp);
    assert_eq!(
        refused(&response(&forged)),
        Refusal::Structure("saml:Assertion")
    );
}

#[test]
fn cbc_data_without_a_covering_signature_is_refused_before_decryption() {
    let encrypted = encrypt(
        "EncryptedAssertion",
        &Assertion::default().signed(),
        Data::Cbc,
    );
    assert_eq!(refused(&response(&encrypted)), Refusal::UnprotectedCbc);
}

#[test]
fn an_unsigned_assertion_under_gcm_is_still_unprotected() {
    let encrypted = encrypt("EncryptedAssertion", &Assertion::default().xml(), Data::Gcm);
    assert_eq!(refused(&response(&encrypted)), Refusal::Unprotected);
}

#[test]
fn a_tampered_ciphertext_is_one_decryption_refusal() {
    let encrypted = encrypt(
        "EncryptedAssertion",
        &Assertion::default().signed(),
        Data::Gcm,
    );
    let start = encrypted.rfind("<xenc:CipherValue>").expect("data") + "<xenc:CipherValue>".len();
    let mut tampered = encrypted.clone();
    let flipped = if encrypted.get(start + 20..start + 21) == Some("A") {
        "B"
    } else {
        "A"
    };
    tampered.replace_range(start + 20..start + 21, flipped);
    assert_eq!(refused(&response(&tampered)), Refusal::Decryption);
}

#[test]
fn rsa_v1_5_key_transport_is_refused() {
    let encrypted = encrypt(
        "EncryptedAssertion",
        &Assertion::default().signed(),
        Data::Gcm,
    )
    .replace(
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
        "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
    );
    assert_eq!(
        refused(&response(&encrypted)),
        Refusal::Algorithm("key transport")
    );
}

#[test]
fn an_encrypted_key_for_another_recipient_is_not_used() {
    let encrypted = encrypt(
        "EncryptedAssertion",
        &Assertion::default().signed(),
        Data::Gcm,
    )
    .replace(
        "<xenc:EncryptedKey>",
        "<xenc:EncryptedKey Recipient=\"https://other.example.org/saml\">",
    );
    assert_eq!(
        refused(&response(&encrypted)),
        Refusal::Structure("xenc:EncryptedKey")
    );
}

#[test]
fn a_response_that_is_not_base64_is_refused() {
    assert_eq!(
        check_post("not base64!", &expect()).expect_err("refused"),
        Refusal::Encoding
    );
}
