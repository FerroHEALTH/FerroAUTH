// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A response FerroSMART did not sign: the assertion's canonical form was
//! written by libxml2 (`xmllint --exc-c14n`), its digest and signature by
//! `openssl dgst -sha256 [-sign]`, so the case holds the canonicalization,
//! the digest and the signature check against independent tools. Only the
//! identity provider's certificate is committed beside it; its key was
//! thrown away once the response was signed.

use ferrosmart::saml::metadata::IdentityProvider;
use ferrosmart::saml::response::{Expectations, check_post};

use super::kit::{IDP, expect, metadata, now, pem_der, posted};

const RESPONSE: &str = include_str!("interop/libxml2-openssl-response.xml");
const CERTIFICATE: &str = include_str!("interop/idp-certificate.pem");

#[test]
fn a_response_signed_by_libxml2_and_openssl_is_accepted() {
    let der = pem_der(CERTIFICATE);
    let provider = IdentityProvider::from_metadata(&metadata(&[&der], ""), IDP, now(), None)
        .expect("metadata");
    let expectations = Expectations {
        idp: &provider,
        ..expect()
    };
    let login = check_post(&posted(RESPONSE), &expectations).expect("accepted");
    assert_eq!(login.name_id.value, "person-17");
    assert_eq!(login.attribute("role"), ["clinician & nurse"]);
}

#[test]
fn the_same_response_with_one_character_changed_is_refused() {
    let der = pem_der(CERTIFICATE);
    let provider = IdentityProvider::from_metadata(&metadata(&[&der], ""), IDP, now(), None)
        .expect("metadata");
    let expectations = Expectations {
        idp: &provider,
        ..expect()
    };
    let tampered = RESPONSE.replace("clinician &amp; nurse", "clinician &amp; nursE");
    assert_eq!(
        check_post(&posted(&tampered), &expectations).expect_err("refused"),
        ferrosmart::saml::Refusal::Digest
    );
}
