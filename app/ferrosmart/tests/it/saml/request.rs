// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `AuthnRequest` and its HTTP-Redirect and HTTP-POST encodings.

use std::io::Read as _;

use aws_lc_rs::signature;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ferrosmart::saml::HTTP_ARTIFACT;
use ferrosmart::saml::request::AuthnRequest;
use url::form_urlencoded;

use super::kit::{ACS, CLASSES, KIT, REQUEST, SP, now};

fn request() -> AuthnRequest<'static> {
    AuthnRequest {
        id: REQUEST,
        issue_instant: now(),
        destination: "https://idp.example.org/sso?tenant=7",
        entity_id: SP,
        acs_url: ACS,
        protocol_binding: HTTP_ARTIFACT,
        force_authn: true,
        name_id_format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
        authn_contexts: &CLASSES,
    }
}

#[test]
fn the_request_asks_for_an_exact_class_and_a_fresh_login() {
    let xml = request().xml();
    let document = roxmltree::Document::parse(&xml).expect("well formed");
    let root = document.root_element();
    assert_eq!(root.attribute("ID"), Some(REQUEST));
    assert_eq!(root.attribute("ForceAuthn"), Some("true"));
    assert_eq!(root.attribute("AssertionConsumerServiceURL"), Some(ACS));
    assert_eq!(root.attribute("ProtocolBinding"), Some(HTTP_ARTIFACT));
    let requested = document
        .descendants()
        .find(|node| node.has_tag_name("RequestedAuthnContext"))
        .expect("asked for");
    assert_eq!(requested.attribute("Comparison"), Some("exact"));
    assert!(
        xml.contains("<saml:AuthnContextClassRef>urn:example:loa:high</saml:AuthnContextClassRef>")
    );
}

#[test]
fn the_redirect_is_deflated_and_its_query_signed_as_sent() {
    let url = request().redirect(&KIT.sp, "abc").expect("encoded");
    let query = url.query().expect("a query");
    let (kept, ours) = query.split_once('&').expect("the tenant is kept");
    assert_eq!(kept, "tenant=7");
    let (signed, signature_param) = ours.rsplit_once("&Signature=").expect("signed");
    assert!(signed.starts_with("SAMLRequest="));
    assert!(signed.contains("&RelayState=abc&SigAlg="));
    let pairs: Vec<(String, String)> = form_urlencoded::parse(ours.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    let value = |name: &str| {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
            .expect("present")
    };
    assert_eq!(value("SigAlg"), KIT.sp.algorithm());
    let signature_value = STANDARD
        .decode(
            form_urlencoded::parse(format!("s={signature_param}").as_bytes())
                .next()
                .expect("one")
                .1
                .as_bytes(),
        )
        .expect("base64");
    let certificate = x509_parser::parse_x509_certificate(KIT.sp.certificate_der())
        .expect("a certificate")
        .1;
    let point = certificate.public_key().subject_public_key.data.to_vec();
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
        .verify(signed.as_bytes(), &signature_value)
        .expect("the signature covers the query as sent");
    let deflated = STANDARD.decode(value("SAMLRequest")).expect("base64");
    let mut inflated = String::new();
    flate2::read::DeflateDecoder::new(deflated.as_slice())
        .read_to_string(&mut inflated)
        .expect("raw DEFLATE");
    assert_eq!(inflated, request().xml());
}

#[test]
fn a_relay_state_over_80_bytes_is_refused() {
    assert!(request().redirect(&KIT.sp, &"r".repeat(81)).is_err());
}

#[test]
fn the_posted_request_carries_its_signature_after_the_issuer() {
    let encoded = request().post(&KIT.sp).expect("signed");
    let xml = String::from_utf8(STANDARD.decode(encoded).expect("base64")).expect("UTF-8");
    let document = roxmltree::Document::parse(&xml).expect("well formed");
    let names: Vec<&str> = document
        .root_element()
        .children()
        .filter(roxmltree::Node::is_element)
        .map(|child| child.tag_name().name())
        .collect();
    assert_eq!(
        names,
        [
            "Issuer",
            "Signature",
            "NameIDPolicy",
            "RequestedAuthnContext"
        ]
    );
}
