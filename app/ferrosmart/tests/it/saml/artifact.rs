// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The HTTP-Artifact binding: the artifact, the `ArtifactResolve` and the
//! check of the `ArtifactResponse`.

use aws_lc_rs::digest;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ferrosmart::saml::Refusal;
use ferrosmart::saml::artifact::{Artifact, ArtifactResolve, check_response};

use super::kit::{Assertion, IDP, KIT, SP, at, expect, now, response, sign};

/// The `ID` of the `ArtifactResolve` the responses answer.
const RESOLVE: &str = "_resolve1";

fn artifact(type_code: [u8; 2], issuer: &str) -> String {
    let mut bytes = type_code.to_vec();
    bytes.extend([0, 1]);
    bytes.extend(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, issuer.as_bytes()).as_ref());
    bytes.extend([7_u8; 20]);
    STANDARD.encode(bytes)
}

fn soap(artifact_response: &str) -> String {
    format!(
        "<soap11:Envelope xmlns:soap11=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap11:Body>{artifact_response}</soap11:Body></soap11:Envelope>"
    )
}

fn artifact_response(in_response_to: &str, inner: &str) -> String {
    format!(
        concat!(
            "<samlp:ArtifactResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ",
            "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_ar1\" Version=\"2.0\" ",
            "IssueInstant=\"{issued}\" InResponseTo=\"{irt}\"><saml:Issuer>{idp}</saml:Issuer>",
            "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>",
            "</samlp:Status>{inner}</samlp:ArtifactResponse>"
        ),
        issued = at(-1),
        irt = in_response_to,
        idp = IDP,
        inner = inner,
    )
}

#[test]
fn a_type_4_artifact_names_its_issuer_and_endpoint() {
    let read = Artifact::parse(&artifact([0, 4], IDP)).expect("an artifact");
    assert_eq!(read.endpoint_index(), 1);
    assert!(read.issued_by(IDP));
    assert!(!read.issued_by("https://attacker.example/saml"));
}

#[test]
fn another_type_or_length_is_refused() {
    assert_eq!(
        Artifact::parse(&artifact([0, 1], IDP)).expect_err("refused"),
        Refusal::Encoding
    );
    assert_eq!(
        Artifact::parse(&STANDARD.encode([0_u8, 4, 0, 1])).expect_err("refused"),
        Refusal::Encoding
    );
}

#[test]
fn the_artifact_resolve_is_signed_and_carries_the_artifact() {
    let read = Artifact::parse(&artifact([0, 4], IDP)).expect("an artifact");
    let envelope = ArtifactResolve {
        id: RESOLVE,
        issue_instant: now(),
        destination: "https://idp.example.org/ars",
        entity_id: SP,
        artifact: &read,
    }
    .envelope(&KIT.sp)
    .expect("signed");
    let document = roxmltree::Document::parse(&envelope).expect("well formed");
    let resolve = document
        .descendants()
        .find(|node| node.has_tag_name("ArtifactResolve"))
        .expect("the request");
    let names: Vec<&str> = resolve
        .children()
        .filter(roxmltree::Node::is_element)
        .map(|child| child.tag_name().name())
        .collect();
    assert_eq!(names, ["Issuer", "Signature", "Artifact"]);
    assert!(envelope.contains(read.encoded()));
}

#[test]
fn a_signed_artifact_response_covers_an_unsigned_assertion() {
    let signed = sign(
        &artifact_response(RESOLVE, &response(&Assertion::default().xml())),
        &KIT.idp,
    );
    let login = check_response(&soap(&signed), RESOLVE, &expect()).expect("accepted");
    assert_eq!(login.name_id.value, "person-17");
}

#[test]
fn an_unsigned_artifact_response_needs_a_signed_assertion() {
    let unsigned = artifact_response(RESOLVE, &response(&Assertion::default().xml()));
    assert_eq!(
        check_response(&soap(&unsigned), RESOLVE, &expect()).expect_err("refused"),
        Refusal::Unprotected
    );
    let inner = artifact_response(RESOLVE, &response(&Assertion::default().signed()));
    assert!(check_response(&soap(&inner), RESOLVE, &expect()).is_ok());
}

#[test]
fn an_artifact_response_to_another_resolve_is_refused() {
    let signed = sign(
        &artifact_response("_another", &response(&Assertion::default().signed())),
        &KIT.idp,
    );
    assert_eq!(
        check_response(&soap(&signed), RESOLVE, &expect()).expect_err("refused"),
        Refusal::InResponseTo
    );
}

#[test]
fn a_tampered_artifact_response_is_refused() {
    let signed = sign(
        &artifact_response(RESOLVE, &response(&Assertion::default().xml())),
        &KIT.idp,
    )
    .replace("person-17", "admin");
    assert_eq!(
        check_response(&soap(&signed), RESOLVE, &expect()).expect_err("refused"),
        Refusal::Digest
    );
}
