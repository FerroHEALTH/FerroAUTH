// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The eHDSI HP Identity Assertion and Treatment Relationship Confirmation
//! check through the public API. Each assertion is built from the eHDSI
//! SAML Profile 10.0.0 §2.1, §2.3 and §4 tables, with invented values, and
//! signed when the case runs by a seal certificate generated for it; the
//! hostile variants are unsigned, wrongly signed, expired, short-keyed,
//! weakly hashed and wrapped.

use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::RSA_PKCS1_SHA256;
use aws_lc_rs::signature::RsaEncoding;
use aws_lc_rs::signature::RsaKeyPair;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ferrohealth_smart::federation::assertion::AssertionError;
use ferrohealth_smart::federation::assertion::Floor;
use ferrohealth_smart::federation::assertion::Integrity;
use ferrohealth_smart::federation::assertion::Validator;
use ferrohealth_smart::federation::assertion::identity::IdentityAssertion;
use ferrohealth_smart::federation::assertion::identity::PurposeOfUse;
use ferrohealth_smart::federation::assertion::identity::Role;
use ferrohealth_smart::federation::assertion::identity::ehdsi_claim;
use ferrohealth_smart::federation::assertion::signer::SignerError;
use ferrohealth_smart::federation::assertion::signer::TrustedSigner;
use ferrohealth_smart::federation::assertion::treatment::PatientIdSource;
use ferrohealth_smart::federation::contact::EhdsiCode;
use ferrohealth_smart::federation::contact::NameIdFormat;
use jiff::Timestamp;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::PKCS_ECDSA_P256_SHA256;
use rcgen::PKCS_RSA_SHA256;
use rcgen::RsaKeySize;

/// NCP-B, the issuer of both assertions.
const ISSUER: &str = "https://ncp-b.example.org/sts";
/// The cross-border audience (SAML Profile 10.0.0 §2.1).
const AUDIENCE: &str = "urn:ehdsi:assertions.audience:x-border";
/// The identity assertion's `@ID`.
const IDA_ID: &str = "urn:uuid:5b9e3f6a-0c1d-4e2f-8a3b-6c7d8e9f0a1b";
/// The treatment confirmation's `@ID`.
const TRC_ID: &str = "_0f8fad5b-d9cb-469f-a165-70867728950e";
/// The invented professional's `NameID`.
const NAME_ID: &str = "CN=Invented Doctor,O=Invented Hospital,C=BE";
const SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// A seal certificate generated for the case, with its private key.
struct Seal {
    der: Vec<u8>,
    key: RsaKeyPair,
}

impl Seal {
    /// A seal certificate of the X.509 Certificates Profile 7.0.0 §3.1 over
    /// an RSA key of `size`.
    fn new(size: RsaKeySize) -> Self {
        let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, size).expect("an RSA key");
        let der = seal_params()
            .self_signed(&key)
            .expect("a certificate")
            .der()
            .to_vec();
        let key = RsaKeyPair::from_pkcs8(&key.serialize_der()).expect("a PKCS#8 key");
        Self { der, key }
    }

    fn trusted(&self) -> TrustedSigner {
        TrustedSigner::from_der(ISSUER, self.der.clone()).expect("a trusted seal")
    }

    fn sign(&self, encoding: &'static dyn RsaEncoding, message: &[u8]) -> Vec<u8> {
        let mut signature = vec![0; self.key.public_modulus_len()];
        self.key
            .sign(encoding, &SystemRandom::new(), message, &mut signature)
            .expect("a signature");
        signature
    }
}

fn seal_params() -> CertificateParams {
    let mut params = CertificateParams::new(Vec::new()).expect("parameters");
    params.distinguished_name.push(DnType::CountryName, "BE");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Invented NCP-B");
    params
        .distinguished_name
        .push(DnType::CommonName, "Invented NCP-B seal");
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.is_ca = IsCa::ExplicitNoCa;
    params
}

/// The signature parameters of a case.
struct Signing<'s> {
    seal: &'s Seal,
    /// The certificate `ds:KeyInfo` carries.
    key_info: Vec<u8>,
    signature_method: &'static str,
    digest_method: &'static str,
    encoding: &'static dyn RsaEncoding,
    /// The `ds:Reference` URI.
    uri: String,
}

impl<'s> Signing<'s> {
    fn by(seal: &'s Seal, id: &str) -> Self {
        Self {
            seal,
            key_info: seal.der.clone(),
            signature_method: RSA_SHA256,
            digest_method: SHA256,
            encoding: &RSA_PKCS1_SHA256,
            uri: format!("#{id}"),
        }
    }

    /// Signs `unsigned`, in canonical form, by placing the signature at its
    /// `{SIG}` mark.
    fn sign(&self, unsigned: &str) -> String {
        let covered = unsigned.replace("{SIG}", "");
        let algorithm = if self.digest_method == SHA256 {
            &digest::SHA256
        } else {
            &digest::SHA1_FOR_LEGACY_USE_ONLY
        };
        let digest_value = STANDARD.encode(digest::digest(algorithm, covered.as_bytes()));
        let body = format!(
            concat!(
                r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>"#,
                r#"<ds:SignatureMethod Algorithm="{}"></ds:SignatureMethod>"#,
                r#"<ds:Reference URI="{}"><ds:Transforms>"#,
                r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>"#,
                r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>"#,
                r#"</ds:Transforms><ds:DigestMethod Algorithm="{}"></ds:DigestMethod>"#,
                r#"<ds:DigestValue>{}</ds:DigestValue></ds:Reference>"#
            ),
            self.signature_method, self.uri, self.digest_method, digest_value
        );
        let canonical = format!(r#"<ds:SignedInfo xmlns:ds="{DSIG}">{body}</ds:SignedInfo>"#);
        let value = STANDARD.encode(self.seal.sign(self.encoding, canonical.as_bytes()));
        let certificate = STANDARD.encode(&self.key_info);
        let signature = format!(
            r#"<ds:Signature xmlns:ds="{DSIG}"><ds:SignedInfo>{body}</ds:SignedInfo><ds:SignatureValue>{value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#
        );
        unsigned.replace("{SIG}", &signature)
    }
}

/// Renders a time as SAML writes it.
fn at(seconds: i64) -> String {
    Timestamp::from_second(seconds).expect("a time").to_string()
}

fn now() -> Timestamp {
    Timestamp::from_second(1_800_000_000).expect("a time")
}

/// An attribute with one plain value.
fn attribute(name: &str, value: &str) -> String {
    format!(
        r#"<saml:Attribute Name="{name}"><saml:AttributeValue>{value}</saml:AttributeValue></saml:Attribute>"#
    )
}

/// An attribute with one HL7 v3 coded value.
fn coded(name: &str, element: &str, code: &str) -> String {
    let value = format!(
        r#"<{element} xmlns="urn:hl7-org:v3" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" code="{code}" codeSystem="2.16.840.1.113883.2.9.6.2.7" xsi:type="CE"></{element}>"#
    );
    attribute(name, &value)
}

/// The parts of an assertion a case changes.
struct Parts {
    id: String,
    version: &'static str,
    issuer: String,
    not_before: i64,
    not_on_or_after: i64,
    audience: String,
    name_id: Option<String>,
    confirmation: String,
    advice: String,
    authn_class: String,
    attributes: Vec<String>,
}

impl Parts {
    /// An HP Identity Assertion of SAML Profile 10.0.0 §2.1 and §2.3.
    fn identity() -> Self {
        let now = now().as_second();
        Self {
            id: IDA_ID.to_owned(),
            version: "2.0",
            issuer: ISSUER.to_owned(),
            not_before: now - 60,
            not_on_or_after: now + 3 * 3600,
            audience: AUDIENCE.to_owned(),
            name_id: Some(format!(
                r#"<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName">{NAME_ID}</saml:NameID>"#
            )),
            confirmation: r#"<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"></saml:SubjectConfirmation>"#.to_owned(),
            advice: String::new(),
            authn_class: "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI".to_owned(),
            attributes: vec![
                attribute("urn:ihe:iti:xca:2010:homeCommunityId", "urn:oid:1.2.3"),
                attribute("urn:oasis:names:tc:xspa:1.0:subject:subject-id", "Invented Doctor"),
                coded("urn:oasis:names:tc:xacml:2.0:subject:role", "Role", "221"),
                attribute(
                    "urn:oasis:names:tc:xspa:1.0:subject:hl7:permission",
                    "urn:oasis:names:tc:xspa:1.0:subject:hl7:permission:PPD-046",
                ),
                attribute("urn:oasis:names:tc:xspa:1.0:subject:organization-id", "urn:oid:1.2.3.4"),
                attribute("urn:ehdsi:names:subject:healthcare-facility-type", "Pharmacy"),
                coded("urn:oasis:names:tc:xspa:1.0:subject:purposeofuse", "PurposeOfUse", "TREATMENT"),
                attribute("urn:oasis:names:tc:xspa:1.0:environment:locality", "Invented Pharmacy"),
            ],
        }
    }

    /// A Treatment Relationship Confirmation of SAML Profile 10.0.0 §4.
    fn treatment() -> Self {
        let now = now().as_second();
        Self {
            id: TRC_ID.to_owned(),
            not_on_or_after: now + 3600,
            advice: format!(
                "<saml:Advice><saml:AssertionIDRef>{IDA_ID}</saml:AssertionIDRef></saml:Advice>"
            ),
            authn_class: "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession".to_owned(),
            attributes: vec![attribute(
                "urn:oasis:names:tc:xspa:1.0:subject:subject-id",
                "invented-patient^^^&amp;1.2.3&amp;ISO",
            )],
            ..Self::identity()
        }
    }

    /// Drops the attribute whose name ends in `suffix`.
    fn without(mut self, suffix: &str) -> Self {
        self.attributes
            .retain(|attribute| !attribute.contains(&format!("{suffix}\"")));
        self
    }

    /// Renders the assertion in canonical form, with the `{SIG}` mark.
    fn render(&self) -> String {
        let instant = at(self.not_before);
        format!(
            concat!(
                r#"<saml:Assertion xmlns:saml="{saml}" ID="{id}" IssueInstant="{instant}" Version="{version}">"#,
                "<saml:Issuer>{issuer}</saml:Issuer>{{SIG}}",
                "<saml:Subject>{name_id}{confirmation}</saml:Subject>",
                r#"<saml:Conditions NotBefore="{nb}" NotOnOrAfter="{noa}">"#,
                "<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>",
                "</saml:Conditions>{advice}",
                r#"<saml:AuthnStatement AuthnInstant="{instant}"><saml:AuthnContext>"#,
                "<saml:AuthnContextClassRef>{class}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>",
                "<saml:AttributeStatement>{attributes}</saml:AttributeStatement></saml:Assertion>"
            ),
            saml = SAML,
            id = self.id,
            instant = instant,
            version = self.version,
            issuer = self.issuer,
            name_id = self.name_id.clone().unwrap_or_default(),
            confirmation = self.confirmation,
            nb = at(self.not_before),
            noa = at(self.not_on_or_after),
            audience = self.audience,
            advice = self.advice,
            class = self.authn_class,
            attributes = self.attributes.concat(),
        )
    }
}

/// The trusted seal and the validator that trusts it.
struct Case {
    seal: Seal,
    validator: Validator,
}

impl Case {
    fn new() -> Self {
        let seal = Seal::new(RsaKeySize::_3072);
        let validator = Validator::new(vec![seal.trusted()], vec![AUDIENCE.to_owned()]);
        Self { seal, validator }
    }

    fn signed(&self, parts: &Parts) -> String {
        Signing::by(&self.seal, &parts.id).sign(&parts.render())
    }

    fn identity(&self, parts: &Parts) -> Result<IdentityAssertion, AssertionError> {
        self.validator.identity(&self.signed(parts), now())
    }

    fn valid_identity(&self) -> IdentityAssertion {
        self.identity(&Parts::identity())
            .expect("the identity assertion is valid")
    }
}

/// Returns the integrity refusal of `result`, if it is one.
fn integrity<T>(result: Result<T, AssertionError>) -> Option<Integrity> {
    match result.err()? {
        AssertionError::Integrity(integrity) => Some(integrity),
        _ => None,
    }
}

/// Returns the code and fields of the attribute refusal of `result`, if it
/// is one.
fn attributes<T>(result: Result<T, AssertionError>) -> Option<(EhdsiCode, Vec<&'static str>)> {
    match result {
        Err(AssertionError::Attributes { code, missing }) => Some((code, missing)),
        _ => None,
    }
}

#[test]
fn a_signed_identity_assertion_yields_its_values() {
    let case = Case::new();
    let identity = case.valid_identity();
    assert_eq!(identity.id(), IDA_ID);
    assert_eq!(identity.issuer(), ISSUER);
    assert_eq!(identity.name_id().value(), NAME_ID);
    assert_eq!(identity.name_id().format(), NameIdFormat::X509SubjectName);
    assert_eq!(identity.name(), "Invented Doctor");
    assert_eq!(identity.roles().first().map(Role::code), Some("221"));
    assert_eq!(identity.organization_id(), "urn:oid:1.2.3.4");
    assert_eq!(identity.facility_type(), "Pharmacy");
    assert_eq!(identity.home_community_id(), "urn:oid:1.2.3");
    assert_eq!(identity.point_of_care(), "Invented Pharmacy");
    assert_eq!(identity.purpose_of_use(), PurposeOfUse::Treatment);
    assert!(identity.has_permission("PPD-046"), "PPD-046 is asserted");
    assert!(!identity.has_permission("PPD-029"), "PPD-029 is not");
    assert_eq!(identity.not_before().as_second(), now().as_second() - 60);
    assert_eq!(
        identity.authentication_class(),
        "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"
    );
}

#[test]
fn a_linked_treatment_confirmation_yields_the_patient() {
    let case = Case::new();
    let identity = case.valid_identity();
    let trc = case
        .validator
        .treatment(&case.signed(&Parts::treatment()), &identity, now())
        .expect("the TRC is valid");
    assert_eq!(trc.id(), TRC_ID);
    assert_eq!(trc.identity_id(), IDA_ID);
    assert_eq!(trc.patient_id(), "invented-patient^^^&1.2.3&ISO");
    assert_eq!(trc.purpose_of_use(), None);
    assert_eq!(trc.not_on_or_after().as_second(), now().as_second() + 3600);
}

#[test]
fn the_canonical_form_ignores_serialization_details() {
    let case = Case::new();
    let signed = case.signed(&Parts::identity());
    let reserialized = signed
        .replacen(
            &format!(r#"xmlns:saml="{SAML}" ID="{IDA_ID}""#),
            &format!(r#"ID='{IDA_ID}' xmlns:unused="urn:invented" xmlns:saml="{SAML}""#),
            1,
        )
        .replace("></ds:Transform>", "/>")
        .replace("<saml:Issuer>", "<!-- a comment --><saml:Issuer>")
        .replace("Invented Doctor<", "Invented Docto&#x72;<")
        .replace("</saml:Assertion>", "</saml:Assertion >");
    let reserialized = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n{reserialized}");
    assert_ne!(signed, reserialized, "the case changes the serialization");
    case.validator
        .identity(&reserialized, now())
        .expect("the reserialized assertion keeps its signature");
}

#[test]
fn an_unsigned_assertion_is_refused() {
    let case = Case::new();
    let unsigned = Parts::identity().render().replace("{SIG}", "");
    let refused = case.validator.identity(&unsigned, now());
    assert_eq!(integrity(refused.clone()), Some(Integrity::Unsigned));
    assert_eq!(
        refused.map(|_| ()).unwrap_err().code(),
        EhdsiCode::SecDataIntegrityNotEnsured
    );
}

#[test]
fn a_signature_by_another_key_is_refused() {
    let case = Case::new();
    let other = Seal::new(RsaKeySize::_3072);
    let parts = Parts::identity();
    let mut signing = Signing::by(&other, IDA_ID);
    signing.key_info = case.seal.der.clone();
    let refused = case
        .validator
        .identity(&signing.sign(&parts.render()), now());
    assert_eq!(integrity(refused), Some(Integrity::BadSignature));
}

#[test]
fn a_certificate_outside_the_trusted_set_is_refused() {
    let case = Case::new();
    let other = Seal::new(RsaKeySize::_3072);
    let refused = case.validator.identity(
        &Signing::by(&other, IDA_ID).sign(&Parts::identity().render()),
        now(),
    );
    assert_eq!(integrity(refused), Some(Integrity::Untrusted));
}

#[test]
fn an_issuer_without_a_trusted_signer_is_refused() {
    let case = Case::new();
    let parts = Parts {
        issuer: "https://ncp-c.example.org/sts".to_owned(),
        ..Parts::identity()
    };
    assert_eq!(integrity(case.identity(&parts)), Some(Integrity::Untrusted));
}

#[test]
fn a_content_change_after_signing_is_refused() {
    let case = Case::new();
    let tampered = case
        .signed(&Parts::identity())
        .replace("urn:oid:1.2.3.4", "urn:oid:9.9.9.9");
    assert_eq!(
        integrity(case.validator.identity(&tampered, now())),
        Some(Integrity::Digest)
    );
}

#[test]
fn a_signer_key_below_3000_bits_is_refused() {
    let seal = Seal::new(RsaKeySize::_2048);
    assert_eq!(
        TrustedSigner::from_der(ISSUER, seal.der).map(|_| ()),
        Err(SignerError::ShortKey { bits: 2048 })
    );
}

#[test]
fn an_elliptic_curve_signer_is_refused() {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("an EC key");
    let der = seal_params()
        .self_signed(&key)
        .expect("a certificate")
        .der()
        .to_vec();
    assert_eq!(
        TrustedSigner::from_der(ISSUER, der).map(|_| ()),
        Err(SignerError::EllipticCurve)
    );
}

#[test]
fn a_signer_without_the_seal_key_usage_is_refused() {
    let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_3072).expect("an RSA key");
    let mut params = seal_params();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let der = params
        .self_signed(&key)
        .expect("a certificate")
        .der()
        .to_vec();
    assert_eq!(
        TrustedSigner::from_der(ISSUER, der).map(|_| ()),
        Err(SignerError::KeyUsage)
    );
}

#[test]
fn a_signer_without_basic_constraints_is_refused() {
    let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_3072).expect("an RSA key");
    let mut params = seal_params();
    params.is_ca = IsCa::NoCa;
    let der = params
        .self_signed(&key)
        .expect("a certificate")
        .der()
        .to_vec();
    assert_eq!(
        TrustedSigner::from_der(ISSUER, der).map(|_| ()),
        Err(SignerError::BasicConstraints)
    );
}

#[test]
fn a_sha1_signature_method_is_refused() {
    let case = Case::new();
    let mut signing = Signing::by(&case.seal, IDA_ID);
    // NOTE: the method is refused before the value is read, so a SHA-256 value serves.
    signing.signature_method = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    let refused = case
        .validator
        .identity(&signing.sign(&Parts::identity().render()), now());
    assert_eq!(integrity(refused), Some(Integrity::Floor(Floor::Hash)));
}

#[test]
fn a_sha1_digest_is_refused() {
    let case = Case::new();
    let mut signing = Signing::by(&case.seal, IDA_ID);
    signing.digest_method = "http://www.w3.org/2000/09/xmldsig#sha1";
    let refused = case
        .validator
        .identity(&signing.sign(&Parts::identity().render()), now());
    assert_eq!(integrity(refused), Some(Integrity::Floor(Floor::Hash)));
}

#[test]
fn an_elliptic_curve_signature_method_is_refused() {
    let case = Case::new();
    let mut signing = Signing::by(&case.seal, IDA_ID);
    signing.signature_method = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    let refused = case
        .validator
        .identity(&signing.sign(&Parts::identity().render()), now());
    assert_eq!(
        integrity(refused),
        Some(Integrity::Floor(Floor::EllipticCurve))
    );
}

#[test]
fn a_reference_to_another_element_is_refused() {
    let case = Case::new();
    let mut signing = Signing::by(&case.seal, IDA_ID);
    signing.uri = "#_11111111-2222-3333-4444-555555555555".to_owned();
    let refused = case
        .validator
        .identity(&signing.sign(&Parts::identity().render()), now());
    assert_eq!(integrity(refused), Some(Integrity::Wrapped));
}

#[test]
fn a_signed_assertion_wrapped_in_an_unsigned_one_is_refused() {
    let case = Case::new();
    let original = case.signed(&Parts::identity());
    let evil = Parts {
        advice: format!("<saml:Advice>{original}</saml:Advice>"),
        ..Parts::identity()
    }
    .render()
    .replace("{SIG}", "");
    assert_eq!(
        integrity(case.validator.identity(&evil, now())),
        Some(Integrity::Wrapped)
    );
}

#[test]
fn a_repeated_id_is_refused() {
    let case = Case::new();
    let parts = Parts {
        advice: format!(
            r#"<saml:Advice><saml:AssertionIDRef ID="{IDA_ID}">x</saml:AssertionIDRef></saml:Advice>"#
        ),
        ..Parts::identity()
    };
    assert_eq!(integrity(case.identity(&parts)), Some(Integrity::Wrapped));
}

#[test]
fn a_signature_away_from_the_assertion_element_is_refused() {
    let case = Case::new();
    let signed = case.signed(&Parts::identity());
    let start = signed.find("<ds:Signature").expect("a signature");
    let end = signed.find("</ds:Signature>").expect("a signature end") + "</ds:Signature>".len();
    let signature = signed.get(start..end).expect("the signature element");
    let moved = signed
        .replace(signature, "")
        .replace("</saml:Subject>", &format!("{signature}</saml:Subject>"));
    assert_eq!(
        integrity(case.validator.identity(&moved, now())),
        Some(Integrity::Wrapped)
    );
}

#[test]
fn an_expired_assertion_is_refused_past_the_drift() {
    let case = Case::new();
    let signed = case.signed(&Parts::identity());
    let end = now().as_second() + 3 * 3600;
    let at_drift = Timestamp::from_second(end + 59).expect("a time");
    case.validator
        .identity(&signed, at_drift)
        .expect("59 s past the end is within the drift");
    let past = Timestamp::from_second(end + 60).expect("a time");
    assert_eq!(
        integrity(case.validator.identity(&signed, past)),
        Some(Integrity::Expired)
    );
}

#[test]
fn an_assertion_not_yet_valid_is_refused() {
    let case = Case::new();
    let parts = Parts {
        not_before: now().as_second() + 61,
        ..Parts::identity()
    };
    assert_eq!(
        integrity(case.identity(&parts)),
        Some(Integrity::NotYetValid)
    );
}

#[test]
fn an_identity_window_over_four_hours_is_refused() {
    let case = Case::new();
    let parts = Parts {
        not_on_or_after: now().as_second() - 60 + 4 * 3600 + 1,
        ..Parts::identity()
    };
    assert_eq!(integrity(case.identity(&parts)), Some(Integrity::Window));
}

#[test]
fn another_audience_is_refused() {
    let case = Case::new();
    let parts = Parts {
        audience: "urn:invented:other".to_owned(),
        ..Parts::identity()
    };
    assert_eq!(integrity(case.identity(&parts)), Some(Integrity::Audience));
}

#[test]
fn a_bearer_confirmation_is_refused() {
    let case = Case::new();
    let parts = Parts {
        confirmation: r#"<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"></saml:SubjectConfirmation>"#.to_owned(),
        ..Parts::identity()
    };
    assert_eq!(
        integrity(case.identity(&parts)),
        Some(Integrity::Confirmation)
    );
}

#[test]
fn subject_confirmation_data_is_refused() {
    let case = Case::new();
    let parts = Parts {
        confirmation: r#"<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"><saml:SubjectConfirmationData></saml:SubjectConfirmationData></saml:SubjectConfirmation>"#.to_owned(),
        ..Parts::identity()
    };
    assert_eq!(
        integrity(case.identity(&parts)),
        Some(Integrity::Confirmation)
    );
}

#[test]
fn another_version_is_refused() {
    let case = Case::new();
    let parts = Parts {
        version: "1.1",
        ..Parts::identity()
    };
    assert_eq!(integrity(case.identity(&parts)), Some(Integrity::Version));
}

#[test]
fn an_id_that_is_no_uuid_is_refused() {
    let case = Case::new();
    let parts = Parts {
        id: "_ida-1".to_owned(),
        ..Parts::identity()
    };
    assert_eq!(integrity(case.identity(&parts)), Some(Integrity::Id));
}

#[test]
fn a_document_type_declaration_is_refused() {
    let case = Case::new();
    let signed = case.signed(&Parts::identity());
    let declared = format!("<!DOCTYPE saml:Assertion [<!ENTITY x \"y\">]>{signed}");
    assert_eq!(
        integrity(case.validator.identity(&declared, now())),
        Some(Integrity::Malformed)
    );
}

#[test]
fn an_assertion_naming_no_professional_is_refused() {
    let case = Case::new();
    let parts = Parts {
        name_id: None,
        ..Parts::identity()
            .without("subject-id")
            .without("subject:role")
    };
    assert_eq!(
        attributes(case.identity(&parts)),
        Some((EhdsiCode::HpiNoInformation, Vec::new()))
    );
}

#[test]
fn a_missing_role_is_refused_naming_it() {
    let case = Case::new();
    let parts = Parts::identity().without("subject:role");
    assert_eq!(
        attributes(case.identity(&parts)),
        Some((
            EhdsiCode::HpiInsufficientInformation,
            vec!["professional.hp_professional_role"]
        ))
    );
}

#[test]
fn a_clerical_role_without_on_behalf_of_is_refused() {
    let case = Case::new();
    let mut parts = Parts::identity().without("subject:role");
    parts.attributes.push(coded(
        "urn:oasis:names:tc:xacml:2.0:subject:role",
        "Role",
        "44",
    ));
    assert_eq!(
        attributes(case.identity(&parts)),
        Some((
            EhdsiCode::HpiInsufficientInformation,
            vec!["professional.on_behalf_of"]
        ))
    );
}

#[test]
fn a_missing_organization_id_is_refused() {
    let case = Case::new();
    let parts = Parts::identity().without("organization-id");
    assert_eq!(
        attributes(case.identity(&parts)),
        Some((
            EhdsiCode::HpiHaiNoInformation,
            vec!["provider.healthcare_provider_identifier"]
        ))
    );
}

#[test]
fn a_missing_point_of_care_is_refused() {
    let case = Case::new();
    let parts = Parts::identity().without("locality");
    assert_eq!(
        attributes(case.identity(&parts)),
        Some((EhdsiCode::HpiPocNoInformation, vec!["point_of_care"]))
    );
}

#[test]
fn an_unknown_authentication_class_is_refused() {
    let case = Case::new();
    let parts = Parts {
        authn_class: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password".to_owned(),
        ..Parts::identity()
    };
    assert_eq!(
        attributes(case.identity(&parts)),
        Some((
            EhdsiCode::HpiAuthenticationNotReceived,
            vec!["professional.authentication_method"]
        ))
    );
}

#[test]
fn another_purpose_of_use_is_refused() {
    let case = Case::new();
    let mut parts = Parts::identity().without("purposeofuse");
    parts.attributes.push(coded(
        "urn:oasis:names:tc:xspa:1.0:subject:purposeofuse",
        "PurposeOfUse",
        "RESEARCH",
    ));
    assert_eq!(
        attributes(case.identity(&parts)),
        Some((
            EhdsiCode::HpiInsufficientInformation,
            vec!["purpose_of_use"]
        ))
    );
}

#[test]
fn a_treatment_confirmation_naming_another_identity_assertion_is_refused() {
    let case = Case::new();
    let identity = case.valid_identity();
    let parts = Parts {
        advice: "<saml:Advice><saml:AssertionIDRef>urn:uuid:00000000-0000-0000-0000-000000000000</saml:AssertionIDRef></saml:Advice>".to_owned(),
        ..Parts::treatment()
    };
    let refused = case
        .validator
        .treatment(&case.signed(&parts), &identity, now());
    assert_eq!(integrity(refused), Some(Integrity::Link));
}

#[test]
fn a_treatment_confirmation_for_another_professional_is_refused() {
    let case = Case::new();
    let identity = case.valid_identity();
    let parts = Parts {
        name_id: Some(r#"<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName">CN=Other</saml:NameID>"#.to_owned()),
        ..Parts::treatment()
    };
    let refused = case
        .validator
        .treatment(&case.signed(&parts), &identity, now());
    assert_eq!(integrity(refused), Some(Integrity::Link));
}

#[test]
fn a_treatment_confirmation_without_the_patient_is_refused() {
    let case = Case::new();
    let identity = case.valid_identity();
    let parts = Parts::treatment().without("subject-id");
    let refused = case
        .validator
        .treatment(&case.signed(&parts), &identity, now());
    assert_eq!(
        attributes(refused),
        Some((EhdsiCode::SecDataIntegrityNotEnsured, vec!["patient.id"]))
    );
}

#[test]
fn a_treatment_confirmation_window_over_two_hours_is_refused() {
    let case = Case::new();
    let identity = case.valid_identity();
    let parts = Parts {
        not_on_or_after: now().as_second() - 60 + 2 * 3600 + 1,
        ..Parts::treatment()
    };
    let refused = case
        .validator
        .treatment(&case.signed(&parts), &identity, now());
    assert_eq!(integrity(refused), Some(Integrity::Window));
}

#[test]
fn a_treatment_confirmation_needs_the_previous_session_class() {
    let case = Case::new();
    let identity = case.valid_identity();
    let parts = Parts {
        authn_class: "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI".to_owned(),
        ..Parts::treatment()
    };
    let refused = case
        .validator
        .treatment(&case.signed(&parts), &identity, now());
    assert_eq!(
        integrity(refused),
        Some(Integrity::Structure("saml:AuthnContextClassRef"))
    );
}

#[test]
fn a_wallet_patient_id_needs_the_pid_issuer_country() {
    let case = Case::new();
    let identity = case.valid_identity();
    let mut parts = Parts::treatment();
    parts.attributes.push(attribute(
        "urn:ehdsi:names:subject:patient-id-source",
        "EUDI_WALLET_PID",
    ));
    let refused = case
        .validator
        .treatment(&case.signed(&parts), &identity, now());
    assert_eq!(
        attributes(refused),
        Some((
            EhdsiCode::SecDataIntegrityNotEnsured,
            vec!["patient.pid_issuer_country"]
        ))
    );
    parts.attributes.push(attribute(
        "urn:ehdsi:names:subject:pid-issuer-country",
        "BE",
    ));
    let trc = case
        .validator
        .treatment(&case.signed(&parts), &identity, now())
        .expect("the wallet-sourced TRC is valid");
    assert_eq!(
        trc.patient_id_source(),
        Some(PatientIdSource::EudiWalletPid)
    );
    assert_eq!(trc.pid_issuer_country(), Some("BE"));
}

#[test]
fn debug_carries_no_assertion_content() {
    let case = Case::new();
    let identity = case.valid_identity();
    let trc = case
        .validator
        .treatment(&case.signed(&Parts::treatment()), &identity, now())
        .expect("the TRC is valid");
    let rendered = format!("{identity:?} {trc:?} {:?}", case.seal.trusted());
    for secret in [
        NAME_ID,
        "Invented Doctor",
        "invented-patient",
        "urn:oid:1.2.3.4",
        IDA_ID,
    ] {
        assert!(!rendered.contains(secret), "Debug renders {secret}");
    }
}

#[test]
fn the_claim_carries_the_contact_point_field_set() {
    let case = Case::new();
    let identity = case.valid_identity();
    let trc = case
        .validator
        .treatment(&case.signed(&Parts::treatment()), &identity, now())
        .expect("the TRC is valid");
    let claim = ehdsi_claim(&identity, Some(&trc));
    assert_eq!(claim["professional"]["hp_identifier"], NAME_ID);
    assert_eq!(
        claim["professional"]["hp_professional_role"][0]["code"],
        "221"
    );
    assert_eq!(
        claim["provider"]["healthcare_provider_identifier"],
        "urn:oid:1.2.3.4"
    );
    assert_eq!(claim["purpose_of_use"], "TREATMENT");
    assert_eq!(claim["assertion"]["id"], IDA_ID);
    assert_eq!(
        claim["assertion"]["not_on_or_after"],
        now().as_second() + 3 * 3600
    );
    assert_eq!(claim["trc"]["not_on_or_after"], now().as_second() + 3600);
    assert_eq!(claim["patient"]["id"], "invented-patient^^^&1.2.3&ISO");
    let discovery = ehdsi_claim(&identity, None);
    assert!(
        discovery.get("trc").is_none(),
        "a discovery-phase claim has no TRC"
    );
}
