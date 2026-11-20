// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A test identity provider: keys generated when the run starts, the
//! messages it writes, signed with FerroSMART's own enveloped signer, and
//! the XML Encryption it encrypts for FerroSMART with.

use std::sync::LazyLock;

use aws_lc_rs::aead;
use aws_lc_rs::cipher;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa;
use aws_lc_rs::rsa::KeySize;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ferrosmart::saml::dsig;
use ferrosmart::saml::keys::DecryptionKey;
use ferrosmart::saml::keys::SigningKey;
use ferrosmart::saml::keys::TrustedKey;
use ferrosmart::saml::metadata::IdentityProvider;
use ferrosmart::saml::response::Expectations;
use jiff::SignedDuration;
use jiff::Timestamp;

/// The identity provider's entity ID.
pub(crate) const IDP: &str = "https://idp.example.org/saml";
/// FerroSMART's entity ID.
pub(crate) const SP: &str = "https://smart.example.org/saml";
/// FerroSMART's assertion consumer service.
pub(crate) const ACS: &str = "https://smart.example.org/saml/acs";
/// The `ID` of the request the responses answer.
pub(crate) const REQUEST: &str = "_0123456789abcdef0123456789abcdef01234567";
/// The accepted authentication context classes.
pub(crate) const STRONG: &str = "urn:example:loa:high";
/// A class below the provider's minimum.
pub(crate) const WEAK: &str = "urn:example:loa:low";

/// The time every case checks at.
pub(crate) fn now() -> Timestamp {
    "2026-11-19T10:00:00Z".parse().expect("a timestamp")
}

/// Returns `now` moved by `seconds`, as a SAML instant.
pub(crate) fn at(seconds: i64) -> String {
    now()
        .checked_add(SignedDuration::from_secs(seconds))
        .expect("in range")
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// A key pair as PEM, with a self-signed certificate.
pub(crate) struct Pem {
    /// The PKCS#8 private key.
    pub(crate) key: String,
    /// The certificate.
    pub(crate) certificate: String,
    /// The certificate, DER.
    pub(crate) der: Vec<u8>,
}

/// Returns a fresh RSA key of 2048 bits.
pub(crate) fn rsa_pem() -> Pem {
    let key = rsa::PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("a key");
    let pkcs8 = key.as_der().expect("PKCS#8");
    let body = STANDARD.encode(pkcs8.as_ref());
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        lines.join("\n")
    );
    let pair = rcgen::KeyPair::from_pem_and_sign_algo(&pem, &rcgen::PKCS_RSA_SHA256)
        .expect("rcgen reads it");
    pem_of(&pair)
}

/// Returns a fresh ECDSA key on P-256.
pub(crate) fn p256_pem() -> Pem {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a key");
    pem_of(&pair)
}

fn pem_of(pair: &rcgen::KeyPair) -> Pem {
    let certificate = rcgen::CertificateParams::new(vec![String::from("saml.example.org")])
        .expect("params")
        .self_signed(pair)
        .expect("a certificate");
    Pem {
        key: pair.serialize_pem(),
        certificate: certificate.pem(),
        der: certificate.der().to_vec(),
    }
}

/// The keys of one run.
pub(crate) struct Kit {
    /// The identity provider's signing key.
    pub(crate) idp: SigningKey,
    /// Its certificate, DER.
    pub(crate) idp_der: Vec<u8>,
    /// A key the identity provider does not publish.
    pub(crate) stranger: SigningKey,
    /// FerroSMART's signing key.
    pub(crate) sp: SigningKey,
    /// FerroSMART's decryption key.
    pub(crate) decryption: DecryptionKey,
    /// Its public half, for the test provider to encrypt to.
    pub(crate) encryption: rsa::PublicEncryptingKey,
    /// The provider as its metadata describes it.
    pub(crate) provider: IdentityProvider,
}

/// The keys of the run, generated once.
pub(crate) static KIT: LazyLock<Kit> = LazyLock::new(|| {
    let idp = rsa_pem();
    let stranger = rsa_pem();
    let sp = p256_pem();
    let decryption = rsa_pem();
    let public = rsa::PrivateDecryptingKey::from_pkcs8(&pem_der(&decryption.key))
        .expect("PKCS#8")
        .public_key();
    let provider = IdentityProvider::from_metadata(&metadata(&[&idp.der], ""), IDP, now(), None)
        .expect("the metadata reads");
    Kit {
        idp: SigningKey::from_pem(idp.key.as_bytes(), idp.certificate.as_bytes())
            .expect("a signing key"),
        idp_der: idp.der,
        stranger: SigningKey::from_pem(stranger.key.as_bytes(), stranger.certificate.as_bytes())
            .expect("a signing key"),
        sp: SigningKey::from_pem(sp.key.as_bytes(), sp.certificate.as_bytes())
            .expect("a signing key"),
        decryption: DecryptionKey::from_pem(
            decryption.key.as_bytes(),
            decryption.certificate.as_bytes(),
        )
        .expect("a decryption key"),
        encryption: public,
        provider,
    }
});

/// Returns the DER of the one PEM block of `pem`.
pub(crate) fn pem_der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD.decode(body).expect("base64")
}

/// Writes identity provider metadata naming `certificates` as signing
/// keys, with `extra` inside the descriptor.
pub(crate) fn metadata(certificates: &[&[u8]], extra: &str) -> String {
    let mut keys = String::new();
    for der in certificates {
        keys.push_str(
            "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>",
        );
        keys.push_str(&STANDARD.encode(der));
        keys.push_str("</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>");
    }
    format!(
        concat!(
            "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ",
            "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" ID=\"_md\" entityID=\"{idp}\">",
            "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" ",
            "WantAuthnRequestsSigned=\"true\">{keys}{extra}",
            "<md:ArtifactResolutionService index=\"1\" ",
            "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\"https://idp.example.org/ars\"/>",
            "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" ",
            "Location=\"https://idp.example.org/sso\"/>",
            "</md:IDPSSODescriptor></md:EntityDescriptor>"
        ),
        idp = IDP,
        keys = keys,
        extra = extra,
    )
}

/// The accepted classes.
pub(crate) static CLASSES: LazyLock<Vec<String>> = LazyLock::new(|| vec![String::from(STRONG)]);

/// What FerroSMART expects of a response to [`REQUEST`] at [`now`].
pub(crate) fn expect() -> Expectations<'static> {
    Expectations {
        entity_id: SP,
        acs_url: ACS,
        request_id: REQUEST,
        idp: &KIT.provider,
        decryption_keys: std::slice::from_ref(&KIT.decryption),
        authn_contexts: &CLASSES,
        now: now(),
        skew: SignedDuration::from_secs(180),
    }
}

/// The parts of an assertion a case changes.
#[derive(Clone)]
pub(crate) struct Assertion {
    pub(crate) id: String,
    pub(crate) issuer: String,
    pub(crate) subject: String,
    pub(crate) recipient: String,
    pub(crate) in_response_to: String,
    pub(crate) confirm_until: String,
    pub(crate) not_before: String,
    pub(crate) not_on_or_after: String,
    pub(crate) audience: String,
    pub(crate) class: String,
    pub(crate) attributes: String,
    pub(crate) extra_conditions: String,
}

impl Default for Assertion {
    fn default() -> Self {
        Self {
            id: String::from("_assertion1"),
            issuer: String::from(IDP),
            subject: String::from(
                "<saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">person-17</saml:NameID>",
            ),
            recipient: String::from(ACS),
            in_response_to: String::from(REQUEST),
            confirm_until: at(300),
            not_before: at(-60),
            not_on_or_after: at(300),
            audience: String::from(SP),
            class: String::from(STRONG),
            attributes: String::from(
                "<saml:Attribute Name=\"role\"><saml:AttributeValue>clinician</saml:AttributeValue><saml:AttributeValue>nurse</saml:AttributeValue></saml:Attribute>",
            ),
            extra_conditions: String::new(),
        }
    }
}

impl Assertion {
    /// Writes the assertion, unsigned.
    pub(crate) fn xml(&self) -> String {
        format!(
            concat!(
                "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ",
                "ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{issued}\">",
                "<saml:Issuer>{issuer}</saml:Issuer>",
                "<saml:Subject>{subject}",
                "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">",
                "<saml:SubjectConfirmationData NotOnOrAfter=\"{confirm}\" Recipient=\"{recipient}\" ",
                "InResponseTo=\"{irt}\"/></saml:SubjectConfirmation></saml:Subject>",
                "<saml:Conditions NotBefore=\"{nb}\" NotOnOrAfter=\"{noa}\">",
                "<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience>",
                "</saml:AudienceRestriction>{extra}</saml:Conditions>",
                "<saml:AuthnStatement AuthnInstant=\"{authn}\" SessionIndex=\"_s1\">",
                "<saml:AuthnContext><saml:AuthnContextClassRef>{class}</saml:AuthnContextClassRef>",
                "</saml:AuthnContext></saml:AuthnStatement>",
                "<saml:AttributeStatement>{attributes}</saml:AttributeStatement>",
                "</saml:Assertion>"
            ),
            id = self.id,
            issued = at(-5),
            issuer = self.issuer,
            subject = self.subject,
            confirm = self.confirm_until,
            recipient = self.recipient,
            irt = self.in_response_to,
            nb = self.not_before,
            noa = self.not_on_or_after,
            audience = self.audience,
            extra = self.extra_conditions,
            authn = at(-10),
            class = self.class,
            attributes = self.attributes,
        )
    }

    /// Writes the assertion signed by the identity provider.
    pub(crate) fn signed(&self) -> String {
        sign(&self.xml(), &KIT.idp)
    }
}

/// Signs `xml` with `key`.
pub(crate) fn sign(xml: &str, key: &SigningKey) -> String {
    dsig::sign(xml, key).expect("the test message signs")
}

/// Writes a response carrying `assertions`, unsigned.
pub(crate) fn response(assertions: &str) -> String {
    response_with("_response1", REQUEST, "Success", assertions)
}

/// Writes a response with the given `ID`, `InResponseTo` and status.
pub(crate) fn response_with(
    id: &str,
    in_response_to: &str,
    status: &str,
    assertions: &str,
) -> String {
    format!(
        concat!(
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ",
            "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{id}\" Version=\"2.0\" ",
            "IssueInstant=\"{issued}\" Destination=\"{acs}\" InResponseTo=\"{irt}\">",
            "<saml:Issuer>{idp}</saml:Issuer><samlp:Status>",
            "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:{status}\"/>",
            "</samlp:Status>{assertions}</samlp:Response>"
        ),
        id = id,
        issued = at(-5),
        acs = ACS,
        irt = in_response_to,
        idp = IDP,
        status = status,
        assertions = assertions,
    )
}

/// Returns `xml` as the `SAMLResponse` form value.
pub(crate) fn posted(xml: &str) -> String {
    STANDARD.encode(xml)
}

/// The data algorithm of a test encryption.
#[derive(Clone, Copy)]
pub(crate) enum Data {
    Gcm,
    Cbc,
}

/// Wraps `plaintext` in `<saml:{element}>` as XML Encryption writes it
/// for FerroSMART: AES-256 data, its key transported by RSA-OAEP with
/// MGF1 and SHA-1.
pub(crate) fn encrypt(element: &str, plaintext: &str, data: Data) -> String {
    let mut content_key = [0_u8; 32];
    aws_lc_rs::rand::fill(&mut content_key).expect("random");
    let (method, cipher_value) = match data {
        Data::Gcm => {
            let mut iv = [0_u8; 12];
            aws_lc_rs::rand::fill(&mut iv).expect("random");
            let key = aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_256_GCM, &content_key).expect("a key"),
            );
            let mut sealed = plaintext.as_bytes().to_vec();
            key.seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(iv),
                aead::Aad::empty(),
                &mut sealed,
            )
            .expect("sealed");
            let mut out = iv.to_vec();
            out.extend(sealed);
            ("http://www.w3.org/2009/xmlenc11#aes256-gcm", out)
        }
        Data::Cbc => {
            let key = cipher::PaddedBlockEncryptingKey::cbc_pkcs7(
                cipher::UnboundCipherKey::new(&cipher::AES_256, &content_key).expect("a key"),
            )
            .expect("a key");
            let mut in_out = plaintext.as_bytes().to_vec();
            let context = key.encrypt(&mut in_out).expect("encrypted");
            let iv: &[u8] = (&context).try_into().expect("an IV");
            let mut out = iv.to_vec();
            out.extend(in_out);
            ("http://www.w3.org/2001/04/xmlenc#aes256-cbc", out)
        }
    };
    let oaep = rsa::OaepPublicEncryptingKey::new(KIT.encryption.clone()).expect("a key");
    let mut wrapped = vec![0_u8; oaep.ciphertext_size()];
    let wrapped = oaep
        .encrypt(&rsa::OAEP_SHA1_MGF1SHA1, &content_key, &mut wrapped, None)
        .expect("wrapped")
        .to_vec();
    format!(
        concat!(
            "<saml:{element} xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">",
            "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" ",
            "Type=\"http://www.w3.org/2001/04/xmlenc#Element\">",
            "<xenc:EncryptionMethod Algorithm=\"{method}\"/>",
            "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey>",
            "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\">",
            "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>",
            "</xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>{key}</xenc:CipherValue>",
            "</xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>",
            "<xenc:CipherData><xenc:CipherValue>{data}</xenc:CipherValue></xenc:CipherData>",
            "</xenc:EncryptedData></saml:{element}>"
        ),
        element = element,
        method = method,
        key = STANDARD.encode(wrapped),
        data = STANDARD.encode(cipher_value),
    )
}

/// Returns `key`'s certificate as a trusted key.
pub(crate) fn trusted(der: &[u8]) -> TrustedKey {
    TrustedKey::from_certificate_der(der).expect("a trusted key")
}
