// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The check of the `Response` that answers FerroSMART's `AuthnRequest`
//! (saml-profiles-2.0-os §4.1.4.2 and §4.1.4.3 as errata E26 amends them;
//! saml-core-2.0-os §2, §3.2.2), and the [`Login`] it asserts.
//!
//! The rules beyond the profile, each our own design recorded in
//! `docs/architecture.md` §13.26:
//!
//! - exactly one assertion, plain or encrypted, and no `saml:Advice`, so
//!   there is one assertion to read and no nested one to confuse it with;
//! - the assertion is covered by a verified signature whatever the
//!   binding: its own, the `Response`'s, or the `ArtifactResponse`'s that
//!   carried it (§4.1.4.5 as E26 words it for HTTP-POST, held for
//!   HTTP-Artifact too);
//! - every `ds:Signature` of the document is one of those, at its place,
//!   and verified;
//! - no unsolicited response: `InResponseTo` names the request (§4.1.5);
//! - one `AuthnStatement`, with an `AuthnContextClassRef`.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jiff::SignedDuration;
use jiff::Timestamp;
use roxmltree::Document;
use roxmltree::Node;
use roxmltree::NodeId;

use crate::saml::ASSERTION;
use crate::saml::DSIG;
use crate::saml::ENTITY;
use crate::saml::PROTOCOL;
use crate::saml::Refusal;
use crate::saml::SUCCESS;
use crate::saml::VERSION;
use crate::saml::dsig;
use crate::saml::keys::DecryptionKey;
use crate::saml::metadata::IdentityProvider;
use crate::saml::xenc;
use crate::saml::xml;
use crate::saml::xml::Children;

/// The bearer subject confirmation method (saml-profiles-2.0-os §3.3).
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// What FerroSMART expects of the response to one of its requests.
#[derive(Debug, Clone, Copy)]
pub struct Expectations<'a> {
    /// FerroSMART's entity ID, the audience and the encrypted keys'
    /// recipient.
    pub entity_id: &'a str,
    /// The assertion consumer service URL the response or artifact was
    /// delivered to.
    pub acs_url: &'a str,
    /// The `ID` of the `AuthnRequest` the response answers.
    pub request_id: &'a str,
    /// The identity provider the request was sent to.
    pub idp: &'a IdentityProvider,
    /// FerroSMART's keys for an encrypted assertion, identifier or
    /// attribute.
    pub decryption_keys: &'a [DecryptionKey],
    /// The `AuthnContextClassRef` values the provider accepts; empty
    /// accepts any.
    pub authn_contexts: &'a [String],
    /// The time of the check.
    pub now: Timestamp,
    /// The clock skew admitted at each bound (saml-core-2.0-os §1.3.3 as
    /// errata E92 adds to it).
    pub skew: SignedDuration,
}

/// How the response reached FerroSMART.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// In a form posted to the assertion consumer service
    /// (saml-bindings-2.0-os §3.5).
    Post,
    /// Resolved from an artifact over the SOAP binding
    /// (saml-bindings-2.0-os §3.6), with whether a verified
    /// `ArtifactResponse` signature covers it.
    Artifact {
        /// Whether the `ArtifactResponse` that carried the response is
        /// signed by the identity provider.
        signed: bool,
    },
}

/// The subject's name identifier (saml-core-2.0-os §2.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameId {
    /// The identifier.
    pub value: String,
    /// Its `Format`, when named.
    pub format: Option<String>,
    /// Its `NameQualifier`, when named.
    pub name_qualifier: Option<String>,
    /// Its `SPNameQualifier`, when named.
    pub sp_name_qualifier: Option<String>,
}

/// What a checked response asserts about the person who logged in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    /// The identity provider's entity ID.
    pub issuer: String,
    /// The subject, decrypted when it came as an `EncryptedID`.
    pub name_id: NameId,
    /// The attributes by `Name`, each with its values in document order,
    /// encrypted ones decrypted.
    pub attributes: BTreeMap<String, Vec<String>>,
    /// The `AuthnContextClassRef` of the authentication.
    pub authn_context: String,
    /// When the person authenticated.
    pub authn_instant: Timestamp,
    /// The identity provider's session index, when it names one.
    pub session_index: Option<String>,
    /// When the identity provider's session ends, when it says.
    pub session_not_on_or_after: Option<Timestamp>,
    /// The assertion's `ID`, which FerroSMART admits once
    /// (saml-profiles-2.0-os §4.1.4.5).
    pub assertion_id: String,
    /// Until when the assertion could be confirmed, the time the `ID` is
    /// remembered for.
    pub confirmable_until: Timestamp,
}

impl Login {
    /// The values of the attribute `name`, none when it is absent.
    #[must_use]
    pub fn attribute(&self, name: &str) -> &[String] {
        self.attributes.get(name).map_or(&[], Vec::as_slice)
    }
}

/// Checks the base64 `SAMLResponse` form value an HTTP-POST delivered
/// (saml-bindings-2.0-os §3.5.4).
///
/// # Errors
///
/// The [`Refusal`] of the first check that fails.
pub fn check_post(saml_response: &str, expect: &Expectations<'_>) -> Result<Login, Refusal> {
    let compact: String = saml_response
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let bytes = STANDARD
        .decode(compact)
        .map_err(|_invalid| Refusal::Encoding)?;
    let text = String::from_utf8(bytes).map_err(|_not_utf8| Refusal::Encoding)?;
    let prepared = xml::prepare(&text)?;
    let document = xml::parse(&prepared)?;
    let response = document.root_element();
    if !xml::is(response, PROTOCOL, "Response") {
        return Err(Refusal::Structure("samlp:Response"));
    }
    check(response, Delivery::Post, &[], expect)
}

/// Checks `response`, a `samlp:Response` element, delivered as `delivery`
/// says; `outer` are the elements above it that may carry a signature,
/// which the caller has verified.
pub(super) fn check(
    response: Node<'_, '_>,
    delivery: Delivery,
    outer: &[NodeId],
    expect: &Expectations<'_>,
) -> Result<Login, Refusal> {
    let (mut parts, signed, status) =
        status_response(response, "samlp:Response", expect.request_id, expect)?;
    let mut assertions = Vec::new();
    loop {
        if let Some(plain) = parts.optional(ASSERTION, "Assertion") {
            assertions.push(plain);
        } else if let Some(encrypted) = parts.optional(ASSERTION, "EncryptedAssertion") {
            assertions.push(encrypted);
        } else {
            break;
        }
    }
    parts.end()?;
    // NOTE: saml-bindings-2.0-os §3.5.5.2: a signed message posted through the user agent
    // names its destination, which must be where it arrived; E59 leaves it open for artifacts.
    match response.attribute("Destination") {
        Some(destination) if destination != expect.acs_url => return Err(Refusal::Destination),
        None if delivery == Delivery::Post && signed => {
            return Err(Refusal::Destination);
        }
        _ => {}
    }
    check_status(status)?;
    let [assertion] = assertions[..] else {
        return Err(if assertions.is_empty() {
            Refusal::Structure("saml:Assertion")
        } else {
            Refusal::MultipleAssertions
        });
    };
    let covered = signed || matches!(delivery, Delivery::Artifact { signed: true });
    let mut signed_parents: Vec<NodeId> = outer.to_vec();
    signed_parents.push(response.id());
    if xml::is(assertion, ASSERTION, "Assertion") {
        signed_parents.push(assertion.id());
        placed(response.document(), &signed_parents)?;
        return check_assertion(assertion, covered, expect);
    }
    placed(response.document(), &signed_parents)?;
    let plaintext = xenc::decrypt(assertion, expect.decryption_keys, expect.entity_id, covered)?;
    let prepared = xml::prepare(&plaintext).map_err(|_refused| Refusal::Decryption)?;
    let decrypted = xml::parse(&prepared).map_err(|_refused| Refusal::Decryption)?;
    let inner = decrypted.root_element();
    if !xml::is(inner, ASSERTION, "Assertion") {
        return Err(Refusal::Decryption);
    }
    placed(&decrypted, &[inner.id()])?;
    check_assertion(inner, covered, expect)
}

/// Checks the `StatusResponseType` head of `node`, the element `of`
/// (saml-core-2.0-os §3.2.2): its version, `ID`, `InResponseTo`,
/// `IssueInstant`, `Issuer` and signature, verified when present. Returns
/// the children left after `samlp:Status`, whether it is signed, and the
/// status.
pub(super) fn status_response<'a, 'input>(
    node: Node<'a, 'input>,
    of: &'static str,
    in_response_to: &str,
    expect: &Expectations<'_>,
) -> Result<(Children<'a, 'input>, bool, Node<'a, 'input>), Refusal> {
    if node.attribute("Version") != Some(VERSION) {
        return Err(Refusal::Version);
    }
    node.attribute("ID").ok_or(Refusal::Structure("ID"))?;
    if node.attribute("InResponseTo") != Some(in_response_to) {
        return Err(Refusal::InResponseTo);
    }
    not_ahead(node, "IssueInstant", expect)?.ok_or(Refusal::Structure("IssueInstant"))?;
    let mut parts = Children::of(node, of)?;
    let issuer = parts.optional(ASSERTION, "Issuer");
    let signature = parts.optional(DSIG, "Signature");
    parts.optional(PROTOCOL, "Extensions");
    let status = parts.required(PROTOCOL, "Status", "samlp:Status")?;
    if let Some(issuer) = issuer {
        check_issuer(issuer, expect)?;
    }
    if signature.is_some() {
        dsig::verify(node, expect.idp.signing_keys())?;
    }
    Ok((parts, signature.is_some(), status))
}

/// Refuses a `ds:Signature` anywhere in `document` but as a child of one
/// of `parents`, each of which the check verifies when it carries one.
fn placed(document: &Document<'_>, parents: &[NodeId]) -> Result<(), Refusal> {
    let stray = document.descendants().any(|node| {
        xml::is(node, DSIG, "Signature")
            && !node
                .parent()
                .is_some_and(|parent| parents.contains(&parent.id()))
    });
    if stray { Err(Refusal::Wrapped) } else { Ok(()) }
}

/// Refuses an `Issuer` that names another entity, or a format other than
/// the entity format (saml-profiles-2.0-os §4.1.4.2).
pub(super) fn check_issuer(issuer: Node<'_, '_>, expect: &Expectations<'_>) -> Result<(), Refusal> {
    if issuer
        .attribute("Format")
        .is_some_and(|format| format != ENTITY)
    {
        return Err(Refusal::Issuer);
    }
    if xml::text(issuer, "saml:Issuer")? == expect.idp.entity_id() {
        Ok(())
    } else {
        Err(Refusal::Issuer)
    }
}

/// Refuses a status other than success (saml-core-2.0-os §3.2.2.1).
pub(super) fn check_status(status: Node<'_, '_>) -> Result<(), Refusal> {
    let mut parts = Children::of(status, "samlp:Status")?;
    let code = parts.required(PROTOCOL, "StatusCode", "samlp:StatusCode")?;
    parts.optional(PROTOCOL, "StatusMessage");
    parts.optional(PROTOCOL, "StatusDetail");
    parts.end()?;
    match code.attribute("Value") {
        Some(SUCCESS) => Ok(()),
        Some(other) => Err(Refusal::Status(other.to_owned())),
        None => Err(Refusal::Structure("samlp:StatusCode")),
    }
}

/// Returns the instant of the attribute `name`, refusing one ahead of now
/// by more than the skew.
pub(super) fn not_ahead(
    node: Node<'_, '_>,
    name: &str,
    expect: &Expectations<'_>,
) -> Result<Option<Timestamp>, Refusal> {
    let instant = xml::instant(node, name)?;
    if instant.is_some_and(|instant| instant > later(expect.now, expect.skew)) {
        return Err(Refusal::Instant);
    }
    Ok(instant)
}

/// Returns `now` plus `skew`, held at the end of time.
fn later(now: Timestamp, skew: SignedDuration) -> Timestamp {
    now.checked_add(skew).unwrap_or(Timestamp::MAX)
}

/// Returns `now` minus `skew`, held at the start of time.
fn earlier(now: Timestamp, skew: SignedDuration) -> Timestamp {
    now.checked_sub(skew).unwrap_or(Timestamp::MIN)
}

/// Checks one assertion (saml-core-2.0-os §2.3.3), `covered` saying
/// whether a verified signature above it covers it.
fn check_assertion(
    assertion: Node<'_, '_>,
    covered: bool,
    expect: &Expectations<'_>,
) -> Result<Login, Refusal> {
    if assertion.attribute("Version") != Some(VERSION) {
        return Err(Refusal::Version);
    }
    let id = assertion.attribute("ID").ok_or(Refusal::Structure("ID"))?;
    not_ahead(assertion, "IssueInstant", expect)?.ok_or(Refusal::Structure("IssueInstant"))?;
    let mut parts = Children::of(assertion, "saml:Assertion")?;
    let issuer = parts.required(ASSERTION, "Issuer", "saml:Issuer")?;
    let signature = parts.optional(DSIG, "Signature");
    let subject = parts.required(ASSERTION, "Subject", "saml:Subject")?;
    let conditions = parts.required(ASSERTION, "Conditions", "saml:Conditions")?;
    // NOTE: our own design: `saml:Advice` may carry further assertions, a second assertion to
    // confuse with the first, so the statements must follow the conditions directly.
    let mut authn = Vec::new();
    let mut attribute_statements = Vec::new();
    for statement in parts.rest() {
        if xml::is(statement, ASSERTION, "AuthnStatement") {
            authn.push(statement);
        } else if xml::is(statement, ASSERTION, "AttributeStatement") {
            attribute_statements.push(statement);
        } else {
            return Err(Refusal::Structure("saml:Assertion"));
        }
    }
    check_issuer(issuer, expect)?;
    if signature.is_some() {
        dsig::verify(assertion, expect.idp.signing_keys())?;
    } else if !covered {
        return Err(Refusal::Unprotected);
    }
    check_conditions(conditions, expect)?;
    let (name_id, confirmable_until) = check_subject(subject, expect)?;
    let [authn] = authn[..] else {
        return Err(Refusal::Structure("saml:AuthnStatement"));
    };
    let authn = check_authn(authn, expect)?;
    let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for statement in attribute_statements {
        read_attributes(statement, &mut attributes, expect)?;
    }
    Ok(Login {
        issuer: expect.idp.entity_id().to_owned(),
        name_id,
        attributes,
        authn_context: authn.context,
        authn_instant: authn.instant,
        session_index: authn.session_index,
        session_not_on_or_after: authn.session_not_on_or_after,
        assertion_id: id.to_owned(),
        confirmable_until,
    })
}

/// Checks the conditions (saml-core-2.0-os §2.5.1): the window, and an
/// audience restriction naming FerroSMART in each one present, of which
/// there is at least one (saml-profiles-2.0-os §4.1.4.2).
fn check_conditions(conditions: Node<'_, '_>, expect: &Expectations<'_>) -> Result<(), Refusal> {
    if xml::instant(conditions, "NotBefore")?
        .is_some_and(|not_before| not_before > later(expect.now, expect.skew))
    {
        return Err(Refusal::NotYetValid);
    }
    if xml::instant(conditions, "NotOnOrAfter")?
        .is_some_and(|end| end <= earlier(expect.now, expect.skew))
    {
        return Err(Refusal::Expired);
    }
    let mut restrictions = 0_usize;
    let (mut one_time, mut proxy) = (0_usize, 0_usize);
    for condition in Children::of(conditions, "saml:Conditions")?.rest() {
        if xml::is(condition, ASSERTION, "AudienceRestriction") {
            restrictions = restrictions.saturating_add(1);
            let mut named = false;
            for audience in Children::of(condition, "saml:AudienceRestriction")?.rest() {
                if !xml::is(audience, ASSERTION, "Audience") {
                    return Err(Refusal::Structure("saml:AudienceRestriction"));
                }
                named |= xml::uri(audience, "saml:Audience")? == expect.entity_id;
            }
            // NOTE: saml-core-2.0-os §2.5.1.4 as errata E46 states it: each restriction is
            // evaluated on its own, so every one present must name FerroSMART.
            if !named {
                return Err(Refusal::Audience);
            }
        } else if xml::is(condition, ASSERTION, "OneTimeUse") {
            one_time = one_time.saturating_add(1);
        } else if xml::is(condition, ASSERTION, "ProxyRestriction") {
            proxy = proxy.saturating_add(1);
        } else {
            return Err(Refusal::Condition);
        }
    }
    if one_time > 1 || proxy > 1 {
        return Err(Refusal::Structure("saml:Conditions"));
    }
    if restrictions == 0 {
        return Err(Refusal::Audience);
    }
    Ok(())
}

/// Checks the subject and returns its name identifier, with the end of
/// the window of the bearer confirmation that holds (saml-profiles-2.0-os
/// §4.1.4.2, §4.1.4.3 as errata E26 amends them).
fn check_subject(
    subject: Node<'_, '_>,
    expect: &Expectations<'_>,
) -> Result<(NameId, Timestamp), Refusal> {
    let mut parts = Children::of(subject, "saml:Subject")?;
    let name_id = if let Some(plain) = parts.optional(ASSERTION, "NameID") {
        name_id(plain)?
    } else if let Some(encrypted) = parts.optional(ASSERTION, "EncryptedID") {
        let plaintext = xenc::decrypt(encrypted, expect.decryption_keys, expect.entity_id, true)?;
        let prepared = xml::prepare(&plaintext).map_err(|_refused| Refusal::Decryption)?;
        let decrypted = xml::parse(&prepared).map_err(|_refused| Refusal::Decryption)?;
        let inner = decrypted.root_element();
        if !xml::is(inner, ASSERTION, "NameID") {
            return Err(Refusal::Decryption);
        }
        name_id(inner)?
    } else {
        return Err(Refusal::Structure("saml:NameID"));
    };
    let confirmations = parts.many(ASSERTION, "SubjectConfirmation");
    parts.end()?;
    let confirmed = confirmations
        .into_iter()
        .filter(|confirmation| confirmation.attribute("Method") == Some(BEARER))
        .find_map(|confirmation| bearer(confirmation, expect))
        .ok_or(Refusal::SubjectConfirmation)?;
    Ok((name_id, confirmed))
}

/// Returns the end of the window of a bearer confirmation that names
/// FerroSMART's assertion consumer service and request and has not
/// passed, or `None` for one that does not hold.
///
/// A confirmation that does not hold is not a defect of the assertion:
/// another bearer confirmation may hold (saml-profiles-2.0-os §4.1.4.3 as
/// errata E26 amends it), and the caller refuses when none does.
fn bearer(confirmation: Node<'_, '_>, expect: &Expectations<'_>) -> Option<Timestamp> {
    let data = confirmation
        .children()
        .filter(Node::is_element)
        .find(|child| xml::is(*child, ASSERTION, "SubjectConfirmationData"))?;
    if data.attribute("NotBefore").is_some()
        || data.attribute("Recipient") != Some(expect.acs_url)
        || data.attribute("InResponseTo") != Some(expect.request_id)
    {
        return None;
    }
    let end = xml::parse_instant(data.attribute("NotOnOrAfter")?).ok()?;
    (end > earlier(expect.now, expect.skew)).then_some(end)
}

/// Reads a `saml:NameID` (saml-core-2.0-os §2.2.3).
fn name_id(node: Node<'_, '_>) -> Result<NameId, Refusal> {
    let value = xml::text(node, "saml:NameID")?;
    if value.trim().is_empty() {
        return Err(Refusal::Structure("saml:NameID"));
    }
    Ok(NameId {
        value: value.to_owned(),
        format: node.attribute("Format").map(str::to_owned),
        name_qualifier: node.attribute("NameQualifier").map(str::to_owned),
        sp_name_qualifier: node.attribute("SPNameQualifier").map(str::to_owned),
    })
}

/// What the one authentication statement says.
struct Authn {
    /// The `AuthnContextClassRef`.
    context: String,
    /// The `AuthnInstant`.
    instant: Timestamp,
    /// The `SessionIndex`, when named.
    session_index: Option<String>,
    /// The `SessionNotOnOrAfter`, when named.
    session_not_on_or_after: Option<Timestamp>,
}

/// Checks the one authentication statement (saml-core-2.0-os §2.7.2).
fn check_authn(authn: Node<'_, '_>, expect: &Expectations<'_>) -> Result<Authn, Refusal> {
    let authn_instant =
        not_ahead(authn, "AuthnInstant", expect)?.ok_or(Refusal::Structure("AuthnInstant"))?;
    let session_not_on_or_after = xml::instant(authn, "SessionNotOnOrAfter")?;
    if session_not_on_or_after.is_some_and(|end| end <= earlier(expect.now, expect.skew)) {
        return Err(Refusal::Expired);
    }
    let mut parts = Children::of(authn, "saml:AuthnStatement")?;
    parts.optional(ASSERTION, "SubjectLocality");
    let context = parts.required(ASSERTION, "AuthnContext", "saml:AuthnContext")?;
    parts.end()?;
    let mut context_parts = Children::of(context, "saml:AuthnContext")?;
    let class = context_parts
        .optional(ASSERTION, "AuthnContextClassRef")
        .ok_or(Refusal::AuthnContext)?;
    if context_parts
        .optional(ASSERTION, "AuthnContextDecl")
        .is_none()
    {
        context_parts.optional(ASSERTION, "AuthnContextDeclRef");
    }
    context_parts.many(ASSERTION, "AuthenticatingAuthority");
    context_parts.end()?;
    let class = xml::uri(class, "saml:AuthnContextClassRef")?;
    // NOTE: saml-core-2.0-os §3.3.2.2.1: the request asked for an exact match of one of the
    // provider's accepted classes, so any other class is below the provider's minimum.
    if !expect.authn_contexts.is_empty()
        && !expect
            .authn_contexts
            .iter()
            .any(|accepted| accepted == class)
    {
        return Err(Refusal::AuthnContext);
    }
    Ok(Authn {
        context: class.to_owned(),
        instant: authn_instant,
        session_index: authn.attribute("SessionIndex").map(str::to_owned),
        session_not_on_or_after,
    })
}

/// Reads the attributes of one statement into `attributes`, decrypting an
/// `EncryptedAttribute` (saml-core-2.0-os §2.7.3).
fn read_attributes(
    statement: Node<'_, '_>,
    attributes: &mut BTreeMap<String, Vec<String>>,
    expect: &Expectations<'_>,
) -> Result<(), Refusal> {
    for child in Children::of(statement, "saml:AttributeStatement")?.rest() {
        if xml::is(child, ASSERTION, "Attribute") {
            read_attribute(child, attributes)?;
        } else if xml::is(child, ASSERTION, "EncryptedAttribute") {
            let plaintext = xenc::decrypt(child, expect.decryption_keys, expect.entity_id, true)?;
            let prepared = xml::prepare(&plaintext).map_err(|_refused| Refusal::Decryption)?;
            let decrypted = xml::parse(&prepared).map_err(|_refused| Refusal::Decryption)?;
            let inner = decrypted.root_element();
            if !xml::is(inner, ASSERTION, "Attribute") {
                return Err(Refusal::Decryption);
            }
            read_attribute(inner, attributes)?;
        } else {
            return Err(Refusal::Structure("saml:AttributeStatement"));
        }
    }
    Ok(())
}

/// Reads one `saml:Attribute`: each value is text, or one `saml:NameID`
/// whose text it takes (saml-core-2.0-os §2.7.3.1.1).
fn read_attribute(
    attribute: Node<'_, '_>,
    attributes: &mut BTreeMap<String, Vec<String>>,
) -> Result<(), Refusal> {
    let name = attribute
        .attribute("Name")
        .ok_or(Refusal::Structure("saml:Attribute"))?;
    let mut values = Vec::new();
    for value in Children::of(attribute, "saml:Attribute")?.rest() {
        if !xml::is(value, ASSERTION, "AttributeValue") {
            return Err(Refusal::Structure("saml:Attribute"));
        }
        let text = if value.children().any(|child| child.is_element()) {
            match Children::of(value, "saml:AttributeValue")?.rest()[..] {
                [inner] if xml::is(inner, ASSERTION, "NameID") => xml::text(inner, "saml:NameID")?,
                _ => return Err(Refusal::Structure("saml:AttributeValue")),
            }
        } else {
            xml::text(value, "saml:AttributeValue")?
        };
        values.push(text.to_owned());
    }
    attributes
        .entry(name.to_owned())
        .or_default()
        .extend(values);
    Ok(())
}
