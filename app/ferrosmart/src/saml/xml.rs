// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The reading every SAML message shares: the bounded parse with no DTD,
//! the one-carrier rule for `ID` values, the schema order of an element's
//! children, and text read only from elements that hold nothing else.

use std::borrow::Cow;
use std::collections::BTreeSet;

use ferrohealth_smart::xml;
use jiff::Timestamp;
use roxmltree::Document;
use roxmltree::Node;

use crate::saml::Refusal;

/// The caps a SAML message is held to before and while it is parsed: a
/// response with a few dozen attributes, a signed and encrypted assertion
/// and a SOAP envelope stays far below each (no specification governs
/// them: our own design).
const LIMITS: xml::Limits = xml::Limits {
    bytes: 256 * 1024,
    nodes: 16_384,
    depth: 32,
    namespaces: 256,
};

/// Returns `raw` held to the caps, with its line ends translated.
pub(super) fn prepare(raw: &str) -> Result<Cow<'_, str>, Refusal> {
    xml::prepare(raw, LIMITS).map_err(|_refused| Refusal::Xml)
}

/// Parses `prepared` with no DTD, refusing a document in which an `ID`
/// value is carried by more than one attribute.
pub(super) fn parse(prepared: &str) -> Result<Document<'_>, Refusal> {
    let document = xml::parse(prepared, LIMITS).map_err(|_refused| Refusal::Xml)?;
    unique_ids(&document)?;
    Ok(document)
}

/// Refuses a document in which two attributes named `ID`, `Id` or `id`, in
/// any namespace, carry one value.
///
/// A same-document reference resolves by ID (xmldsig-core1 §4.4.3.3), so a
/// second carrier is the lever of every signature wrapping shape; FerroSMART
/// never resolves a reference by ID, and refuses the document besides.
fn unique_ids(document: &Document<'_>) -> Result<(), Refusal> {
    let mut seen = BTreeSet::new();
    for attribute in document.descendants().flat_map(|node| node.attributes()) {
        if attribute.name().eq_ignore_ascii_case("id") && !seen.insert(attribute.value()) {
            return Err(Refusal::DuplicateId);
        }
    }
    Ok(())
}

/// Whether `node` is the element `name` of namespace `namespace`, empty for
/// none.
pub(super) fn is(node: Node<'_, '_>, namespace: &str, name: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace().unwrap_or_default() == namespace
        && node.tag_name().name() == name
}

/// The element children of one element, read in their schema order.
pub(super) struct Children<'a, 'input> {
    /// The element children, in document order.
    items: Vec<Node<'a, 'input>>,
    /// The next child not yet read.
    at: usize,
    /// The element whose children these are, as its refusal names it.
    of: &'static str,
}

impl<'a, 'input> Children<'a, 'input> {
    /// Returns the element children of `node`, refusing text that is not
    /// white space between them.
    pub(super) fn of(node: Node<'a, 'input>, of: &'static str) -> Result<Self, Refusal> {
        let mut items = Vec::new();
        for child in node.children() {
            if child.is_element() {
                items.push(child);
            } else if child.is_text() && !child.text().unwrap_or_default().trim().is_empty() {
                return Err(Refusal::Structure(of));
            }
        }
        Ok(Self { items, at: 0, of })
    }

    /// Returns the next child when it is `name`, and moves past it.
    pub(super) fn optional(&mut self, namespace: &str, name: &str) -> Option<Node<'a, 'input>> {
        let next = self.items.get(self.at).copied()?;
        if is(next, namespace, name) {
            self.at = self.at.saturating_add(1);
            Some(next)
        } else {
            None
        }
    }

    /// Returns the next child, which must be `name`.
    pub(super) fn required(
        &mut self,
        namespace: &str,
        name: &str,
        what: &'static str,
    ) -> Result<Node<'a, 'input>, Refusal> {
        self.optional(namespace, name)
            .ok_or(Refusal::Structure(what))
    }

    /// Returns every next child that is `name`.
    pub(super) fn many(&mut self, namespace: &str, name: &str) -> Vec<Node<'a, 'input>> {
        let mut found = Vec::new();
        while let Some(node) = self.optional(namespace, name) {
            found.push(node);
        }
        found
    }

    /// Returns every child not yet read.
    pub(super) fn rest(self) -> Vec<Node<'a, 'input>> {
        self.items.into_iter().skip(self.at).collect()
    }

    /// Refuses a child left unread.
    pub(super) fn end(self) -> Result<(), Refusal> {
        if self.at == self.items.len() {
            Ok(())
        } else {
            Err(Refusal::Structure(self.of))
        }
    }
}

/// Whether `node` holds no element and no text but white space.
pub(super) fn empty(node: Node<'_, '_>) -> bool {
    node.children().all(|child| {
        !child.is_element()
            && (!child.is_text() || child.text().unwrap_or_default().trim().is_empty())
    })
}

/// Returns the text of `node`, an element whose content is text alone.
///
/// An element that also holds a comment, a processing instruction or an
/// element is refused: a comment splits a text node, and a reader that
/// takes one part reads a value the signature did not cover as written
/// (the canonical form without comments drops the comment).
pub(super) fn text<'a>(node: Node<'a, '_>, what: &'static str) -> Result<&'a str, Refusal> {
    let mut children = node.children();
    match (children.next(), children.next()) {
        (None, _) => Ok(""),
        (Some(only), None) if only.is_text() => Ok(only.text().unwrap_or_default()),
        _ => Err(Refusal::Structure(what)),
    }
}

/// Returns the text of `node` with the leading and trailing white space
/// the `whiteSpace="collapse"` facet of `xs:anyURI` removes (XML Schema
/// Part 2 §3.2.17).
pub(super) fn uri<'a>(node: Node<'a, '_>, what: &'static str) -> Result<&'a str, Refusal> {
    let value = text(node, what)?.trim_matches(['\u{20}', '\t', '\n', '\r']);
    if value.is_empty() || value.contains(['\u{20}', '\t', '\n', '\r']) {
        Err(Refusal::Structure(what))
    } else {
        Ok(value)
    }
}

/// Returns the instant of the attribute `name` of `node`, a UTC
/// `xs:dateTime` with no time zone but `Z` (saml-core-2.0-os §1.3.3).
pub(super) fn instant(node: Node<'_, '_>, name: &str) -> Result<Option<Timestamp>, Refusal> {
    node.attribute(name).map(parse_instant).transpose()
}

/// Parses a UTC `xs:dateTime` (saml-core-2.0-os §1.3.3).
pub(super) fn parse_instant(value: &str) -> Result<Timestamp, Refusal> {
    let date_and_time = value.strip_suffix('Z').ok_or(Refusal::Instant)?;
    if date_and_time.contains(['+', 'z']) || !date_and_time.contains('T') {
        return Err(Refusal::Instant);
    }
    value
        .parse::<Timestamp>()
        .map_err(|_malformed| Refusal::Instant)
}

/// Writes `instant` as a UTC `xs:dateTime` to the second, the form a
/// message FerroSMART writes carries (saml-core-2.0-os §1.3.3).
pub(super) fn format_instant(instant: Timestamp) -> String {
    instant.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::{Children, parse, parse_instant, prepare, text, uri};
    use crate::saml::Refusal;

    #[test]
    fn a_dtd_and_an_external_entity_are_refused() {
        for xml in [
            "<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>",
            "<!DOCTYPE r [<!ENTITY a \"aaaa\"><!ENTITY b \"&a;&a;&a;\">]><r>&b;</r>",
            "<!DOCTYPE r SYSTEM \"http://attacker.example/r.dtd\"><r/>",
        ] {
            let refused = prepare(xml).and_then(|text| parse(&text).map(|_doc| ()));
            assert_eq!(refused, Err(Refusal::Xml), "{xml}");
        }
    }

    #[test]
    fn an_id_carried_twice_in_any_spelling_is_refused() {
        for xml in [
            r#"<r ID="a"><c ID="a"/></r>"#,
            r#"<r ID="a"><c Id="a"/></r>"#,
            r#"<r xmlns:w="urn:w" ID="a"><c w:id="a"/></r>"#,
        ] {
            assert_eq!(
                parse(xml).map(|_doc| ()),
                Err(Refusal::DuplicateId),
                "{xml}"
            );
        }
        assert!(parse(r#"<r ID="a"><c ID="b"/></r>"#).is_ok());
    }

    #[test]
    fn text_split_by_a_comment_is_refused() {
        let document = parse("<r><a>user@example.org<!---->.attacker.example</a><b>x</b></r>")
            .expect("well formed");
        let mut children = Children::of(document.root_element(), "r").expect("elements only");
        let a = children.required("", "a", "a").expect("a first");
        let b = children.required("", "b", "b").expect("b second");
        assert_eq!(text(a, "a"), Err(Refusal::Structure("a")));
        assert_eq!(text(b, "b"), Ok("x"));
        children.end().expect("nothing left");
    }

    #[test]
    fn children_out_of_order_or_left_over_are_refused() {
        let document = parse("<r><b/><a/></r>").expect("well formed");
        let mut children = Children::of(document.root_element(), "r").expect("elements only");
        assert!(children.optional("", "a").is_none());
        assert!(children.required("", "b", "b").is_ok());
        assert_eq!(children.end(), Err(Refusal::Structure("r")));
        let document = parse("<r>text<a/></r>").expect("well formed");
        assert!(Children::of(document.root_element(), "r").is_err());
    }

    #[test]
    fn a_uri_is_collapsed_and_one_with_inner_space_refused() {
        let document = parse("<r><a>\n urn:x \n</a><b>urn: x</b></r>").expect("well formed");
        let mut nodes = document
            .root_element()
            .children()
            .filter(roxmltree::Node::is_element);
        let (a, b) = (nodes.next().expect("a"), nodes.next().expect("b"));
        assert_eq!(uri(a, "a"), Ok("urn:x"));
        assert_eq!(uri(b, "b"), Err(Refusal::Structure("b")));
    }

    #[test]
    fn only_utc_instants_are_read() {
        assert!(parse_instant("2026-11-19T10:00:00Z").is_ok());
        assert!(parse_instant("2026-11-19T10:00:00.123Z").is_ok());
        for refused in [
            "2026-11-19T10:00:00",
            "2026-11-19T10:00:00+01:00",
            "2026-11-19T10:00:00+00:00Z",
            "2026-11-19Z",
        ] {
            assert_eq!(parse_instant(refused), Err(Refusal::Instant), "{refused}");
        }
    }
}
