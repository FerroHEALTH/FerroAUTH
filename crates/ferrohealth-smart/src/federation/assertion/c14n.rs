// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Exclusive XML Canonicalization 1.0 without comments (W3C Recommendation,
//! 18 July 2002), of one element and its descendants, less one excluded
//! subtree: the enveloped signature of XML-DSig §6.6.4.
//!
//! The input is the `XPath` data model `roxmltree` builds from text whose
//! line ends [`line_ends`] normalized first (XML 1.0 §2.11), so character
//! references and attribute values arrive normalized too (§3.3.3); the
//! prefixes are read from the source text, since the canonical form keeps
//! the prefix the signer wrote (Exc-C14N §3).

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use roxmltree::Node;
use roxmltree::NodeId;

/// Returns `xml` with every `\r\n` and every `\r` not followed by `\n`
/// as one `\n`, the translation XML 1.0 §2.11 has a processor make before
/// parsing. A carriage return written as `&#xD;` is no literal one, so it
/// survives into the canonical form as C14N 1.0 §2.3 writes it.
pub(super) fn line_ends(xml: &str) -> Cow<'_, str> {
    if xml.contains('\r') {
        Cow::Owned(xml.replace("\r\n", "\n").replace('\r', "\n"))
    } else {
        Cow::Borrowed(xml)
    }
}

/// One step of the walk: entering a node, or leaving an element.
enum Step<'a, 'input> {
    /// Write the node, and enter its children.
    Open(Node<'a, 'input>),
    /// Write the element's end tag.
    Close(Node<'a, 'input>),
}

/// A node the canonical form cannot be written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Unrepresentable;

/// Returns the canonical octets of `apex` and its descendants, without the
/// subtree of `excluded`, with the prefixes of `inclusive` treated as
/// Exc-C14N §3's `InclusiveNamespaces PrefixList` (`#default` names the
/// default namespace).
pub(super) fn canonicalize(
    apex: Node<'_, '_>,
    excluded: Option<NodeId>,
    inclusive: &[&str],
) -> Result<Vec<u8>, Unrepresentable> {
    let mut out = String::new();
    // NOTE: the walk keeps its own stack, so nesting cannot exhaust the thread's; each open
    // element holds what it and its output ancestors rendered (Exc-C14N §3).
    let mut stack: Vec<Step<'_, '_>> = vec![Step::Open(apex)];
    let mut scopes: Vec<BTreeMap<String, String>> = vec![BTreeMap::new()];
    while let Some(step) = stack.pop() {
        match step {
            Step::Open(node) if Some(node.id()) == excluded => {}
            Step::Open(node) if node.is_element() => {
                let parent = scopes.last().cloned().unwrap_or_default();
                let rendered = open(&mut out, node, parent, inclusive)?;
                scopes.push(rendered);
                stack.push(Step::Close(node));
                let children: Vec<Node<'_, '_>> = node.children().collect();
                stack.extend(children.into_iter().rev().map(Step::Open));
            }
            Step::Open(node) if node.is_text() => {
                escape_text(&mut out, node.text().unwrap_or_default());
            }
            Step::Open(node) => {
                if let Some(pi) = node.pi() {
                    out.push_str("<?");
                    out.push_str(pi.target);
                    if let Some(value) = pi.value.filter(|value| !value.is_empty()) {
                        out.push(' ');
                        out.push_str(value);
                    }
                    out.push_str("?>");
                }
            }
            Step::Close(node) => {
                scopes.pop();
                out.push_str("</");
                out.push_str(qname(node)?);
                out.push('>');
            }
        }
    }
    Ok(out.into_bytes())
}

/// Writes the start tag of `node`, and returns the namespaces rendered in
/// its scope.
fn open(
    out: &mut String,
    node: Node<'_, '_>,
    mut rendered: BTreeMap<String, String>,
    inclusive: &[&str],
) -> Result<BTreeMap<String, String>, Unrepresentable> {
    let name = qname(node)?;
    let source = node.document().input_text();
    let mut attributes = Vec::new();
    let mut prefixes = BTreeSet::new();
    prefixes.insert(prefix(name).to_owned());
    for attribute in node.attributes() {
        let attribute_name = source.get(attribute.range_qname()).ok_or(Unrepresentable)?;
        if attribute_name.contains(':') {
            prefixes.insert(prefix(attribute_name).to_owned());
        }
        attributes.push((
            attribute.namespace().unwrap_or_default(),
            attribute.name(),
            attribute_name,
            attribute.value(),
        ));
    }
    for listed in inclusive {
        let listed = if *listed == "#default" { "" } else { listed };
        let bound = if listed.is_empty() {
            node.default_namespace().is_some()
        } else {
            node.lookup_namespace_uri(Some(listed)).is_some()
        };
        if bound {
            prefixes.insert(listed.to_owned());
        }
    }
    out.push('<');
    out.push_str(name);
    // NOTE: Exc-C14N §3 renders a visibly utilized namespace unless its nearest output
    // ancestor rendered the same; namespace nodes sort by prefix, the default first.
    for prefix in prefixes {
        if prefix == "xml" {
            continue;
        }
        let uri = if prefix.is_empty() {
            node.default_namespace().unwrap_or_default()
        } else {
            node.lookup_namespace_uri(Some(&prefix))
                .ok_or(Unrepresentable)?
        };
        let inherited = rendered.get(&prefix).map_or("", String::as_str);
        if inherited == uri {
            continue;
        }
        out.push_str(" xmlns");
        if !prefix.is_empty() {
            out.push(':');
            out.push_str(&prefix);
        }
        out.push_str("=\"");
        escape_attribute(out, uri);
        out.push('"');
        rendered.insert(prefix, uri.to_owned());
    }
    // NOTE: C14N 1.0 §2.2: attributes sort by namespace URI, then local name, the
    // unqualified first; exclusive canonicalization inherits no xml:* attribute (Exc-C14N §3).
    attributes.sort_by(|left, right| (left.0, left.1).cmp(&(right.0, right.1)));
    for (_, _, attribute_name, value) in attributes {
        out.push(' ');
        out.push_str(attribute_name);
        out.push_str("=\"");
        escape_attribute(out, value);
        out.push('"');
    }
    out.push('>');
    Ok(rendered)
}

/// Returns the qualified name of an element as the source spells it.
pub(super) fn qname<'input>(node: Node<'_, 'input>) -> Result<&'input str, Unrepresentable> {
    let source = node.document().input_text();
    let tag = source
        .get(node.range().start..)
        .and_then(|rest| rest.strip_prefix('<'))
        .ok_or(Unrepresentable)?;
    let end = tag
        .find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>')
        .ok_or(Unrepresentable)?;
    let name = tag.get(..end).ok_or(Unrepresentable)?;
    // NOTE: the source name and the parsed name agree, or the range points elsewhere.
    let local = name.rsplit(':').next().unwrap_or_default();
    if local == node.tag_name().name() {
        Ok(name)
    } else {
        Err(Unrepresentable)
    }
}

/// Returns the prefix of a qualified name, empty for the default namespace.
fn prefix(name: &str) -> &str {
    name.split_once(':').map_or("", |(prefix, _)| prefix)
}

/// Escapes a text node (C14N 1.0 §2.3, "Text Nodes").
fn escape_text(out: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(c),
        }
    }
}

/// Escapes an attribute value (C14N 1.0 §2.3, "Attribute Nodes").
fn escape_attribute(out: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::canonicalize;
    use super::line_ends;

    fn canonical(xml: &str, inclusive: &[&str]) -> String {
        let xml = line_ends(xml);
        let doc = roxmltree::Document::parse(&xml).expect("the case is well formed");
        let bytes = canonicalize(doc.root_element(), None, inclusive).expect("canonicalizable");
        String::from_utf8(bytes).expect("UTF-8")
    }

    #[test]
    fn empty_elements_become_pairs_and_attributes_sort() {
        assert_eq!(
            canonical(r#"<e b="2" a='1'/>"#, &[]),
            r#"<e a="1" b="2"></e>"#
        );
    }

    #[test]
    fn unused_namespaces_are_dropped_and_used_ones_rendered_once() {
        let xml = r#"<n0:a xmlns:n0="urn:a" xmlns:n1="urn:b"><n0:b><n1:c/></n0:b></n0:a>"#;
        assert_eq!(
            canonical(xml, &[]),
            r#"<n0:a xmlns:n0="urn:a"><n0:b><n1:c xmlns:n1="urn:b"></n1:c></n0:b></n0:a>"#
        );
    }

    #[test]
    fn an_inclusive_prefix_is_rendered_at_the_apex() {
        let xml = r#"<a xmlns:xs="urn:xs" xmlns:n="urn:n"><b>xs:string</b></a>"#;
        assert_eq!(
            canonical(xml, &["xs"]),
            r#"<a xmlns:xs="urn:xs"><b>xs:string</b></a>"#
        );
    }

    #[test]
    fn qualified_attributes_sort_after_unqualified_by_namespace() {
        let xml = r#"<e xmlns:z="urn:a" xmlns:y="urn:b" y:k="1" z:k="2" k="3"/>"#;
        assert_eq!(
            canonical(xml, &[]),
            r#"<e xmlns:y="urn:b" xmlns:z="urn:a" k="3" z:k="2" y:k="1"></e>"#
        );
    }

    #[test]
    fn text_and_attribute_values_are_escaped() {
        let xml = "<e a=\"&lt;&amp;&quot;&#x9;&#xA;&#xD;\">&lt;&amp;&gt;&#xD;<![CDATA[<x>]]></e>";
        assert_eq!(
            canonical(xml, &[]),
            "<e a=\"&lt;&amp;&quot;&#x9;&#xA;&#xD;\">&lt;&amp;&gt;&#xD;&lt;x&gt;</e>"
        );
    }

    #[test]
    fn comments_go_and_line_ends_are_normalized() {
        assert_eq!(
            canonical("<e>a\r\n<!-- c -->b\rc</e>", &[]),
            "<e>a\nb\nc</e>"
        );
    }

    #[test]
    fn a_default_namespace_is_undeclared_beneath_one_that_set_it() {
        let xml = r#"<a xmlns="urn:a"><b xmlns=""/></a>"#;
        assert_eq!(
            canonical(xml, &[]),
            r#"<a xmlns="urn:a"><b xmlns=""></b></a>"#
        );
    }

    #[test]
    fn the_excluded_subtree_is_left_out() {
        let xml = "<a> <s><t/></s> <b/></a>";
        let doc = roxmltree::Document::parse(xml).expect("the case is well formed");
        let excluded = doc
            .descendants()
            .find(|node| node.has_tag_name("s"))
            .map(|node| node.id());
        let bytes = canonicalize(doc.root_element(), excluded, &[]).expect("canonicalizable");
        assert_eq!(String::from_utf8(bytes).expect("UTF-8"), "<a>  <b></b></a>");
    }

    #[test]
    fn a_lone_carriage_return_is_a_line_feed_as_libxml2_writes_it() {
        // NOTE: XML 1.0 §2.11; the expectations are `xmllint --exc-c14n`'s (FerroHEALTH/FerroAUTH#316).
        for (text, expected) in [
            ("a\rb", "a\nb"),
            ("a\r<b/>", "a\n<b></b>"),
            ("a\r&amp;", "a\n&amp;"),
            ("&amp;\r", "&amp;\n"),
        ] {
            assert_eq!(
                canonical(&format!("<e>{text}</e>"), &[]),
                format!("<e>{expected}</e>"),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_carriage_return_written_as_a_reference_stays_one() {
        assert_eq!(canonical("<e>a&#xD;\r\nb</e>", &[]), "<e>a&#xD;\nb</e>");
    }
}
