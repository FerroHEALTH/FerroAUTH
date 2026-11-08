// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The pre-scan that holds an assertion's element depth and namespace
//! declarations to their caps before `roxmltree` parses it.
//!
//! `roxmltree` copies the namespaces in scope into every element that
//! declares one, so nesting that declares a fresh prefix at each level costs
//! time quadratic in the depth before any check runs. The scan reads the raw
//! input once, in linear time and without allocating, and refuses an input
//! past either cap. It is no parser: an input it admits may still be
//! refused by `roxmltree`, and an input it cannot follow is refused, since
//! `roxmltree` would refuse it too.

/// The deepest element nesting read: the deepest eHDSI path, through
/// `ds:Signature`, is 7 (no specification governs the cap: our own design).
pub(super) const MAX_DEPTH: usize = 32;
/// The most namespace declarations a document carries: an `IdA` that declares
/// `xs` and `xsi` on every value, as eHDSI Section II Security Services
/// 10.0.0 §10.1 shows, carries about 50 (our own design).
pub(super) const MAX_NAMESPACES: usize = 128;

/// An input past a cap, or one the scan cannot follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct OutOfBounds;

/// Refuses `xml` when an element nests deeper than [`MAX_DEPTH`] or the
/// document declares more than [`MAX_NAMESPACES`] namespaces.
pub(super) fn check(xml: &str) -> Result<(), OutOfBounds> {
    let mut scan = Scan {
        bytes: xml.as_bytes(),
        at: 0,
    };
    let mut depth = 0_usize;
    let mut namespaces = 0_usize;
    while let Some(open) = scan.find(b'<') {
        scan.at = open.saturating_add(1);
        if scan.eat(b"!--") {
            scan.skip_past(b"-->")?;
        } else if scan.eat(b"![CDATA[") {
            scan.skip_past(b"]]>")?;
        } else if scan.eat(b"?") {
            scan.skip_past(b"?>")?;
        } else if scan.eat(b"!") {
            // The parser options refuse a DTD, so the scan refuses any declaration.
            return Err(OutOfBounds);
        } else if scan.eat(b"/") {
            depth = depth.checked_sub(1).ok_or(OutOfBounds)?;
            scan.skip_past(b">")?;
        } else {
            depth = depth.saturating_add(1);
            if depth > MAX_DEPTH {
                return Err(OutOfBounds);
            }
            let tag = scan.start_tag()?;
            namespaces = namespaces.saturating_add(tag.namespaces);
            if namespaces > MAX_NAMESPACES {
                return Err(OutOfBounds);
            }
            if tag.empty {
                depth = depth.saturating_sub(1);
            }
        }
    }
    Ok(())
}

/// What a start tag declares.
struct Tag {
    /// The `xmlns` and `xmlns:*` attributes it carries.
    namespaces: usize,
    /// Whether it ends in `/>`.
    empty: bool,
}

/// A cursor over the raw input.
struct Scan<'a> {
    /// The input.
    bytes: &'a [u8],
    /// The next byte read.
    at: usize,
}

impl Scan<'_> {
    /// Returns the next byte, without moving.
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    /// Returns the position of the next `byte`, from the cursor.
    fn find(&self, byte: u8) -> Option<usize> {
        let rest = self.bytes.get(self.at..)?;
        rest.iter()
            .position(|b| *b == byte)
            .map(|offset| self.at.saturating_add(offset))
    }

    /// Moves past `token` when the input continues with it.
    fn eat(&mut self, token: &[u8]) -> bool {
        let found = self
            .bytes
            .get(self.at..)
            .is_some_and(|rest| rest.starts_with(token));
        if found {
            self.at = self.at.saturating_add(token.len());
        }
        found
    }

    /// Moves past the next `token`, refusing an input that ends first.
    fn skip_past(&mut self, token: &[u8]) -> Result<(), OutOfBounds> {
        let rest = self.bytes.get(self.at..).ok_or(OutOfBounds)?;
        let offset = rest
            .windows(token.len())
            .position(|window| window == token)
            .ok_or(OutOfBounds)?;
        self.at = self.at.saturating_add(offset).saturating_add(token.len());
        Ok(())
    }

    /// Moves past white space (XML 1.0 §2.3, `S`).
    fn space(&mut self) {
        while self
            .peek()
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.at = self.at.saturating_add(1);
        }
    }

    /// Returns the name at the cursor, up to white space, `=`, `/` or `>`.
    fn name(&mut self) -> Result<&[u8], OutOfBounds> {
        let start = self.at;
        while self
            .peek()
            .is_some_and(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'=' | b'/' | b'>'))
        {
            self.at = self.at.saturating_add(1);
        }
        match self.bytes.get(start..self.at) {
            Some(name) if !name.is_empty() => Ok(name),
            _ => Err(OutOfBounds),
        }
    }

    /// Reads a start tag after its `<`: the name, then each attribute with
    /// its quoted value, which may hold `>` and `/` (XML 1.0 §3.1).
    fn start_tag(&mut self) -> Result<Tag, OutOfBounds> {
        self.name()?;
        let mut namespaces = 0_usize;
        loop {
            self.space();
            if self.eat(b"/>") {
                return Ok(Tag {
                    namespaces,
                    empty: true,
                });
            }
            if self.eat(b">") {
                return Ok(Tag {
                    namespaces,
                    empty: false,
                });
            }
            let name = self.name()?;
            if name == b"xmlns" || name.starts_with(b"xmlns:") {
                namespaces = namespaces.saturating_add(1);
            }
            self.space();
            if !self.eat(b"=") {
                return Err(OutOfBounds);
            }
            self.space();
            let quote = self.peek().filter(|b| matches!(b, b'"' | b'\''));
            let quote = quote.ok_or(OutOfBounds)?;
            self.at = self.at.saturating_add(1);
            self.skip_past(&[quote])?;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use super::{MAX_DEPTH, MAX_NAMESPACES, OutOfBounds, check};

    fn nested(depth: usize, declare: bool) -> String {
        let mut xml = String::new();
        for level in 0..depth {
            if declare {
                write!(xml, "<p{level}:a xmlns:p{level}=\"u\">").expect("a String takes it");
            } else {
                xml.push_str("<a>");
            }
        }
        for level in (0..depth).rev() {
            if declare {
                write!(xml, "</p{level}:a>").expect("a String takes it");
            } else {
                xml.push_str("</a>");
            }
        }
        xml
    }

    #[test]
    fn the_depth_cap_admits_its_limit_and_refuses_one_more() {
        assert_eq!(check(&nested(MAX_DEPTH, false)), Ok(()));
        assert_eq!(check(&nested(MAX_DEPTH + 1, false)), Err(OutOfBounds));
    }

    #[test]
    fn empty_elements_and_siblings_do_not_deepen() {
        let siblings = "<a/>".repeat(MAX_DEPTH * 2);
        assert_eq!(check(&format!("<r>{siblings}<b></b><c /></r>")), Ok(()));
    }

    #[test]
    fn the_namespace_cap_counts_every_declaration() {
        let declarations = |n: usize| -> String {
            let mut out = String::new();
            for i in 0..n {
                write!(out, " xmlns:p{i}=\"u\"").expect("a String takes it");
            }
            out
        };
        let at_cap = format!("<a xmlns=\"d\"{}/>", declarations(MAX_NAMESPACES - 1));
        assert_eq!(check(&at_cap), Ok(()));
        let past = format!("<a xmlns=\"d\"{}/>", declarations(MAX_NAMESPACES));
        assert_eq!(check(&past), Err(OutOfBounds));
    }

    #[test]
    fn markup_in_values_comments_and_cdata_is_not_read_as_tags() {
        let xml = concat!(
            "<?xml version=\"1.0\"?><a k='<b>' l = \"/>x\" xmlnsx=\"n\">",
            "<!-- <c><c><c> --><![CDATA[<d><d>]]><?pi <e>?>text &amp; more</a>"
        );
        assert_eq!(check(xml), Ok(()));
    }

    #[test]
    fn an_input_the_scan_cannot_follow_is_refused() {
        for xml in [
            "<!DOCTYPE a><a/>",
            "<a k=v/>",
            "<a k=\"v/>",
            "<a><!-- open</a>",
            "</a>",
            "< a/>",
        ] {
            assert_eq!(check(xml), Err(OutOfBounds), "{xml}");
        }
    }

    #[test]
    fn the_reviewed_nesting_is_refused() {
        assert_eq!(check(&nested(2500, true)), Err(OutOfBounds));
    }
}
