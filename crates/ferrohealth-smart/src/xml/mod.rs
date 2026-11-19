// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The bounded XML reader and the Exclusive XML Canonicalization the XML
//! signature checks share (behind `xml`).
//!
//! An XML document that arrives from a network is read in three steps
//! before any check runs: [`prepare`] holds it to a byte cap, pre-scans
//! its element depth and namespace declarations in linear time, and
//! translates its line ends (XML 1.0 §2.11); [`parse`] builds the
//! `roxmltree` tree with no DTD and a node cap; and [`c14n::canonicalize`]
//! writes the canonical octets of one element (W3C Exclusive XML
//! Canonicalization 1.0 without comments) that a digest covers. The
//! caps are the caller's [`Limits`]; no specification sets them.
//!
//! The eHDSI assertion check of [`crate::federation::assertion`] reads its
//! assertions through this module, and FerroSMART reads its upstream SAML
//! 2.0 responses through it.

use std::borrow::Cow;

use roxmltree::Document;
use roxmltree::ParsingOptions;

mod bounds;
pub mod c14n;

/// The caps an untrusted document is held to before and while it is
/// parsed (no specification governs them: each caller's own design).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The largest document read, in bytes.
    pub bytes: usize,
    /// The most nodes the document is parsed into.
    pub nodes: u32,
    /// The deepest element nesting read.
    pub depth: usize,
    /// The most namespace declarations the document carries.
    pub namespaces: usize,
}

/// Why a document is refused before any check of its content runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refused {
    /// The document is larger than [`Limits::bytes`].
    #[error("the XML document is larger than the cap")]
    TooLarge,
    /// The document nests deeper than [`Limits::depth`], declares more
    /// than [`Limits::namespaces`] namespaces, carries a document type
    /// declaration, or cannot be followed by the pre-scan.
    #[error("the XML document is past the depth or namespace cap, or carries a DTD")]
    OutOfBounds,
    /// The document is not well formed, carries a DTD, or parses into more
    /// than [`Limits::nodes`] nodes.
    #[error("the XML document is not well formed or is past the node cap")]
    Malformed,
}

/// Returns `xml` held to `limits` and with its line ends translated
/// (XML 1.0 §2.11), the text [`parse`] reads.
///
/// # Errors
///
/// [`Refused::TooLarge`] past the byte cap, and [`Refused::OutOfBounds`]
/// past the depth or namespace cap, on a document type declaration, or on
/// an input the pre-scan cannot follow.
pub fn prepare(xml: &str, limits: Limits) -> Result<Cow<'_, str>, Refused> {
    if xml.len() > limits.bytes {
        return Err(Refused::TooLarge);
    }
    bounds::check(xml, limits.depth, limits.namespaces)
        .map_err(|_out_of_bounds| Refused::OutOfBounds)?;
    Ok(c14n::line_ends(xml))
}

/// Parses `prepared`, the text [`prepare`] returned, with no DTD and at
/// most [`Limits::nodes`] nodes.
///
/// # Errors
///
/// [`Refused::Malformed`] when the text is not well formed, declares a
/// DTD, or is past the node cap.
pub fn parse(prepared: &str, limits: Limits) -> Result<Document<'_>, Refused> {
    let options = ParsingOptions {
        allow_dtd: false,
        nodes_limit: limits.nodes,
        ..ParsingOptions::default()
    };
    Document::parse_with_options(prepared, options).map_err(|_malformed| Refused::Malformed)
}
