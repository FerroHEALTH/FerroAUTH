// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The issuer a SMART discovery document describes.
//!
//! SMART App Launch 2.2.0, Conformance, §Metadata requires the document's
//! `authorization_endpoint` whenever it advertises `launch-ehr` or
//! `launch-standalone`, so the document describes one authorization server,
//! the one every user launch starts at. Which of several trusted issuers that
//! is, SMART does not say. No specification governs the choice: our own
//! design, one rule for every product.
//!
//! - **Eligible:** an issuer whose kind is not
//!   [`IssuerKind::Machines`] and whose metadata is available. A `machines`
//!   issuer signs client credentials tokens only, and this crate refuses its
//!   every token that is not app-only, so no user launch can work there.
//! - **Named:** `[auth] described_issuer`, when set, must name an eligible
//!   issuer; anything else is refused.
//! - **Unnamed:** the one eligible issuer is described; several are refused,
//!   naming them, and so is none.
//!
//! The order the issuers are offered in, which is the order of the
//! `[[auth.issuer]]` tables, never decides: a refusal names the issuers sorted.
//!
//! ```
//! use ferrohealth_smart::kind::IssuerKind;
//! use ferrohealth_smart::resource::described::{Candidate, Metadata, describe};
//!
//! let candidates = [
//!     Candidate::new("https://m2m.example", IssuerKind::Machines, Metadata::Available, 1),
//!     Candidate::new("https://login.example", IssuerKind::Persons, Metadata::Available, 2),
//! ];
//! let described = describe(candidates, None)?;
//! assert_eq!(described.issuer(), "https://login.example");
//! assert_eq!(described.into_check(), 2);
//! # Ok::<(), ferrohealth_smart::resource::described::DescribeError>(())
//! ```

use std::fmt;

use ferrohealth_secret::secret_url::SecretUrl;

use crate::kind::IssuerKind;
use crate::resource::ResourceServer;

/// Whether an issuer's metadata is available to build the document from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metadata {
    /// Read from the issuer, introspected, or supplied by the operator
    /// ([`ResourceServer::with_metadata`]).
    Available,
    /// Not known: the key set comes from a `jwks_file` and no metadata was
    /// supplied for it.
    Absent,
}

/// One trusted issuer offered to the discovery document, with the product's
/// own check of it, which builds the document once the issuer is chosen.
#[derive(Debug, Clone)]
pub struct Candidate<T> {
    /// The issuer identifier.
    issuer: String,
    /// Whose tokens it signs.
    kind: IssuerKind,
    /// Whether its metadata is available.
    metadata: Metadata,
    /// The product's check of it.
    check: T,
}

impl<T> Candidate<T> {
    /// Returns the candidate `issuer`, of `kind`, whose metadata is
    /// `metadata`, carrying the product's `check`.
    #[must_use]
    pub fn new(issuer: impl Into<String>, kind: IssuerKind, metadata: Metadata, check: T) -> Self {
        Self {
            issuer: issuer.into(),
            kind,
            metadata,
            check,
        }
    }

    /// Returns the candidate `server` checks the tokens of, its issuer, kind
    /// and metadata read from it, carrying the product's `check`.
    #[must_use]
    pub fn of_server(server: &ResourceServer, check: T) -> Self {
        let settings = server.settings();
        Self::new(
            settings.issuer.clone(),
            settings.kind,
            server.metadata_state(),
            check,
        )
    }

    /// Returns the candidate `introspector` checks the tokens of, carrying
    /// the product's `check`; an introspected issuer's metadata is always
    /// available, since it is read to find the introspection endpoint.
    #[cfg(feature = "fetch")]
    #[must_use]
    pub fn of_introspector(
        introspector: &crate::resource::introspection::Introspector,
        check: T,
    ) -> Self {
        let settings = introspector.settings();
        Self::new(
            settings.issuer.clone(),
            settings.kind,
            Metadata::Available,
            check,
        )
    }

    /// Returns the issuer identifier.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns whose tokens the issuer signs.
    #[must_use]
    pub const fn kind(&self) -> IssuerKind {
        self.kind
    }

    /// Returns whether the issuer's metadata is available.
    #[must_use]
    pub const fn metadata(&self) -> Metadata {
        self.metadata
    }

    /// Returns whether the document may describe this issuer: its kind is
    /// not `machines` and its metadata is available.
    #[must_use]
    pub fn is_eligible(&self) -> bool {
        self.kind != IssuerKind::Machines && self.metadata == Metadata::Available
    }

    /// Returns the product's check of the issuer.
    #[must_use]
    pub fn check(&self) -> &T {
        &self.check
    }

    /// Returns the product's check of the issuer, consuming the candidate.
    #[must_use]
    pub fn into_check(self) -> T {
        self.check
    }
}

/// Why no issuer can be described.
///
/// Every issuer a refusal names renders with any userinfo masked.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DescribeError {
    /// `described_issuer` names no offered issuer.
    #[error("described_issuer names {issuer}, which is no trusted issuer")]
    UnknownIssuer {
        /// The issuer named.
        issuer: SecretUrl,
    },
    /// `described_issuer` names a `machines` issuer.
    #[error(
        "described_issuer names the machines issuer {issuer}: it signs client credentials \
         tokens only, so no user launch can start there"
    )]
    MachinesIssuer {
        /// The issuer named.
        issuer: SecretUrl,
    },
    /// `described_issuer` names an issuer whose metadata is not available.
    #[error(
        "described_issuer names {issuer}, whose metadata is not available: its key set is a \
         jwks_file and no metadata was supplied for it"
    )]
    NoMetadata {
        /// The issuer named.
        issuer: SecretUrl,
    },
    /// No issuer is named and several are eligible.
    #[error(
        "the discovery document can describe any of the issuers {}; set described_issuer to \
         the one user launches start at",
        Listed(.issuers)
    )]
    SeveralEligible {
        /// The eligible issuers, sorted.
        issuers: Vec<SecretUrl>,
    },
    /// No issuer is eligible.
    #[error(
        "the discovery document can describe no issuer: it needs a trusted issuer that is not \
         of kind machines and whose metadata is available"
    )]
    NoneEligible,
}

/// The issuers of a refusal, comma-separated.
struct Listed<'a>(&'a [SecretUrl]);

impl fmt::Display for Listed<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (at, issuer) in self.0.iter().enumerate() {
            if at > 0 {
                f.write_str(", ")?;
            }
            fmt::Display::fmt(issuer, f)?;
        }
        Ok(())
    }
}

/// Returns the candidate the discovery document describes: the one `named`
/// names when set, else the one eligible candidate.
///
/// A product calls it when it serves the document, with
/// [`Resolved::described_issuer`](crate::config::Resolved::described_issuer)
/// as `named` and a [`Candidate`] for every issuer it trusts, whatever its
/// kind, so a named `machines` issuer is refused as such.
///
/// # Errors
///
/// With `named`: [`DescribeError::UnknownIssuer`] when no candidate is that
/// issuer, [`DescribeError::MachinesIssuer`] when it is a `machines` issuer
/// and [`DescribeError::NoMetadata`] when its metadata is absent. Without:
/// [`DescribeError::SeveralEligible`] naming every eligible issuer when there
/// are several, and [`DescribeError::NoneEligible`] when there is none.
pub fn describe<T>(
    candidates: impl IntoIterator<Item = Candidate<T>>,
    named: Option<&SecretUrl>,
) -> Result<Candidate<T>, DescribeError> {
    let mut candidates = candidates.into_iter();
    if let Some(named) = named {
        let Some(found) = candidates.find(|candidate| candidate.issuer == named.expose()) else {
            return Err(DescribeError::UnknownIssuer {
                issuer: named.clone(),
            });
        };
        if found.kind == IssuerKind::Machines {
            return Err(DescribeError::MachinesIssuer {
                issuer: named.clone(),
            });
        }
        if found.metadata == Metadata::Absent {
            return Err(DescribeError::NoMetadata {
                issuer: named.clone(),
            });
        }
        return Ok(found);
    }
    let mut eligible: Vec<Candidate<T>> = candidates.filter(Candidate::is_eligible).collect();
    if eligible.len() > 1 {
        let mut issuers: Vec<SecretUrl> = eligible
            .iter()
            .map(|candidate| SecretUrl::new(candidate.issuer.clone()))
            .collect();
        issuers.sort_by(|left, right| left.expose().cmp(right.expose()));
        return Err(DescribeError::SeveralEligible { issuers });
    }
    eligible.pop().ok_or(DescribeError::NoneEligible)
}
