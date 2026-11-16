// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The issuer a SMART discovery document describes, and what for.
//!
//! SMART App Launch 2.2.0, Conformance, §Metadata requires the document's
//! `authorization_endpoint` whenever it advertises `launch-ehr` or
//! `launch-standalone`, and its `token_endpoint` always, which a Backend
//! Services client discovers from the same document (Backend Services,
//! §Retrieve `.well-known/smart-configuration`). So the document describes
//! one authorization server. Which of several trusted issuers that is, SMART
//! does not say. No specification governs the choice: our own design, one
//! rule for every product.
//!
//! - **Named:** `[auth] described_issuer`, when set, is described, once it
//!   is a trusted issuer with metadata. A `machines` issuer is described for
//!   Backend Services only, and only while no issuer is eligible for app
//!   launch, so naming it never hides the launch issuer from SMART apps.
//! - **App launch:** otherwise, when the deployment trusts an issuer of a
//!   kind that signs user tokens (`persons`, `patients`, `federation`), the
//!   one such issuer with metadata is described for SMART App Launch;
//!   several are refused, naming them, and so is none.
//! - **Backend Services:** otherwise, the one `machines` issuer with
//!   metadata is described for Backend Services only
//!   ([`Purpose::BackendServices`]); several are refused, naming them.
//! - **None:** otherwise the document describes no issuer, and is refused.
//!
//! The order the issuers are offered in, which is the order of the
//! `[[auth.issuer]]` tables, never decides: a refusal names the issuers sorted.
//!
//! ```
//! use ferrohealth_smart::kind::IssuerKind;
//! use ferrohealth_smart::resource::configuration::Purpose;
//! use ferrohealth_smart::resource::described::{Candidate, Metadata, describe};
//!
//! let candidates = [
//!     Candidate::new("https://m2m.example", IssuerKind::Machines, Metadata::Available, 1),
//!     Candidate::new("https://login.example", IssuerKind::Persons, Metadata::Available, 2),
//! ];
//! let described = describe(candidates, None)?;
//! assert_eq!(described.issuer(), "https://login.example");
//! assert_eq!(described.purpose(), Purpose::AppLaunch);
//! assert_eq!(described.into_check(), 2);
//!
//! let machines = [
//!     Candidate::new("https://m2m.example", IssuerKind::Machines, Metadata::Available, 1),
//! ];
//! let described = describe(machines, None)?;
//! assert_eq!(described.purpose(), Purpose::BackendServices);
//! # Ok::<(), ferrohealth_smart::resource::described::DescribeError>(())
//! ```

use std::fmt;

use ferrohealth_secret::secret_url::SecretUrl;

use crate::kind::IssuerKind;
use crate::resource::ResourceServer;
use crate::resource::configuration::Purpose;

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

    /// Returns whether the document may describe this issuer for SMART App
    /// Launch: its kind is not `machines` and its metadata is available.
    #[must_use]
    pub fn is_eligible(&self) -> bool {
        self.kind != IssuerKind::Machines && self.metadata == Metadata::Available
    }

    /// Returns whether the document may describe this issuer for SMART
    /// Backend Services alone: its kind is `machines` and its metadata is
    /// available.
    #[must_use]
    pub fn is_backend_eligible(&self) -> bool {
        self.kind == IssuerKind::Machines && self.metadata == Metadata::Available
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

/// The issuer the discovery document describes, with what it describes it
/// for.
#[derive(Debug, Clone)]
pub struct Described<T> {
    /// The issuer described.
    candidate: Candidate<T>,
    /// What the document advertises it for.
    purpose: Purpose,
}

impl<T> Described<T> {
    /// Returns the issuer identifier.
    #[must_use]
    pub fn issuer(&self) -> &str {
        self.candidate.issuer()
    }

    /// Returns whose tokens the issuer signs.
    #[must_use]
    pub const fn kind(&self) -> IssuerKind {
        self.candidate.kind
    }

    /// Returns what the document advertises the issuer for, the
    /// [`SmartOptions::purpose`](crate::resource::configuration::SmartOptions::purpose)
    /// the product builds the document under.
    #[must_use]
    pub const fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// Returns the product's check of the issuer.
    #[must_use]
    pub fn check(&self) -> &T {
        self.candidate.check()
    }

    /// Returns the product's check of the issuer, consuming the result.
    #[must_use]
    pub fn into_check(self) -> T {
        self.candidate.into_check()
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
    /// `described_issuer` names a `machines` issuer while an issuer is
    /// eligible for app launch.
    #[error(
        "described_issuer names the machines issuer {issuer}, while the deployment trusts an \
         issuer user launches start at: the document would advertise Backend Services only"
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
    /// No issuer is named and several are eligible for app launch.
    #[error(
        "the discovery document can describe any of the issuers {}; set described_issuer to \
         the one user launches start at",
        Listed(.issuers)
    )]
    SeveralEligible {
        /// The eligible issuers, sorted.
        issuers: Vec<SecretUrl>,
    },
    /// No issuer is named, no issuer signs user tokens, and several
    /// `machines` issuers are eligible for Backend Services.
    #[error(
        "the discovery document can describe any of the machines issuers {} for Backend \
         Services; set described_issuer to the one backend clients take tokens from",
        Listed(.issuers)
    )]
    SeveralMachines {
        /// The eligible `machines` issuers, sorted.
        issuers: Vec<SecretUrl>,
    },
    /// No issuer is eligible.
    #[error(
        "the discovery document can describe no issuer: it needs a trusted issuer whose \
         metadata is available, of kind persons, patients or federation for app launch, or, \
         when the deployment trusts none of those kinds, of kind machines for Backend Services"
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

/// Returns the issuer the discovery document describes, and what for.
///
/// That is the one `named` names when set, else the one issuer eligible for
/// app launch, else, when no trusted issuer signs user tokens, the one
/// `machines` issuer for Backend Services.
///
/// A product calls it when it loads, with
/// [`Resolved::described_issuer`](crate::config::Resolved::described_issuer)
/// as `named` and a [`Candidate`] for every issuer it trusts, whatever its
/// kind, and builds the document under the [`Described::purpose`].
///
/// # Errors
///
/// With `named`: [`DescribeError::UnknownIssuer`] when no candidate is that
/// issuer, [`DescribeError::NoMetadata`] when its metadata is absent, and
/// [`DescribeError::MachinesIssuer`] when it is a `machines` issuer while a
/// candidate is eligible for app launch. Without:
/// [`DescribeError::SeveralEligible`] naming every issuer eligible for app
/// launch when there are several, [`DescribeError::SeveralMachines`] naming
/// every `machines` issuer with metadata when no candidate signs user tokens
/// and there are several, and [`DescribeError::NoneEligible`] when no issuer
/// can be described.
pub fn describe<T>(
    candidates: impl IntoIterator<Item = Candidate<T>>,
    named: Option<&SecretUrl>,
) -> Result<Described<T>, DescribeError> {
    let mut candidates: Vec<Candidate<T>> = candidates.into_iter().collect();
    if let Some(named) = named {
        let Some(at) = candidates
            .iter()
            .position(|candidate| candidate.issuer == named.expose())
        else {
            return Err(DescribeError::UnknownIssuer {
                issuer: named.clone(),
            });
        };
        let launch = candidates.iter().any(Candidate::is_eligible);
        let found = candidates.swap_remove(at);
        if found.metadata == Metadata::Absent {
            return Err(DescribeError::NoMetadata {
                issuer: named.clone(),
            });
        }
        if found.kind != IssuerKind::Machines {
            return Ok(Described {
                candidate: found,
                purpose: Purpose::AppLaunch,
            });
        }
        if launch {
            return Err(DescribeError::MachinesIssuer {
                issuer: named.clone(),
            });
        }
        return Ok(Described {
            candidate: found,
            purpose: Purpose::BackendServices,
        });
    }
    let signs_user_tokens = candidates
        .iter()
        .any(|candidate| candidate.kind != IssuerKind::Machines);
    let (eligible, purpose): (fn(&Candidate<T>) -> bool, Purpose) = if signs_user_tokens {
        (Candidate::is_eligible, Purpose::AppLaunch)
    } else {
        (Candidate::is_backend_eligible, Purpose::BackendServices)
    };
    let mut chosen: Vec<Candidate<T>> = candidates.into_iter().filter(eligible).collect();
    if chosen.len() > 1 {
        let mut issuers: Vec<SecretUrl> = chosen
            .iter()
            .map(|candidate| SecretUrl::new(candidate.issuer.clone()))
            .collect();
        issuers.sort_by(|left, right| left.expose().cmp(right.expose()));
        return Err(match purpose {
            Purpose::BackendServices => DescribeError::SeveralMachines { issuers },
            Purpose::AppLaunch => DescribeError::SeveralEligible { issuers },
        });
    }
    chosen
        .pop()
        .map(|candidate| Described { candidate, purpose })
        .ok_or(DescribeError::NoneEligible)
}
