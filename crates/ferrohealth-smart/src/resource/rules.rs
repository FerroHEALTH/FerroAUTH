// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The rules an issuer's settings are held to beside its keys, shared by the
//! JWT and the introspection settings.

use std::collections::BTreeSet;

use crate::assurance::AssuranceSection;
use crate::federation::FederationSection;
use crate::kind::IssuerKind;
use crate::profile::Profile;
use crate::resource::ResourceError;

/// Checks what an issuer of `kind` is configured with beside its keys: its
/// profile, its assurance mapping, and the settings its kind refuses.
pub(super) fn check_issuer_rules(
    kind: IssuerKind,
    profile: &Profile,
    assurance: Option<&AssuranceSection>,
    federation: Option<&FederationSection>,
    scopeless_subjects: &BTreeSet<String>,
    role_claims: &[String],
) -> Result<(), ResourceError> {
    profile.validate(kind)?;
    match (kind, federation) {
        (IssuerKind::Federation, Some(section)) => section.validate()?,
        (IssuerKind::Federation, None) | (_, Some(_)) => {
            return Err(ResourceError::Kind {
                key: "federation",
                kind,
            });
        }
        (_, None) => {}
    }
    if let Some(assurance) = assurance {
        assurance.validate()?;
    }
    // NOTE: no specification governs the allowlist: our own design; a patient
    // or another party is never granted system-wide access.
    if !scopeless_subjects.is_empty()
        && matches!(kind, IssuerKind::Patients | IssuerKind::Federation)
    {
        return Err(ResourceError::Kind {
            key: "scopeless_subjects",
            kind,
        });
    }
    // NOTE: no specification governs this: our own design; another party's
    // issuer asserts no role of this deployment.
    if !role_claims.is_empty() && kind == IssuerKind::Federation {
        return Err(ResourceError::Kind {
            key: "role_claims",
            kind,
        });
    }
    Ok(())
}
