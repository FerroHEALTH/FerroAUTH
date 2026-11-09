// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The vendor adapters: code for what an issuer's profile cannot express as
//! data, each behind its own Cargo feature and reached by the core only
//! through [`IdpAdapter`].
//!
//! A profile names an adapter by its feature name (`adapter = "idp-entra"`),
//! and [`Profile::validate`] refuses a name this build does not compile in.
//! This module is the one tree outside the preset selector where a vendor's
//! name stands. No specification governs adapters: our own design.
//!
//! - `entra` (feature `idp-entra`): a Microsoft Entra ID groups overage,
//!   resolved through Microsoft Graph.
//! - `section`: the `[auth.idp]` table that configures them, one table per
//!   adapter, and the adapters it builds.
//!
//! [`IdpAdapter`]: crate::party::adapter::IdpAdapter
//! [`Profile::validate`]: crate::profile::Profile::validate

#[cfg(feature = "idp-entra")]
pub mod entra;
pub mod section;

/// The adapter names this build compiles in, which a profile's `adapter`
/// may name.
pub const COMPILED: &[&str] = &[
    #[cfg(feature = "idp-entra")]
    entra::NAME,
];

/// Returns whether this build compiles in the adapter `name`.
#[must_use]
pub fn is_compiled(name: &str) -> bool {
    COMPILED.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_no_feature_compiles_is_never_compiled() {
        assert!(!is_compiled("idp-unknown"));
        assert!(!is_compiled(""));
        assert_eq!(cfg!(feature = "idp-entra"), is_compiled("idp-entra"));
    }
}
