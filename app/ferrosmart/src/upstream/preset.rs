// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The upstream presets: the OpenID Connect defaults of a vendor's tested
//! setup, as data files under `presets/` compiled in.
//!
//! An entry names one as `preset`, and each key its `[ferrosmart.upstream.oidc]`
//! table sets wins over the file, which wins over the built-in defaults. A
//! preset holds only what FerroSMART's setup with that vendor fixes (the
//! scopes, the claims and the assertion algorithm), never a deployment's
//! issuer, client or keys. No specification governs the presets: our own
//! design (`docs/architecture.md` §13.22).

use serde::{Deserialize, Serialize};

/// A vendor whose setup FerroSMART ships the defaults of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    /// Keycloak (`docs/architecture.md` §13.16).
    Keycloak,
    /// Microsoft Entra ID (§13.18).
    Entra,
    /// Okta's custom authorization server (§13.19).
    Okta,
    /// ZITADEL (§13.20).
    Zitadel,
}

impl Preset {
    /// Every preset, in the order the documentation lists them.
    pub const ALL: [Self; 4] = [Self::Keycloak, Self::Entra, Self::Okta, Self::Zitadel];

    /// Returns the preset's name, as an entry's `preset` names it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Keycloak => "keycloak",
            Self::Entra => "entra",
            Self::Okta => "okta",
            Self::Zitadel => "zitadel",
        }
    }

    /// Returns the text of the preset's data file.
    #[must_use]
    pub const fn source(self) -> &'static str {
        match self {
            Self::Keycloak => include_str!("../../presets/keycloak.toml"),
            Self::Entra => include_str!("../../presets/entra.toml"),
            Self::Okta => include_str!("../../presets/okta.toml"),
            Self::Zitadel => include_str!("../../presets/zitadel.toml"),
        }
    }

    /// Returns the defaults the preset's data file holds.
    ///
    /// # Errors
    /// Returns [`PresetError`] when the file does not read as a preset,
    /// which the tests rule out for every compiled preset.
    pub fn defaults(self) -> Result<Defaults, PresetError> {
        toml::from_str(self.source()).map_err(|source| PresetError {
            preset: self.name(),
            source: Box::new(source),
        })
    }
}

/// The keys a preset file sets: those of `[ferrosmart.upstream.oidc]` a
/// vendor's setup fixes, each unset when the file leaves it to the
/// built-in default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Defaults {
    /// The scopes asked for.
    pub scopes: Option<Vec<String>>,
    /// The claim of `fhirUser`.
    pub fhir_user_claim: Option<String>,
    /// The claims of the roles.
    pub role_claims: Option<Vec<String>>,
    /// The audiences trusted beside the client id.
    pub trusted_audiences: Option<Vec<String>>,
    /// `[private_key_jwt]`.
    pub private_key_jwt: PrivateKeyJwtDefaults,
}

/// The `[private_key_jwt]` table of a preset file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivateKeyJwtDefaults {
    /// The algorithm the vendor's registration names.
    pub algorithm: Option<String>,
}

/// A compiled preset file that does not read as a preset.
#[derive(Debug, thiserror::Error)]
#[error("the upstream preset `{preset}` does not read as a preset")]
pub struct PresetError {
    /// The preset.
    pub preset: &'static str,
    /// Why.
    #[source]
    pub source: Box<toml::de::Error>,
}

#[cfg(test)]
mod tests {
    use super::Preset;

    #[test]
    fn every_preset_file_reads_and_names_its_algorithm() {
        for preset in Preset::ALL {
            let defaults = preset.defaults().expect("the preset reads");
            assert!(
                defaults.private_key_jwt.algorithm.is_some(),
                "{}",
                preset.name()
            );
            let named: Preset =
                serde_json::from_value(serde_json::json!(preset.name())).expect("named");
            assert_eq!(preset, named);
        }
    }
}
