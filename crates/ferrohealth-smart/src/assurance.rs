// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The assurance level of the authentication behind a bearer token, and the
//! natural person it names.
//!
//! [`AssuranceSection`] maps the values of the token's authentication
//! context class claim (`acr`, OpenID Connect Core 1.0 §2, by default) to the
//! three eIDAS levels a deployment reads them as, and refuses a token below
//! its minimum with the RFC 9470 §3 step-up challenge, which names the
//! accepted values in `acr_values`. [`ProfessionalSection`] reads the claim
//! that names the natural person behind a token, and tells a client token
//! apart: RFC 9068 §2.2 has `sub` identify the client application when no
//! resource owner is involved. Which routes a product holds to these, and
//! what it records of them, stay the product's; RFC 9470 §3 leaves "the
//! logic through which the resource server determines that the current
//! request does not meet the authentication requirements" out of scope.
//!
//! A Basic credential carries neither a level nor an issuer-asserted person,
//! so a Basic caller has neither. The mapping of claim values to levels is
//! the deployment's (no specification governs it: our own design).

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;

use crate::refusal::AcrValueError;
use crate::refusal::Refusal;
use crate::refusal::StepUp;
use crate::resource::Caller;
use crate::resource::Via;

/// A level of assurance of an electronic identification, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AssuranceLevel {
    /// The level of assurance low.
    Low,
    /// The level of assurance substantial.
    Substantial,
    /// The level of assurance high.
    High,
}

impl AssuranceLevel {
    /// The configuration spelling: `low`, `substantial` or `high`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Substantial => "substantial",
            Self::High => "high",
        }
    }
}

/// The level a token carries and the minimum a request is held to.
///
/// Off by default: with no `minimum` nothing is refused, and with an empty
/// `levels` map no value carries a level.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AssuranceSection {
    /// The claim carrying the authentication context class, a dotted path;
    /// `acr` by default (OpenID Connect Core 1.0 §2).
    pub claim: String,
    /// The level each claim value the issuer emits stands for; a value the
    /// map does not name carries none.
    pub levels: BTreeMap<String, AssuranceLevel>,
    /// The level a request held to the section must carry; none refuses
    /// nothing.
    pub minimum: Option<AssuranceLevel>,
}

impl Default for AssuranceSection {
    fn default() -> Self {
        Self {
            claim: String::from("acr"),
            levels: BTreeMap::new(),
            minimum: None,
        }
    }
}

/// What a token says about the authentication behind it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Assessment {
    /// The claim's value, trimmed.
    pub value: Option<String>,
    /// The level the value stands for.
    pub level: Option<AssuranceLevel>,
}

/// Why an [`AssuranceSection`] or a [`ProfessionalSection`] is refused at
/// boot.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AssuranceError {
    /// A claim path is blank or has an empty step.
    #[error("the claim path {key} is blank or has an empty step")]
    Claim {
        /// The key of the path.
        key: &'static str,
    },
    /// A minimum is set and no value of the map reaches it, so every
    /// request held to it would be refused.
    #[error("assurance minimum {minimum} is set and no value of the levels map reaches it")]
    Unreachable {
        /// The minimum.
        minimum: &'static str,
    },
    /// A value of the map cannot travel in the step-up challenge.
    #[error("an assurance value cannot travel in the step-up challenge")]
    Value(#[source] AcrValueError),
}

impl AssuranceSection {
    /// Checks the section: a claim path with no empty step, a minimum some
    /// mapped value reaches, and values the step-up challenge can carry.
    ///
    /// # Errors
    ///
    /// The [`AssuranceError`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), AssuranceError> {
        if !path_ok(&self.claim) {
            return Err(AssuranceError::Claim {
                key: "assurance.claim",
            });
        }
        StepUp::new()
            .with_acr_values(self.levels.keys().cloned())
            .map_err(AssuranceError::Value)?;
        if let Some(minimum) = self.minimum
            && self.accepted().is_empty()
        {
            return Err(AssuranceError::Unreachable {
                minimum: minimum.as_str(),
            });
        }
        Ok(())
    }

    /// Returns the claim values that meet the minimum, in the map's order;
    /// none when no minimum is set.
    #[must_use]
    pub fn accepted(&self) -> Vec<&str> {
        let Some(minimum) = self.minimum else {
            return Vec::new();
        };
        self.levels
            .iter()
            .filter(|(_, level)| **level >= minimum)
            .map(|(value, _)| value.as_str())
            .collect()
    }

    /// Returns what `caller`'s token says about its authentication; a Basic
    /// caller says nothing.
    #[must_use]
    pub fn assess(&self, caller: &Caller) -> Assessment {
        if caller.via() == Via::Basic {
            return Assessment::default();
        }
        let value = caller.claim_text(&self.claim).map(str::to_owned);
        let level = value
            .as_deref()
            .and_then(|value| self.levels.get(value).copied());
        Assessment { value, level }
    }

    /// Returns whether `caller` meets the minimum; every caller does when
    /// none is set.
    #[must_use]
    pub fn meets(&self, caller: &Caller) -> bool {
        self.minimum.is_none_or(|minimum| {
            self.assess(caller)
                .level
                .is_some_and(|level| level >= minimum)
        })
    }

    /// Returns the refusal of a caller below the minimum: `401` with
    /// `insufficient_user_authentication` and the accepted values in
    /// `acr_values` (RFC 9470 §3).
    ///
    /// # Errors
    ///
    /// [`AcrValueError`] for a mapped value the challenge cannot carry,
    /// which [`AssuranceSection::validate`] refuses at boot.
    pub fn step_up(&self) -> Result<Refusal, AcrValueError> {
        StepUp::new()
            .with_acr_values(self.accepted())
            .map(Refusal::StepUp)
    }
}

/// How a client token is told apart from a token that names a person.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientTokens {
    /// A token whose `sub` equals its `client_id` or `azp` names the client
    /// application (RFC 9068 §2.2; OpenID Connect Core 1.0 §2), and so does a
    /// token that lacks the person claim.
    #[default]
    SubIsClient,
    /// Only a token that lacks the person claim is a client token.
    ClaimAbsent,
}

/// How a bearer token names the natural person behind it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProfessionalSection {
    /// The claim naming the natural person, a dotted path; `sub` by default.
    pub claim: String,
    /// How a client token is told apart.
    pub client_tokens: ClientTokens,
    /// The claim a client token names the professional it acts for in, a
    /// dotted path (such as `act.sub`); none when a client token acts for
    /// no one.
    pub acting_for_claim: Option<String>,
}

impl Default for ProfessionalSection {
    fn default() -> Self {
        Self {
            claim: String::from("sub"),
            client_tokens: ClientTokens::SubIsClient,
            acting_for_claim: None,
        }
    }
}

/// Whether a token names a person or a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActingMode {
    /// The token names the natural person behind it.
    Person,
    /// The token is a client's, acting for the professional
    /// [`Actor::professional`] names, if any.
    Client,
}

/// Who acts behind a token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Actor {
    /// Whether the token names a person or a client; `None` for a Basic
    /// caller.
    pub mode: Option<ActingMode>,
    /// The natural person: the person claim of a person's token, or the
    /// acting-for claim of a client's.
    pub professional: Option<String>,
}

impl ProfessionalSection {
    /// Checks the section: claim paths with no empty step.
    ///
    /// # Errors
    ///
    /// [`AssuranceError::Claim`] naming the path refused.
    pub fn validate(&self) -> Result<(), AssuranceError> {
        if !path_ok(&self.claim) {
            return Err(AssuranceError::Claim {
                key: "professional.claim",
            });
        }
        if self
            .acting_for_claim
            .as_deref()
            .is_some_and(|path| !path_ok(path))
        {
            return Err(AssuranceError::Claim {
                key: "professional.acting_for_claim",
            });
        }
        Ok(())
    }

    /// Returns who acts behind `caller`'s token; a Basic caller names no
    /// one.
    #[must_use]
    pub fn actor(&self, caller: &Caller) -> Actor {
        if caller.via() == Via::Basic {
            return Actor::default();
        }
        let person = caller.claim_text(&self.claim);
        let client = person.is_none()
            || (self.client_tokens == ClientTokens::SubIsClient && names_the_client(caller));
        if client {
            Actor {
                mode: Some(ActingMode::Client),
                professional: self
                    .acting_for_claim
                    .as_deref()
                    .and_then(|path| caller.claim_text(path))
                    .map(str::to_owned),
            }
        } else {
            Actor {
                mode: Some(ActingMode::Person),
                professional: person.map(str::to_owned),
            }
        }
    }
}

/// Returns whether the token's `sub` is its `client_id` or `azp`.
fn names_the_client(caller: &Caller) -> bool {
    ["client_id", "azp"]
        .iter()
        .any(|claim| caller.claim_text(claim) == Some(caller.subject()))
}

/// Returns whether `path` is a dotted claim path with no empty step.
fn path_ok(path: &str) -> bool {
    !path.split('.').any(|step| step.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn bearer(sub: &str, claims: &serde_json::Value) -> Caller {
        Caller::new(String::from(sub), None, "", None, false)
            .with_claims(claims.as_object().cloned().expect("an object"))
    }

    fn section(minimum: Option<AssuranceLevel>) -> AssuranceSection {
        AssuranceSection {
            levels: BTreeMap::from([
                (String::from("urn:acr:low"), AssuranceLevel::Low),
                (
                    String::from("urn:acr:substantial"),
                    AssuranceLevel::Substantial,
                ),
                (String::from("urn:acr:high"), AssuranceLevel::High),
            ]),
            minimum,
            ..AssuranceSection::default()
        }
    }

    #[test]
    fn a_token_carries_the_level_its_value_maps_to() {
        let caller = bearer("p-1", &json!({ "acr": "urn:acr:substantial" }));
        let assessment = section(None).assess(&caller);
        assert_eq!(assessment.value.as_deref(), Some("urn:acr:substantial"));
        assert_eq!(assessment.level, Some(AssuranceLevel::Substantial));
        let unmapped = bearer("p-1", &json!({ "acr": "urn:acr:other" }));
        assert_eq!(section(None).assess(&unmapped).level, None);
    }

    #[test]
    fn the_minimum_refuses_lower_unmapped_and_missing_levels() {
        let substantial = section(Some(AssuranceLevel::Substantial));
        assert!(substantial.meets(&bearer("p", &json!({ "acr": "urn:acr:high" }))));
        assert!(!substantial.meets(&bearer("p", &json!({ "acr": "urn:acr:low" }))));
        assert!(!substantial.meets(&bearer("p", &json!({ "acr": "urn:acr:other" }))));
        assert!(!substantial.meets(&bearer("p", &json!({}))));
        assert!(!substantial.meets(&Caller::basic(String::from("etl"), "")));
        assert!(section(None).meets(&bearer("p", &json!({}))));
    }

    #[test]
    fn the_step_up_names_the_accepted_values() {
        let refusal = section(Some(AssuranceLevel::Substantial))
            .step_up()
            .expect("the values travel");
        let Refusal::StepUp(step_up) = refusal else {
            panic!("expected a step-up refusal, got {refusal:?}");
        };
        assert_eq!(
            step_up.acr_values(),
            ["urn:acr:high", "urn:acr:substantial"]
        );
    }

    #[test]
    fn a_section_that_would_refuse_everything_is_refused() {
        let unreachable = AssuranceSection {
            minimum: Some(AssuranceLevel::High),
            ..AssuranceSection::default()
        };
        assert_eq!(
            unreachable.validate(),
            Err(AssuranceError::Unreachable { minimum: "high" })
        );
        let blank = AssuranceSection {
            claim: String::from("a..b"),
            ..AssuranceSection::default()
        };
        assert!(matches!(
            blank.validate(),
            Err(AssuranceError::Claim { .. })
        ));
        let quoted = AssuranceSection {
            levels: BTreeMap::from([(String::from("a b"), AssuranceLevel::Low)]),
            ..AssuranceSection::default()
        };
        assert!(matches!(quoted.validate(), Err(AssuranceError::Value(_))));
        assert_eq!(section(Some(AssuranceLevel::High)).validate(), Ok(()));
    }

    #[test]
    fn a_person_token_names_the_person() {
        let caller = bearer("dr-42", &json!({ "sub": "dr-42", "client_id": "ehr-app" }));
        assert_eq!(
            ProfessionalSection::default().actor(&caller),
            Actor {
                mode: Some(ActingMode::Person),
                professional: Some(String::from("dr-42"))
            }
        );
    }

    #[test]
    fn a_client_token_names_whom_it_acts_for() {
        let professional = ProfessionalSection {
            acting_for_claim: Some(String::from("act.sub")),
            ..ProfessionalSection::default()
        };
        let caller = bearer(
            "svc",
            &json!({ "sub": "svc", "client_id": "svc", "act": { "sub": "dr-7" } }),
        );
        assert_eq!(
            professional.actor(&caller),
            Actor {
                mode: Some(ActingMode::Client),
                professional: Some(String::from("dr-7"))
            }
        );
        let alone = bearer("svc", &json!({ "sub": "svc", "azp": "svc" }));
        assert_eq!(
            ProfessionalSection::default().actor(&alone),
            Actor {
                mode: Some(ActingMode::Client),
                professional: None
            }
        );
    }

    #[test]
    fn claim_absent_reads_a_matching_sub_as_a_person() {
        let professional = ProfessionalSection {
            client_tokens: ClientTokens::ClaimAbsent,
            ..ProfessionalSection::default()
        };
        let caller = bearer("svc", &json!({ "sub": "svc", "client_id": "svc" }));
        assert_eq!(professional.actor(&caller).mode, Some(ActingMode::Person));
    }

    #[test]
    fn a_basic_caller_names_no_one() {
        let basic = Caller::basic(String::from("etl"), "");
        assert_eq!(
            ProfessionalSection::default().actor(&basic),
            Actor::default()
        );
        assert_eq!(section(None).assess(&basic), Assessment::default());
        assert!(matches!(
            ProfessionalSection {
                acting_for_claim: Some(String::new()),
                ..ProfessionalSection::default()
            }
            .validate(),
            Err(AssuranceError::Claim { .. })
        ));
    }
}
