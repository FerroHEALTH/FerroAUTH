// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The launch context an EHR hands FerroSMART, which the token response
//! carries to the app (SMART App Launch 2.2.0, Scopes and Launch Context,
//! Launch context arrives with your `access_token`).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

/// The launch context parameters, each named as SMART App Launch 2.2.0's
/// table of launch context parameters names it, with `ehrId` of the SMART
/// on openEHR draft (Context Selection).
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    /// The patient in context: "a patient id".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patient: Option<String>,
    /// The encounter in context: "an encounter id".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encounter: Option<String>,
    /// The other resources in context.
    #[expect(
        clippy::struct_field_names,
        reason = "`fhirContext` is the parameter's name in SMART App Launch 2.2.0"
    )]
    #[serde(rename = "fhirContext", default, skip_serializing_if = "Vec::is_empty")]
    pub fhir_context: Vec<Value>,
    /// The intent of the launch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    /// Whether the app shows a patient banner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub need_patient_banner: Option<bool>,
    /// The organization that launches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// The openEHR EHR in context, for an openEHR resource server.
    #[serde(rename = "ehrId", skip_serializing_if = "Option::is_none")]
    pub ehr_id: Option<String>,
}

impl std::fmt::Debug for Context {
    // NOTE: CLAUDE.md, no claim beyond sub, client_id and iss reaches a Debug
    // rendering, so the context shows which parameters it holds and no value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("patient", &self.patient.is_some())
            .field("encounter", &self.encounter.is_some())
            .field("fhir_context", &self.fhir_context.len())
            .field("intent", &self.intent.is_some())
            .field("need_patient_banner", &self.need_patient_banner.is_some())
            .field("tenant", &self.tenant.is_some())
            .field("ehr_id", &self.ehr_id.is_some())
            .finish()
    }
}

impl Context {
    /// Checks the context for a resource server that serves openEHR when
    /// `openehr` holds, and FHIR otherwise.
    ///
    /// # Errors
    /// Returns the rule broken, a description that quotes no value.
    pub fn check(&self, openehr: bool) -> Result<(), &'static str> {
        let present = [
            &self.patient,
            &self.encounter,
            &self.intent,
            &self.tenant,
            &self.ehr_id,
        ];
        if present
            .iter()
            .any(|value| value.as_deref().is_some_and(str::is_empty))
        {
            return Err("a context parameter is empty");
        }
        // NOTE: SMART on openEHR draft, Context Selection, `ehrId` names an EHR of
        // the openEHR server the token is for.
        if self.ehr_id.is_some() && !openehr {
            return Err("an ehrId is only for an openEHR resource server");
        }
        self.fhir_context.iter().try_for_each(check_item)
    }
}

/// Checks one `fhirContext` item (SMART App Launch 2.2.0, Scopes and Launch
/// Context, `fhirContext`): an object with at least one of `reference`,
/// `canonical` and `identifier`; a `role` never empty, relative only as
/// `launch`, the one role the specification defines; Patient and Encounter
/// only under a role other than `launch`.
fn check_item(item: &Value) -> Result<(), &'static str> {
    let object = item.as_object().ok_or("a fhirContext item is no object")?;
    let text = |member: &str| object.get(member).and_then(Value::as_str);
    let names = ["reference", "canonical"]
        .iter()
        .any(|member| text(member).is_some_and(|value| !value.is_empty()))
        || object.get("identifier").is_some_and(Value::is_object);
    if !names {
        return Err("a fhirContext item has no reference, canonical or identifier");
    }
    let role = match object.get("role") {
        None => None,
        Some(Value::String(role)) if role == "launch" => None,
        Some(Value::String(role)) if Url::parse(role).is_ok() => Some(role),
        Some(_) => return Err("a fhirContext role is empty, relative or no string"),
    };
    let patient_or_encounter = text("type")
        .is_some_and(|kind| kind == "Patient" || kind == "Encounter")
        || text("reference").is_some_and(|reference| {
            reference.starts_with("Patient/") || reference.starts_with("Encounter/")
        });
    if patient_or_encounter && role.is_none() {
        return Err("a Patient or Encounter in fhirContext needs a role other than launch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Context;
    use serde_json::json;

    fn with_items(items: serde_json::Value) -> Context {
        Context {
            fhir_context: serde_json::from_value(items).expect("an array"),
            ..Context::default()
        }
    }

    #[test]
    fn a_fhir_context_item_follows_smart() {
        let good = with_items(json!([
            {"reference": "DiagnosticReport/123"},
            {"canonical": "http://example.org/Questionnaire/1", "type": "Questionnaire"},
            {"identifier": {"value": "x"}, "type": "ImagingStudy"},
            {"reference": "List/1", "role": "https://example.org/med-list-at-home"},
            {"reference": "Patient/2", "role": "https://example.org/referring"},
            {"reference": "Observation/3", "role": "launch"}
        ]));
        assert_eq!(Ok(()), good.check(false));
        for bad in [
            json!([{"type": "Observation"}]),
            json!([{"reference": "Observation/1", "role": ""}]),
            json!([{"reference": "Observation/1", "role": "sibling"}]),
            json!([{"reference": "Patient/1"}]),
            json!([{"reference": "Encounter/1", "role": "launch"}]),
            json!([{"identifier": {"value": "1"}, "type": "Patient"}]),
            json!(["Observation/1"]),
        ] {
            assert!(with_items(bad.clone()).check(false).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_ehr_id_is_only_for_openehr_and_no_parameter_is_empty() {
        let ehr = Context {
            ehr_id: Some(String::from("7d44b88c-4199-4bad-97dc-d78268e01398")),
            ..Context::default()
        };
        assert_eq!(Ok(()), ehr.check(true));
        assert!(ehr.check(false).is_err());
        let empty = Context {
            patient: Some(String::new()),
            ..Context::default()
        };
        assert!(empty.check(false).is_err());
    }

    #[test]
    fn the_debug_rendering_shows_no_value() {
        let context = Context {
            patient: Some(String::from("secret-patient-id")),
            ..Context::default()
        };
        assert!(!format!("{context:?}").contains("secret-patient-id"));
    }
}
