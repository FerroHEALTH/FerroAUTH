// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The patient picker at an openEHR resource server paired with the
//! platform's FHIR server (`docs/architecture.md` §13.6 item 4).
//!
//! At an openEHR resource server `launch/patient` asks for "both FHIR
//! `Patient` resource and corresponding openEHR `EHR` instance" (SMART on
//! openEHR draft, Context Selection), and the platform names its FHIR
//! server as the `org.fhir.rest` service beside `org.openehr.rest` (Service
//! Discovery). The person picks the patient at that FHIR server, and
//! FerroSMART looks the patient's EHR up at the openEHR server by the
//! identifier the configuration names, each as the person, so the launch
//! context carries `patient` and `ehrId`. The draft does not say how a
//! `Patient` names its EHR's subject: the identifier system is our own
//! design, set per base.

use std::net::IpAddr;

use axum::response::Response;
use http::HeaderMap;
use serde_json::Value;

use super::{PickerError, enter, is_fhir_id, openehr, read_patient};
use crate::config::settings::Pairing;
use crate::form::Params;
use crate::launch::context::Context;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::Pending;

/// The words the picker shows when the chosen patient has no EHR the
/// person may see.
const NO_EHR: &str = "picker-paired-none";

/// Reads the patient the form `form` chose at the FHIR server of `pairing`
/// again as the person, looks their EHR up at the openEHR server of
/// `pending`, and sends the browser on with both in the launch context.
pub(super) async fn choose(
    state: &AppState,
    headers: &HeaderMap,
    pending: &Pending,
    from: IpAddr,
    pairing: &Pairing,
    form: &Params,
) -> Response {
    let Some(id) = form.get("patient").filter(|id| is_fhir_id(id)) else {
        return pages::fault(state, Fault::BadRequest);
    };
    let Some(namespace) = state.settings().subject_namespaces.get(&pending.audience) else {
        return pages::fault(state, Fault::Server);
    };
    let patient = match read_patient(state, pending, from, &pairing.fhir_base, id).await {
        Ok(patient) => patient,
        Err(response) => return *response,
    };
    let subject_id = match subject_id(&patient, &pairing.subject_system) {
        Ok(Some(subject_id)) => subject_id,
        Ok(None) => return pages::picker(state, headers, pending, None, None, Some(NO_EHR)),
        Err(error) => return pages::server_error(state, &error),
    };
    // NOTE: SMART on openEHR draft, Context Selection, `ehrId` names the EHR of the
    // selected FHIR Patient, which is looked up as the person.
    match openehr::by_subject(state, pending, from, namespace, subject_id).await {
        Ok(Some(found)) => {
            let context = Context {
                patient: Some(id.to_owned()),
                ehr_id: Some(found.ehr_id),
                ..Context::default()
            };
            enter(state, pending, &context, from).await
        }
        Ok(None) => pages::picker(state, headers, pending, None, None, Some(NO_EHR)),
        Err(error) => pages::server_error(state, &error),
    }
}

/// Returns the subject id of the EHR of `patient`: the value of its one
/// current identifier in `system`, or `None` when it has none.
///
/// # Errors
/// Returns [`PickerError::Ambiguous`] when two current identifiers of the
/// system carry different values, since either could name the EHR.
fn subject_id<'p>(patient: &'p Value, system: &str) -> Result<Option<&'p str>, PickerError> {
    let mut values = patient
        .get("identifier")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|identifier| identifier.get("system").and_then(Value::as_str) == Some(system))
        // NOTE: FHIR R4 Identifier.use, `old` is "no longer considered valid, but
        // may be relevant for search purposes", so it names no current subject.
        .filter(|identifier| identifier.get("use").and_then(Value::as_str) != Some("old"))
        .filter_map(|identifier| identifier.get("value").and_then(Value::as_str))
        .filter(|value| !value.trim().is_empty());
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.any(|other| other != first) {
        return Err(PickerError::Ambiguous);
    }
    Ok(Some(first))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const SYSTEM: &str = "urn:example:mrn";

    #[test]
    fn the_subject_is_the_one_current_identifier_of_the_system() {
        let patient = json!({ "identifier": [
            { "system": "urn:example:other", "value": "X-1" },
            { "system": SYSTEM, "use": "old", "value": "MRN-0" },
            { "system": SYSTEM, "value": "MRN-1" },
            { "system": SYSTEM, "use": "official", "value": "MRN-1" },
        ] });
        assert_eq!(
            Some("MRN-1"),
            subject_id(&patient, SYSTEM).expect("one subject")
        );
    }

    #[test]
    fn a_patient_without_an_identifier_of_the_system_has_no_subject() {
        for patient in [
            json!({}),
            json!({ "identifier": [{ "system": "urn:example:other", "value": "X-1" }] }),
            json!({ "identifier": [{ "system": SYSTEM, "use": "old", "value": "MRN-0" }] }),
            json!({ "identifier": [{ "system": SYSTEM, "value": " " }] }),
            json!({ "identifier": [{ "value": "MRN-1" }] }),
        ] {
            assert_eq!(
                None,
                subject_id(&patient, SYSTEM).expect("no subject"),
                "{patient}"
            );
        }
    }

    #[test]
    fn two_current_identifiers_of_the_system_name_no_one_subject() {
        let patient = json!({ "identifier": [
            { "system": SYSTEM, "value": "MRN-1" },
            { "system": SYSTEM, "value": "MRN-2" },
        ] });
        assert!(matches!(
            subject_id(&patient, SYSTEM),
            Err(PickerError::Ambiguous)
        ));
    }
}
