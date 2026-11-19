// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! How a requested scope is matched against a client's ceiling and a
//! person's roles, with the SMART v1 scope syntax read as its v2 form.
//!
//! "Servers SHOULD process v1 scopes with the following semantics in v2":
//! `read` as `rs`, `write` as `cud` and `*` as `cruds` (SMART App Launch
//! 2.2.0, Scopes and Launch Context, Scopes for requesting FHIR Resources),
//! and a scope granted as v1 is returned as v1. Matching a scope as written
//! is our own design.

/// Returns the v2 form of the clinical scope `scope`: its v1 suffix
/// replaced by the v2 letters, or the scope itself when it carries none.
#[must_use]
pub fn v2_form(scope: &str) -> String {
    let Some((head, suffix)) = scope.rsplit_once('.') else {
        return scope.to_owned();
    };
    let clinical = ["patient/", "user/", "system/"]
        .iter()
        .any(|context| head.starts_with(context));
    let letters = match suffix {
        "read" => "rs",
        "write" => "cud",
        "*" => "cruds",
        _ => return scope.to_owned(),
    };
    if clinical {
        format!("{head}.{letters}")
    } else {
        scope.to_owned()
    }
}

/// Returns whether `listed` admits the requested `scope`: as written, or by
/// its v2 form.
#[must_use]
pub fn admits(listed: &[String], scope: &str) -> bool {
    let v2 = v2_form(scope);
    listed
        .iter()
        .any(|allowed| allowed == scope || *allowed == v2)
}

/// Returns whether `scope` is an extension scope.
///
/// SMART App Launch 2.2.0, Scopes and Launch Context, Extensibility: "any
/// string starting with `__` (two underscores)". A person is granted one
/// only when the client's ceiling and one of their roles list it
/// (`docs/architecture.md` §13.6 item 5).
#[must_use]
pub fn is_extension(scope: &str) -> bool {
    scope.len() > 2 && scope.starts_with("__")
}

/// Returns the scope of a standalone request, `requested`, with
/// `launch/patient` added when it asks a `patient/` scope without it.
///
/// A `patient/` scope needs a patient in context, and SMART lets the server
/// infer `launch/patient` for a standalone app that did not ask it (SMART
/// App Launch 2.2.0, Scopes and Launch Context, Standalone apps: the EHR
/// "may infer" it), so the picker supplies the patient instead of the
/// `patient/` scopes being dropped (`docs/architecture.md` §13.6 item 4).
#[must_use]
pub fn with_inferred_patient(requested: &str) -> String {
    let mut scopes = requested.split(' ').filter(|scope| !scope.is_empty());
    let asks_patient = scopes.clone().any(|scope| scope.starts_with("patient/"));
    if asks_patient && !scopes.any(|scope| scope == "launch/patient") {
        format!("{} launch/patient", requested.trim_end())
    } else {
        requested.to_owned()
    }
}

/// Returns whether `scope` is drawn on the consent page as a fixed line,
/// granted with the app and never unticked.
///
/// These are the identity, launch and refresh scopes, which say who the
/// person is, which context the app opens in and how long it stays signed
/// in; unticking one would break the app without keeping any data back
/// (`docs/architecture.md` §13.6 item 3; our own design). Resource scopes
/// and extension scopes keep their boxes.
#[must_use]
pub fn is_fixed(scope: &str) -> bool {
    matches!(
        scope,
        "openid" | "fhirUser" | "profile" | "email" | "launch" | "offline_access" | "online_access"
    ) || scope.starts_with("launch/")
}

#[cfg(test)]
mod tests {
    use super::{admits, is_fixed, v2_form, with_inferred_patient};

    #[test]
    fn a_standalone_patient_scope_infers_launch_patient() {
        assert_eq!(
            "openid patient/Observation.rs launch/patient",
            with_inferred_patient("openid patient/Observation.rs")
        );
        for unchanged in [
            "openid launch/patient patient/Observation.rs",
            "openid user/Observation.rs",
            "openid",
        ] {
            assert_eq!(unchanged, with_inferred_patient(unchanged));
        }
    }

    #[test]
    fn identity_launch_and_refresh_scopes_are_fixed_and_resource_scopes_are_not() {
        for fixed in [
            "openid",
            "fhirUser",
            "profile",
            "email",
            "launch",
            "launch/patient",
            "launch/encounter",
            "offline_access",
            "online_access",
        ] {
            assert!(is_fixed(fixed), "{fixed}");
        }
        for chosen in [
            "patient/Observation.rs",
            "user/Patient.r",
            "system/*.rs",
            "__ferroehr.platform",
            "launcher",
            "openid2",
        ] {
            assert!(!is_fixed(chosen), "{chosen}");
        }
    }

    #[test]
    fn the_v1_suffixes_read_as_their_v2_letters() {
        assert_eq!(
            "patient/Observation.rs",
            v2_form("patient/Observation.read")
        );
        assert_eq!("user/Observation.cud", v2_form("user/Observation.write"));
        assert_eq!("system/*.cruds", v2_form("system/*.*"));
        assert_eq!("user/Observation.rs", v2_form("user/Observation.rs"));
        assert_eq!("launch/patient", v2_form("launch/patient"));
        assert_eq!("openid", v2_form("openid"));
    }

    #[test]
    fn a_v1_request_is_admitted_by_its_v2_form() {
        let listed = vec![String::from("user/Observation.rs")];
        assert!(admits(&listed, "user/Observation.read"));
        assert!(admits(&listed, "user/Observation.rs"));
        assert!(!admits(&listed, "user/Observation.write"));
        assert!(!admits(&listed, "user/Patient.read"));
    }
}
