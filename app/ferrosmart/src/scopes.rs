// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! How a requested scope is matched against a client's ceiling and a
//! person's roles, with the SMART v1 scope syntax read as its v2 form.
//!
//! "Servers SHOULD process v1 scopes with the following semantics in v2":
//! `read` as `rs`, `write` as `cud` and `*` as `cruds` (SMART App Launch
//! 2.2.0, Scopes and Launch Context, Scopes for requesting FHIR Resources),
//! and a scope granted as v1 is returned as v1.
//!
//! A clinical scope names a context, a resource, its permissions and,
//! optionally, query parameters (`patient/Observation.rs?category=…`). A
//! listed scope admits a requested one in the same context whose
//! permissions are a subset of its own (SMART v2 builds a scope from the
//! letters `c`, `r`, `u`, `d`, `s`, and "the server may grant less than
//! asked"), on the same resource or under the wildcard `*`, and with the same
//! query parameters, or any when the listed scope names none. Every other
//! scope is matched as written (our own design).

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

/// Returns whether `listed` admits the requested `scope`: as written, by
/// its v2 form, or as a clinical scope inside a listed one ([`covers`]).
#[must_use]
pub fn admits(listed: &[String], scope: &str) -> bool {
    let v2 = v2_form(scope);
    listed
        .iter()
        .any(|allowed| allowed == scope || *allowed == v2 || covers(allowed, &v2))
}

/// One clinical scope in its v2 form: `context/resource.permissions`, with
/// the query parameters after a `?`.
struct Clinical<'a> {
    /// `patient`, `user` or `system`.
    context: &'a str,
    /// The resource type, `*`, or a SMART on openEHR resource.
    resource: &'a str,
    /// The permission letters.
    permissions: &'a str,
    /// The query parameters, when the scope names any.
    query: Option<&'a str>,
}

impl<'a> Clinical<'a> {
    /// Returns the clinical scope `scope` reads as, or `None` for any other
    /// scope, which is then matched as written.
    fn read(scope: &'a str) -> Option<Self> {
        let (head, query) = match scope.split_once('?') {
            Some((head, query)) => (head, Some(query)),
            None => (scope, None),
        };
        let (context, rest) = head.split_once('/')?;
        if !matches!(context, "patient" | "user" | "system") {
            return None;
        }
        let (resource, permissions) = rest.rsplit_once('.')?;
        // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, SMART v2: the
        // permissions are the letters c, r, u, d, s, in that order.
        let ordered = permissions
            .bytes()
            .try_fold(0_usize, |at, letter| {
                b"cruds"
                    .iter()
                    .skip(at)
                    .position(|known| *known == letter)
                    .map(|found| at.saturating_add(found).saturating_add(1))
            })
            .is_some();
        (!resource.is_empty() && !permissions.is_empty() && ordered).then_some(Self {
            context,
            resource,
            permissions,
            query,
        })
    }
}

/// Returns whether the listed clinical scope `allowed` covers the requested
/// clinical scope `requested`, both in their v2 form.
///
/// It does with the same context, the same resource or the wildcard `*`,
/// permissions that are a subset of its own, and the same query parameters,
/// or any when `allowed` names none.
#[must_use]
pub fn covers(allowed: &str, requested: &str) -> bool {
    let (Some(allowed), Some(requested)) = (Clinical::read(allowed), Clinical::read(requested))
    else {
        return false;
    };
    allowed.context == requested.context
        && (allowed.resource == "*" || allowed.resource == requested.resource)
        && requested
            .permissions
            .chars()
            .all(|letter| allowed.permissions.contains(letter))
        && allowed
            .query
            .is_none_or(|query| requested.query == Some(query))
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
    use super::{admits, covers, is_fixed, v2_form, with_inferred_patient};

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

    // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, SMART v2: a request
    // whose permissions are a subset of a listed scope's is inside it (#731).
    #[test]
    fn a_ceiling_admits_a_subset_of_its_permission_letters() {
        let listed = vec![String::from("patient/Composition.crs")];
        for inside in [
            "patient/Composition.crs",
            "patient/Composition.rs",
            "patient/Composition.r",
            "patient/Composition.s",
            "patient/Composition.cr",
            "patient/Composition.read",
        ] {
            assert!(admits(&listed, inside), "{inside}");
        }
        for outside in [
            "patient/Composition.cruds",
            "patient/Composition.u",
            "patient/Composition.rd",
            "user/Composition.r",
            "patient/Observation.r",
            "patient/Composition.sr",
            "patient/Composition.",
        ] {
            assert!(!admits(&listed, outside), "{outside}");
        }
    }

    #[test]
    fn a_wildcard_resource_admits_each_resource() {
        let listed = vec![String::from("user/*.rs")];
        assert!(admits(&listed, "user/Observation.r"));
        assert!(admits(&listed, "user/Patient.rs"));
        assert!(admits(&listed, "user/*.s"));
        assert!(!admits(&listed, "user/Patient.c"));
        assert!(!admits(&listed, "patient/Patient.r"), "another context");
        let named = vec![String::from("user/Observation.rs")];
        assert!(
            !admits(&named, "user/*.r"),
            "a named resource never admits *"
        );
    }

    #[test]
    fn query_parameters_must_match_a_restricted_ceiling() {
        let restricted = vec![String::from(
            "patient/Observation.rs?category=http://terminology.hl7.org/CodeSystem/observation-category|vital-signs",
        )];
        assert!(admits(
            &restricted,
            "patient/Observation.r?category=http://terminology.hl7.org/CodeSystem/observation-category|vital-signs"
        ));
        assert!(
            !admits(&restricted, "patient/Observation.r"),
            "a restricted ceiling never admits the unrestricted scope"
        );
        assert!(!admits(
            &restricted,
            "patient/Observation.r?category=laboratory"
        ));
        let open = vec![String::from("patient/Observation.rs")];
        assert!(
            admits(&open, "patient/Observation.r?category=laboratory"),
            "a restricted request is inside an unrestricted ceiling"
        );
        assert!(
            !covers("openid", "openid"),
            "a non-clinical scope matches as written"
        );
        assert!(admits(&[String::from("openid")], "openid"));
        assert!(!admits(
            &[String::from("launch/patient")],
            "launch/encounter"
        ));
    }
}
