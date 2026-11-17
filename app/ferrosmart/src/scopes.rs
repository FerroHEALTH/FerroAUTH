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

#[cfg(test)]
mod tests {
    use super::{admits, v2_form};

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
