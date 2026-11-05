// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The subject read from a `ferrohealth-smart` 0.9.0 caller of every kind
//! its classification gives.

use ferrohealth_authz::request::Subject;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::resource::Caller;
use serde_json::json;

/// Returns a caller of `kind` holding a role and a claim.
fn caller(kind: CallerKind) -> Caller {
    let claims = json!({ "org": { "unit": "ward-7" } });
    Caller::new(
        String::from("synthetic-subject"),
        Some(String::from("synthetic-client")),
        "user/Observation.rs",
        None,
        false,
        kind,
    )
    .with_roles(vec![String::from("clinician")])
    .with_claims(claims.as_object().cloned().unwrap_or_default())
}

// NOTE: NIST SP 800-162 §2: the decision reads the attributes of the subject; the subject
// carries the caller's id, roles, scopes and the named claims, whatever its kind.
#[test]
fn a_subject_is_read_from_a_caller_of_every_kind() {
    for kind in [
        CallerKind::Person,
        CallerKind::System,
        CallerKind::Patient,
        CallerKind::Delegated { actor: None },
        CallerKind::Representative {
            represented: String::from("synthetic-represented"),
            ground: None,
        },
        CallerKind::Guest(Box::new(CallerKind::Person)),
    ] {
        let subject = Subject::of(&caller(kind.clone()), &[("unit", "org.unit")]);
        assert_eq!("synthetic-subject", subject.id(), "{kind:?}");
        assert_eq!([String::from("clinician")], subject.roles(), "{kind:?}");
        assert_eq!(
            [String::from("user/Observation.rs")],
            subject.scopes(),
            "{kind:?}"
        );
        assert_eq!(
            Some("ward-7"),
            subject.attributes().get("unit").map(String::as_str),
            "{kind:?}"
        );
    }
}
