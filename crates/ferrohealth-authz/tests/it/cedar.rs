// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The Cedar engine: the schema the model writes, strict validation at load,
//! deny by default, a forbid over a permit, the fan-out, and an erroring
//! policy that decides nothing.

use std::time::Duration;

use ferrohealth_authz::cedar::CedarEngine;
use ferrohealth_authz::cedar::Model;
use ferrohealth_authz::cedar::ModelError;
use ferrohealth_authz::engine::AuthzError;
use ferrohealth_authz::engine::PolicyEngine;
use ferrohealth_authz::request::Attr;
use ferrohealth_authz::request::Decision;
use ferrohealth_authz::request::Request;
use ferrohealth_authz::request::Subject;

/// The model of a synthetic records service.
fn model() -> Model {
    Model::new()
        .subject_attribute("organization")
        .resource("Composition", ["patient", "template"])
        .resource("Query", ["patient"])
        .action("composition.create", ["Composition"])
        .action("composition.read", ["Composition"])
        .action("query.execute", ["Query"])
        .context("operation")
}

fn engine(source: &str) -> CedarEngine {
    CedarEngine::from_source(model(), source).expect("the policies load")
}

fn create(subject: &Subject, patient: Option<Attr>) -> Request<'_> {
    let request = Request::new(subject, "composition.create", "Composition")
        .with_context("operation", "composition_create");
    match patient {
        Some(patient) => request
            .with_attribute("patient", patient)
            .expect("a request"),
        None => request,
    }
}

fn permit(decision: Result<Decision, AuthzError>) -> bool {
    decision.expect("the engine decides").is_permit()
}

#[tokio::test]
async fn a_policy_reads_the_subject_roles_scopes_and_attributes() {
    let engine = engine(
        r#"permit(principal, action, resource) when {
            principal.roles.contains("CLINICIAN") &&
            principal.scopes.contains("user/composition-*.c") &&
            principal has organization && principal.organization == "Qz7-hospital"
        };"#,
    );
    let granted = Subject::new("dr-a")
        .with_roles(vec!["CLINICIAN".into()])
        .with_scopes(vec!["user/composition-*.c".into()])
        .with_attribute("organization", "Qz7-hospital");
    assert!(permit(engine.decide(&create(&granted, None)).await));
    let other = granted.clone().with_attribute("organization", "Qz7-clinic");
    assert!(!permit(engine.decide(&create(&other, None)).await));
    let no_role = Subject::new("dr-b").with_attribute("organization", "Qz7-hospital");
    assert!(!permit(engine.decide(&create(&no_role, None)).await));
}

#[tokio::test]
async fn the_principal_is_the_subject_and_cannot_be_forged() {
    let engine = engine(r#"permit(principal == User::"admin", action, resource);"#);
    assert!(permit(
        engine.decide(&create(&Subject::new("admin"), None)).await
    ));
    let forged = Subject::new(r#"x", action, resource); permit(principal == User::"admin"#);
    assert!(!permit(engine.decide(&create(&forged, None)).await));
}

#[tokio::test]
async fn nothing_is_permitted_by_default_and_a_forbid_overrides() {
    let forbid_only = engine(
        r#"forbid(principal, action, resource) when { resource has patient && resource.patient == "blocked" };"#,
    );
    let subject = Subject::new("dr-a");
    assert_eq!(
        forbid_only
            .decide(&create(&subject, Some(Attr::One("p-1".into()))))
            .await
            .expect("decides"),
        Decision::Deny {
            policies: Vec::new()
        }
    );
    let both = engine(
        r#"permit(principal, action, resource);
           forbid(principal, action, resource) when { resource has patient && resource.patient == "blocked" };"#,
    );
    assert!(permit(
        both.decide(&create(&subject, Some(Attr::One("ok".into()))))
            .await
    ));
    let refused = both
        .decide(&create(&subject, Some(Attr::One("blocked".into()))))
        .await
        .expect("decides");
    assert_eq!(
        refused,
        Decision::Deny {
            policies: vec!["policy1".into()]
        }
    );
}

#[tokio::test]
async fn every_combination_must_be_permitted() {
    let engine = engine(
        r#"permit(principal, action, resource) when { resource has patient && resource.patient == "ok" };"#,
    );
    let subject = Subject::new("dr-a");
    assert!(permit(
        engine
            .decide(&create(
                &subject,
                Some(Attr::Set(vec!["ok".into(), "ok".into()]))
            ))
            .await
    ));
    assert!(!permit(
        engine
            .decide(&create(
                &subject,
                Some(Attr::Set(vec!["ok".into(), "bad".into()]))
            ))
            .await
    ));
}

#[tokio::test]
async fn an_erroring_forbid_is_an_evaluation_error() {
    let engine = engine(
        r"permit(principal, action, resource);
          forbid(principal, action, resource) when { 9223372036854775807 + 1 > 0 };",
    );
    let outcome = engine.decide(&create(&Subject::new("dr-a"), None)).await;
    assert!(
        matches!(outcome, Err(AuthzError::Evaluation(_))),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_request_outside_the_model_is_refused() {
    let engine = engine("permit(principal, action, resource);");
    let subject = Subject::new("dr-a");
    let undeclared = Request::new(&subject, "composition.delete", "Composition");
    assert!(matches!(
        engine.decide(&undeclared).await,
        Err(AuthzError::Undeclared { what: "action", .. })
    ));
    let wrong_type = Request::new(&subject, "query.execute", "Composition");
    assert!(matches!(
        engine.decide(&wrong_type).await,
        Err(AuthzError::Undeclared {
            what: "resource type",
            ..
        })
    ));
    let missing_context = Request::new(&subject, "composition.read", "Composition");
    assert!(matches!(
        engine.decide(&missing_context).await,
        Err(AuthzError::Evaluation(_))
    ));
}

#[test]
fn a_policy_that_does_not_parse_or_validate_never_loads() {
    for source in [
        "permit(this is not cedar);",
        r#"permit(principal, action, resource) when { resource.nonsense == "x" };"#,
        r#"permit(principal, action, resource) when { principal.organization == "x" };"#,
    ] {
        assert!(
            matches!(
                CedarEngine::from_source(model(), source),
                Err(AuthzError::Load(_))
            ),
            "{source}"
        );
    }
}

#[test]
fn a_model_with_a_bad_name_is_refused() {
    assert_eq!(Model::new().validate(), Err(ModelError::Empty));
    for (model, what) in [
        (model().subject_attribute("roles"), "subject attribute"),
        (model().resource("in", ["x"]), "resource type"),
        (
            model().resource("Thing", ["two words"]),
            "resource attribute",
        ),
        (model().context("1st"), "context attribute"),
    ] {
        assert!(
            matches!(model.validate(), Err(ModelError::Name { what: w, .. }) if w == what),
            "{what}"
        );
    }
    assert!(matches!(
        model().action("x.read", ["Unknown"]).validate(),
        Err(ModelError::Unknown { .. })
    ));
    assert!(matches!(
        model().action("quote\"d", ["Query"]).validate(),
        Err(ModelError::Action { .. })
    ));
}

#[tokio::test]
async fn a_directory_reloads_a_valid_set_and_keeps_the_set_in_force_otherwise() {
    let directory = tempfile::tempdir().expect("a directory");
    let path = directory.path().join("policy.cedar");
    std::fs::write(&path, "forbid(principal, action, resource);").expect("written");
    let engine =
        CedarEngine::from_directory(model(), directory.path(), Some(Duration::from_millis(50)))
            .expect("the directory loads");
    let subject = Subject::new("dr-a");
    assert!(!permit(engine.decide(&create(&subject, None)).await));
    std::fs::write(&path, "permit(principal, action, resource);").expect("written");
    let mut reloaded = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if permit(engine.decide(&create(&subject, None)).await) {
            reloaded = true;
            break;
        }
    }
    assert!(reloaded, "the valid set was swapped in");
    std::fs::write(&path, "permit(this is not cedar);").expect("written");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        permit(engine.decide(&create(&subject, None)).await),
        "an invalid set keeps the one in force"
    );
    let empty = tempfile::tempdir().expect("a directory");
    assert!(matches!(
        CedarEngine::from_directory(model(), empty.path(), None),
        Err(AuthzError::Load(_))
    ));
}
