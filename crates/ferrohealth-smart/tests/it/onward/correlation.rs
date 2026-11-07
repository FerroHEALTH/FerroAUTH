// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The correlation id of a chained organisation request through the
//! federation exchange: the token a `federation` issuer issues for an
//! organisation that carries one must carry the same id, read under that
//! issuer's own table, and a chained route refuses a subject without its
//! correlation claim before anything is sent.

use std::collections::BTreeMap;

use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::client::onward::Rejected;
use ferrohealth_smart::federation::Attribute;
use ferrohealth_smart::federation::External;
use ferrohealth_smart::federation::FederationSection;
use ferrohealth_smart::federation::Field;
use ferrohealth_smart::federation::Source;
use ferrohealth_smart::kind::CallerKind;
use serde_json::Value;
use serde_json::json;

use super::federation::Case;
use super::federation::organisation_token;
use super::federation::organisations;
use super::federation::partner;
use super::federation::professional;

/// The id the requester set, carried as the claim `txn`.
const ID: &str = "correlation-1";

/// Returns the organisations table with `correlation_id` read from the claim
/// `txn` of the tokens the issuer issues.
fn mapped() -> FederationSection {
    let mut section = organisations();
    section.fields.insert(
        Field::CorrelationId,
        vec![Source::Claim(String::from("txn"))],
    );
    section
}

/// Returns an organisation of another party whose token carried `id` as its
/// correlation id.
fn organisation(id: Option<&str>) -> CallerKind {
    let fields = id
        .map(|value| BTreeMap::from([(Field::CorrelationId, Attribute::Text(String::from(value)))]))
        .unwrap_or_default();
    CallerKind::ExternalOrganisation(Box::new(External::new("partner-app", fields)))
}

/// Returns the claims of the organisation's own token, with `txn` when
/// `id` is given.
fn subject(id: Option<&str>) -> Value {
    let mut claims = professional();
    if let Some(members) = claims.as_object_mut() {
        members.insert(String::from("sub"), json!("partner-app"));
        members.remove("txn");
        if let Some(id) = id {
            members.insert(String::from("txn"), json!(id));
        }
    }
    claims
}

/// Returns the issued organisation token carrying `id` in `txn`.
fn issued(id: Option<&str>) -> Value {
    let mut token = organisation_token();
    if let (Some(id), Some(members)) = (id, token.as_object_mut()) {
        members.insert(String::from("txn"), json!(id));
    }
    token
}

#[tokio::test]
async fn a_chained_request_that_keeps_its_id_is_accepted() {
    let case = Case::start(mapped()).await;
    let outcome = case
        .exchange(
            &subject(Some(ID)),
            organisation(Some(ID)),
            &issued(Some(ID)),
            &partner().with_correlation_claim("txn"),
        )
        .await;
    assert!(outcome.is_ok(), "{outcome:?}");
}

#[tokio::test]
async fn an_issued_token_naming_another_id_is_refused() {
    let case = Case::start(mapped()).await;
    let outcome = case
        .exchange(
            &subject(Some(ID)),
            organisation(Some(ID)),
            &issued(Some("correlation-2")),
            &partner(),
        )
        .await;
    assert!(
        matches!(outcome, Err(OnwardError::Rejected(Rejected::Correlation))),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn an_issued_token_that_drops_the_id_is_refused() {
    let case = Case::start(mapped()).await;
    let outcome = case
        .exchange(
            &subject(Some(ID)),
            organisation(Some(ID)),
            &issued(None),
            &partner(),
        )
        .await;
    assert!(
        matches!(outcome, Err(OnwardError::Rejected(Rejected::Correlation))),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_chained_route_refuses_a_subject_without_the_id_before_sending() {
    let case = Case::start(mapped()).await;
    let outcome = case
        .exchange(
            &subject(None),
            organisation(None),
            &issued(Some(ID)),
            &partner().with_correlation_claim("txn"),
        )
        .await;
    assert!(
        matches!(outcome, Err(OnwardError::NoCorrelation)),
        "{outcome:?}"
    );
    assert_eq!(0, case.calls().await, "nothing reaches the token endpoint");
}

#[tokio::test]
async fn a_route_that_is_not_chained_admits_an_organisation_without_an_id() {
    let case = Case::start(mapped()).await;
    let outcome = case
        .exchange(
            &subject(None),
            organisation(None),
            &issued(None),
            &partner(),
        )
        .await;
    assert!(outcome.is_ok(), "{outcome:?}");
}
