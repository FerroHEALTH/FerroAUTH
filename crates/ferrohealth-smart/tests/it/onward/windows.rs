// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The assertion windows of a MyHealth@EU contact-point caller: a token
//! issued on its behalf may not outlive the HP Identity Assertion's
//! `NotOnOrAfter` or the Treatment Relationship Confirmation's, with 60 s of
//! drift (eHDSI SAML Profile 10.0.0 §2.1, §4.1).

use std::collections::BTreeMap;

use ferrohealth_smart::client::onward::AssertionWindow;
use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::client::onward::Rejected;
use ferrohealth_smart::federation::Attribute;
use ferrohealth_smart::federation::External;
use ferrohealth_smart::federation::Field;
use ferrohealth_smart::kind::CallerKind;

use super::federation::Case;
use super::federation::issued;
use super::federation::partner;
use super::federation::professional;
use super::federation::section;
use crate::support::now;

/// The seconds from now at which the issued token of the cases expires.
const ISSUED_LIFE: i64 = 300;

/// Returns a contact-point caller whose windows end `ida` and `trc` seconds
/// after `base`, each when given.
fn caller_at(base: i64, ida: Option<i64>, trc: Option<i64>) -> CallerKind {
    let mut fields = BTreeMap::new();
    for (field, end) in [
        (Field::AssertionNotOnOrAfter, ida),
        (Field::TrcNotOnOrAfter, trc),
    ] {
        if let Some(end) = end {
            fields.insert(field, Attribute::Text((base + end).to_string()));
        }
    }
    CallerKind::ExternalPerson(Box::new(External::new("remote-hp-1", fields)))
}

/// Returns the outcome of exchanging for a caller whose windows end `ida`
/// and `trc` seconds after one instant, answered with a token that expires
/// `ISSUED_LIFE` seconds after that same instant.
async fn exchange_for(ida: Option<i64>, trc: Option<i64>) -> Result<(), OnwardError> {
    let base = now();
    let mut token = issued();
    if let Some(claims) = token.as_object_mut() {
        claims.insert(String::from("iat"), base.into());
        claims.insert(String::from("exp"), (base + ISSUED_LIFE).into());
    }
    exchange(caller_at(base, ida, trc), &token).await
}

/// Returns the outcome of exchanging for `kind`, answered with `token`.
async fn exchange(kind: CallerKind, token: &serde_json::Value) -> Result<(), OnwardError> {
    let case = Case::start(section()).await;
    case.exchange(&professional(), kind, token, &partner())
        .await
}

fn refused_by(outcome: &Result<(), OnwardError>, window: AssertionWindow) -> bool {
    matches!(outcome, Err(OnwardError::Rejected(Rejected::AssertionWindow(named))) if *named == window)
}

#[tokio::test]
async fn a_token_within_both_windows_is_accepted() {
    let outcome = exchange_for(Some(3600), Some(1800)).await;
    assert!(outcome.is_ok(), "{outcome:?}");
}

#[tokio::test]
async fn a_token_past_the_identity_window_is_refused() {
    let outcome = exchange_for(Some(ISSUED_LIFE - 61), Some(1800)).await;
    assert!(
        refused_by(&outcome, AssertionWindow::Identity),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_token_past_the_treatment_window_is_refused() {
    let outcome = exchange_for(Some(3600), Some(ISSUED_LIFE - 61)).await;
    assert!(
        refused_by(&outcome, AssertionWindow::Treatment),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn the_drift_admits_a_token_up_to_60_seconds_past_a_window() {
    let outcome = exchange_for(Some(ISSUED_LIFE - 60), Some(ISSUED_LIFE - 60)).await;
    assert!(outcome.is_ok(), "{outcome:?}");
}

#[tokio::test]
async fn a_discovery_phase_caller_is_held_to_the_identity_window_alone() {
    let outcome = exchange_for(Some(ISSUED_LIFE - 61), None).await;
    assert!(
        refused_by(&outcome, AssertionWindow::Identity),
        "{outcome:?}"
    );
    let outcome = exchange_for(Some(3600), None).await;
    assert!(outcome.is_ok(), "{outcome:?}");
}

#[tokio::test]
async fn an_unreadable_window_end_is_refused() {
    let fields = BTreeMap::from([(
        Field::TrcNotOnOrAfter,
        Attribute::Text(String::from("tomorrow")),
    )]);
    let kind = CallerKind::ExternalPerson(Box::new(External::new("remote-hp-1", fields)));
    let outcome = exchange(kind, &issued()).await;
    assert!(
        refused_by(&outcome, AssertionWindow::Treatment),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_caller_without_windows_keeps_todays_check() {
    let outcome = exchange_for(None, None).await;
    assert!(outcome.is_ok(), "{outcome:?}");
    let outcome = exchange(CallerKind::Person, &issued()).await;
    assert!(outcome.is_ok(), "{outcome:?}");
}

#[test]
fn each_window_names_its_field() {
    assert_eq!(
        AssertionWindow::Identity.field(),
        Field::AssertionNotOnOrAfter
    );
    assert_eq!(
        AssertionWindow::Treatment.to_string(),
        "trc.not_on_or_after"
    );
}
