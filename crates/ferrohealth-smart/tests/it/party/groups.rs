// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The groups a token asserts: the group claim, the overage marker and the
//! adapter called in its place, intersected with the party's memberships.

use super::*;

// NOTE: Microsoft, "Access token claims reference", §Groups overage claim and `hasgroups`:
// above the limit the token "doesn't emit the groups claim" and carries an overage claim.
#[tokio::test]
async fn an_overage_marker_without_an_adapter_is_groups_unavailable() -> Outcome2 {
    let source = FakeSource::answering(one_professional());
    let binding = binding(&source);
    for claims in [
        json!({
            "_claim_names": { "groups": "src1" },
            "_claim_sources": { "src1": { "endpoint": "https://graph.invalid/getMemberObjects" } }
        }),
        json!({ "hasgroups": true }),
    ] {
        let outcome = binding.resolve(&person(&claims)).await?;
        assert!(
            matches!(
                outcome,
                Some(Outcome::GroupsUnavailable(GroupsCause::Overage))
            ),
            "{claims}: {outcome:?}"
        );
    }
    assert_eq!(
        0,
        source.calls(),
        "the groups are decided before the lookup"
    );
    Ok(())
}

/// Returns the profile of an issuer naming the adapter `test-idp`.
fn adapter_profile() -> Profile {
    Profile {
        adapter: Some(String::from("test-idp")),
        ..profile()
    }
}

/// Returns the binding of an issuer whose profile names an adapter that
/// answers with `answer`.
fn with_adapter(
    source: &Arc<FakeSource>,
    answer: Result<Vec<String>, AdapterError>,
) -> Result<PartyBinding, PartyError> {
    let adapter = Arc::new(FakeAdapter {
        answer,
        log: Arc::clone(&source.log),
    });
    let concrete = Arc::clone(source);
    let dynamic: Arc<dyn PartySource> = concrete;
    PartyBinding::new(dynamic)
        .with_adapter("test-idp", adapter)
        .with_issuer(table(), IssuerKind::Persons, &adapter_profile())
}

// NOTE: Microsoft, "Access token claims reference", §Groups overage claim: the groups are
// read from the identity provider; the adapter is called first and its groups are used.
#[tokio::test]
async fn with_an_adapter_the_adapter_is_called_first_and_its_groups_are_used() -> Outcome2 {
    let source = FakeSource::answering(Lookup::Parties(vec![
        record("p-1", Markers::PROFESSIONAL).with_memberships(vec![
            Membership::new(group_ref("g-1"), "group-1"),
            Membership::new(group_ref("g-2"), "group-2"),
        ]),
    ]));
    let binding = with_adapter(&source, Ok(vec![String::from("group-2")]))?;
    let overage = json!({ "_claim_names": { "groups": "src1" } });
    let party = bound(binding.resolve(&person(&overage)).await?)?;
    assert_eq!(vec!["adapter", "source"], source.log(), "the adapter first");
    assert_eq!(vec![group_ref("g-2")], party.groups, "the adapter's groups");
    let plain = bound(
        binding
            .resolve(&person(&json!({ "groups": ["group-1"] })))
            .await?,
    )?;
    assert_eq!(
        vec![group_ref("g-1")],
        plain.groups,
        "no overage, no adapter call"
    );
    assert_eq!(vec!["adapter", "source", "source"], source.log());
    Ok(())
}

// NOTE: no specification governs the seam: our own design, in which an adapter failure is
// GroupsUnavailable carrying the upstream status and its Retry-After, never no groups.
#[tokio::test]
async fn an_adapter_failure_is_groups_unavailable_carrying_the_upstream_status() -> Outcome2 {
    let source = FakeSource::answering(one_professional());
    let throttled = AdapterError::Status {
        status: StatusCode::TOO_MANY_REQUESTS,
        retry_after: Some(Duration::from_secs(30)),
        body: None,
    };
    let binding = with_adapter(&source, Err(throttled))?;
    let outcome = binding
        .resolve(&person(&json!({ "hasgroups": true })))
        .await?;
    let Some(Outcome::GroupsUnavailable(GroupsCause::Adapter(AdapterError::Status {
        status,
        retry_after,
        ..
    }))) = outcome
    else {
        panic!("an adapter failure, not {outcome:?}");
    };
    assert_eq!(StatusCode::TOO_MANY_REQUESTS, status);
    assert_eq!(Some(Duration::from_secs(30)), retry_after);
    assert_eq!(0, source.calls(), "no lookup on a failed adapter");
    Ok(())
}

// NOTE: no specification governs the registration: our own design, in which a profile
// naming an adapter the binding does not hold refuses the issuer at start.
#[test]
fn a_profile_naming_an_unregistered_adapter_refuses_the_issuer() {
    let source: Arc<dyn PartySource> = FakeSource::answering(one_professional());
    assert_eq!(
        Err(PartyError::Adapter {
            issuer: String::from(ISSUER),
            adapter: String::from("test-idp"),
        }),
        PartyBinding::new(source)
            .with_issuer(table(), IssuerKind::Persons, &adapter_profile())
            .map(|_binding| ())
    );
}

// NOTE: Microsoft, "Access token claims reference", `groups`: a "JSON array of GUIDs"; a
// group claim in any other form is GroupsUnavailable, an absent one the empty set.
#[tokio::test]
async fn a_group_claim_that_is_no_set_of_strings_is_groups_unavailable() -> Outcome2 {
    let source = FakeSource::answering(one_professional());
    let binding = binding(&source);
    for groups in [json!("src1"), json!(["g", 1]), json!({ "g": true })] {
        let outcome = binding
            .resolve(&person(&json!({ "groups": groups })))
            .await?;
        assert!(
            matches!(
                outcome,
                Some(Outcome::GroupsUnavailable(GroupsCause::Malformed))
            ),
            "{groups}: {outcome:?}"
        );
    }
    Ok(())
}

// NOTE: no specification governs the groups: our own design, in which an absent group
// claim is the empty set and binds with no groups.
#[tokio::test]
async fn a_token_with_no_group_claim_binds_with_no_groups() -> Outcome2 {
    let source = FakeSource::answering(Lookup::Parties(vec![
        record("p-1", Markers::PROFESSIONAL)
            .with_memberships(vec![Membership::new(group_ref("g-1"), "group-1")]),
    ]));
    let party = bound(binding(&source).resolve(&person(&json!({}))).await?)?;
    assert!(party.groups.is_empty(), "{:?}", party.groups);
    assert_eq!(
        Some(String::from(GROUPS)),
        source
            .seen()
            .first()
            .and_then(|seen| seen.group_identifier_issuer.clone()),
        "the memberships are asked under the group identifier issuer"
    );
    Ok(())
}

// NOTE: no specification governs the groups: our own design, in which the memberships are
// intersected with the group claim on each request, so a person in two groups has two.
#[tokio::test]
async fn a_party_in_three_groups_whose_token_names_two_lists_exactly_those_two() -> Outcome2 {
    let source = FakeSource::answering(Lookup::Parties(vec![
        record("p-1", Markers::PROFESSIONAL).with_memberships(vec![
            Membership::new(group_ref("g-1"), "group-1"),
            Membership::new(group_ref("g-2"), "group-2"),
            Membership::new(group_ref("g-3"), "group-3"),
        ]),
    ]));
    let claims = json!({ "groups": ["group-3", "group-1", "group-not-held"] });
    let party = bound(binding(&source).resolve(&person(&claims)).await?)?;
    assert_eq!(vec![group_ref("g-1"), group_ref("g-3")], party.groups);
    Ok(())
}
