// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The correlation id of a chained organisation request: the field
//! `correlation_id` a `federation` issuer's table maps, here to a member of
//! the attested `authorization_details` entry (RFC 9396 §2), read onto the
//! caller as a typed value.

use std::collections::BTreeMap;
use std::error::Error as StdError;

use ferrohealth_smart::federation::FederationSection;
use ferrohealth_smart::federation::Field;
use ferrohealth_smart::federation::Source;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::Unclassified;
use serde_json::Value;
use serde_json::json;

use crate::federation::Harness;
use crate::federation::iua;
use crate::federation::refused;
use crate::support::now;

type Outcome = Result<(), Box<dyn StdError>>;

/// This node's audience, as the federation cases name it.
const AUDIENCE: &str = "https://ehr.example.org/openehr";
/// The id the requester set.
const ID: &str = "5f0c6a1e-correlation-1";

/// Returns a table whose issuer states an organisation's access in an
/// attested entry and maps `correlation_id` to its `correlation_id` member.
fn chained() -> FederationSection {
    FederationSection {
        mapping: None,
        attests_authorization_details: true,
        organisation_types: vec![String::from("nl_organisation_access")],
        authorization_details_type: Some(String::from("nl_organisation_access")),
        fields: BTreeMap::from([(
            Field::CorrelationId,
            vec![Source::AuthorizationDetails(String::from("correlation_id"))],
        )]),
        ..iua()
    }
}

/// Returns an organisation's token whose access statement carries `id`.
fn organisation(id: Option<Value>) -> Value {
    let mut entry = json!({ "type": "nl_organisation_access", "locations": [AUDIENCE] });
    if let (Some(id), Some(members)) = (id, entry.as_object_mut()) {
        members.insert(String::from("correlation_id"), id);
    }
    json!({
        "iss": "https://sts.partner.example.org", "sub": "partner-app",
        "client_id": "partner-app", "aud": AUDIENCE, "jti": "jti-c",
        "exp": now() + 300, "iat": now(), "scope": "system/*.rs",
        "authorization_details": [entry]
    })
}

#[tokio::test]
async fn a_chained_organisation_carries_its_correlation_id() -> Outcome {
    let caller = Harness::new()
        .admit(chained(), &organisation(Some(json!(ID))))
        .await?;
    assert!(
        matches!(caller.kind(), CallerKind::ExternalOrganisation(_)),
        "{caller:?}"
    );
    let id = caller.correlation_id().ok_or("a correlation id")?;
    assert_eq!(ID, id.as_str());
    Ok(())
}

#[tokio::test]
async fn an_organisation_without_the_id_carries_none() -> Outcome {
    let caller = Harness::new().admit(chained(), &organisation(None)).await?;
    assert_eq!(None, caller.correlation_id());
    Ok(())
}

// NOTE: no specification governs the form: our own design, in which the id is
// one string and a coded value refuses the token naming the field.
#[tokio::test]
async fn a_coded_id_is_refused_naming_the_field() -> Outcome {
    assert_eq!(
        Some(Unclassified::Attribute {
            field: "correlation_id"
        }),
        refused(
            Harness::new()
                .admit(chained(), &organisation(Some(json!([ID]))))
                .await
        )
    );
    Ok(())
}

#[tokio::test]
async fn the_id_renders_no_value() -> Outcome {
    let caller = Harness::new()
        .admit(chained(), &organisation(Some(json!(ID))))
        .await?;
    let id = caller.correlation_id().ok_or("a correlation id")?;
    let rendered = format!("{id:?}");
    assert!(!rendered.contains("correlation-1"), "{rendered}");
    Ok(())
}

#[test]
fn the_field_loads_from_toml_by_its_name() -> Outcome {
    let section: FederationSection = toml::from_str(
        "[fields]\n\"correlation_id\" = [{ authorization_details = \"correlation_id\" }]\n",
    )?;
    assert_eq!(
        Some(&vec![Source::AuthorizationDetails(String::from(
            "correlation_id"
        ))]),
        section.fields.get(&Field::CorrelationId)
    );
    assert_eq!("correlation_id", Field::CorrelationId.as_str());
    Ok(())
}
