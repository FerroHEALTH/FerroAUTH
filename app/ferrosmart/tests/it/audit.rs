// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The audit store as the outbox of the ITI-20 FHIR Feed.

use std::time::Duration;

use ferrosmart::audit::Audit;
use ferrosmart::store::Store;
use ferrosmart::store::audit::AuditRow;
use ihe_atna::atna::forwarder::Outbox as _;
use ihe_atna::balp::{NetworkAddress, Observer};
use secrecy::ExposeSecret as _;
use serde_json::Value;

use crate::support::Database;

/// Returns a row whose document names `n`.
fn row(n: u32) -> AuditRow {
    AuditRow {
        recorded_at: String::from("2026-11-16T12:00:00Z"),
        kind: "login",
        outcome: "0",
        subject: Some(String::from("synthetic-subject")),
        client_id: None,
        document: format!("{{\"resourceType\":\"AuditEvent\",\"id\":\"r{n}\"}}"),
    }
}

#[tokio::test]
async fn the_feed_sends_the_oldest_record_first_and_keeps_a_refused_one() {
    let database = Database::create().await;
    let store = Store::connect(&database.url, 2).await.expect("connects");
    store.migrate().await.expect("migrates");
    let audit = Audit::new(Observer {
        source_id: String::from("smart.example.org"),
        site: None,
        host: NetworkAddress::host("smart.example.org"),
        source_types: Vec::new(),
    });
    for n in 1..=3 {
        audit.record(&store, &row(n)).await.expect("stored");
    }
    let outbox = audit.outbox(store.clone(), Duration::from_millis(10));
    let id = |message: &[u8]| {
        serde_json::from_slice::<Value>(message).expect("JSON")["id"]
            .as_str()
            .expect("an id")
            .to_owned()
    };
    let first = outbox.oldest().await.expect("reads").expect("a record");
    assert_eq!("r1", id(first.message.expose_secret()), "oldest first");
    assert_eq!(3, outbox.depth().waiting(), "three wait");
    outbox.remove(first.sequence).await.expect("delivered");
    let second = outbox.oldest().await.expect("reads").expect("a record");
    assert_eq!("r2", id(second.message.expose_secret()));
    outbox.quarantine(second.sequence).await.expect("set aside");
    let third = outbox.oldest().await.expect("reads").expect("a record");
    assert_eq!(
        "r3",
        id(third.message.expose_secret()),
        "the refused one is passed"
    );
    assert_eq!(1, outbox.depth().quarantined, "the refused one is kept");
    outbox.remove(third.sequence).await.expect("delivered");
    assert!(
        outbox.oldest().await.expect("reads").is_none(),
        "none waits"
    );
    assert_eq!(
        3,
        crate::support::records(&store).await.len(),
        "every record stays readable"
    );
    database.drop(store).await;
}
