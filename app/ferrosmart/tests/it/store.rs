// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The store against a real PostgreSQL: a fresh database per case on the
//! server `FERROSMART_TEST_PG_URL` names, a URL whose role may `CREATE
//! DATABASE`. CI sets it (the `nextest (core and axum)` job's PostgreSQL
//! service); a run without it fails the case, never skips it.

use ferrosmart::clients::{ClientKind, ClientSection, GrantType, resolve};
use ferrosmart::store::Store;
use secrecy::SecretString;

use crate::support::Database;

/// Returns a configured Backend Services client.
fn backend(client_id: &str, scope: &str) -> ClientSection {
    ClientSection {
        client_id: client_id.to_owned(),
        kind: ClientKind::ConfidentialAsymmetric,
        jwks_uri: String::from("https://export.example.org/jwks.json"),
        scopes: vec![scope.to_owned()],
        grant_types: vec![GrantType::ClientCredentials],
        ..ClientSection::default()
    }
}

#[tokio::test]
async fn the_configured_clients_are_registered_replaced_and_removed() {
    let database = Database::create().await;
    let store = Store::connect(&database.url, 2).await.expect("connects");
    store.migrate().await.expect("migrates");
    store
        .migrate()
        .await
        .expect("a second run migrates nothing");
    store.ping().await.expect("answers");

    let first = resolve(&[
        backend("export", "system/Patient.rs"),
        backend("audit", "system/AuditEvent.rs"),
    ])
    .expect("admitted");
    store.register(&first).await.expect("registered");
    assert_eq!(
        Some(first[0].clone()),
        store.client("export").await.expect("read")
    );
    assert_eq!(
        Some(first[1].clone()),
        store.client("audit").await.expect("read")
    );
    assert_eq!(None, store.client("unknown").await.expect("read"));

    let second = resolve(&[backend("export", "system/Observation.rs")]).expect("admitted");
    store.register(&second).await.expect("registered again");
    assert_eq!(
        Some(second[0].clone()),
        store.client("export").await.expect("read"),
        "replaced"
    );
    assert_eq!(
        None,
        store.client("audit").await.expect("read"),
        "no longer configured"
    );

    database.drop(store).await;
}

#[tokio::test]
async fn an_unreachable_database_is_an_error() {
    let url = SecretString::from(String::from(crate::support::UNREACHED_DATABASE));
    assert!(Store::connect(&url, 1).await.is_err());
}
