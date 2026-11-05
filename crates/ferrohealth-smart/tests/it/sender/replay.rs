// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The replay refusal of RFC 9449 §11.1: a proof's `jti` is spent once.
//! With a store the instances share, a replay to another instance is
//! refused; with the in-memory store each instance keeps its own, so a
//! replay is refused on the instance that saw the proof alone.

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

use ferrohealth_smart::resource::Caller;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::sender::Check;
use ferrohealth_smart::sender::SenderConstraint;
use ferrohealth_smart::sender::proof::Presented;
use ferrohealth_smart::sender::proof::ProofCheck;
use ferrohealth_smart::sender::replay::MemoryReplayStore;
use ferrohealth_smart::sender::replay::ProofId;
use ferrohealth_smart::sender::replay::ReplayStore;
use ferrohealth_smart::sender::replay::ReplayStoreError;
use http::HeaderMap;
use http::Method;
use serde_json::json;

use super::Bound;
use super::EXTERNAL;
use super::assert_refused;
use super::check_over;
use super::dpop_key;
use super::proof;
use super::proof_claims;
use super::proofs;

/// A store shared by every instance that holds it, standing in for a
/// product's database table.
#[derive(Default)]
struct Shared {
    /// Each recorded proof and the end of its window.
    seen: Mutex<BTreeMap<ProofId, SystemTime>>,
}

impl ReplayStore for Shared {
    fn first_use<'a>(
        &'a self,
        proof: &'a ProofId,
        until: SystemTime,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ReplayStoreError>> + Send + 'a>> {
        let mut seen = self.seen.lock().expect("the lock holds");
        let first = seen.insert(proof.clone(), until).is_none();
        Box::pin(std::future::ready(Ok(first)))
    }
}

/// A store that cannot be reached.
struct Down;

impl ReplayStore for Down {
    fn first_use<'a>(
        &'a self,
        _proof: &'a ProofId,
        _until: SystemTime,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ReplayStoreError>> + Send + 'a>> {
        Box::pin(std::future::ready(Err(ReplayStoreError::new(
            std::io::Error::other("connection refused"),
        ))))
    }
}

/// Returns the outcome of `headers` with `token` at the instance `check`.
async fn at(
    check: &ProofCheck,
    bound: &Bound,
    token: &str,
    headers: &HeaderMap,
) -> Result<Caller, Rejection> {
    let server = bound.server(SenderConstraint::None).await;
    check
        .authenticate(
            server.as_ref(),
            &Presented {
                method: &Method::GET,
                path: "/fhir/metadata",
                headers,
                token,
                certificate: None,
            },
        )
        .await
}

/// Returns a bound token of `bound` and one proof for it.
fn token_and_proof(bound: &Bound) -> (String, HeaderMap) {
    let key = dpop_key();
    let token = bound.token(Some(json!({ "jkt": key.jkt })));
    let htu = format!("{EXTERNAL}/fhir/metadata");
    let headers = proofs(&[&proof(&key, &proof_claims("GET", &htu, &token))]);
    (token, headers)
}

#[tokio::test]
async fn a_replayed_proof_is_refused() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 9449 §11.1, "HTTP requests to the same URI for which the jti
    // value has been seen before would be declined".
    let bound = Bound::start().await;
    let (token, headers) = token_and_proof(&bound);
    let instance = check_over(Arc::new(MemoryReplayStore::new()));
    at(&instance, &bound, &token, &headers).await?;
    assert_refused(
        &at(&instance, &bound, &token, &headers).await,
        Check::ProofReplayed,
        "the same proof again",
    );
    Ok(())
}

#[tokio::test]
async fn a_shared_store_refuses_a_replay_to_a_second_instance() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 9449 §11.1, single use holds across servers "behind a single
    // endpoint" only when they share state, which a shared store is.
    let bound = Bound::start().await;
    let (token, headers) = token_and_proof(&bound);
    let shared: Arc<dyn ReplayStore> = Arc::new(Shared::default());
    let first = check_over(Arc::clone(&shared));
    let second = check_over(shared);
    at(&first, &bound, &token, &headers).await?;
    assert_refused(
        &at(&second, &bound, &token, &headers).await,
        Check::ProofReplayed,
        "the replay to the second instance",
    );
    Ok(())
}

#[tokio::test]
async fn the_in_memory_store_refuses_a_replay_on_its_own_instance_alone()
-> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 9449 §11.1, single use "may not always be feasible in practice,
    // e.g., when multiple servers behind a single endpoint have no shared
    // state", which two in-memory stores are.
    let bound = Bound::start().await;
    let (token, headers) = token_and_proof(&bound);
    let first = check_over(Arc::new(MemoryReplayStore::new()));
    let second = check_over(Arc::new(MemoryReplayStore::new()));
    at(&first, &bound, &token, &headers).await?;
    assert!(
        at(&second, &bound, &token, &headers).await.is_ok(),
        "the second instance has not seen the proof"
    );
    assert_refused(
        &at(&first, &bound, &token, &headers).await,
        Check::ProofReplayed,
        "the first instance has",
    );
    Ok(())
}

#[tokio::test]
async fn a_proof_whose_token_fails_is_not_spent() -> Result<(), Box<dyn StdError>> {
    // NOTE: no specification governs this: our own design; the `jti` is
    // recorded after every other check, so a refused request spends nothing.
    let bound = Bound::start().await;
    let (token, headers) = token_and_proof(&bound);
    let store = Arc::new(MemoryReplayStore::new());
    let held = Arc::clone(&store);
    let shared: Arc<dyn ReplayStore> = held;
    let instance = check_over(shared);
    let required = bound.server(SenderConstraint::Required).await;
    let unbound = bound.token(None);
    let outcome = instance
        .authenticate(
            required.as_ref(),
            &Presented {
                method: &Method::GET,
                path: "/fhir/metadata",
                headers: &headers,
                token: &unbound,
                certificate: None,
            },
        )
        .await;
    assert_refused(
        &outcome,
        Check::ProofTokenHash,
        "the proof names another token",
    );
    assert!(store.is_empty(), "a refused proof is not recorded");
    at(&instance, &bound, &token, &headers).await?;
    assert_eq!(1, store.len());
    Ok(())
}

#[tokio::test]
async fn a_store_that_fails_answers_503() {
    // NOTE: no specification governs this: our own design; a store that cannot
    // answer never admits a proof, and the failure is the upstream's.
    let bound = Bound::start().await;
    let (token, headers) = token_and_proof(&bound);
    let instance = check_over(Arc::new(Down));
    let outcome = at(&instance, &bound, &token, &headers).await;
    assert!(
        matches!(outcome, Err(Rejection::Upstream { .. })),
        "{outcome:?}"
    );
}
