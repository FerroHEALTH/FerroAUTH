// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The onward token cache: one exchange per subject token, target and
//! scope, an entry living until a margin before the earlier `exp`, the
//! check run again on every hit, and no token in a log line.

use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;

use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::client::onward::Rejected;
use ferrohealth_smart::client::onward::SubjectToken;
use ferrohealth_smart::client::onward::Target;
use ferrohealth_smart::kind::CallerKind;
use secrecy::SecretString;
use serde_json::json;

use super::caller;
use super::harness::FLAVORS;
use super::harness::Flavor;
use super::harness::Harness;

#[tokio::test]
async fn a_second_request_for_the_same_subject_target_and_scope_is_served_from_the_cache() {
    for flavor in FLAVORS {
        let harness = Harness::start(flavor).await;
        let (subject, claims) = harness.person();
        harness
            .issue(&flavor.issued_claims(&claims, harness.now()), None)
            .await;
        let first = harness
            .token(&subject, None)
            .await
            .expect("the first token");
        let second = harness
            .token(&subject, None)
            .await
            .expect("the cached token");
        assert_eq!(first.header(), second.header(), "{flavor:?}");
        assert_eq!(1, harness.calls().await, "{flavor:?}: one exchange");
    }
}

#[tokio::test]
async fn two_audiences_with_one_scope_are_two_exchanges() {
    // NOTE: RFC 8707 §2, a token issued for one target is never handed to
    // another, so the target is part of the cache key.
    let harness = Harness::start(Flavor::Keycloak).await;
    let (subject, claims) = harness.person();
    let mut issued = Flavor::Keycloak.issued_claims(&claims, harness.now());
    issued["aud"] = json!(["target-client1", "target-client2"]);
    harness.issue(&issued, None).await;
    for audience in ["target-client1", "target-client2"] {
        let target = Target::new(["target-client1", "target-client2"])
            .with_indicator(audience)
            .with_scope("optional-scope2");
        harness
            .onward
            .token(&subject, None, &target)
            .await
            .expect("a token");
    }
    assert_eq!(2, harness.calls().await);
}

#[tokio::test]
async fn another_subject_token_is_another_exchange() {
    let harness = Harness::start(Flavor::Generic).await;
    let (subject, claims) = harness.person();
    harness
        .issue(&Flavor::Generic.issued_claims(&claims, harness.now()), None)
        .await;
    harness.token(&subject, None).await.expect("a token");
    let mut again = claims.clone();
    again["jti"] = json!("subject-2");
    let other = harness.subject(&again, CallerKind::Person);
    harness.token(&other, None).await.expect("a token");
    assert_eq!(2, harness.calls().await);
}

#[tokio::test]
async fn an_entry_is_renewed_the_margin_before_it_expires() {
    let harness = Harness::start(Flavor::Generic).await;
    let (subject, claims) = harness.person();
    harness
        .issue(&Flavor::Generic.issued_claims(&claims, harness.now()), None)
        .await;
    harness.token(&subject, None).await.expect("a token");
    harness.clock.advance(269);
    harness
        .token(&subject, None)
        .await
        .expect("the cached token");
    assert_eq!(1, harness.calls().await, "still within the margin");
    harness.clock.advance(1);
    harness.token(&subject, None).await.expect("a new token");
    assert_eq!(2, harness.calls().await, "30 seconds before exp");
}

#[tokio::test]
async fn an_entra_token_outliving_its_subject_is_used_only_until_the_subjects_exp() {
    // NOTE: Microsoft, "On-behalf-of flow", "Success response example": the
    // issued token carries its own `expires_in`, here past the subject's.
    let harness = Harness::start(Flavor::Entra).await;
    let now = harness.now();
    let mut claims = Flavor::Entra.subject_claims(now);
    claims["exp"] = json!(now + 120);
    let subject = harness.subject(&claims, CallerKind::Person);
    let mut issued = Flavor::Entra.issued_claims(&claims, now);
    issued["exp"] = json!(now + 3269);
    harness.issue(&issued, None).await;
    let token = harness.token(&subject, None).await.expect("accepted");
    assert_eq!(now + 120, token.expires_at(), "the subject token's exp");
    harness.clock.advance(89);
    harness
        .token(&subject, None)
        .await
        .expect("the cached token");
    assert_eq!(1, harness.calls().await, "within the subject token's life");
    harness.clock.advance(1);
    harness.token(&subject, None).await.expect("a new token");
    assert_eq!(
        2,
        harness.calls().await,
        "the margin before the subject's exp"
    );
    harness.clock.advance(30);
    let error = harness.token(&subject, None).await.expect_err("expired");
    assert!(
        matches!(error, OnwardError::Rejected(Rejected::Expired)),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_cache_hit_that_no_longer_passes_the_check_is_refused_and_dropped() {
    let harness = Harness::start(Flavor::Generic).await;
    let now = harness.now();
    let claims = Flavor::Generic.subject_claims(now);
    let opaque = "opaque-subject-token-1";
    let admitted = |claims: &serde_json::Value| {
        SubjectToken::from_caller(
            &caller(claims, CallerKind::Person),
            SecretString::from(opaque),
        )
        .expect("an opaque token stands on its introspected claims")
    };
    harness
        .issue(&Flavor::Generic.issued_claims(&claims, now), None)
        .await;
    harness
        .token(&admitted(&claims), None)
        .await
        .expect("a token");
    let mut moved = claims.clone();
    moved["sub"] = json!("person-2");
    let error = harness
        .token(&admitted(&moved), None)
        .await
        .expect_err("the hit fails the check");
    assert!(
        matches!(&error, OnwardError::Rejected(Rejected::Person { claim }) if claim == "sub"),
        "{error:?}"
    );
    harness
        .token(&admitted(&claims), None)
        .await
        .expect("a token");
    assert_eq!(2, harness.calls().await, "the refused entry is dropped");
}

/// A writer that keeps every byte a formatter writes.
#[derive(Debug, Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("not poisoned")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn no_token_reaches_a_log_line_or_a_debug_rendering() {
    let buffer = Buffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(buffer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let harness = Harness::start(Flavor::Generic).await;
    let now = harness.now();
    let claims = Flavor::Generic.subject_claims(now);
    let subject_token = super::sign(&harness.key, &claims);
    let subject = super::subject_of(&subject_token, &claims, CallerKind::Person);
    let issued = harness
        .issue(&Flavor::Generic.issued_claims(&claims, now), None)
        .await;
    let token = harness.token(&subject, None).await.expect("a token");
    harness
        .token(&subject, None)
        .await
        .expect("the cached token");
    let error = harness
        .onward
        .token(&subject, None, &Target::new(Vec::<String>::new()))
        .await
        .expect_err("refused");
    let rendered = format!("{subject:?} {token:?} {error:?} {:?}", harness.onward);
    let logged = String::from_utf8(buffer.0.lock().expect("not poisoned").clone())
        .expect("the log is UTF-8");
    assert!(logged.contains("onward token"), "the client logs: {logged}");
    for secret in [subject_token.as_str(), issued.as_str()] {
        assert!(!logged.contains(secret), "no token is logged");
        assert!(!rendered.contains(secret), "no token is rendered");
    }
    assert!(
        !rendered.contains("person-1"),
        "no claim of the subject token is rendered"
    );
}
