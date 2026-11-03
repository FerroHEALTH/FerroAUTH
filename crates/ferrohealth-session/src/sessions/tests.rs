// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use ferrohealth_secret::secret::Secret;
use ferrohealth_smart::oidc::{PendingSignIn, TokenTypeHint};
use http::header::COOKIE;
use http::{HeaderMap, HeaderValue};

use super::{SessionError, Sessions};
use crate::clock;
use crate::config::{SessionSection, StoreKind};
use crate::cookies::CookieNames;
use crate::record::{Credential, Held, SignedIn};
use crate::return_path::ReturnPath;

const START: i64 = 1_800_000_000;

fn section(store: StoreKind) -> SessionSection {
    let key = (store == StoreKind::Sealed).then(|| {
        let mut raw = [0_u8; 64];
        aws_lc_rs::rand::fill(&mut raw).expect("the random source works");
        Secret::new(base64::engine::general_purpose::STANDARD.encode(raw))
    });
    SessionSection {
        store,
        sign_in_timeout_s: 60,
        max_sign_ins: 4,
        idle_timeout_s: 60,
        absolute_timeout_s: 600,
        max_sessions: 2,
        key,
        ..SessionSection::default()
    }
}

fn store(store: StoreKind) -> (Sessions, Arc<AtomicI64>) {
    store_of(&section(store))
}

fn store_of(section: &SessionSection) -> (Sessions, Arc<AtomicI64>) {
    let (clock, now) = clock::manual(START);
    let settings = section.check_with(false).expect("a valid section");
    (
        Sessions::with_clock(
            settings,
            CookieNames::for_console("synthetic_console"),
            clock,
        ),
        now,
    )
}

fn both() -> [StoreKind; 2] {
    [StoreKind::Memory, StoreKind::Sealed]
}

fn signed_in() -> SignedIn {
    SignedIn {
        operator: Some(String::from("Synthetic Operator")),
        subject: Some(String::from("synthetic-subject")),
        scopes: vec![String::from("openid"), String::from("profile")],
        credential: Credential::Bearer(Secret::new("synthetic-access-token")),
        expires_in: None,
        refresh_token: None,
        id_token: Some(Secret::new("synthetic-id-token")),
    }
}

/// The request `Cookie` header that sends back what `set` set.
fn sent(set: &HeaderValue) -> HeaderMap {
    let pair = set
        .to_str()
        .expect("ASCII")
        .split(';')
        .next()
        .expect("a pair")
        .to_owned();
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, pair.parse().expect("a header"));
    headers
}

fn advance(now: &AtomicI64, seconds: i64) {
    now.fetch_add(seconds, Ordering::SeqCst);
}

fn is_removal(cookies: &[HeaderValue]) -> bool {
    cookies
        .iter()
        .any(|cookie| cookie.to_str().is_ok_and(|text| text.contains("Max-Age=0")))
}

#[test]
fn a_pending_sign_in_is_taken_once_with_its_return_path() {
    for kind in both() {
        let (sessions, _now) = store(kind);
        let pending = PendingSignIn::mint().expect("minted");
        let state = pending.state().to_owned();
        let back = ReturnPath::parse("/sources?page=2", "/sign-in");
        let cookie = sessions.begin(pending, back).expect("begun");
        assert!(
            cookie.to_str().expect("ASCII").contains("Max-Age=60"),
            "{kind:?}"
        );
        let taken = sessions.take_pending(&sent(&cookie)).expect("usable");
        assert!(is_removal(&taken.cookies), "the sign-in cookie is removed");
        let pending = taken.value.expect("pending");
        assert_eq!(state, pending.sign_in.state(), "{kind:?}");
        assert_eq!(
            Some("/sources?page=2"),
            pending.back.as_ref().map(ReturnPath::as_str)
        );
        if kind == StoreKind::Memory {
            let again = sessions.take_pending(&sent(&cookie)).expect("usable");
            assert!(again.value.is_none(), "a memory sign-in is taken once");
        }
    }
}

#[test]
fn an_expired_sign_in_is_refused() {
    for kind in both() {
        let (sessions, now) = store(kind);
        let cookie = sessions
            .begin(PendingSignIn::mint().expect("minted"), None)
            .expect("begun");
        advance(&now, 60);
        let taken = sessions.take_pending(&sent(&cookie)).expect("usable");
        assert!(taken.value.is_none(), "{kind:?}");
    }
}

#[test]
fn a_session_carries_the_sign_in_time_and_what_the_sign_in_left() {
    for kind in both() {
        let (sessions, _now) = store(kind);
        let cookie = sessions
            .establish(&HeaderMap::new(), signed_in())
            .expect("room");
        let held = sessions.held(&sent(&cookie)).expect("usable").value;
        let Held::SignedIn(session) = held else {
            panic!("{kind:?}: {held:?}");
        };
        assert_eq!(START, session.signed_in_at(), "the sign-in time");
        assert_eq!(Some("Synthetic Operator"), session.operator());
        assert_eq!(Some("synthetic-subject"), session.subject());
        assert_eq!(2, session.scopes().len(), "the granted scopes");
        assert_eq!(
            &Credential::Bearer(Secret::new("synthetic-access-token")),
            session.credential(),
            "the access token"
        );
        assert_eq!((60, 600), (session.left().idle, session.left().absolute));
    }
}

#[test]
fn the_idle_lifetime_ends_a_session_and_activity_moves_it() {
    for kind in both() {
        let (sessions, now) = store(kind);
        let mut cookie = sessions
            .establish(&HeaderMap::new(), signed_in())
            .expect("room");
        advance(&now, 50);
        let held = sessions.held(&sent(&cookie)).expect("usable");
        assert!(matches!(held.value, Held::SignedIn(_)), "{kind:?}");
        if let Some(resealed) = held.cookies.first() {
            cookie = resealed.clone();
        }
        advance(&now, 50);
        assert!(
            matches!(
                sessions.held(&sent(&cookie)).expect("usable").value,
                Held::SignedIn(_)
            ),
            "{kind:?}: the read at 50 s started the idle lifetime again"
        );
        advance(&now, 60);
        let held = sessions.held(&sent(&cookie)).expect("usable");
        assert!(
            matches!(held.value, Held::Ended),
            "{kind:?}: sixty idle seconds"
        );
        assert!(
            is_removal(&held.cookies),
            "an ended session's cookie is removed"
        );
    }
}

#[test]
fn the_absolute_lifetime_ends_a_session_whatever_the_activity() {
    for kind in both() {
        let (sessions, now) = store(kind);
        let mut cookie = sessions
            .establish(&HeaderMap::new(), signed_in())
            .expect("room");
        for _ in 0..12 {
            advance(&now, 50);
            let held = sessions.held(&sent(&cookie)).expect("usable");
            if let Some(resealed) = held.cookies.first() {
                cookie = resealed.clone();
            }
        }
        let held = sessions.held(&sent(&cookie)).expect("usable").value;
        assert!(
            matches!(held, Held::Ended),
            "{kind:?}: 600 s from the sign-in: {held:?}"
        );
    }
}

#[test]
fn a_watch_read_never_counts_as_activity_and_an_extension_does() {
    for kind in both() {
        let (sessions, now) = store(kind);
        let cookie = sessions
            .establish(&HeaderMap::new(), signed_in())
            .expect("room");
        advance(&now, 30);
        let read = sessions.left(&sent(&cookie), false).expect("usable");
        assert!(read.cookies.is_empty(), "{kind:?}: a read sets nothing");
        let read = read.value.expect("live");
        assert_eq!((30, 570), (read.idle, read.absolute), "{kind:?}");
        let again = sessions
            .left(&sent(&cookie), false)
            .expect("usable")
            .value
            .expect("live");
        assert_eq!(read, again, "{kind:?}: the read moved nothing");
        let extended = sessions.left(&sent(&cookie), true).expect("usable");
        assert_eq!((60, 570), {
            let left = extended.value.expect("live");
            (left.idle, left.absolute)
        });
        assert_eq!(
            kind == StoreKind::Sealed,
            !extended.cookies.is_empty(),
            "a sealed extension seals the cookie again"
        );
    }
}

#[test]
fn an_ended_session_hands_back_its_hint_and_its_revocable_token() {
    for kind in both() {
        let (sessions, _now) = store(kind);
        let cookie = sessions
            .establish(&HeaderMap::new(), signed_in())
            .expect("room");
        let ended = sessions.end(&sent(&cookie)).expect("usable");
        assert!(is_removal(&ended.cookies), "the cookie is removed");
        let ended = ended.value.expect("held");
        assert_eq!(
            Some("synthetic-id-token"),
            ended.id_token.as_ref().map(Secret::expose),
            "{kind:?}"
        );
        let (token, hint) = ended.revocable.expect("a bearer session");
        assert_eq!(
            ("synthetic-access-token", TokenTypeHint::AccessToken),
            (token.expose(), hint)
        );
        if kind == StoreKind::Memory {
            assert!(
                matches!(
                    sessions.held(&sent(&cookie)).expect("usable").value,
                    Held::Ended
                ),
                "an ended memory session is gone"
            );
        }
    }
}

#[test]
fn a_basic_sign_in_carries_its_password_and_nothing_to_revoke() {
    for kind in both() {
        let (sessions, _now) = store(kind);
        let signed_in = SignedIn::basic("synthetic-user", Secret::new("synthetic-password"));
        let cookie = sessions
            .establish(&HeaderMap::new(), signed_in)
            .expect("room");
        let Held::SignedIn(session) = sessions.held(&sent(&cookie)).expect("usable").value else {
            panic!("{kind:?}: live");
        };
        assert!(
            matches!(session.credential(), Credential::Basic { username, password }
                if username == "synthetic-user" && password.expose() == "synthetic-password"),
            "{kind:?}"
        );
        let ended = sessions
            .end(&sent(&cookie))
            .expect("usable")
            .value
            .expect("held");
        assert!(ended.revocable.is_none(), "nothing to revoke");
    }
}

#[test]
fn an_access_token_no_refresh_token_replaces_ends_the_session() {
    for kind in both() {
        let (sessions, now) = store(kind);
        let cookie = sessions
            .establish(
                &HeaderMap::new(),
                SignedIn {
                    expires_in: Some(Duration::from_secs(30)),
                    ..signed_in()
                },
            )
            .expect("room");
        let left = sessions
            .left(&sent(&cookie), false)
            .expect("usable")
            .value
            .expect("live");
        assert_eq!((30, 30), (left.idle, left.absolute), "{kind:?}");
        advance(&now, 30);
        assert!(
            matches!(
                sessions.held(&sent(&cookie)).expect("usable").value,
                Held::Ended
            ),
            "{kind:?}"
        );
    }
}

#[test]
fn a_sealed_store_keeps_no_refresh_token() {
    let (sessions, now) = store(StoreKind::Sealed);
    let cookie = sessions
        .establish(
            &HeaderMap::new(),
            SignedIn {
                expires_in: Some(Duration::from_secs(30)),
                refresh_token: Some(Secret::new("synthetic-refresh-token")),
                ..signed_in()
            },
        )
        .expect("sealed");
    advance(&now, 30);
    assert!(
        matches!(
            sessions.held(&sent(&cookie)).expect("usable").value,
            Held::Ended
        ),
        "the session ends with its access token"
    );
}

#[test]
fn a_memory_session_with_a_refresh_token_outlives_its_access_token() {
    let (sessions, now) = store(StoreKind::Memory);
    let cookie = sessions
        .establish(
            &HeaderMap::new(),
            SignedIn {
                expires_in: Some(Duration::from_secs(30)),
                refresh_token: Some(Secret::new("synthetic-refresh-token")),
                ..signed_in()
            },
        )
        .expect("room");
    advance(&now, 30);
    assert!(
        matches!(
            sessions.held(&sent(&cookie)).expect("usable").value,
            Held::TokenExpired
        ),
        "live, waiting for its refresh"
    );
}

#[test]
fn a_tampered_or_foreign_sealed_cookie_is_no_session() {
    let (sessions, _now) = store(StoreKind::Sealed);
    let (other, _other_now) = store(StoreKind::Sealed);
    let cookie = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("sealed");
    let held = other.held(&sent(&cookie)).expect("usable");
    assert!(
        matches!(held.value, Held::Ended),
        "another key opens nothing"
    );
    let text = cookie.to_str().expect("ASCII");
    let (pair, _attributes) = text.split_once(';').expect("attributes");
    let (name, value) = pair.split_once('=').expect("a pair");
    let mut bytes = value.as_bytes().to_vec();
    let last = bytes.last_mut().expect("a value");
    *last = if *last == b'A' { b'B' } else { b'A' };
    let tampered = format!("{name}={}", String::from_utf8(bytes).expect("ASCII"));
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, tampered.parse().expect("a header"));
    assert!(
        matches!(sessions.held(&headers).expect("usable").value, Held::Ended),
        "tampered"
    );
}

#[test]
fn a_sealed_session_too_large_for_a_browser_is_refused() {
    let (sessions, _now) = store(StoreKind::Sealed);
    let refused = sessions.establish(
        &HeaderMap::new(),
        SignedIn {
            scopes: vec!["x".repeat(4096)],
            ..signed_in()
        },
    );
    assert!(
        matches!(refused, Err(SessionError::TooLarge { .. })),
        "{refused:?}"
    );
}

#[test]
fn a_full_sign_in_pool_drops_its_oldest_and_never_touches_the_sessions() {
    let (sessions, _now) = store(StoreKind::Memory);
    let session = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("room");
    let first = sessions
        .begin(PendingSignIn::mint().expect("minted"), None)
        .expect("begun");
    let mut last = first.clone();
    for _ in 0..100 {
        last = sessions
            .begin(PendingSignIn::mint().expect("minted"), None)
            .expect("begun");
    }
    let occupancy = sessions.occupancy().expect("usable").expect("memory");
    assert_eq!(
        (4, 1),
        (occupancy.sign_ins, occupancy.sessions),
        "the bound holds"
    );
    assert!(
        sessions
            .take_pending(&sent(&first))
            .expect("usable")
            .value
            .is_none(),
        "dropped"
    );
    assert!(
        sessions
            .take_pending(&sent(&last))
            .expect("usable")
            .value
            .is_some(),
        "kept"
    );
    assert!(matches!(
        sessions.held(&sent(&session)).expect("usable").value,
        Held::SignedIn(_)
    ));
}

#[test]
fn a_full_session_pool_refuses_a_new_session_and_keeps_the_live_ones() {
    let (sessions, _now) = store(StoreKind::Memory);
    let first = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("room");
    let second = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("room");
    let refused = sessions.establish(&HeaderMap::new(), signed_in());
    assert!(matches!(refused, Err(SessionError::Full)), "{refused:?}");
    for kept in [first, second] {
        assert!(matches!(
            sessions.held(&sent(&kept)).expect("usable").value,
            Held::SignedIn(_)
        ));
    }
}

#[test]
fn signing_in_again_ends_the_session_the_browser_held() {
    let (sessions, _now) = store(StoreKind::Memory);
    let first = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("room");
    let second = sessions
        .establish(&sent(&first), signed_in())
        .expect("room");
    let third = sessions.establish(&sent(&second), signed_in());
    assert!(third.is_ok(), "the pool of two never fills: {third:?}");
    assert!(matches!(
        sessions.held(&sent(&first)).expect("usable").value,
        Held::Ended
    ));
}

#[test]
fn a_poisoned_memory_store_answers_poisoned_everywhere() {
    let (sessions, _now) = store(StoreKind::Memory);
    let cookie = sessions
        .establish(&HeaderMap::new(), signed_in())
        .expect("room");
    sessions.memory().expect("memory").poison();
    assert!(matches!(
        sessions.held(&sent(&cookie)),
        Err(SessionError::Poisoned)
    ));
    assert!(matches!(
        sessions.begin(PendingSignIn::mint().expect("minted"), None),
        Err(SessionError::Poisoned)
    ));
    assert!(matches!(
        sessions.end(&sent(&cookie)),
        Err(SessionError::Poisoned)
    ));
}

#[test]
fn no_token_password_or_id_reaches_a_debug_rendering() {
    for kind in both() {
        let (sessions, _now) = store(kind);
        let cookie = sessions
            .establish(
                &HeaderMap::new(),
                SignedIn {
                    refresh_token: Some(Secret::new("synthetic-refresh-token")),
                    ..signed_in()
                },
            )
            .expect("room");
        let held = sessions.held(&sent(&cookie)).expect("usable");
        let ended = sessions.end(&sent(&cookie)).expect("usable");
        let id = sent(&cookie)
            .get(COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|pair| pair.split_once('='))
            .map(|(_, id)| id.to_owned())
            .expect("an id");
        let shown = format!(
            "{sessions:?} {:?} {:?} {:?}",
            held.value,
            ended.value,
            signed_in()
        );
        for secret in [
            "synthetic-access-token",
            "synthetic-id-token",
            "synthetic-refresh-token",
            &id,
        ] {
            assert!(!shown.contains(secret), "{kind:?}: {shown}");
        }
        let basic = SignedIn::basic("synthetic-user", Secret::new("synthetic-password"));
        assert!(
            !format!("{basic:?}").contains("synthetic-password"),
            "the password"
        );
    }
}

#[test]
fn a_session_preference_carries_no_max_age_and_reads_back() {
    for kind in both() {
        let (sessions, _now) = store(kind);
        let cookie = sessions
            .session_preference("sidebar", "rail")
            .expect("a cookie");
        let text = cookie.to_str().expect("text");
        assert_eq!(
            "__Host-synthetic_console_sidebar=rail; HttpOnly; SameSite=Lax; Secure; Path=/", text,
            "{kind:?}: no Max-Age, so the browser drops it with its session"
        );
        assert!(!text.contains("Expires"), "{kind:?}");
        let kept = sessions
            .preference("sidebar", "rail", Duration::from_secs(60))
            .expect("a cookie");
        assert!(
            kept.to_str().expect("text").ends_with("; Max-Age=60"),
            "the kept form keeps its Max-Age"
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_static("__Host-synthetic_console_sidebar=rail"),
        );
        assert_eq!(
            Some(String::from("rail")),
            sessions.preference_in(&headers, "sidebar"),
            "{kind:?}"
        );
    }
}
