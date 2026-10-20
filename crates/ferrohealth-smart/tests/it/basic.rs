// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! HTTP Basic end to end: the credential one side sends is the one the
//! other side verifies, a verified user carries its scopes, and a refused
//! credential is one outcome.

use std::error::Error as StdError;

use argon2::Argon2;
use argon2::password_hash::PasswordHasher;
use ferrohealth_smart::basic::Credential;
use ferrohealth_smart::basic::InvalidCredential;
use ferrohealth_smart::basic::PasswordStore;
use ferrohealth_smart::basic::Verified;
use secrecy::SecretString;

/// Returns the Argon2id PHC string of `password` under a fixed salt.
fn hash(password: &str) -> SecretString {
    SecretString::from(
        Argon2::default()
            .hash_password_with_salt(password.as_bytes(), b"synthetic-salt-16")
            .expect("the hash")
            .to_string(),
    )
}

#[test]
fn the_sent_credential_verifies_against_the_store() -> Result<(), Box<dyn StdError>> {
    let store = PasswordStore::new()
        .with_user("ferro-bridge", hash("synthetic-pw"), "system/*.rs")?
        .with_user("ferro-fed", hash("another-pw"), "")?;
    let sent = Credential::new("ferro-bridge", SecretString::from("synthetic-pw"))?;
    assert_eq!(
        Ok(Verified {
            username: String::from("ferro-bridge"),
            scope: String::from("system/*.rs"),
            cached: false,
        }),
        store.verify(&sent.header_value())
    );
    let wrong = Credential::new("ferro-bridge", SecretString::from("another-pw"))?;
    assert_eq!(Err(InvalidCredential), store.verify(&wrong.header_value()));
    let unknown = Credential::new("ferro-term", SecretString::from("synthetic-pw"))?;
    assert_eq!(
        Err(InvalidCredential),
        store.verify(&unknown.header_value())
    );
    assert_eq!(2, store.len());
    Ok(())
}

#[test]
fn a_bearer_value_is_no_basic_credential() -> Result<(), Box<dyn StdError>> {
    let store = PasswordStore::new().with_user("ferro-bridge", hash("synthetic-pw"), "")?;
    let bearer = http::HeaderValue::from_static("Bearer ZmVycm8tYnJpZGdlOnN5bnRoZXRpYy1wdw==");
    assert_eq!(Err(InvalidCredential), store.verify(&bearer));
    let bare = http::HeaderValue::from_static("Basic");
    assert_eq!(Err(InvalidCredential), store.verify(&bare));
    Ok(())
}
