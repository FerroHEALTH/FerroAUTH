// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What the cases share: generated keys written to PEM files, and a
//! configuration over them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, RsaKeyPair};
use base64::Engine as _;
use ferrosmart::config::Config;
use tempfile::TempDir;

/// Returns `der` as a PEM `PRIVATE KEY` document.
fn pem(der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect();
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        lines.join("\n")
    )
}

/// Writes a fresh RSA key to `dir/name` and returns its path.
pub(crate) fn rsa_key(dir: &Path, name: &str) -> PathBuf {
    let pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("a key pair");
    let der = pair.as_der().expect("PKCS#8");
    let path = dir.join(name);
    std::fs::write(&path, pem(der.as_ref())).expect("the key is written");
    path
}

/// Writes a fresh P-384 key to `dir/name` and returns its path.
pub(crate) fn ec_key(dir: &Path, name: &str) -> PathBuf {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let der =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).expect("a key pair");
    let path = dir.join(name);
    std::fs::write(&path, pem(der.as_ref())).expect("the key is written");
    path
}

/// A directory of keys that lives as long as the case.
pub(crate) struct Keys {
    /// The directory.
    pub(crate) dir: TempDir,
    /// The current key.
    pub(crate) current: PathBuf,
}

impl Keys {
    /// Returns a directory with one current RSA key.
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().expect("a directory");
        let current = rsa_key(dir.path(), "current.pem");
        Self { dir, current }
    }
}

/// Returns the configuration `text` holds, with `[ferrosmart.keys]` naming
/// `keys`' current key unless `text` names one.
pub(crate) fn config(text: &str, keys: &Keys) -> Config {
    let text = if text.contains("private_key_file") {
        text.to_owned()
    } else {
        format!(
            "{text}\n[ferrosmart.keys]\nprivate_key_file = {:?}\n",
            keys.current.display().to_string()
        )
    };
    Config::from_sources(Some(&text), &BTreeMap::new()).expect("the configuration reads")
}
