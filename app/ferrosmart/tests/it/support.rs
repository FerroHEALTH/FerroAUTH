// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What the cases share: generated keys written to PEM files, a
//! configuration over them, the audit lane and the records it stored.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, RsaKeyPair};
use base64::Engine as _;
use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use ferrosmart::audit::Audit;
use ferrosmart::config::Config;
use ferrosmart::config::settings::Settings;
use ferrosmart::store::Store;
use http::Request;
use secrecy::SecretString;
use serde_json::Value;
use sqlx::Connection as _;
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

/// The resource server a case configures unless it names its own.
pub(crate) const RESOURCE: &str = "https://ehr.example.org/fhir";

/// The Audit Record Repository a case configures unless it names its own;
/// no case delivers to it.
pub(crate) const AUDIT_FEED: &str = "https://audit.example.org/fhir";

/// The address every case's requests come from (RFC 5737).
pub(crate) const CLIENT_ADDRESS: &str = "192.0.2.10";

/// The database URL a case that never reaches the database configures.
pub(crate) const UNREACHED_DATABASE: &str = "postgres://ferrosmart@127.0.0.1:1/unreached";

/// Returns the configuration `text` holds, with `[ferrosmart.keys]` naming
/// `keys`' current key unless `text` names one, and
/// [`UNREACHED_DATABASE`] as the database unless `text` names one, and an
/// audit spool in the keys' directory with [`AUDIT_FEED`] unless `text`
/// names `[ferrosmart.audit]`.
pub(crate) fn config(text: &str, keys: &Keys) -> Config {
    let mut environment = BTreeMap::new();
    if !text.contains("[ferrosmart.database]") {
        environment.insert(
            String::from("FERROSMART__FERROSMART__DATABASE__URL"),
            String::from(UNREACHED_DATABASE),
        );
    }
    if !text.contains("[[ferrosmart.resource]]") {
        environment.insert(
            String::from("FERROSMART__FERROSMART__RESOURCE"),
            format!("[{{ base = {RESOURCE:?} }}]"),
        );
    }
    if !text.contains("[ferrosmart.audit]") {
        environment.insert(
            String::from("FERROSMART__FERROSMART__AUDIT__SPOOL_DIR"),
            spool(keys).display().to_string(),
        );
        environment.insert(
            String::from("FERROSMART__FERROSMART__AUDIT__FEED__URL"),
            String::from(AUDIT_FEED),
        );
    }
    if !text.contains("private_key_file") {
        environment.insert(
            String::from("FERROSMART__FERROSMART__KEYS__PRIVATE_KEY_FILE"),
            keys.current.display().to_string(),
        );
    }
    Config::from_sources(Some(text), &environment).expect("the configuration reads")
}

/// Returns the audit lane `settings` describe, its forwarder never started,
/// so every record stays in the spool for [`records`] to read.
pub(crate) fn audit(settings: &Settings) -> Audit {
    Audit::open(&settings.audit).expect("the audit spool opens")
}

/// Returns the spool directory [`config`] gives a case over `keys`.
pub(crate) fn spool(keys: &Keys) -> PathBuf {
    keys.dir.path().join("audit")
}

/// Returns every `AuditEvent` the spool in `dir` holds, oldest first.
pub(crate) fn records(dir: &Path) -> Vec<Value> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("the spool reads")
        .map(|entry| entry.expect("an entry").path())
        .filter(|path| path.is_file())
        .collect();
    files.sort();
    files
        .iter()
        .map(|path| {
            serde_json::from_slice(&std::fs::read(path).expect("the record reads"))
                .expect("the record is JSON")
        })
        .collect()
}

/// Returns `request` as if it came over a connection from
/// [`CLIENT_ADDRESS`], which the stack names the client by.
pub(crate) fn from_client(mut request: Request<Body>) -> Request<Body> {
    let peer: SocketAddr = format!("{CLIENT_ADDRESS}:49152")
        .parse()
        .expect("an address");
    request.extensions_mut().insert(ConnectInfo(peer));
    request
}

/// The variable naming the test server.
const ENV: &str = "FERROSMART_TEST_PG_URL";

/// A database that lives as long as the case.
pub(crate) struct Database {
    /// The server's administrative URL.
    admin: String,
    /// The database's name.
    name: String,
    /// The database's URL.
    pub(crate) url: SecretString,
}

impl Database {
    /// Creates a fresh, empty database.
    pub(crate) async fn create() -> Self {
        let admin = std::env::var(ENV)
            .expect("FERROSMART_TEST_PG_URL names the PostgreSQL server to test against");
        let mut bytes = [0_u8; 8];
        aws_lc_rs::rand::fill(&mut bytes).expect("the random source draws");
        let name = bytes
            .iter()
            .fold(String::from("ferrosmart_test_"), |mut name, byte| {
                use std::fmt::Write as _;
                write!(name, "{byte:02x}").expect("a String takes every write");
                name
            });
        let mut connection = sqlx::PgConnection::connect(&admin)
            .await
            .expect("the server answers");
        // The name is the fixed prefix and the hex digits this case drew, never input.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut connection)
            .await
            .expect("the database is created");
        let mut url = url::Url::parse(&admin).expect("a URL");
        url.set_path(&name);
        Self {
            admin,
            name,
            url: SecretString::from(url.to_string()),
        }
    }

    /// Drops the database.
    pub(crate) async fn drop(self, store: Store) {
        drop(store);
        let mut connection = sqlx::PgConnection::connect(&self.admin)
            .await
            .expect("the server answers");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {} WITH (FORCE)",
            self.name
        )))
        .execute(&mut connection)
        .await
        .expect("the database is dropped");
    }
}
