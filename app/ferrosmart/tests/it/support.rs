// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What the cases share: generated keys written to PEM files, a
//! configuration over them, the audit lane and the records it stored.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, RsaKeyPair};
use base64::Engine as _;

use axum::body::Body;
use axum::extract::ConnectInfo;
use ferrosmart::audit::Audit;
use ferrosmart::config::Config;
use ferrosmart::config::settings::Settings;
use ferrosmart::store::Store;
use ferrosmart::store::Transaction;
use ferrosmart::store::audit::{AuditQuery, AuditRow};
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

/// The address every case's requests come from (RFC 5737).
pub(crate) const CLIENT_ADDRESS: &str = "192.0.2.10";

/// The database URL a case that never reaches the database configures.
pub(crate) const UNREACHED_DATABASE: &str = "postgres://ferrosmart@127.0.0.1:1/unreached";

/// Returns the configuration `text` holds, with `[ferrosmart.keys]` naming
/// `keys`' current key unless `text` names one, and
/// [`UNREACHED_DATABASE`] as the database unless `text` names one.
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
    if !text.contains("private_key_file") {
        environment.insert(
            String::from("FERROSMART__FERROSMART__KEYS__PRIVATE_KEY_FILE"),
            keys.current.display().to_string(),
        );
    }
    Config::from_sources(Some(text), &environment).expect("the configuration reads")
}

/// Returns the audit lane `settings` describe.
pub(crate) fn audit(settings: &Settings) -> Audit {
    Audit::new(settings.audit.observer.clone())
}

/// Returns every `AuditEvent` `store` keeps, oldest first.
pub(crate) async fn records(store: &Store) -> Vec<Value> {
    let mut records = store
        .audit_records(&AuditQuery {
            limit: 1000,
            ..AuditQuery::default()
        })
        .await
        .expect("the records read");
    records.reverse();
    records
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

/// Checks `record` against BALP 1.1.4's profile `IHE.IUA.71`, the FHIR
/// form of the ITI-71 audit event, element by element of its differential.
///
/// # Errors
///
/// Returns the first constraint the record breaks.
pub(crate) fn iua_71(record: &Value) -> Result<(), String> {
    let at = |pointer: &str| record.pointer(pointer);
    let coded = |value: Option<&Value>, system: &str, code: &str| {
        value.is_some_and(|coding| {
            coding.get("system") == Some(&Value::from(system))
                && coding.get("code") == Some(&Value::from(code))
        })
    };
    let concept = |value: Option<&Value>, system: &str, code: &str| {
        value
            .and_then(|concept| concept.get("coding"))
            .and_then(Value::as_array)
            .is_some_and(|codings| {
                codings
                    .iter()
                    .any(|coding| coded(Some(coding), system, code))
            })
    };
    let profiled = at("/meta/profile")
        .and_then(Value::as_array)
        .is_some_and(|profiles| profiles.iter().any(|profile| profile == IUA_71));
    if !profiled {
        return Err(String::from("meta.profile names no IHE.IUA.71"));
    }
    if !coded(at("/type"), DCM, "110114") {
        return Err(String::from("type is no 110114"));
    }
    let subtypes = at("/subtype").and_then(Value::as_array).map_or(0, Vec::len);
    if subtypes != 1 || !coded(at("/subtype/0"), "urn:ihe:event-type-code", "ITI-71") {
        return Err(String::from("subtype is not ITI-71 alone"));
    }
    if at("/outcome").is_none() {
        return Err(String::from("no outcome"));
    }
    let agents = at("/agent")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !(2..=3).contains(&agents.len()) {
        return Err(format!("{} agents", agents.len()));
    }
    let (mut clients, mut servers, mut users) = (0, 0, 0);
    for agent in &agents {
        let kind = agent.get("type");
        let has = |member: &str| agent.get(member).is_some();
        if concept(kind, DCM, "110150") {
            clients += 1;
            if !has("who") || !has("network") || has("media") {
                return Err(String::from("agent:client needs who and network"));
            }
        } else if concept(kind, USER_AGENT_TYPES, "AuthzOauthService") {
            servers += 1;
            if !has("who") || !has("network") || has("media") {
                return Err(String::from("agent:auth-server needs who and network"));
            }
        } else if concept(kind, PARTICIPATION_TYPE, "IRCP") {
            users += 1;
            if !has("who") || has("network") || has("altId") || has("media") {
                return Err(String::from("agent:user needs who and no network or altId"));
            }
        } else {
            return Err(String::from(
                "an agent fills no slice of the closed slicing",
            ));
        }
    }
    if clients != 1 || servers != 1 || users > 1 {
        return Err(format!(
            "{clients} clients, {servers} servers, {users} users"
        ));
    }
    let entities = at("/entity").and_then(Value::as_array).map_or(0, Vec::len);
    if entities != 1 {
        return Err(format!("{entities} entities"));
    }
    let request = at("/entity/0");
    let entity = |member: &str| request.and_then(|entity| entity.get(member));
    if !coded(entity("type"), AUDIT_ENTITY_TYPE, "2")
        || !coded(entity("role"), OBJECT_ROLE, "24")
        || entity("what").is_some()
        || entity("query").is_none()
    {
        return Err(String::from("the entity is no token-request"));
    }
    Ok(())
}

/// The canonical URL of BALP 1.1.4's `IHE.IUA.71`.
const IUA_71: &str = "https://profiles.ihe.net/ITI/BALP/StructureDefinition/IHE.IUA.71";
/// The DICOM code system.
const DCM: &str = "http://dicom.nema.org/resources/ontology/DCM";
/// BALP's agent types.
const USER_AGENT_TYPES: &str = "https://profiles.ihe.net/ITI/BALP/CodeSystem/UserAgentTypes";
/// HL7 v3 `ParticipationType`.
const PARTICIPATION_TYPE: &str = "http://terminology.hl7.org/CodeSystem/v3-ParticipationType";
/// FHIR R4 `audit-entity-type`.
const AUDIT_ENTITY_TYPE: &str = "http://terminology.hl7.org/CodeSystem/audit-entity-type";
/// FHIR R4 `object-role`.
const OBJECT_ROLE: &str = "http://terminology.hl7.org/CodeSystem/object-role";

/// Commits `tx`, a write a case makes in place of the endpoint that would,
/// with a record of it, as every audited write commits.
pub(crate) async fn commit(mut tx: Transaction) {
    tx.record(&AuditRow {
        recorded_at: jiff::Timestamp::now().to_string(),
        kind: "test",
        outcome: "0",
        subject: None,
        client_id: None,
        document: String::from("{\"resourceType\":\"AuditEvent\"}"),
    })
    .await
    .expect("recorded");
    tx.commit().await.expect("committed");
}

/// Returns the FerroSMART event codes of `records`, in order: each
/// record's subtype in `urn:ferrosmart:audit-event`.
pub(crate) fn events(records: &[Value]) -> Vec<String> {
    records
        .iter()
        .filter_map(|record| record.get("subtype").and_then(Value::as_array))
        .flat_map(|subtypes| subtypes.iter())
        .filter(|coding| coding.get("system").and_then(Value::as_str) == Some(OWN_EVENTS))
        .filter_map(|coding| coding.get("code").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

/// FerroSMART's own code system of audit events.
const OWN_EVENTS: &str = "urn:ferrosmart:audit-event";

/// Returns the caller `token` is read as by a resource server for
/// `audience` that trusts FerroSMART's `issuer` under the `ferrosmart`
/// preset with the deployment's `keys` over it, with the published JWK Set
/// `jwks` as its key set.
pub(crate) async fn read_under_preset(
    jwks: &Value,
    issuer: &str,
    audience: &str,
    kind: ferrohealth_smart::kind::IssuerKind,
    keys: &ferrohealth_smart::profile::ProfileKeys,
    token: &str,
) -> Result<ferrohealth_smart::resource::Caller, ferrohealth_smart::resource::Rejection> {
    use ferrohealth_smart::profile::{Preset, Profile};
    use ferrohealth_smart::resource::{ResourceServer, Settings as ResourceSettings};

    let dir = tempfile::tempdir().expect("a directory");
    let path = dir.path().join("ferrosmart-jwks.json");
    std::fs::write(&path, jwks.to_string()).expect("written");
    let mut settings = ResourceSettings::new(issuer, audience, kind);
    settings.profile = Profile::resolve(Preset::Ferrosmart, keys).expect("the preset reads");
    settings.jwks_file = Some(path);
    let server = ResourceServer::discover(settings)
        .await
        .expect("the resource server starts");
    server.authenticate(token).await
}

/// The profile keys of `docs/architecture.md` §13.21's one `persons` table
/// for FerroSMART: the `ferrosmart` preset with the SMART app `app` listed
/// as a delegate, which reads a person through `app` as delegated and a
/// Backend Services token as the system.
pub(crate) fn one_table(app: &str) -> ferrohealth_smart::profile::ProfileKeys {
    ferrohealth_smart::profile::ProfileKeys {
        delegates: Some(vec![ferrohealth_smart::profile::Delegate::Client(
            app.to_owned(),
        )]),
        ..ferrohealth_smart::profile::ProfileKeys::default()
    }
}
