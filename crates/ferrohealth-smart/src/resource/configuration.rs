// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The SMART discovery document, `.well-known/smart-configuration`, built
//! from the authorization server's metadata.
//!
//! "FHIR endpoints requiring authorization SHALL serve a JSON document at
//! the location formed by appending `/.well-known/smart-configuration` to
//! their base URL" (SMART App Launch 2.2.0, Conformance, §Using Well-Known).
//! The product mounts the route and serves the value this module builds,
//! which "SHALL be JSON, regardless of `Accept` headers". The document is
//! the product's own assertion about itself, so a value the specification
//! does not define for a member is dropped rather than copied from the
//! issuer.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use serde_json::Map;
use serde_json::Value;

use crate::metadata::ServerMetadata;

/// The path of the SMART discovery document under a FHIR base.
pub const SMART_CONFIGURATION: &str = "/.well-known/smart-configuration";

/// The capability of SMART's `OpenID` Connect profile (SMART App Launch
/// 2.2.0, Conformance, §Single Sign-on).
const SSO_OPENID_CONNECT: &str = "sso-openid-connect";

/// The scope an `OpenID` Connect issuer lists in `scopes_supported`
/// (`OpenID` Connect Discovery 1.0 §3: "The server MUST support the `openid`
/// scope value").
const OPENID_SCOPE: &str = "openid";

/// A permission capability (SMART App Launch 2.2.0, Conformance,
/// §Permissions).
///
/// The product declares the ones its route table enforces in
/// [`SmartOptions::permissions`]; the document claims none by default,
/// because a capability is one "that the server supports" (§Metadata).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PermissionCapability {
    /// `permission-offline`: "offline" refresh tokens.
    Offline,
    /// `permission-online`: "online" refresh tokens requested during an EHR
    /// launch, which the page deems experimental.
    Online,
    /// `permission-patient`: patient-level scopes (`patient/Observation.rs`).
    Patient,
    /// `permission-user`: user-level scopes (`user/Appointment.rs`).
    User,
    /// `permission-v1`: the SMART v1 scope syntax (`patient/Observation.read`).
    V1,
    /// `permission-v2`: the SMART v2 granular scope syntax, which a product
    /// declares only when it supplies an evaluator of granular constraints.
    V2,
}

impl PermissionCapability {
    /// Returns the capability string the document lists.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "permission-offline",
            Self::Online => "permission-online",
            Self::Patient => "permission-patient",
            Self::User => "permission-user",
            Self::V1 => "permission-v1",
            Self::V2 => "permission-v2",
        }
    }
}

/// Whether the document advertises `sso-openid-connect`, with the `issuer`
/// that capability requires.
///
/// "`issuer`: CONDITIONAL, … Required if the server's capabilities include
/// `sso-openid-connect`; otherwise, omitted" (SMART App Launch 2.2.0,
/// Conformance, §Metadata).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpenIdConnect {
    /// Advertised when the issuer's metadata lists the `openid` scope in
    /// `scopes_supported`, or the product lists `sso-openid-connect` in
    /// [`SmartOptions::capabilities`].
    #[default]
    FromIssuer,
    /// Advertised, the product's declaration.
    Advertised,
    /// Never advertised, whatever the issuer supports.
    Withheld,
}

/// The grant types the document may name (SMART App Launch 2.2.0,
/// Conformance, §Metadata).
const GRANT_TYPES: [&str; 2] = ["authorization_code", "client_credentials"];

/// The client authentication methods the document may name.
const AUTH_METHODS: [&str; 3] = [
    "client_secret_post",
    "client_secret_basic",
    "private_key_jwt",
];

/// The capabilities a SMART on openEHR platform advertises.
///
/// `master04 §Capabilities`: the EHR launch context conveyed by the `ehrId`
/// claim, the openEHR resource scopes, and the base64 JSON launch parameter.
pub const OPENEHR_CAPABILITIES: [&str; 3] = [
    "context-openehr-ehr",
    "openehr-permission-v1",
    "launch-base64-json",
];

/// The capabilities SMART App Launch 2.2.0 defines (Conformance,
/// §Capabilities), which reserves "simple, non-URI capability strings" for
/// itself.
pub const SMART_CAPABILITIES: [&str; 20] = [
    "launch-ehr",
    "launch-standalone",
    "authorize-post",
    "client-public",
    "client-confidential-symmetric",
    "client-confidential-asymmetric",
    "sso-openid-connect",
    "context-banner",
    "context-style",
    "context-ehr-patient",
    "context-ehr-encounter",
    "context-standalone-patient",
    "context-standalone-encounter",
    "permission-offline",
    "permission-online",
    "permission-patient",
    "permission-user",
    "permission-v1",
    "permission-v2",
    "smart-app-state",
];

/// The experimental episode context of a SMART on openEHR platform
/// (`master04 §Capabilities`), which a product adds only by configuration.
pub const OPENEHR_EPISODE_CAPABILITY: &str = "context-openehr-episode";

/// Returns whether `capability` is one a discovery document may list: a
/// capability of [`SMART_CAPABILITIES`], of the SMART on openEHR draft, or
/// a full URI.
///
/// "Additional capabilities MAY be listed by a server or defined by other
/// implementation guides, as long as these capabilities are represented
/// with full URIs" (SMART App Launch 2.2.0, Conformance, §Capabilities);
/// the SMART on openEHR draft is the one other guide whose simple strings
/// the crate admits.
#[must_use]
pub fn is_capability(capability: &str) -> bool {
    SMART_CAPABILITIES.contains(&capability)
        || OPENEHR_CAPABILITIES.contains(&capability)
        || capability == OPENEHR_EPISODE_CAPABILITY
        || (crate::scope::is_scope_token(capability) && crate::scope::is_full_uri(capability))
}

/// The key of the openEHR REST API in the `services` map, required of a
/// SMART on openEHR platform (`master04 §Services`).
pub const OPENEHR_REST_SERVICE: &str = "org.openehr.rest";

/// The key of the FHIR API in the `services` map, recommended
/// (`master04 §Services`).
pub const FHIR_REST_SERVICE: &str = "org.fhir.rest";

/// What the product adds to the discovery document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SmartOptions {
    /// The scopes the product honours, listed as `scopes_supported`;
    /// omitted when empty.
    ///
    /// The member is RECOMMENDED, and "the server SHALL support all scopes
    /// listed here" (SMART App Launch 2.2.0, Conformance, §Metadata), so a
    /// resource server lists only scopes its route table enforces, never
    /// the issuer's own `scopes_supported`.
    /// [`crate::config::Resolved::smart_options`] fills it from `[auth]
    /// scopes_supported`.
    pub scopes_supported: Vec<String>,
    /// The capabilities the product adds to the derived ones (`launch-ehr`,
    /// `context-ehr-patient`).
    pub capabilities: Vec<String>,
    /// The permission capabilities the product's route table enforces;
    /// none by default.
    pub permissions: BTreeSet<PermissionCapability>,
    /// Whether the document advertises `sso-openid-connect` and writes
    /// `issuer`.
    pub openid_connect: OpenIdConnect,
    /// The `services` map of a SMART on openEHR platform, each key a
    /// reverse domain name and each value the service's metadata with its
    /// `baseUrl` (`master04 §Services`); omitted when empty.
    pub services: BTreeMap<String, Value>,
}

impl SmartOptions {
    /// Returns these options as a SMART on openEHR platform's, with the
    /// openEHR REST API at `openehr_base_url`, the FHIR API at
    /// `fhir_base_url` when the product serves one, and the openEHR
    /// capabilities added.
    #[must_use]
    pub fn with_openehr(mut self, openehr_base_url: &str, fhir_base_url: Option<&str>) -> Self {
        self.services.insert(
            String::from(OPENEHR_REST_SERVICE),
            serde_json::json!({ "baseUrl": openehr_base_url }),
        );
        if let Some(fhir) = fhir_base_url {
            self.services.insert(
                String::from(FHIR_REST_SERVICE),
                serde_json::json!({ "baseUrl": fhir }),
            );
        }
        for capability in OPENEHR_CAPABILITIES {
            if !self.capabilities.iter().any(|added| added == capability) {
                self.capabilities.push(String::from(capability));
            }
        }
        self
    }
}

/// Returns the discovery document of `metadata` under `options`.
///
/// `grant_types_supported` and `token_endpoint_auth_methods_supported` keep
/// only the options the page defines, each when the issuer advertises it;
/// `code_challenge_methods_supported` carries `S256` and never `plain`:
/// "The `S256` method SHALL be included in this list, and the `plain`
/// method SHALL NOT be included" (SMART App Launch 2.2.0, Conformance,
/// §Metadata). The client types and the standalone launch are derived from
/// what the issuer supports.
#[must_use]
pub fn document(metadata: &ServerMetadata, options: &SmartOptions) -> Value {
    let mut document = Map::new();
    let mut put = |name: &str, value: Option<Value>| {
        if let Some(value) = value {
            document.insert(String::from(name), value);
        }
    };
    let text = |value: &Option<String>| value.clone().map(Value::String);
    let list = |items: &[String]| Value::from(items.iter().map(String::as_str).collect::<Vec<_>>());
    let keep = |advertised: &[String], allowed: &[&str]| -> Vec<String> {
        allowed
            .iter()
            .filter(|option| advertised.iter().any(|value| value == *option))
            .map(|option| (*option).to_owned())
            .collect()
    };
    let grant_types = keep(&metadata.grant_types(), &GRANT_TYPES);
    let auth_methods = keep(&metadata.token_endpoint_auth_methods(), &AUTH_METHODS);
    let sso = openid_connect(metadata, options);
    if sso {
        put("issuer", Some(Value::String(metadata.issuer.clone())));
    }
    put("jwks_uri", text(&metadata.jwks_uri));
    put(
        "authorization_endpoint",
        text(&metadata.authorization_endpoint),
    );
    put("token_endpoint", text(&metadata.token_endpoint));
    put(
        "token_endpoint_auth_methods_supported",
        Some(list(&auth_methods)),
    );
    put("grant_types_supported", Some(list(&grant_types)));
    put(
        "registration_endpoint",
        text(&metadata.registration_endpoint),
    );
    if !options.scopes_supported.is_empty() {
        put("scopes_supported", Some(list(&options.scopes_supported)));
    }
    if !options.services.is_empty() {
        put(
            "services",
            Some(Value::Object(
                options
                    .services
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            )),
        );
    }
    put(
        "response_types_supported",
        metadata.response_types_supported.as_deref().map(list),
    );
    put(
        "introspection_endpoint",
        text(&metadata.introspection_endpoint),
    );
    put("revocation_endpoint", text(&metadata.revocation_endpoint));
    let mut challenge: Vec<&str> = vec!["S256"];
    for method in metadata.code_challenge_methods_supported.iter().flatten() {
        if method != "plain" && !challenge.contains(&method.as_str()) {
            challenge.push(method);
        }
    }
    put(
        "code_challenge_methods_supported",
        Some(Value::from(challenge)),
    );
    put(
        "capabilities",
        Some(Value::from(capabilities(
            metadata,
            options,
            &grant_types,
            &auth_methods,
            sso,
        ))),
    );
    Value::Object(document)
}

/// Returns whether the document advertises `sso-openid-connect` under
/// `options`.
///
/// The capability also makes `jwks_uri` required (SMART App Launch 2.2.0,
/// Conformance, §Metadata), so it is advertised only when the issuer's
/// metadata names one, which a key set read from a file leaves unknown.
fn openid_connect(metadata: &ServerMetadata, options: &SmartOptions) -> bool {
    let wanted = match options.openid_connect {
        OpenIdConnect::Withheld => false,
        OpenIdConnect::Advertised => true,
        OpenIdConnect::FromIssuer => {
            options
                .capabilities
                .iter()
                .any(|capability| capability == SSO_OPENID_CONNECT)
                || metadata
                    .scopes_supported
                    .iter()
                    .flatten()
                    .any(|scope| scope == OPENID_SCOPE)
        }
    };
    wanted && metadata.jwks_uri.is_some()
}

/// Returns the capabilities of the document: the product's permissions, the
/// client types and the standalone launch the issuer supports, single
/// sign-on when advertised, and the product's own.
fn capabilities<'a>(
    metadata: &'a ServerMetadata,
    options: &'a SmartOptions,
    grant_types: &[String],
    auth_methods: &[String],
    sso: bool,
) -> Vec<&'a str> {
    let mut capabilities: Vec<&str> = options
        .permissions
        .iter()
        .map(|permission| permission.as_str())
        .collect();
    let symmetric = auth_methods
        .iter()
        .any(|method| method == "client_secret_basic" || method == "client_secret_post");
    if symmetric {
        capabilities.push("client-confidential-symmetric");
    }
    if auth_methods
        .iter()
        .any(|method| method == "private_key_jwt")
    {
        capabilities.push("client-confidential-asymmetric");
    }
    if metadata
        .token_endpoint_auth_methods()
        .iter()
        .any(|method| method == "none")
    {
        capabilities.push("client-public");
    }
    if grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
    {
        capabilities.push("launch-standalone");
    }
    if sso {
        capabilities.push(SSO_OPENID_CONNECT);
    }
    for added in &options.capabilities {
        // NOTE: SMART App Launch 2.2.0, Conformance, §Metadata, `issuer` is
        // written only with `sso-openid-connect`, so the two never part.
        if added != SSO_OPENID_CONNECT && !capabilities.contains(&added.as_str()) {
            capabilities.push(added);
        }
    }
    capabilities
}

#[cfg(test)]
mod tests {
    use super::{OpenIdConnect, PermissionCapability, SmartOptions, document, is_capability};
    use crate::metadata::ServerMetadata;
    use std::collections::BTreeSet;

    #[test]
    fn the_document_keeps_only_the_defined_options_and_adds_the_products() {
        let metadata = ServerMetadata {
            issuer: String::from("https://as.example.org"),
            token_endpoint: Some(String::from("https://as.example.org/token")),
            grant_types_supported: Some(vec![
                String::from("authorization_code"),
                String::from("client_credentials"),
                String::from("urn:ietf:params:oauth:grant-type:token-exchange"),
            ]),
            token_endpoint_auth_methods_supported: Some(vec![
                String::from("private_key_jwt"),
                String::from("tls_client_auth"),
            ]),
            code_challenge_methods_supported: Some(vec![String::from("plain")]),
            scopes_supported: Some(vec![String::from("issuer-scope")]),
            ..ServerMetadata::default()
        };
        let options = SmartOptions {
            scopes_supported: vec![String::from("system/Condition.rs")],
            capabilities: vec![String::from("launch-ehr"), String::from("permission-v1")],
            permissions: BTreeSet::from([
                PermissionCapability::V1,
                PermissionCapability::V2,
                PermissionCapability::User,
            ]),
            ..SmartOptions::default()
        };
        let document = document(&metadata, &options);
        assert_eq!(
            serde_json::json!(["S256"]),
            document["code_challenge_methods_supported"]
        );
        assert_eq!(
            serde_json::json!(["authorization_code", "client_credentials"]),
            document["grant_types_supported"]
        );
        assert_eq!(
            serde_json::json!(["private_key_jwt"]),
            document["token_endpoint_auth_methods_supported"]
        );
        assert_eq!(
            serde_json::json!(["system/Condition.rs"]),
            document["scopes_supported"]
        );
        assert_eq!(
            serde_json::json!([
                "permission-user",
                "permission-v1",
                "permission-v2",
                "client-confidential-asymmetric",
                "launch-standalone",
                "launch-ehr"
            ]),
            document["capabilities"]
        );
        assert!(document.get("jwks_uri").is_none());
        assert!(
            document.get("issuer").is_none(),
            "SMART App Launch 2.2.0, Conformance, Metadata: issuer is omitted without sso-openid-connect"
        );
    }

    #[test]
    fn the_defaults_of_rfc_8414_stand_in_for_omitted_members() {
        let metadata = ServerMetadata {
            issuer: String::from("https://as.example.org"),
            ..ServerMetadata::default()
        };
        let document = document(&metadata, &SmartOptions::default());
        assert_eq!(
            serde_json::json!(["authorization_code"]),
            document["grant_types_supported"]
        );
        assert_eq!(
            serde_json::json!(["client_secret_basic"]),
            document["token_endpoint_auth_methods_supported"]
        );
        assert_eq!(
            serde_json::json!(["client-confidential-symmetric", "launch-standalone"]),
            document["capabilities"],
            "no permission capability is claimed unless the product declares it"
        );
        assert!(document.get("scopes_supported").is_none());
        assert!(document.get("issuer").is_none());
    }

    /// The metadata of an `OpenID` Connect issuer: the `openid` scope and a
    /// key set URL.
    fn openid_issuer() -> ServerMetadata {
        ServerMetadata {
            issuer: String::from("https://as.example.org"),
            jwks_uri: Some(String::from("https://as.example.org/jwks")),
            scopes_supported: Some(vec![String::from("openid"), String::from("profile")]),
            ..ServerMetadata::default()
        }
    }

    // NOTE: SMART App Launch 2.2.0, Conformance, Metadata, `issuer` is
    // "Required if the server's capabilities include `sso-openid-connect`;
    // otherwise, omitted".
    #[test]
    fn the_issuer_is_written_only_with_sso_openid_connect() {
        let sso = |document: &serde_json::Value| {
            document["capabilities"]
                .as_array()
                .is_some_and(|all| all.iter().any(|value| value == "sso-openid-connect"))
        };
        let derived = document(&openid_issuer(), &SmartOptions::default());
        assert!(sso(&derived), "derived from the issuer's openid scope");
        assert_eq!(
            serde_json::json!("https://as.example.org"),
            derived["issuer"]
        );
        assert_eq!(
            serde_json::json!("https://as.example.org/jwks"),
            derived["jwks_uri"]
        );
        let withheld = document(
            &openid_issuer(),
            &SmartOptions {
                openid_connect: OpenIdConnect::Withheld,
                capabilities: vec![String::from("sso-openid-connect")],
                ..SmartOptions::default()
            },
        );
        assert!(!sso(&withheld), "the product withholds it");
        assert!(withheld.get("issuer").is_none());
        let plain_oauth = ServerMetadata {
            scopes_supported: Some(vec![String::from("system/*.rs")]),
            ..openid_issuer()
        };
        let without = document(&plain_oauth, &SmartOptions::default());
        assert!(!sso(&without), "an issuer without the openid scope");
        assert!(without.get("issuer").is_none());
        for declared in [
            SmartOptions {
                openid_connect: OpenIdConnect::Advertised,
                ..SmartOptions::default()
            },
            SmartOptions {
                capabilities: vec![String::from("sso-openid-connect")],
                ..SmartOptions::default()
            },
        ] {
            let document = document(&plain_oauth, &declared);
            assert!(sso(&document), "the product declares it");
            assert_eq!(
                serde_json::json!("https://as.example.org"),
                document["issuer"]
            );
        }
        let no_key_set = ServerMetadata {
            jwks_uri: None,
            ..openid_issuer()
        };
        let unbacked = document(
            &no_key_set,
            &SmartOptions {
                openid_connect: OpenIdConnect::Advertised,
                ..SmartOptions::default()
            },
        );
        assert!(
            !sso(&unbacked) && unbacked.get("issuer").is_none(),
            "sso-openid-connect requires a jwks_uri the document can carry"
        );
    }

    #[test]
    fn a_capability_is_defined_by_smart_or_a_full_uri() {
        for capability in [
            "launch-ehr",
            "smart-app-state",
            "context-openehr-ehr",
            "context-openehr-episode",
            "https://example.org/capability/x",
        ] {
            assert!(is_capability(capability), "{capability}");
        }
        for capability in ["launch-anything", "x:y", "", "https://example.org/a b"] {
            assert!(!is_capability(capability), "{capability}");
        }
    }
}
