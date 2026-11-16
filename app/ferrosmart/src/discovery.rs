// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The documents that describe the authorization server: its RFC 8414
//! metadata and its SMART configuration.
//!
//! Both list only what the server supports (`docs/architecture.md` §13.5,
//! Discovery and metadata). The SMART document is built by the same
//! builder the resource servers use
//! ([`ferrohealth_smart::resource::configuration`]), from the metadata, so
//! the two never disagree.

use ferrohealth_smart::metadata::ServerMetadata;
use ferrohealth_smart::resource::configuration::{self, Purpose, SmartOptions};
use serde_json::{Value, json};

use crate::config::settings::Settings;

/// The token endpoint's route under the issuer.
pub const TOKEN_ROUTE: &str = "/token";
/// The JWK Set's route under the issuer.
pub const JWKS_ROUTE: &str = "/jwks";
/// The SMART configuration's route under the issuer (SMART App Launch
/// 2.2.0, Conformance, Using well-known).
pub const SMART_CONFIGURATION_ROUTE: &str = "/.well-known/smart-configuration";
/// The introspection endpoint's route under the issuer (RFC 7662 §2).
pub const INTROSPECT_ROUTE: &str = "/introspect";
/// The revocation endpoint's route under the issuer (RFC 7009 §2).
pub const REVOKE_ROUTE: &str = "/revoke";

/// The client authentication methods of the token endpoint.
const AUTH_METHODS: [&str; 1] = ["private_key_jwt"];
/// The algorithms a client assertion may be signed with: the two of which
/// "The FHIR authorization server SHALL be capable of validating signatures
/// with at least one" (SMART App Launch 2.2.0, Client Authentication:
/// Asymmetric, Registering a client).
const ASSERTION_ALGORITHMS: [&str; 2] = ["RS384", "ES384"];
/// The grants of the token endpoint.
const GRANT_TYPES: [&str; 1] = ["client_credentials"];

/// Returns the RFC 8414 §2 metadata of the server `settings` describe.
///
/// `response_types_supported` is REQUIRED and lists the response types the
/// server supports; with no authorization endpoint yet the list is empty,
/// and the authorization code flow adds `code` (#515).
#[must_use]
pub fn metadata(settings: &Settings) -> ServerMetadata {
    let strings = |values: &[&str]| Some(values.iter().map(|&value| value.to_owned()).collect());
    ServerMetadata {
        issuer: settings.issuer.clone(),
        jwks_uri: Some(settings.endpoint(JWKS_ROUTE)),
        token_endpoint: Some(settings.endpoint(TOKEN_ROUTE)),
        token_endpoint_auth_methods_supported: strings(&AUTH_METHODS),
        token_endpoint_auth_signing_alg_values_supported: strings(&ASSERTION_ALGORITHMS),
        grant_types_supported: strings(&GRANT_TYPES),
        response_types_supported: Some(Vec::new()),
        introspection_endpoint: Some(settings.endpoint(INTROSPECT_ROUTE)),
        revocation_endpoint: Some(settings.endpoint(REVOKE_ROUTE)),
        ..ServerMetadata::default()
    }
}

/// Returns the RFC 8414 document of `metadata`: its members with how the
/// introspection and revocation endpoints authenticate a client, which
/// RFC 8414 §2 has default to `client_secret_basic` when absent.
///
/// The introspection endpoint takes a client's `private_key_jwt` assertion
/// (or a bearer token, which is no client authentication method); the
/// revocation endpoint takes it too, and `none` with the `client_id` of a
/// public client (RFC 7009 §2.1, RFC 6749 §2.3).
///
/// # Panics
///
/// Never: the metadata is plain strings and lists, which `serde_json`
/// always serializes.
#[must_use]
#[expect(
    clippy::expect_used,
    reason = "ServerMetadata is plain strings and lists, which serde_json always serializes"
)]
pub fn metadata_document(metadata: &ServerMetadata) -> Value {
    let mut document =
        serde_json::to_value(metadata).expect("the metadata should serialize as JSON");
    if let Some(members) = document.as_object_mut() {
        members.insert(
            String::from("introspection_endpoint_auth_methods_supported"),
            json!(AUTH_METHODS),
        );
        members.insert(
            String::from("introspection_endpoint_auth_signing_alg_values_supported"),
            json!(ASSERTION_ALGORITHMS),
        );
        members.insert(
            String::from("revocation_endpoint_auth_methods_supported"),
            json!(["private_key_jwt", "none"]),
        );
        members.insert(
            String::from("revocation_endpoint_auth_signing_alg_values_supported"),
            json!(ASSERTION_ALGORITHMS),
        );
    }
    document
}

/// Returns the SMART configuration of `metadata`.
///
/// It is the Backend Services document while the client credentials grant
/// is the one grant (SMART App Launch 2.2.0, Backend Services, Retrieve
/// `.well-known/smart-configuration`).
#[must_use]
pub fn smart_configuration(metadata: &ServerMetadata) -> Value {
    let options = SmartOptions {
        purpose: Purpose::BackendServices,
        ..SmartOptions::default()
    };
    configuration::document(metadata, &options)
}
