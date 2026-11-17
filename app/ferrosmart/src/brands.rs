// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The deployment's User Access Brands Bundle (SMART App Launch 2.2.0, User
//! Access Brands and Endpoints), built from `[ferrosmart.brand]` and served
//! at `GET {issuer}/brands`.
//!
//! The Bundle holds one primary brand, an `Organization` that references
//! every `Endpoint` of the Bundle ("SHALL publish at least a 'primary
//! brand' that references each FHIR endpoint"), the affiliated brands that
//! name it as `partOf`, and one `Endpoint` per configured FHIR server.
//! Every element the profiles mark Must-Support has a key, since a
//! publisher "SHALL allow Health Data Providers to manage" them all.
//! Which URL each resource server names in its own
//! `user_access_brand_bundle` is that server's choice.

use std::collections::BTreeSet;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::server::AppState;
use crate::store::{Store, StoreError};

/// The route of the Brands Bundle under the issuer. No specification names
/// the route: our own design.
pub const BRANDS_ROUTE: &str = "/brands";

/// The media type of the Bundle (FHIR R4, http.html §3.1.0.1.5).
const FHIR_JSON: &str = "application/fhir+json";

/// The extension that carries a brand's logo.
const ORGANIZATION_BRAND: &str = "http://hl7.org/fhir/StructureDefinition/organization-brand";

/// The extension that carries one portal of a brand.
const ORGANIZATION_PORTAL: &str = "http://hl7.org/fhir/StructureDefinition/organization-portal";

/// The extension that names an endpoint's FHIR version.
const ENDPOINT_FHIR_VERSION: &str = "http://hl7.org/fhir/StructureDefinition/endpoint-fhir-version";

/// The code system of the brand categories.
const ORGANIZATION_TYPE: &str = "http://terminology.hl7.org/CodeSystem/organization-type";

/// The codes of `ValueSet/user-access-category`, the binding of
/// `Organization.type` in the brand profile, each with its display.
const CATEGORIES: [(&str, &str); 7] = [
    ("prov", "Healthcare Provider"),
    ("ins", "Insurance Company"),
    ("laboratory", "Laboratory"),
    ("imaging", "Imaging Center"),
    ("pharmacy", "Pharmacy"),
    ("health-information-network", "Health Information Network"),
    ("health-data-aggregator", "Health Data Aggregator"),
];

/// `[ferrosmart.brand]`: the primary brand, the FHIR endpoints it
/// publishes and its affiliated brands. An affiliate is a table of the same
/// shape that names no endpoint and no affiliate of its own.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrandSection {
    /// The name users recognize the brand by (`Organization.name`).
    pub name: String,
    /// The brand's public website, apart from any portal
    /// (`Organization.telecom`, `system` `url`).
    pub website: String,
    /// The identifiers apps merge brands by (`Organization.identifier`).
    pub identifier: Vec<IdentifierSection>,
    /// Other names users may search by, such as former names
    /// (`Organization.alias`).
    pub alias: Vec<String>,
    /// The categories of `ValueSet/user-access-category`, by code
    /// (`Organization.type`).
    pub category: Vec<String>,
    /// The brand's logo, an `https` or `data` URL (`brandLogo`).
    pub logo: String,
    /// The terms of the logo's use, an `https` URL (`brandLogoLicense`).
    pub logo_license: String,
    /// The places the brand is associated with (`Organization.address`).
    pub address: Vec<AddressSection>,
    /// The portals users manage their accounts in
    /// (`organization-portal`).
    pub portal: Vec<PortalSection>,
    /// The FHIR endpoints of the Bundle, each a FHIR `[[ferrosmart.resource]]`
    /// base; the primary brand's alone.
    pub endpoint: Vec<EndpointSection>,
    /// The affiliated brands, each `partOf` the primary one; the primary
    /// brand's alone.
    pub affiliate: Vec<Self>,
}

/// One `identifier` of a brand: customer-supplied, a `value` with the
/// `system` it is unique in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentifierSection {
    /// The namespace, such as `urn:ietf:rfc:3986`.
    pub system: String,
    /// The value.
    pub value: String,
}

/// One `address` of a brand.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AddressSection {
    /// The street lines.
    pub line: Vec<String>,
    /// The city.
    pub city: String,
    /// The state or province.
    pub state: String,
    /// The postal code.
    pub postal_code: String,
    /// The ISO 3166-1 alpha-2 country code.
    pub country: String,
}

/// One `[[ferrosmart.brand.portal]]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PortalSection {
    /// The portal's name as users see it (`portalName`).
    pub name: String,
    /// Who may connect and what they find, in Markdown
    /// (`portalDescription`).
    pub description: String,
    /// The portal's website, an `https` URL (`portalUrl`).
    pub url: String,
    /// The portal's logo, an `https` or `data` URL (`portalLogo`).
    pub logo: String,
    /// The terms of the logo's use, an `https` URL (`portalLogoLicense`).
    pub logo_license: String,
    /// The bases of the brand endpoints the portal offers
    /// (`portalEndpoint`).
    pub endpoints: Vec<String>,
}

/// One `[[ferrosmart.brand.endpoint]]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EndpointSection {
    /// The FHIR base URL, one of the FHIR `[[ferrosmart.resource]]` bases
    /// (`Endpoint.address`).
    pub base: String,
    /// The endpoint's technical name (`Endpoint.name`).
    pub name: String,
    /// The FHIR versions the endpoint serves, such as `4.0.1`
    /// (`endpoint-fhir-version`).
    pub fhir_version: Vec<String>,
    /// The `https` URLs where developers configure access to the endpoint
    /// (`Endpoint.contact`).
    pub contact: Vec<String>,
}

/// Why `[ferrosmart.brand]` was refused: the rule broken, never a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("`ferrosmart.brand`: {0}")]
pub struct BrandError(&'static str);

impl BrandError {
    /// Returns the rule broken.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        self.0
    }
}

/// The Brands Bundle of the deployment, checked, without its timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Brands {
    /// The entries, in their published order.
    entries: Vec<Value>,
    /// The base the entries' `fullUrl` values are under.
    root: String,
}

impl Brands {
    /// Checks `section` against the FHIR bases `fhir` of the configuration
    /// and returns the entries it describes, under the Bundle URL `bundle`.
    ///
    /// # Errors
    /// Returns [`BrandError`] naming the first rule `section` breaks.
    pub fn resolve(
        section: &BrandSection,
        fhir: &[String],
        bundle: &str,
    ) -> Result<Self, BrandError> {
        if section.endpoint.is_empty() {
            return Err(BrandError("names no `endpoint`"));
        }
        let mut bases = Vec::new();
        for endpoint in &section.endpoint {
            check_endpoint(endpoint, fhir)?;
            if bases.contains(&endpoint.base) {
                return Err(BrandError("an `endpoint` base is listed twice"));
            }
            bases.push(endpoint.base.clone());
        }
        let mut identifiers = BTreeSet::new();
        check_brand(section, &bases, &mut identifiers)?;
        for affiliate in &section.affiliate {
            if !affiliate.endpoint.is_empty() || !affiliate.affiliate.is_empty() {
                return Err(BrandError(
                    "an `affiliate` names no `endpoint` or `affiliate` of its own",
                ));
            }
            check_brand(affiliate, &bases, &mut identifiers)?;
        }
        let endpoint_id = |base: &str| {
            bases
                .iter()
                .position(|known| known == base)
                .map(|index| format!("endpoint-{}", index + 1))
                .unwrap_or_default()
        };
        let mut entries = vec![organization(section, "brand", None, &bases, &endpoint_id)];
        for (index, affiliate) in section.affiliate.iter().enumerate() {
            let id = format!("affiliate-{}", index + 1);
            let offered: Vec<String> = bases
                .iter()
                .filter(|base| {
                    affiliate
                        .portal
                        .iter()
                        .any(|portal| portal.endpoints.contains(base))
                })
                .cloned()
                .collect();
            entries.push(organization(
                affiliate,
                &id,
                Some("brand"),
                &offered,
                &endpoint_id,
            ));
        }
        for endpoint in &section.endpoint {
            entries.push(endpoint_resource(endpoint, &endpoint_id(&endpoint.base)));
        }
        Ok(Self {
            entries,
            root: bundle.trim_end_matches('/').to_owned(),
        })
    }

    /// Returns the Bundle with `timestamp`, the instant of the last change
    /// to its contents, as `Bundle.timestamp` and `Bundle.meta.lastUpdated`.
    #[must_use]
    pub fn bundle(&self, timestamp: &str) -> Value {
        let entries: Vec<Value> = self
            .entries
            .iter()
            .map(|resource| {
                let kind = resource
                    .get("resourceType")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let id = resource
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                json!({ "fullUrl": format!("{}/{kind}/{id}", self.root), "resource": resource })
            })
            .collect();
        // NOTE: SMART App Launch 2.2.0, Brands, Conformance Overview: the publisher SHALL
        // populate Bundle.timestamp; the Bundle profile requires meta.lastUpdated.
        json!({
            "resourceType": "Bundle",
            "meta": { "lastUpdated": timestamp },
            "type": "collection",
            "timestamp": timestamp,
            "entry": entries,
        })
    }

    /// Returns the digest of the contents, which moves when and only when
    /// they change: the hex SHA-256 of the entries as JSON.
    #[must_use]
    pub fn digest(&self) -> String {
        let text = Value::Array(self.entries.clone()).to_string();
        sha256_hex(text.as_bytes(), 32)
    }
}

/// The Bundle as served: its body and the weak entity tag of that body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// The body.
    body: String,
    /// The weak entity tag.
    etag: String,
}

impl Published {
    /// Returns `brands` as served with `timestamp`.
    #[must_use]
    pub fn new(brands: &Brands, timestamp: &str) -> Self {
        let body = brands.bundle(timestamp).to_string();
        // NOTE: no specification governs the tag's form: our own design, the first
        // half of the body's SHA-256, which moves with any change of the body.
        let tag = sha256_hex(body.as_bytes(), 16);
        Self {
            body,
            etag: format!("W/\"{tag}\""),
        }
    }

    /// Returns the body.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    /// Returns the weak entity tag.
    #[must_use]
    pub fn etag(&self) -> &str {
        &self.etag
    }
}

/// Returns the first `bytes` bytes of the SHA-256 of `input`, in lowercase
/// hex.
fn sha256_hex(input: &[u8], bytes: usize) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, input);
    digest
        .as_ref()
        .iter()
        .take(bytes)
        .fold(String::new(), |mut hex, byte| {
            use std::fmt::Write as _;
            // NOTE: no specification governs this: our own design; a String takes every write.
            let _written: std::fmt::Result = write!(hex, "{byte:02x}");
            hex
        })
}

/// Returns `brands` as served, with the instant of the last change to their
/// contents the store records.
///
/// # Errors
/// Returns [`StoreError`] when the store cannot record or read it.
pub async fn publish(brands: &Brands, store: &Store) -> Result<Published, StoreError> {
    let changed = store.brands_changed(&brands.digest()).await?;
    let timestamp = jiff::Timestamp::from_millisecond(changed).map_err(|_out_of_range| {
        StoreError::Corrupt {
            client_id: String::from("brand_bundle"),
        }
    })?;
    Ok(Published::new(brands, &timestamp.to_string()))
}

/// Checks the brand fields of `brand`, whose portals may offer the
/// `endpoints`, adding its identifiers to `seen`.
fn check_brand(
    brand: &BrandSection,
    endpoints: &[String],
    seen: &mut BTreeSet<(String, String)>,
) -> Result<(), BrandError> {
    if brand.name.trim().is_empty() {
        return Err(BrandError("a brand names no `name`"));
    }
    // NOTE: SMART App Launch 2.2.0, Brands, Brand Information: the user-facing
    // website is 1..1 (Organization.telecom), an absolute URL.
    if !absolute(&brand.website, false) {
        return Err(BrandError("a brand's `website` is no https URL"));
    }
    for identifier in &brand.identifier {
        if identifier.value.trim().is_empty() {
            return Err(BrandError("an `identifier` names no `value`"));
        }
        // NOTE: SMART App Launch 2.2.0, Brands, Metadata: a server's brand identifier
        // SHALL match exactly one Organization.identifier of the Bundle.
        if !seen.insert((identifier.system.clone(), identifier.value.clone())) {
            return Err(BrandError("an `identifier` is given to two brands"));
        }
    }
    for code in &brand.category {
        if !CATEGORIES.iter().any(|(known, _)| known == code) {
            return Err(BrandError(
                "a `category` is no code of ValueSet/user-access-category",
            ));
        }
    }
    if !brand.logo.is_empty() && !absolute(&brand.logo, true) {
        return Err(BrandError("a `logo` is no https or data URL"));
    }
    if !brand.logo_license.is_empty() && !absolute(&brand.logo_license, false) {
        return Err(BrandError("a `logo_license` is no https URL"));
    }
    for portal in &brand.portal {
        if !portal.url.is_empty() && !absolute(&portal.url, false) {
            return Err(BrandError("a portal `url` is no https URL"));
        }
        if !portal.logo.is_empty() && !absolute(&portal.logo, true) {
            return Err(BrandError("a portal `logo` is no https or data URL"));
        }
        if !portal.logo_license.is_empty() && !absolute(&portal.logo_license, false) {
            return Err(BrandError("a portal `logo_license` is no https URL"));
        }
        if portal
            .endpoints
            .iter()
            .any(|base| !endpoints.contains(base))
        {
            return Err(BrandError(
                "a portal offers an endpoint no `ferrosmart.brand.endpoint` names",
            ));
        }
    }
    Ok(())
}

/// Checks `endpoint` against the FHIR bases `fhir`.
fn check_endpoint(endpoint: &EndpointSection, fhir: &[String]) -> Result<(), BrandError> {
    if !fhir.contains(&endpoint.base) {
        return Err(BrandError(
            "an `endpoint` base is no FHIR `ferrosmart.resource` base",
        ));
    }
    // NOTE: SMART App Launch 2.2.0, UserAccessEndpoint: endpoint-fhir-version is 1..*.
    if endpoint.fhir_version.is_empty()
        || endpoint
            .fhir_version
            .iter()
            .any(|version| version.is_empty() || version.chars().any(char::is_whitespace))
    {
        return Err(BrandError("an `endpoint` names no `fhir_version`"));
    }
    // NOTE: SMART App Launch 2.2.0, UserAccessEndpoint: contact is 1..*, each a url.
    if endpoint.contact.is_empty() || endpoint.contact.iter().any(|url| !absolute(url, false)) {
        return Err(BrandError(
            "an `endpoint` names no `contact`, or one is no https URL",
        ));
    }
    Ok(())
}

/// Whether `text` is an absolute `https` URL, or with `data` a `data` URL.
fn absolute(text: &str, data: bool) -> bool {
    Url::parse(text).is_ok_and(|url| url.scheme() == "https" || (data && url.scheme() == "data"))
}

/// Returns the `Organization` of `brand` with the id `id`, `partOf` the
/// brand `part_of` when it names one, referencing the endpoints `offered`.
fn organization(
    brand: &BrandSection,
    id: &str,
    part_of: Option<&str>,
    offered: &[String],
    endpoint_id: &dyn Fn(&str) -> String,
) -> Value {
    let reference = |base: &str| json!({ "reference": format!("Endpoint/{}", endpoint_id(base)) });
    let mut extensions = Vec::new();
    let logo = [
        ("brandLogo", &brand.logo),
        ("brandLogoLicense", &brand.logo_license),
    ];
    let logo: Vec<Value> = logo
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(url, value)| json!({ "url": url, "valueUrl": value }))
        .collect();
    if !logo.is_empty() {
        extensions.push(json!({ "url": ORGANIZATION_BRAND, "extension": logo }));
    }
    for portal in &brand.portal {
        let mut parts = Vec::new();
        if !portal.name.is_empty() {
            parts.push(json!({ "url": "portalName", "valueString": portal.name }));
        }
        if !portal.description.is_empty() {
            parts.push(json!({ "url": "portalDescription", "valueMarkdown": portal.description }));
        }
        for (url, value) in [
            ("portalUrl", &portal.url),
            ("portalLogo", &portal.logo),
            ("portalLogoLicense", &portal.logo_license),
        ] {
            if !value.is_empty() {
                parts.push(json!({ "url": url, "valueUrl": value }));
            }
        }
        for base in &portal.endpoints {
            parts.push(json!({ "url": "portalEndpoint", "valueReference": reference(base) }));
        }
        extensions.push(json!({ "url": ORGANIZATION_PORTAL, "extension": parts }));
    }
    let mut resource = json!({
        "resourceType": "Organization",
        "id": id,
        "active": true,
        "name": brand.name,
        "telecom": [{ "system": "url", "value": brand.website }],
    });
    let Some(members) = resource.as_object_mut() else {
        return resource;
    };
    if !extensions.is_empty() {
        members.insert(String::from("extension"), Value::Array(extensions));
    }
    if !brand.identifier.is_empty() {
        let identifiers = brand
            .identifier
            .iter()
            .map(|identifier| {
                if identifier.system.is_empty() {
                    json!({ "value": identifier.value })
                } else {
                    json!({ "system": identifier.system, "value": identifier.value })
                }
            })
            .collect();
        members.insert(String::from("identifier"), Value::Array(identifiers));
    }
    if !brand.category.is_empty() {
        let types = brand
            .category
            .iter()
            .map(|code| {
                let display = CATEGORIES
                    .iter()
                    .find(|(known, _)| known == code)
                    .map_or("", |(_, display)| display);
                json!({ "coding": [{ "system": ORGANIZATION_TYPE, "code": code, "display": display }] })
            })
            .collect();
        members.insert(String::from("type"), Value::Array(types));
    }
    if !brand.alias.is_empty() {
        members.insert(String::from("alias"), json!(brand.alias));
    }
    if !brand.address.is_empty() {
        let addresses = brand.address.iter().map(address).collect();
        members.insert(String::from("address"), Value::Array(addresses));
    }
    if let Some(parent) = part_of {
        members.insert(
            String::from("partOf"),
            json!({ "reference": format!("Organization/{parent}") }),
        );
    }
    if !offered.is_empty() {
        let references = offered.iter().map(|base| reference(base)).collect();
        members.insert(String::from("endpoint"), Value::Array(references));
    }
    resource
}

/// Returns `section` as an R4 `Address`, with the members it names.
fn address(section: &AddressSection) -> Value {
    let mut address = serde_json::Map::new();
    if !section.line.is_empty() {
        address.insert(String::from("line"), json!(section.line));
    }
    for (member, value) in [
        ("city", &section.city),
        ("state", &section.state),
        ("postalCode", &section.postal_code),
        ("country", &section.country),
    ] {
        if !value.is_empty() {
            address.insert(member.to_owned(), Value::String(value.clone()));
        }
    }
    Value::Object(address)
}

/// Returns the `Endpoint` of `endpoint` with the id `id`.
fn endpoint_resource(endpoint: &EndpointSection, id: &str) -> Value {
    let versions: Vec<Value> = endpoint
        .fhir_version
        .iter()
        .map(|version| json!({ "url": ENDPOINT_FHIR_VERSION, "valueCode": version }))
        .collect();
    let contacts: Vec<Value> = endpoint
        .contact
        .iter()
        .map(|url| json!({ "system": "url", "value": url }))
        .collect();
    // NOTE: SMART App Launch 2.2.0, UserAccessEndpoint: connectionType hl7-fhir-rest and
    // payloadType none are fixed; status is any valid one, and a configured server is active.
    let mut resource = json!({
        "resourceType": "Endpoint",
        "id": id,
        "extension": versions,
        "status": "active",
        "connectionType": {
            "system": "http://terminology.hl7.org/CodeSystem/endpoint-connection-type",
            "code": "hl7-fhir-rest"
        },
        "contact": contacts,
        "payloadType": [{ "coding": [{
            "system": "http://terminology.hl7.org/CodeSystem/endpoint-payload-type",
            "code": "none"
        }] }],
        "address": endpoint.base,
    });
    if !endpoint.name.is_empty()
        && let Some(members) = resource.as_object_mut()
    {
        members.insert(String::from("name"), Value::String(endpoint.name.clone()));
    }
    resource
}

/// `GET {issuer}/brands`: the Bundle as `application/fhir+json`, readable
/// from any origin, with a weak `ETag`, and `304` to an `If-None-Match`
/// naming it.
pub async fn brands(State(state): State<std::sync::Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(published) = state.brands() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let etag = HeaderValue::from_str(published.etag()).ok();
    // NOTE: RFC 9110 §13.1.2: If-None-Match compares weakly, and a match answers 304.
    let matched = headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|tag| tag == "*" || weak(tag) == weak(published.etag()));
    let mut response = if matched {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (
            [(header::CONTENT_TYPE, HeaderValue::from_static(FHIR_JSON))],
            published.body().to_owned(),
        )
            .into_response()
    };
    let response_headers = response.headers_mut();
    if let Some(etag) = etag {
        response_headers.insert(header::ETAG, etag);
    }
    // NOTE: SMART App Launch 2.2.0, Brands, Managing CORS: CORS for every GET; the app
    // reads the ETag it caches by, so the header is exposed (Fetch, CORS protocol).
    response_headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response_headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("ETag"),
    );
    response
}

/// Returns the opaque tag of the entity tag `tag`, without its weak mark.
fn weak(tag: &str) -> &str {
    tag.strip_prefix("W/").unwrap_or(tag)
}
