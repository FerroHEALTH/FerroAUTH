// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The User Access Brands Bundle (SMART App Launch 2.2.0, User Access Brands
//! and Endpoints): built from `[ferrosmart.brand]`, held to the guide's
//! profiles with `ferrobridge-validator` over the package set
//! `scripts/vendor/fhir-packages.sh` fetches, and served at
//! `{issuer}/brands`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use ferrobridge_validator::release::R4;
use ferrobridge_validator::set::PackageSet;
use ferrobridge_validator::validate::Validator;
use ferrosmart::brands::{Brands, Published};
use ferrosmart::config::error::Error;
use ferrosmart::server::{AppState, router};
use ferrosmart::store::Store;
use fhir_types::codec::Value as FhirValue;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::support::{Database, Keys, audit, config};

/// FerroSMART's issuer in every case.
const ISSUER: &str = "https://smart.example.org";

/// The canonical URL of the Brands Bundle profile.
const BUNDLE_PROFILE: &str =
    "http://hl7.org/fhir/smart-app-launch/StructureDefinition/user-access-brands-bundle";

/// An instant the cases serve the Bundle as last changed at.
const CHANGED: &str = "2026-11-17T10:00:00Z";

/// A deployment with a primary brand of every element, two endpoints, two
/// portals and an affiliated brand.
const BRAND: &str = r#"
[[ferrosmart.resource]]
base = "https://fhir.example.org/r4"
[[ferrosmart.resource]]
base = "https://fhir.example.org/r4-imaging"
[[ferrosmart.resource]]
base = "https://ehr.example.org/openehr"
kind = "openehr"
[ferrosmart.brand]
name = "Example Health"
website = "https://example.org"
identifier = [{ system = "urn:ietf:rfc:3986", value = "https://example.org" }]
alias = ["Example Health Associates"]
category = ["prov", "imaging"]
logo = "https://example.org/logo.svg"
logo_license = "https://example.org/logo-license.html"
address = [{ city = "Utrecht", postal_code = "3511", country = "NL" }]
[[ferrosmart.brand.portal]]
name = "Example Patient Portal"
description = "For **every** patient of Example Health."
url = "https://portal.example.org"
logo = "https://portal.example.org/logo.png"
logo_license = "https://portal.example.org/logo-license.html"
endpoints = ["https://fhir.example.org/r4", "https://fhir.example.org/r4-imaging"]
[[ferrosmart.brand.endpoint]]
base = "https://fhir.example.org/r4"
name = "FHIR R4 endpoint of Example Health"
fhir_version = ["4.0.1"]
contact = ["https://developer.example.org"]
[[ferrosmart.brand.endpoint]]
base = "https://fhir.example.org/r4-imaging"
fhir_version = ["4.0.1"]
contact = ["https://developer.example.org/imaging"]
[[ferrosmart.brand.affiliate]]
name = "Example Children's Clinic"
website = "https://children.example.org"
identifier = [{ system = "urn:ietf:rfc:3986", value = "https://children.example.org" }]
category = ["prov"]
[[ferrosmart.brand.affiliate.portal]]
name = "Example Children's Portal"
url = "https://children.example.org/portal"
endpoints = ["https://fhir.example.org/r4"]
"#;

/// The workspace root.
fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Returns the package set the Bundle is held to: the vendored SMART App
/// Launch package and every package `scripts/vendor/fhir-packages.sh`
/// fetched.
fn package_set() -> PackageSet<R4> {
    let root = workspace();
    let mut paths = vec![root.join("docs/specs/smart-app-launch")];
    let fetched = root.join("docs/specs/fhir-packages");
    let mut pinned: Vec<PathBuf> = std::fs::read_dir(&fetched)
        .expect("the FHIR packages' provenance is committed")
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.is_dir())
        .collect();
    pinned.sort();
    for dir in pinned {
        let tarball = dir.join("package.tgz");
        assert!(
            tarball.is_file(),
            "{} is missing: run scripts/vendor/fhir-packages.sh",
            tarball.display()
        );
        paths.push(tarball);
    }
    PackageSet::load(paths).expect("the package set loads with its closure complete")
}

/// Holds `bundle` to the Brands Bundle profile and returns what the
/// validator found wrong, empty when it conforms.
fn findings(validator: &Validator<'_, R4>, bundle: &Value) -> Vec<String> {
    let instance: FhirValue =
        serde_json::from_value(bundle.clone()).expect("the Bundle reads as a FHIR document");
    let report = validator
        .validate_against(&instance, BUNDLE_PROFILE)
        .expect("the profile and its dependencies resolve");
    let mut found: Vec<String> = report
        .issues()
        .iter()
        .filter(|_| !report.is_valid())
        .map(|issue| format!("{} {}", issue.expression, issue.message))
        .collect();
    found.extend(
        report
            .unevaluated()
            .iter()
            .map(|unevaluated| format!("unevaluated: {unevaluated:?}")),
    );
    found
}

/// Returns the Brands of the deployment `text` configures.
fn brands(text: &str) -> Result<Option<Brands>, Box<Error>> {
    let keys = Keys::new();
    let text = format!("[ferrosmart]\nissuer = {ISSUER:?}\n{text}");
    let settings = config(&text, &keys).resolve().map_err(Box::new)?;
    Ok(settings.brand)
}

#[test]
fn the_ig_example_bundles_hold_to_their_profile() {
    // NOTE: SMART App Launch 2.2.0, User-Access Brand Examples: the four examples
    // are the test vectors the package set and the validator are read against.
    let set = package_set();
    let validator = Validator::new(&set);
    let examples = workspace().join("docs/specs/smart-app-launch/package/example");
    for name in [
        "Bundle-example1.json",
        "Bundle-example2.json",
        "Bundle-example3.json",
        "Bundle-example4.json",
    ] {
        let text = std::fs::read_to_string(examples.join(name)).expect("the example reads");
        let bundle: Value = serde_json::from_str(&text).expect("the example is JSON");
        assert_eq!(
            Vec::<String>::new(),
            findings(&validator, &bundle),
            "{name}"
        );
    }
}

#[test]
fn the_bundle_built_from_configuration_holds_to_the_smart_profiles() {
    let set = package_set();
    let validator = Validator::new(&set);
    let brands = brands(BRAND).expect("resolves").expect("a brand");
    let bundle = brands.bundle(CHANGED);
    assert_eq!(Vec::<String>::new(), findings(&validator, &bundle));
}

#[test]
fn the_primary_brand_references_every_endpoint_and_the_affiliate_is_part_of_it() {
    // NOTE: SMART App Launch 2.2.0, Brands, Conformance Overview: a primary brand
    // SHALL reference each FHIR endpoint; the hierarchy is a SHOULD.
    let bundle = brands(BRAND)
        .expect("resolves")
        .expect("a brand")
        .bundle(CHANGED);
    assert_eq!(json!("collection"), bundle["type"]);
    assert_eq!(json!(CHANGED), bundle["timestamp"]);
    assert_eq!(json!(CHANGED), bundle["meta"]["lastUpdated"]);
    let primary = &bundle["entry"][0];
    assert_eq!(
        json!("https://smart.example.org/brands/Organization/brand"),
        primary["fullUrl"]
    );
    assert_eq!(
        json!([{ "reference": "Endpoint/endpoint-1" }, { "reference": "Endpoint/endpoint-2" }]),
        primary["resource"]["endpoint"]
    );
    let affiliate = &bundle["entry"][1]["resource"];
    assert_eq!(
        json!({ "reference": "Organization/brand" }),
        affiliate["partOf"]
    );
    assert_eq!(
        json!([{ "reference": "Endpoint/endpoint-1" }]),
        affiliate["endpoint"]
    );
    let endpoints: Vec<&Value> = bundle["entry"]
        .as_array()
        .expect("entries")
        .iter()
        .filter(|entry| entry["resource"]["resourceType"] == json!("Endpoint"))
        .collect();
    assert_eq!(2, endpoints.len(), "the openEHR server is no FHIR endpoint");
    assert_eq!(
        json!("https://fhir.example.org/r4"),
        endpoints[0]["resource"]["address"]
    );
}

#[test]
fn the_national_lab_example_is_written_by_configuration() {
    // NOTE: SMART App Launch 2.2.0, User-Access Brand Examples, example1: the
    // configuration writes the national lab's brand and endpoint as published.
    let examples = workspace().join("docs/specs/smart-app-launch/package/example");
    let text = std::fs::read_to_string(examples.join("Bundle-example1.json")).expect("reads");
    let published: Value = serde_json::from_str(&text).expect("JSON");
    let logo = |fill: &str| {
        format!(
            "data:image/svg+xml;utf8,<svg%20xmlns='http://www.w3.org/2000/svg'%20width='1024'%20height='1024'><path%20d='M0%200h1024v1024H0z'%20style='fill:%23{fill}'/><text%20x='40'%20y='170'%20style='font-size:150px'>1024x1024</text></svg>"
        )
    };
    let lab = format!(
        r#"
[[ferrosmart.resource]]
base = "https://fhir.labs.example.com/r4"
[ferrosmart.brand]
name = "ExampleLabs"
website = "https://labs.example.com"
identifier = [{{ system = "urn:ietf:rfc:3986", value = "https://examplelabs.org" }}]
alias = ["ExampleLabs Alaska", "...(more here)...", "ExampleLabs Wisconsin"]
category = ["laboratory"]
logo = {:?}
address = [
  {{ line = ["4015 Lake Otis Pkwy"], city = "Anchorage", state = "AK", postal_code = "99508", country = "US" }},
  {{ state = "...(more here)...", country = "US" }},
  {{ line = ["123 Main St"], city = "Madison", state = "WI", postal_code = "53726", country = "US" }},
]
[[ferrosmart.brand.portal]]
name = "Example Labs HealthCentral Portal"
url = "https://healthcentral.labs.example.com"
logo = {:?}
endpoints = ["https://fhir.labs.example.com/r4"]
[[ferrosmart.brand.endpoint]]
base = "https://fhir.labs.example.com/r4"
name = "FHIR R4 Endpoint for ExampleLabs"
fhir_version = ["4.0.1"]
contact = ["https://dev-portal.labs.example.com"]
"#,
        logo("eee"),
        logo("666")
    );
    let written = brands(&lab)
        .expect("resolves")
        .expect("a brand")
        .bundle(CHANGED);
    // The example's ids, its narrative-free resources and the display of a
    // reference are the publisher's; the rest is what the configuration wrote.
    let normalise = |value: &Value| {
        let text = value
            .to_string()
            .replace("Endpoint/examplelabs", "Endpoint/endpoint-1");
        let mut resource: Value = serde_json::from_str(&text).expect("JSON");
        without_display(&mut resource);
        if let Some(members) = resource.as_object_mut() {
            members.remove("id");
        }
        resource
    };
    for index in 0..2 {
        assert_eq!(
            normalise(&published["entry"][index]["resource"]),
            normalise(&written["entry"][index]["resource"]),
            "entry {index}"
        );
    }
}

/// Removes the `display` of every reference in `value`.
fn without_display(value: &mut Value) {
    match value {
        Value::Object(members) => {
            if members.contains_key("reference") {
                members.remove("display");
            }
            members.values_mut().for_each(without_display);
        }
        Value::Array(items) => items.iter_mut().for_each(without_display),
        _ => {}
    }
}

#[test]
fn a_brand_breaking_a_rule_is_refused() {
    let base = "[[ferrosmart.resource]]\nbase = \"https://fhir.example.org/r4\"\n\
                [[ferrosmart.resource]]\nbase = \"https://ehr.example.org/openehr\"\nkind = \"openehr\"\n";
    let endpoint = "[[ferrosmart.brand.endpoint]]\nbase = \"https://fhir.example.org/r4\"\n\
                    fhir_version = [\"4.0.1\"]\ncontact = [\"https://developer.example.org\"]\n";
    let brand = "[ferrosmart.brand]\nname = \"Example\"\nwebsite = \"https://example.org\"\n";
    let cases = [
        (brand.to_owned(), "names no `endpoint`"),
        (
            format!(
                "{}{endpoint}",
                brand.replace(
                    "website = \"https://example.org\"",
                    "website = \"http://example.org\"",
                )
            ),
            "a brand's `website` is no https URL",
        ),
        (
            format!("{brand}category = [\"hospital\"]\n{endpoint}"),
            "a `category` is no code of ValueSet/user-access-category",
        ),
        (
            format!("{brand}identifier = [{{ system = \"urn:ietf:rfc:3986\" }}]\n{endpoint}"),
            "an `identifier` names no `value`",
        ),
        (
            format!(
                "{brand}[[ferrosmart.brand.endpoint]]\nbase = \"https://ehr.example.org/openehr\"\n\
                 fhir_version = [\"4.0.1\"]\ncontact = [\"https://developer.example.org\"]\n"
            ),
            "an `endpoint` base is no FHIR `ferrosmart.resource` base",
        ),
        (
            format!(
                "{brand}{}",
                endpoint.replace("fhir_version = [\"4.0.1\"]\n", "")
            ),
            "an `endpoint` names no `fhir_version`",
        ),
        (
            format!(
                "{brand}{}",
                endpoint.replace("contact = [\"https://developer.example.org\"]\n", "")
            ),
            "an `endpoint` names no `contact`, or one is no https URL",
        ),
        (
            format!("{brand}{endpoint}{endpoint}"),
            "an `endpoint` base is listed twice",
        ),
        (
            format!(
                "{brand}{endpoint}[[ferrosmart.brand.portal]]\nendpoints = [\"https://fhir.example.org/other\"]\n"
            ),
            "a portal offers an endpoint no `ferrosmart.brand.endpoint` names",
        ),
        (
            format!(
                "{brand}identifier = [{{ value = \"example\" }}]\n{endpoint}[[ferrosmart.brand.affiliate]]\n\
                 name = \"Affiliate\"\nwebsite = \"https://affiliate.example.org\"\nidentifier = [{{ value = \"example\" }}]\n"
            ),
            "an `identifier` is given to two brands",
        ),
        (
            format!(
                "{brand}{endpoint}[[ferrosmart.brand.affiliate]]\nname = \"Affiliate\"\n\
                 website = \"https://affiliate.example.org\"\n[[ferrosmart.brand.affiliate.endpoint]]\n\
                 base = \"https://fhir.example.org/r4\"\nfhir_version = [\"4.0.1\"]\ncontact = [\"https://developer.example.org\"]\n"
            ),
            "an `affiliate` names no `endpoint` or `affiliate` of its own",
        ),
    ];
    for (text, rule) in cases {
        match brands(&format!("{base}{text}")).map_err(|error| *error) {
            Err(Error::Brand(error)) => assert_eq!(rule, error.rule(), "{text}"),
            other => panic!("{text} is refused with {rule}, not {other:?}"),
        }
    }
}

#[test]
fn an_unknown_key_of_the_brand_is_refused() {
    let text = format!(
        "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.brand]\nname = \"Example\"\nslogan = \"Health for all\"\n"
    );
    let loaded = ferrosmart::config::Config::from_sources(Some(&text), &BTreeMap::new());
    assert!(
        matches!(loaded, Err(Error::Load(_))),
        "deny_unknown_fields: {loaded:?}"
    );
}

/// Answers `GET /brands` with the `If-None-Match` header `matching`, if
/// any, on a server publishing `brands` when given.
async fn get_brands(
    brands: Option<&Brands>,
    matching: Option<&str>,
) -> (StatusCode, http::HeaderMap, String) {
    let keys = Keys::new();
    let text = format!("[ferrosmart]\nissuer = {ISSUER:?}");
    let settings = config(&text, &keys).resolve().expect("resolves");
    let store = Store::connect_lazy(&settings.database_url, 1).expect("the URL parses");
    let audit = audit(&settings);
    let mut state = AppState::new(settings, store, audit);
    if let Some(brands) = brands {
        state = state.with_brands(Published::new(brands, CHANGED));
    }
    let mut request = Request::get("/brands");
    if let Some(tag) = matching {
        request = request.header(header::IF_NONE_MATCH, tag);
    }
    let response = router(Arc::new(state))
        .oneshot(request.body(Body::empty()).expect("a request"))
        .await
        .expect("an answer");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("the body")
        .to_bytes();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// Returns the header `name` of `headers` as text.
fn header_text<'h>(headers: &'h http::HeaderMap, name: &header::HeaderName) -> Option<&'h str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

#[tokio::test]
async fn the_bundle_is_served_as_fhir_json_to_any_origin_with_a_weak_etag() {
    let brands = brands(BRAND).expect("resolves").expect("a brand");
    let (status, headers, body) = get_brands(Some(&brands), None).await;
    assert_eq!(StatusCode::OK, status);
    assert_eq!(
        Some("application/fhir+json"),
        header_text(&headers, &header::CONTENT_TYPE)
    );
    // NOTE: SMART App Launch 2.2.0, Brands, Managing CORS and Caching Brand
    // Bundles: CORS for every GET, and a weak ETag on every response.
    assert_eq!(
        Some("*"),
        header_text(&headers, &header::ACCESS_CONTROL_ALLOW_ORIGIN)
    );
    assert_eq!(
        Some("ETag"),
        header_text(&headers, &header::ACCESS_CONTROL_EXPOSE_HEADERS)
    );
    let etag = header_text(&headers, &header::ETAG).expect("an ETag");
    assert!(etag.starts_with("W/\""), "{etag}");
    let bundle: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(brands.bundle(CHANGED), bundle);
}

#[tokio::test]
async fn a_request_naming_the_etag_is_answered_not_modified() {
    // NOTE: SMART App Launch 2.2.0, Brands, Caching Brand Bundles, and RFC 9110
    // §13.1.2: If-None-Match compares weakly and a match answers 304.
    let brands = brands(BRAND).expect("resolves").expect("a brand");
    let (_, headers, _) = get_brands(Some(&brands), None).await;
    let etag = header_text(&headers, &header::ETAG)
        .expect("an ETag")
        .to_owned();
    let strong = etag.trim_start_matches("W/").to_owned();
    for tag in [etag.as_str(), strong.as_str(), "\"other\", W/\"x\", *"] {
        let (status, headers, body) = get_brands(Some(&brands), Some(tag)).await;
        assert_eq!(StatusCode::NOT_MODIFIED, status, "{tag}");
        assert!(body.is_empty(), "{tag}");
        assert_eq!(Some(etag.as_str()), header_text(&headers, &header::ETAG));
    }
    let (status, _, _) = get_brands(Some(&brands), Some("W/\"other\"")).await;
    assert_eq!(StatusCode::OK, status, "another tag gets the Bundle");
}

#[tokio::test]
async fn without_a_brand_the_route_is_absent() {
    let (status, _, _) = get_brands(None, None).await;
    assert_eq!(StatusCode::NOT_FOUND, status);
}

#[tokio::test]
async fn the_last_change_moves_only_when_the_contents_change() {
    // NOTE: SMART App Launch 2.2.0, Brands, Conformance Overview: Bundle.timestamp is
    // the timestamp of the last change to the contents, whatever restarts between.
    let database = Database::create().await;
    let store = Store::connect(&database.url, 2).await.expect("connects");
    let first = store.brands_changed("digest-1").await.expect("recorded");
    let again = store.brands_changed("digest-1").await.expect("recorded");
    assert_eq!(first, again, "the same contents keep their instant");
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let changed = store.brands_changed("digest-2").await.expect("recorded");
    assert!(
        changed > first,
        "new contents move it: {first} then {changed}"
    );
    database.drop(store).await;
}

#[test]
fn the_digest_follows_the_contents() {
    let one = brands(BRAND).expect("resolves").expect("a brand");
    let same = brands(BRAND).expect("resolves").expect("a brand");
    let other = brands(&BRAND.replace("Example Health\"", "Example Care\""))
        .expect("resolves")
        .expect("a brand");
    assert_eq!(one.digest(), same.digest());
    assert_ne!(one.digest(), other.digest());
}
