// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The issuer the SMART discovery document describes: never a `machines`
//! issuer, never one without metadata, the named one or the one eligible
//! issuer, and never the one the table order puts first.

use std::error::Error as StdError;

use ferrohealth_secret::secret_url::SecretUrl;
use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::metadata::ServerMetadata;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::described::Candidate;
use ferrohealth_smart::resource::described::DescribeError;
use ferrohealth_smart::resource::described::Metadata;
use ferrohealth_smart::resource::described::describe;
use jsonwebtoken::Algorithm;

use crate::support::ec_key;
use crate::support::temp_file;

const PERSONS: &str = "https://login.example.org";
const PATIENTS: &str = "https://patients.example.org";
const MACHINES: &str = "https://m2m.example.org";
const FEDERATION: &str = "https://partner.example.org";
const OFFLINE: &str = "https://offline.example.org";

/// Returns a candidate `issuer` of `kind` whose metadata is `metadata`,
/// carrying the issuer as its check.
fn candidate(issuer: &str, kind: IssuerKind, metadata: Metadata) -> Candidate<&str> {
    Candidate::new(issuer, kind, metadata, issuer)
}

/// Returns the issuers of a deployment with one eligible issuer among a
/// `machines` issuer and a `persons` issuer read from a `jwks_file` alone.
fn one_eligible() -> Vec<Candidate<&'static str>> {
    vec![
        candidate(MACHINES, IssuerKind::Machines, Metadata::Available),
        candidate(OFFLINE, IssuerKind::Persons, Metadata::Absent),
        candidate(PERSONS, IssuerKind::Persons, Metadata::Available),
    ]
}

#[test]
fn without_a_name_the_one_eligible_issuer_is_described() -> Result<(), DescribeError> {
    let described = describe(one_eligible(), None)?;
    assert_eq!(described.issuer(), PERSONS);
    assert_eq!(described.kind(), IssuerKind::Persons);
    assert_eq!(described.into_check(), PERSONS);
    Ok(())
}

#[test]
fn a_machines_issuer_written_first_is_never_described() -> Result<(), DescribeError> {
    let mut reversed = one_eligible();
    reversed.reverse();
    for candidates in [one_eligible(), reversed] {
        assert_eq!(describe(candidates, None)?.issuer(), PERSONS);
    }
    Ok(())
}

#[test]
fn every_kind_but_machines_is_eligible() {
    for (issuer, kind, eligible) in [
        (PERSONS, IssuerKind::Persons, true),
        (PATIENTS, IssuerKind::Patients, true),
        (FEDERATION, IssuerKind::Federation, true),
        (MACHINES, IssuerKind::Machines, false),
    ] {
        assert_eq!(
            candidate(issuer, kind, Metadata::Available).is_eligible(),
            eligible,
            "{kind:?}"
        );
        assert!(
            !candidate(issuer, kind, Metadata::Absent).is_eligible(),
            "an issuer without metadata is never eligible: {kind:?}"
        );
    }
}

#[test]
fn without_a_name_several_eligible_issuers_are_refused_in_sorted_order() {
    let written = vec![
        candidate(PERSONS, IssuerKind::Persons, Metadata::Available),
        candidate(MACHINES, IssuerKind::Machines, Metadata::Available),
        candidate(FEDERATION, IssuerKind::Federation, Metadata::Available),
        candidate(PATIENTS, IssuerKind::Patients, Metadata::Available),
    ];
    let mut reversed = written.clone();
    reversed.reverse();
    let sorted = vec![
        SecretUrl::new(PERSONS),
        SecretUrl::new(FEDERATION),
        SecretUrl::new(PATIENTS),
    ];
    for candidates in [written, reversed] {
        let refused = describe(candidates, None);
        let Err(DescribeError::SeveralEligible { issuers }) = &refused else {
            panic!("several eligible issuers are refused: {refused:?}");
        };
        assert_eq!(issuers, &sorted, "the table order never shows");
        let text = refused.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(text.contains("described_issuer"), "{text}");
        assert!(
            text.contains(&format!("{PERSONS}, {FEDERATION}, {PATIENTS}")),
            "{text}"
        );
        assert!(!text.contains(MACHINES), "{text}");
    }
}

#[test]
fn without_a_name_no_eligible_issuer_is_refused() {
    let machines_only = vec![
        candidate(MACHINES, IssuerKind::Machines, Metadata::Available),
        candidate(OFFLINE, IssuerKind::Persons, Metadata::Absent),
    ];
    for candidates in [machines_only, Vec::new()] {
        let refused = describe(candidates, None);
        assert!(
            matches!(refused, Err(DescribeError::NoneEligible)),
            "{refused:?}"
        );
    }
}

#[test]
fn a_named_eligible_issuer_is_described_among_several() -> Result<(), DescribeError> {
    let candidates = vec![
        candidate(PERSONS, IssuerKind::Persons, Metadata::Available),
        candidate(PATIENTS, IssuerKind::Patients, Metadata::Available),
        candidate(MACHINES, IssuerKind::Machines, Metadata::Available),
    ];
    let described = describe(candidates, Some(&SecretUrl::new(PATIENTS)))?;
    assert_eq!(described.issuer(), PATIENTS);
    assert_eq!(*described.check(), PATIENTS);
    Ok(())
}

#[test]
fn a_named_unknown_issuer_is_refused() {
    let refused = describe(one_eligible(), Some(&SecretUrl::new(PATIENTS)));
    let Err(DescribeError::UnknownIssuer { issuer }) = &refused else {
        panic!("an issuer no candidate is is refused: {refused:?}");
    };
    assert_eq!(issuer.expose(), PATIENTS);
}

#[test]
fn a_named_machines_issuer_is_refused() {
    let refused = describe(one_eligible(), Some(&SecretUrl::new(MACHINES)));
    let Err(DescribeError::MachinesIssuer { issuer }) = &refused else {
        panic!("a machines issuer is never described: {refused:?}");
    };
    assert_eq!(issuer.expose(), MACHINES);
}

#[test]
fn a_named_issuer_without_metadata_is_refused() {
    let refused = describe(one_eligible(), Some(&SecretUrl::new(OFFLINE)));
    let Err(DescribeError::NoMetadata { issuer }) = &refused else {
        panic!("an issuer without metadata is never described: {refused:?}");
    };
    assert_eq!(issuer.expose(), OFFLINE);
}

#[test]
fn a_named_issuer_renders_with_its_userinfo_masked() {
    let named = SecretUrl::new("https://user:synthetic-password@unknown.example.org");
    let refused = describe(one_eligible(), Some(&named));
    let error = refused.err();
    let shown = error.as_ref().map(ToString::to_string).unwrap_or_default();
    let debug = format!("{error:?}");
    assert!(shown.contains("unknown.example.org"), "{shown}");
    for text in [shown, debug] {
        assert!(!text.contains("synthetic-password"), "{text}");
        assert!(!text.contains("user:"), "{text}");
    }
}

#[test]
fn a_several_eligible_refusal_masks_every_userinfo() {
    let candidates = vec![
        candidate(
            "https://user:synthetic-password@a.example.org",
            IssuerKind::Persons,
            Metadata::Available,
        ),
        candidate(PATIENTS, IssuerKind::Patients, Metadata::Available),
    ];
    let error = describe(candidates, None).err();
    let shown = error.as_ref().map(ToString::to_string).unwrap_or_default();
    let debug = format!("{error:?}");
    assert!(shown.contains("a.example.org"), "{shown}");
    for text in [shown, debug] {
        assert!(!text.contains("synthetic-password"), "{text}");
    }
}

#[test]
fn the_section_carries_the_named_issuer_to_the_selector() -> Result<(), Box<dyn StdError>> {
    let text = format!(
        "described_issuer = \"{PATIENTS}\"\n\
         [[issuer]]\nissuer = \"{PERSONS}\"\nkind = \"persons\"\naudience = [\"a\"]\n\
         [[issuer]]\nissuer = \"{PATIENTS}\"\nkind = \"patients\"\naudience = [\"a\"]\n"
    );
    let section: AuthSection = toml::from_str(&text)?;
    let resolved = section.resolve()?;
    assert_eq!(
        resolved.described_issuer.as_ref().map(SecretUrl::expose),
        Some(PATIENTS)
    );
    let candidates = resolved.issuers.iter().map(|settings| {
        Candidate::new(
            settings.issuer.clone(),
            settings.kind,
            Metadata::Available,
            (),
        )
    });
    let described = describe(candidates, resolved.described_issuer.as_ref())?;
    assert_eq!(described.issuer(), PATIENTS);
    Ok(())
}

#[test]
fn a_section_without_the_key_names_no_issuer() -> Result<(), Box<dyn StdError>> {
    let section: AuthSection = toml::from_str("enabled = false\n")?;
    assert_eq!(section.described_issuer, None);
    assert_eq!(section.resolve()?.described_issuer, None);
    Ok(())
}

#[tokio::test]
async fn a_key_set_file_issuer_has_metadata_only_once_supplied() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let set = serde_json::json!({ "keys": [key.jwk.clone()] }).to_string();
    let path = temp_file("described-jwks.json", set.as_bytes());
    let mut settings = crate::support::persons(OFFLINE, "https://fhir.example.org");
    settings.jwks_file = Some(path.clone());
    let server = ResourceServer::discover(settings).await?;
    assert_eq!(server.metadata_state(), Metadata::Absent);
    let bare = Candidate::of_server(&server, ());
    assert_eq!(bare.issuer(), OFFLINE);
    assert_eq!(bare.kind(), IssuerKind::Persons);
    assert!(!bare.is_eligible());
    let server = server.with_metadata(ServerMetadata {
        issuer: String::from(OFFLINE),
        token_endpoint: Some(format!("{OFFLINE}/token")),
        authorization_endpoint: Some(format!("{OFFLINE}/authorize")),
        ..ServerMetadata::default()
    })?;
    assert_eq!(server.metadata_state(), Metadata::Available);
    assert!(Candidate::of_server(&server, ()).is_eligible());
    std::fs::remove_file(path)?;
    Ok(())
}

#[cfg(feature = "fetch")]
#[tokio::test]
async fn an_issuer_read_from_the_network_has_metadata() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = crate::support::Issuer::start(&[&key]).await;
    let server = ResourceServer::discover(issuer.settings()).await?;
    let candidate = Candidate::of_server(&server, ());
    assert_eq!(candidate.metadata(), Metadata::Available);
    assert_eq!(candidate.issuer(), issuer.uri());
    assert!(candidate.is_eligible());
    Ok(())
}

#[cfg(feature = "fetch")]
#[tokio::test]
async fn an_introspected_issuer_has_metadata() -> Result<(), Box<dyn StdError>> {
    use ferrohealth_smart::client::ClientCredentials;
    use ferrohealth_smart::client::Endpoint;
    use ferrohealth_smart::resource::introspection::IntrospectionAuth;
    use ferrohealth_smart::resource::introspection::IntrospectionSettings;
    use ferrohealth_smart::resource::introspection::Introspector;
    use secrecy::SecretString;

    let issuer = crate::support::Issuer::bare().await;
    issuer
        .mount_metadata("/.well-known/oauth-authorization-server")
        .await;
    let auth = IntrospectionAuth::Client(Box::new(ClientCredentials::new(
        Endpoint::Issuer(issuer.uri()),
        String::from("ferro-rs"),
        SecretString::from("synthetic-secret"),
    )));
    let settings = IntrospectionSettings::new(
        issuer.uri(),
        "https://fhir.example.org",
        auth,
        IssuerKind::Machines,
    );
    let introspector = Introspector::discover(settings).await?;
    let candidate = Candidate::of_introspector(&introspector, ());
    assert_eq!(candidate.metadata(), Metadata::Available);
    assert_eq!(candidate.kind(), IssuerKind::Machines);
    assert!(!candidate.is_eligible(), "a machines issuer never is");
    Ok(())
}
