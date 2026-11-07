// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The reading of one `federation` token: its fields from their sources,
//! the attribute checks, the bounds, and the professional or organisation
//! it names.

use std::collections::BTreeMap;

use serde_json::Map;
use serde_json::Value;

use crate::assurance::AssuranceLevel;
use crate::federation::Attribute;
use crate::federation::Code;
use crate::federation::Context;
use crate::federation::External;
use crate::federation::FederationSection;
use crate::federation::Field;
use crate::federation::Outcome;
use crate::federation::REQUIRED;
use crate::federation::Source;
use crate::kind::Unclassified;
use crate::roles::lookup;

/// Returns what the verified `claims` of a `federation` token assert.
pub(crate) fn classify(
    claims: &Map<String, Value>,
    client: Option<&str>,
    context: &Context<'_>,
) -> Result<Outcome, Unclassified> {
    let section = context.section;
    let presentations = presentations(claims, section)?;
    let entry = attested_entry(claims, context)?;
    let mut fields = BTreeMap::new();
    for (field, sources) in section.sources() {
        let mut found: Option<Attribute> = None;
        for source in &sources {
            let value = match source {
                Source::Claim(path) => lookup(claims, path).and_then(attribute),
                Source::Constant(value) => Some(Attribute::Text(value.clone())),
                Source::AuthorizationDetails(path) => entry
                    .and_then(|entry| lookup(entry, path))
                    .and_then(attribute),
                Source::Presentation(path) => presentations
                    .credentials
                    .iter()
                    .find_map(|subject| lookup(subject, path))
                    .and_then(attribute),
            };
            match (&found, value) {
                (_, None) => {}
                (None, Some(value)) => found = Some(value),
                (Some(held), Some(value)) if *held == value => {}
                (Some(_), Some(_)) => {
                    return Err(Unclassified::SourcesDisagree {
                        field: field.as_str(),
                    });
                }
            }
        }
        if let Some(value) = found {
            check_attribute(field, &value)?;
            fields.insert(field, value);
        }
    }
    let subject = crate::roles::claim_text(claims, "sub").unwrap_or_default();
    let named = fields.keys().any(|field| field.professional());
    let professional = if presentations.present {
        presentations.user_authenticated
    } else {
        named || client != Some(subject)
    };
    let external = External {
        remote_subject: subject.to_owned(),
        fields,
    };
    check_bounds(&external, section)?;
    let missing: Vec<&'static str> = section
        .required_fields
        .iter()
        .filter(|field| external.field(**field).is_none())
        .map(|field| field.as_str())
        .collect();
    if !missing.is_empty() {
        return Err(Unclassified::RequiredFields { missing });
    }
    // NOTE: MyHealth@EU Requirements Catalogue 10.0.0 requirement 01 has country
    // B send the HP's information, so a contact point never admits an organisation.
    if section.contact_point == Some(true) {
        crate::federation::contact::check(&external, claims)?;
        return Ok(Outcome::Person(external));
    }
    if professional {
        check_professional(&external)?;
        check_level(&external, context)?;
        return Ok(Outcome::Person(external));
    }
    if presentations.present {
        return Ok(Outcome::Organisation(external));
    }
    let stated = entry.is_some_and(|entry| {
        entry
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|kind| {
                section
                    .organisation_types
                    .iter()
                    .any(|listed| listed == kind)
            })
    });
    if stated {
        Ok(Outcome::Organisation(external))
    } else {
        Err(Unclassified::NoOrganisationStatement)
    }
}

/// The credential subjects of a token's Verifiable Presentations.
#[derive(Default)]
struct Presentations {
    /// Whether the token carries the presentations claim at all.
    present: bool,
    /// Whether one credential is of a type the deployment declares
    /// user-authenticated.
    user_authenticated: bool,
    /// The credential subjects, in order.
    credentials: Vec<Map<String, Value>>,
}

/// Returns the credential subjects of the presentations claim.
fn presentations(
    claims: &Map<String, Value>,
    section: &FederationSection,
) -> Result<Presentations, Unclassified> {
    let Some(claim) = section.presentations_claim.as_deref() else {
        return Ok(Presentations::default());
    };
    let Some(value) = claims.get(claim) else {
        return Ok(Presentations::default());
    };
    let presentations: Vec<Value> = match value {
        Value::Array(items) => items.clone(),
        other => vec![other.clone()],
    };
    let mut read = Presentations {
        present: true,
        ..Presentations::default()
    };
    for presentation in presentations {
        let presentation = decoded(&presentation, "vp")?;
        let credentials = match presentation.get("verifiableCredential") {
            Some(Value::Array(items)) => items.clone(),
            Some(other) => vec![other.clone()],
            None => Vec::new(),
        };
        for credential in credentials {
            let credential = decoded(&credential, "vc")?;
            let types: Vec<&str> = match credential.get("type") {
                Some(Value::String(kind)) => vec![kind.as_str()],
                Some(Value::Array(kinds)) => kinds.iter().filter_map(Value::as_str).collect(),
                _ => Vec::new(),
            };
            if types.iter().any(|kind| {
                section
                    .user_credential_types
                    .iter()
                    .any(|listed| listed == kind)
            }) {
                read.user_authenticated = true;
            }
            if let Some(Value::Object(subject)) = credential.get("credentialSubject") {
                read.credentials.push(subject.clone());
            }
        }
    }
    Ok(read)
}

/// Returns a presentation or credential as an object: the object itself,
/// or the `member` of the payload of a JWT-encoded one.
///
/// The introspection endpoint verified the presentations it returns (Nuts
/// RFC021 §6), so a JWT form is read, not verified, here.
fn decoded(value: &Value, member: &str) -> Result<Map<String, Value>, Unclassified> {
    match value {
        Value::Object(object) => Ok(object.clone()),
        Value::String(jwt) => {
            let claims = jwt
                .split('.')
                .nth(1)
                .and_then(crate::jws::object)
                .ok_or(Unclassified::Presentations)?;
            match claims.get(member) {
                Some(Value::Object(object)) => Ok(object.clone()),
                _ => Err(Unclassified::Presentations),
            }
        }
        _ => Err(Unclassified::Presentations),
    }
}

/// Returns the `authorization_details` entry of the declared type, or of an
/// organisation type, that the issuer attests and whose `locations` names
/// this node; none when the token carries no such claim.
fn attested_entry<'a>(
    claims: &'a Map<String, Value>,
    context: &Context<'_>,
) -> Result<Option<&'a Map<String, Value>>, Unclassified> {
    let section = context.section;
    let Some(Value::Array(entries)) = claims.get("authorization_details") else {
        return Ok(None);
    };
    // NOTE: RFC 9396 §12: the parameter is "vulnerable to modifications by the
    // user", so it counts only from an issuer declared to attest it.
    if !section.attests_authorization_details {
        return Ok(None);
    }
    let declared = |kind: &str| {
        section.authorization_details_type.as_deref() == Some(kind)
            || section
                .organisation_types
                .iter()
                .any(|listed| listed == kind)
    };
    let mut typed = entries.iter().filter_map(Value::as_object).filter(|entry| {
        entry
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(declared)
    });
    let Some(entry) = typed.next() else {
        return Err(Unclassified::AuthorizationDetails);
    };
    // NOTE: RFC 9396 §12: `locations` is the audience restriction, compared as
    // exact strings with "no additional transformation or normalization".
    let here = entry
        .get("locations")
        .and_then(Value::as_array)
        .is_some_and(|locations| {
            locations.iter().filter_map(Value::as_str).any(|location| {
                context
                    .audiences
                    .iter()
                    .any(|audience| audience == location)
            })
        });
    if !here || typed.next().is_some() {
        return Err(Unclassified::AuthorizationDetails);
    }
    Ok(Some(entry))
}

/// Returns `value` as an attribute: a string or a number as text, an array
/// of FHIR Coding or of strings as codes.
fn attribute(value: &Value) -> Option<Attribute> {
    match value {
        Value::String(text) => Some(Attribute::Text(text.clone())),
        Value::Number(number) => Some(Attribute::Text(number.to_string())),
        Value::Array(items) => {
            let codes = items
                .iter()
                .filter_map(|item| match item {
                    Value::String(code) => Some(Code {
                        system: None,
                        code: code.clone(),
                    }),
                    Value::Object(coding) => {
                        coding.get("code").and_then(Value::as_str).map(|code| Code {
                            system: coding
                                .get("system")
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                            code: code.to_owned(),
                        })
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            (!codes.is_empty()).then_some(Attribute::Codes(codes))
        }
        _ => None,
    }
}

/// Refuses a value that holds a C0, C1 or bidi-control character, is longer
/// than the field's cap, or is coded where the field takes one string (no
/// specification governs the checks: our own design, against a value that
/// renders other than it reads).
fn check_attribute(field: Field, value: &Attribute) -> Result<(), Unclassified> {
    let refused = |text: &str| {
        text.chars().count() > field.cap()
            || text.chars().any(|c| {
                c.is_control()
                    || matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}')
                    || ('\u{202A}'..='\u{202E}').contains(&c)
                    || ('\u{2066}'..='\u{2069}').contains(&c)
            })
    };
    let coded = matches!(value, Attribute::Codes(_));
    if (coded && field.text_only()) || value.strings().into_iter().any(refused) {
        return Err(Unclassified::Attribute {
            field: field.as_str(),
        });
    }
    Ok(())
}

/// Refuses a country, an issuing authority or a provider identifier outside
/// the table's bounds, naming the field.
fn check_bounds(external: &External, section: &FederationSection) -> Result<(), Unclassified> {
    let checks = [
        (Field::ProfessionalCountryCode, Bound::Country),
        (Field::ProfessionalIssuingAuthorityName, Bound::Authority),
        (Field::ProviderIssuingAuthorityName, Bound::Authority),
        (
            Field::ProfessionalHealthcareProviderIdentifier,
            Bound::Prefix,
        ),
        (Field::ProviderHealthcareProviderIdentifier, Bound::Prefix),
    ];
    for (field, bound) in checks {
        let Some(value) = external.field(field).and_then(Attribute::text) else {
            continue;
        };
        let declared = match bound {
            Bound::Country => !section.countries.is_empty(),
            Bound::Authority => !section.issuing_authorities.is_empty(),
            Bound::Prefix => !section.provider_identifier_prefixes.is_empty(),
        };
        if !declared {
            continue;
        }
        let allowed = match bound {
            Bound::Country => section.countries.iter().any(|listed| listed == value),
            Bound::Authority => section
                .issuing_authorities
                .iter()
                .any(|listed| listed == value),
            Bound::Prefix => section
                .provider_identifier_prefixes
                .iter()
                .any(|prefix| value.starts_with(prefix.as_str())),
        };
        if !allowed {
            return Err(Unclassified::OutOfBounds {
                field: field.as_str(),
            });
        }
    }
    Ok(())
}

/// The bound one field is held to.
#[derive(Clone, Copy)]
enum Bound {
    /// The declared `countries`.
    Country,
    /// The declared `issuing_authorities`.
    Authority,
    /// The declared `provider_identifier_prefixes`.
    Prefix,
}

/// Refuses a professional that misses a required field, naming each.
fn check_professional(external: &External) -> Result<(), Unclassified> {
    let has = |field| external.field(field).is_some();
    let mut missing = Vec::new();
    if !(has(Field::ProfessionalName)
        || has(Field::ProfessionalFamilyName) && has(Field::ProfessionalGivenName))
    {
        missing.push(Field::ProfessionalName.as_str());
    }
    missing.extend(
        REQUIRED
            .iter()
            .filter(|field| !has(**field))
            .map(|field| field.as_str()),
    );
    if missing.is_empty() {
        Ok(())
    } else {
        Err(Unclassified::ExternalIncomplete { missing })
    }
}

/// The moment from which a professional's authentication must be at level
/// high, 26 March 2032 00:00 UTC: Commission Implementing Regulation (EU)
/// 2026/2099 Art. 6(3).
const HIGH_FROM: i64 = 1_963_872_000;

/// Refuses a professional below level substantial, or below level high from
/// 26 March 2032 (2026/2099 Art. 6(3) binds the contact points; holding a
/// domestic federation token to it is our own design).
fn check_level(external: &External, context: &Context<'_>) -> Result<(), Unclassified> {
    let level = match external.field(Field::Assurance).and_then(Attribute::text) {
        Some(value) => context.levels.and_then(|levels| levels.get(value).copied()),
        None => context.level,
    };
    let minimum = if jiff::Timestamp::now().as_second() >= HIGH_FROM {
        AssuranceLevel::High
    } else {
        AssuranceLevel::Substantial
    };
    if level.is_some_and(|level| level >= minimum) {
        Ok(())
    } else {
        Err(Unclassified::AssuranceTooLow)
    }
}
