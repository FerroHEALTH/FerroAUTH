// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The rules of one `[[auth.federation]]` table: how it is set over a
//! preset's defaults, the sources of its fields, and the checks it passes
//! before the issuer loads.

use std::collections::BTreeMap;

use crate::federation::FederationError;
use crate::federation::FederationSection;
use crate::federation::Field;
use crate::federation::Mapping;
use crate::federation::Source;

/// Returns `value` when it is not empty, else `default`.
fn or_default<T>(value: Vec<T>, default: Vec<T>) -> Vec<T> {
    if value.is_empty() { default } else { value }
}

impl FederationSection {
    /// Returns this table set over `defaults`, a preset's
    /// ([`crate::profile::Preset::federation`]): each key this table sets
    /// wins, each field's sources included, and a key it leaves unset or
    /// empty keeps the default. A `true` of either side holds.
    #[must_use]
    pub fn over(self, defaults: Self) -> Self {
        let mut fields = defaults.fields;
        fields.extend(self.fields);
        Self {
            issuer: if self.issuer.is_empty() {
                defaults.issuer
            } else {
                self.issuer
            },
            contact_point: self.contact_point.or(defaults.contact_point),
            mapping: self.mapping.or(defaults.mapping),
            fields,
            countries: or_default(self.countries, defaults.countries),
            issuing_authorities: or_default(self.issuing_authorities, defaults.issuing_authorities),
            provider_identifier_prefixes: or_default(
                self.provider_identifier_prefixes,
                defaults.provider_identifier_prefixes,
            ),
            attests_authorization_details: self.attests_authorization_details
                || defaults.attests_authorization_details,
            authorization_details_type: self
                .authorization_details_type
                .or(defaults.authorization_details_type),
            organisation_types: or_default(self.organisation_types, defaults.organisation_types),
            presentations_claim: self.presentations_claim.or(defaults.presentations_claim),
            user_credential_types: or_default(
                self.user_credential_types,
                defaults.user_credential_types,
            ),
            required_fields: or_default(self.required_fields, defaults.required_fields),
            requires_sender_constraint: self.requires_sender_constraint
                || defaults.requires_sender_constraint,
            exchanges_from: or_default(self.exchanges_from, defaults.exchanges_from),
            person_mapping: self.person_mapping.or(defaults.person_mapping),
        }
    }

    /// Returns the sources of every field: the mapping's, with the table's
    /// own over them.
    #[must_use]
    pub fn sources(&self) -> BTreeMap<Field, Vec<Source>> {
        Mapping::with_fields(self.mapping, &self.fields)
    }

    /// Checks the table: a declared `contact_point`, the countries, the
    /// domestic bounds (a contact point takes no provider prefixes), a source for every field and
    /// every required field, the attestation an `authorization_details`
    /// source needs, and the `country_code` and `issuing_authority_name` no
    /// mapping carries.
    ///
    /// # Errors
    ///
    /// The [`FederationError`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), FederationError> {
        match self.contact_point {
            None => {
                return Err(FederationError::Missing {
                    key: "contact_point",
                });
            }
            Some(true) if !self.provider_identifier_prefixes.is_empty() => {
                return Err(FederationError::ContactPointPrefixes);
            }
            Some(_) => {}
        }
        let contact_point = self.contact_point == Some(true);
        let bounds = [
            ("countries", self.countries.is_empty()),
            (
                "issuing_authorities",
                !contact_point && self.issuing_authorities.is_empty(),
            ),
            (
                "provider_identifier_prefixes",
                !contact_point && self.provider_identifier_prefixes.is_empty(),
            ),
        ];
        if let Some((key, _)) = bounds.iter().find(|(_, empty)| *empty) {
            return Err(FederationError::Missing { key });
        }
        let sources = self.sources();
        for (field, list) in &sources {
            if list.is_empty() {
                return Err(FederationError::NoSource {
                    field: field.as_str(),
                });
            }
        }
        if let Some(field) = self
            .required_fields
            .iter()
            .find(|field| !sources.contains_key(field))
        {
            return Err(FederationError::NoSource {
                field: field.as_str(),
            });
        }
        let all = || sources.values().flatten();
        if all().any(|source| matches!(source, Source::AuthorizationDetails(_)))
            && (!self.attests_authorization_details || self.authorization_details_type.is_none())
        {
            return Err(FederationError::Unattested);
        }
        if all().any(|source| matches!(source, Source::Presentation(_)))
            && self.presentations_claim.is_none()
        {
            return Err(FederationError::Presentations);
        }
        // NOTE: IHE IUA §3.71.4.2.2.1.1 and eHDSI SAML Profile 10.0.0 §2.3 carry no
        // country and no issuing authority, so such a table names a source for both.
        if self.mapping.is_some() || contact_point {
            for field in [
                Field::ProfessionalCountryCode,
                Field::ProfessionalIssuingAuthorityName,
            ] {
                if !sources.contains_key(&field) {
                    return Err(FederationError::NoSource {
                        field: field.as_str(),
                    });
                }
            }
        }
        Ok(())
    }
}
