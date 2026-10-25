// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The request a policy enforcement point puts to a policy decision point,
//! and the decision it gets back.
//!
//! NIST SP 800-162 §2 frames an attribute-based decision as one over the
//! attributes of the subject (who asks), the object (what is touched), the
//! operation and the environment. A [`Request`] carries them: the
//! [`Subject`] that `ferrohealth-smart` authenticated, an action, a resource
//! type with its attributes, and context attributes. A resource attribute may
//! be a set, when one operation touches several objects (a query's result, a
//! batch); the engine then decides every combination of one value per set,
//! and the request is permitted only when every combination is, the first
//! deny ending the evaluation (no specification governs the fan-out: our own
//! design).

use std::collections::BTreeMap;

use ferrohealth_smart::resource::Caller;

/// Who asks: the authenticated subject and the attributes a policy reads
/// about them.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Subject {
    id: String,
    roles: Vec<String>,
    scopes: Vec<String>,
    attributes: BTreeMap<String, String>,
}

impl std::fmt::Debug for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subject")
            .field("id", &self.id)
            .field("roles", &self.roles)
            .field("attributes", &self.attributes.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Subject {
    /// Returns the subject `id` with no role, scope or attribute.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ..Self::default()
        }
    }

    /// Returns the subject `ferrohealth-smart` admitted: its subject id, its
    /// roles and its scopes, and one attribute per `(name, claim path)` pair
    /// whose claim holds a string ([`Caller::claim_text`]).
    #[must_use]
    pub fn of(caller: &Caller, claims: &[(&str, &str)]) -> Self {
        let attributes = claims
            .iter()
            .filter_map(|(name, path)| {
                caller
                    .claim_text(path)
                    .map(|value| ((*name).to_owned(), value.to_owned()))
            })
            .collect();
        Self {
            id: caller.subject().to_owned(),
            roles: caller.roles().to_vec(),
            scopes: caller.scope().to_vec(),
            attributes,
        }
    }

    /// Returns this subject holding `roles`.
    #[must_use]
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Returns this subject granted `scopes`.
    #[must_use]
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Returns this subject with the attribute `name` set to `value`.
    #[must_use]
    pub fn with_attribute(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(name.into(), value.into());
        self
    }

    /// The subject id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The roles.
    #[must_use]
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    /// The scopes.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// The attributes, by name.
    #[must_use]
    pub fn attributes(&self) -> &BTreeMap<String, String> {
        &self.attributes
    }
}

/// A resource attribute: one value, or the values of every object the
/// operation touches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attr {
    /// One value.
    One(String),
    /// Several values, never empty: the engine decides each.
    Set(Vec<String>),
}

/// Why a [`Request`] cannot be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RequestError {
    /// A set attribute holds no value, which would leave nothing to decide
    /// and permit the request without asking.
    #[error("the resource attribute {name} is an empty set")]
    EmptySet {
        /// The attribute.
        name: String,
    },
}

/// One request to a policy decision point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    subject: &'a Subject,
    action: String,
    resource_type: String,
    attributes: BTreeMap<String, Attr>,
    context: BTreeMap<String, String>,
}

/// One value per resource attribute: the object one evaluation decides.
pub type Combination<'a> = BTreeMap<&'a str, &'a str>;

impl<'a> Request<'a> {
    /// Returns the request of `subject` to perform `action` on a resource of
    /// `resource_type`.
    #[must_use]
    pub fn new(
        subject: &'a Subject,
        action: impl Into<String>,
        resource_type: impl Into<String>,
    ) -> Self {
        Self {
            subject,
            action: action.into(),
            resource_type: resource_type.into(),
            attributes: BTreeMap::new(),
            context: BTreeMap::new(),
        }
    }

    /// Returns this request with the resource attribute `name`.
    ///
    /// # Errors
    ///
    /// [`RequestError::EmptySet`] for a set with no value.
    pub fn with_attribute(
        mut self,
        name: impl Into<String>,
        value: Attr,
    ) -> Result<Self, RequestError> {
        let name = name.into();
        if matches!(&value, Attr::Set(values) if values.is_empty()) {
            return Err(RequestError::EmptySet { name });
        }
        self.attributes.insert(name, value);
        Ok(self)
    }

    /// Returns this request with the context attribute `name`, such as the
    /// operation the product serves.
    #[must_use]
    pub fn with_context(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(name.into(), value.into());
        self
    }

    /// The subject.
    #[must_use]
    pub fn subject(&self) -> &Subject {
        self.subject
    }

    /// The action.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    /// The resource type.
    #[must_use]
    pub fn resource_type(&self) -> &str {
        &self.resource_type
    }

    /// The resource attributes, by name.
    #[must_use]
    pub fn attributes(&self) -> &BTreeMap<String, Attr> {
        &self.attributes
    }

    /// The context attributes, by name.
    #[must_use]
    pub fn context(&self) -> &BTreeMap<String, String> {
        &self.context
    }

    /// Every combination of one value per resource attribute, in attribute
    /// name order; one empty combination when the request has no resource
    /// attribute.
    #[must_use]
    pub fn combinations(&self) -> Vec<Combination<'_>> {
        let mut out: Vec<Combination<'_>> = vec![BTreeMap::new()];
        for (name, attr) in &self.attributes {
            let values: Vec<&str> = match attr {
                Attr::One(value) => vec![value.as_str()],
                Attr::Set(values) => values.iter().map(String::as_str).collect(),
            };
            out = out
                .into_iter()
                .flat_map(|partial| {
                    values.iter().map(move |value| {
                        let mut next = partial.clone();
                        next.insert(name.as_str(), *value);
                        next
                    })
                })
                .collect();
        }
        out
    }
}

/// What the engine decided, with the policies that decided it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Every combination is permitted.
    Permit {
        /// The policies that permitted, as the engine names them.
        policies: Vec<String>,
    },
    /// A combination is denied.
    Deny {
        /// The policies that denied, as the engine names them; none when
        /// no policy permitted (a deny by default).
        policies: Vec<String>,
    },
}

impl Decision {
    /// Returns whether the request is permitted.
    #[must_use]
    pub const fn is_permit(&self) -> bool {
        matches!(self, Self::Permit { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_fan_out_as_the_cartesian_product() {
        let subject = Subject::new("dr-1");
        let request = Request::new(&subject, "read", "Composition")
            .with_attribute("patient", Attr::Set(vec!["p1".into(), "p2".into()]))
            .and_then(|r| r.with_attribute("template", Attr::Set(vec!["t1".into(), "t2".into()])))
            .and_then(|r| r.with_attribute("site", Attr::One("s".into())))
            .expect("a request");
        let combinations = request.combinations();
        assert_eq!(combinations.len(), 4);
        assert!(combinations.iter().all(|c| c.get("site") == Some(&"s")));
        assert_eq!(
            combinations.first().map(|c| (c["patient"], c["template"])),
            Some(("p1", "t1"))
        );
    }

    #[test]
    fn a_request_without_attributes_is_one_combination() {
        let subject = Subject::new("dr-1");
        let request = Request::new(&subject, "execute", "Query");
        assert_eq!(request.combinations(), vec![BTreeMap::new()]);
    }

    #[test]
    fn an_empty_set_is_refused() {
        let subject = Subject::new("dr-1");
        assert_eq!(
            Request::new(&subject, "read", "Composition")
                .with_attribute("patient", Attr::Set(Vec::new())),
            Err(RequestError::EmptySet {
                name: "patient".into()
            })
        );
    }

    #[test]
    fn the_subject_debug_shows_no_attribute_value_or_scope() {
        let subject = Subject::new("dr-1")
            .with_attribute("organization", "Qz7-hospital")
            .with_scopes(vec!["user/*.cruds".into()]);
        let shown = format!("{subject:?}");
        assert!(!shown.contains("Qz7-hospital"), "{shown}");
        assert!(!shown.contains("cruds"), "{shown}");
    }
}
