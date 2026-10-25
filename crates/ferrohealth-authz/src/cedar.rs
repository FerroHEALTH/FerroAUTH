// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The embedded engine (feature `cedar`): policies in the Cedar language,
//! checked against a schema the product's [`Model`] declares.
//!
//! The schema is written from the model, so the entity types and actions the
//! policies may name are exactly the ones the product sends: the principal
//! `User` with its `roles`, its `scopes` and the subject attributes the model
//! names, one entity type per resource type with its attributes, and one
//! action per action id with the resource types it applies to and the
//! context attributes. Every attribute is a `String`; a subject or resource
//! attribute is optional, so a policy guards it with `has`, and a context
//! attribute is required. The operator's policies are parsed and validated
//! strictly against the schema when the engine is built and when it reloads,
//! so a set that does not validate never runs; a reload that fails keeps the
//! set in force. Cedar denies by default and a `forbid` overrides every
//! `permit` (Cedar language reference, "Authorization"). A policy that errors
//! during evaluation is skipped by Cedar and reported in the diagnostics; the
//! engine answers such an evaluation with [`AuthzError::Evaluation`], since a
//! skipped `forbid` would otherwise stop forbidding.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use cedar_policy::Authorizer;
use cedar_policy::Context;
use cedar_policy::Decision as CedarDecision;
use cedar_policy::Entities;
use cedar_policy::Entity;
use cedar_policy::EntityId;
use cedar_policy::EntityTypeName;
use cedar_policy::EntityUid;
use cedar_policy::PolicySet;
use cedar_policy::RestrictedExpression;
use cedar_policy::Schema;
use cedar_policy::ValidationMode;
use cedar_policy::Validator;

use crate::engine::AuthzError;
use crate::engine::PolicyEngine;
use crate::request::Combination;
use crate::request::Decision;
use crate::request::Request;

/// The entity type of the principal.
const PRINCIPAL: &str = "User";

/// The id every resource entity carries; a policy reads a resource by its
/// type and attributes (no specification governs the id: our own design).
const RESOURCE_ID: &str = "resource";

/// The words the Cedar grammar reserves, which no declared name may be.
const RESERVED: [&str; 9] = [
    "true", "false", "if", "then", "else", "in", "like", "has", "is",
];

/// What the product sends: the names the schema declares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Model {
    subject_attributes: BTreeSet<String>,
    resources: BTreeMap<String, BTreeSet<String>>,
    actions: BTreeMap<String, BTreeSet<String>>,
    context: BTreeSet<String>,
}

/// Why a [`Model`] is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ModelError {
    /// A name is not a Cedar identifier, or is a reserved word or one of
    /// `roles` and `scopes`, which the principal always carries.
    #[error("the {what} {name:?} is not a Cedar identifier the schema can declare")]
    Name {
        /// What the name names.
        what: &'static str,
        /// The name.
        name: String,
    },
    /// An action id is empty or carries a quote, a backslash or a byte
    /// outside visible ASCII and the space.
    #[error("the action id {id:?} cannot be declared")]
    Action {
        /// The id.
        id: String,
    },
    /// An action applies to a resource type the model does not declare.
    #[error("the action {id:?} applies to the undeclared resource type {resource_type:?}")]
    Unknown {
        /// The action.
        id: String,
        /// The resource type.
        resource_type: String,
    },
    /// The model declares no action, so no policy could permit anything.
    #[error("the model declares no action")]
    Empty,
}

impl Model {
    /// Returns an empty model.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns this model with the subject attribute `name`.
    #[must_use]
    pub fn subject_attribute(mut self, name: impl Into<String>) -> Self {
        self.subject_attributes.insert(name.into());
        self
    }

    /// Returns this model with the resource type `name` and its attributes.
    #[must_use]
    pub fn resource<I, S>(mut self, name: impl Into<String>, attributes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.resources
            .entry(name.into())
            .or_default()
            .extend(attributes.into_iter().map(Into::into));
        self
    }

    /// Returns this model with the action `id`, applying to `resource_types`.
    #[must_use]
    pub fn action<I, S>(mut self, id: impl Into<String>, resource_types: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.actions
            .entry(id.into())
            .or_default()
            .extend(resource_types.into_iter().map(Into::into));
        self
    }

    /// Returns this model with the context attribute `name`, which every
    /// request carries.
    #[must_use]
    pub fn context(mut self, name: impl Into<String>) -> Self {
        self.context.insert(name.into());
        self
    }

    /// Checks every name the model declares.
    ///
    /// # Errors
    ///
    /// The [`ModelError`] of the first name refused.
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.actions.is_empty() {
            return Err(ModelError::Empty);
        }
        for name in &self.subject_attributes {
            identifier("subject attribute", name)?;
            if name == "roles" || name == "scopes" {
                return Err(ModelError::Name {
                    what: "subject attribute",
                    name: name.clone(),
                });
            }
        }
        for name in &self.context {
            identifier("context attribute", name)?;
        }
        for (resource_type, attributes) in &self.resources {
            identifier("resource type", resource_type)?;
            if resource_type == PRINCIPAL {
                return Err(ModelError::Name {
                    what: "resource type",
                    name: resource_type.clone(),
                });
            }
            for name in attributes {
                identifier("resource attribute", name)?;
            }
        }
        for (id, applies) in &self.actions {
            let printable = !id.is_empty()
                && id.bytes().all(|byte| {
                    (byte.is_ascii_graphic() || byte == b' ') && byte != b'"' && byte != b'\\'
                });
            if !printable {
                return Err(ModelError::Action { id: id.clone() });
            }
            if let Some(unknown) = applies
                .iter()
                .find(|name| !self.resources.contains_key(*name))
            {
                return Err(ModelError::Unknown {
                    id: id.clone(),
                    resource_type: unknown.clone(),
                });
            }
        }
        Ok(())
    }

    /// The Cedar schema the model declares, in the human-readable schema
    /// format.
    #[must_use]
    pub fn schema_source(&self) -> String {
        let mut out: Vec<String> = Vec::new();
        let mut principal = vec![
            String::from("roles: Set<String>"),
            String::from("scopes: Set<String>"),
        ];
        principal.extend(
            self.subject_attributes
                .iter()
                .map(|name| format!("{name}?: String")),
        );
        out.push(format!(
            "entity {PRINCIPAL} {{ {} }};",
            principal.join(", ")
        ));
        for (resource_type, attributes) in &self.resources {
            let fields: Vec<String> = attributes
                .iter()
                .map(|name| format!("{name}?: String"))
                .collect();
            out.push(format!(
                "entity {resource_type} {{ {} }};",
                fields.join(", ")
            ));
        }
        let context: Vec<String> = self
            .context
            .iter()
            .map(|name| format!("{name}: String"))
            .collect();
        for (id, applies) in &self.actions {
            let resources: Vec<&str> = applies.iter().map(String::as_str).collect();
            out.push(format!(
                "action \"{id}\" appliesTo {{ principal: [{PRINCIPAL}], resource: [{}], context: {{ {} }} }};",
                resources.join(", "),
                context.join(", ")
            ));
        }
        out.push(String::new());
        out.join("\n")
    }
}

/// Refuses `name` unless it is a Cedar identifier and no reserved word.
fn identifier(what: &'static str, name: &str) -> Result<(), ModelError> {
    let mut chars = name.chars();
    let starts = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    let rest = chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if starts && rest && !RESERVED.contains(&name) && !name.starts_with("__cedar") {
        Ok(())
    } else {
        Err(ModelError::Name {
            what,
            name: name.to_owned(),
        })
    }
}

/// The embedded Cedar engine.
#[derive(Debug)]
pub struct CedarEngine {
    model: Model,
    schema: Arc<Schema>,
    policies: Arc<ArcSwap<PolicySet>>,
    authorizer: Authorizer,
}

impl CedarEngine {
    /// Returns the engine of `model` over the policies in `source`.
    ///
    /// # Errors
    ///
    /// [`AuthzError::Load`] when the model, its schema or the policies do
    /// not hold, the policies validated strictly against the schema.
    pub fn from_source(model: Model, source: &str) -> Result<Self, AuthzError> {
        let schema = Arc::new(schema_of(&model)?);
        let policies = validated(source, &schema)?;
        Ok(Self {
            model,
            schema,
            policies: Arc::new(ArcSwap::from_pointee(policies)),
            authorizer: Authorizer::new(),
        })
    }

    /// Returns the engine of `model` over every `*.cedar` file in
    /// `directory`, read again every `reload` when one is given; a reload
    /// that does not validate is logged and leaves the set in force.
    ///
    /// The reload runs on the Tokio runtime the caller is on.
    ///
    /// # Errors
    ///
    /// [`AuthzError::Load`] when the model, its schema or the policies do
    /// not hold, or the directory holds no policy file.
    pub fn from_directory(
        model: Model,
        directory: &Path,
        reload: Option<Duration>,
    ) -> Result<Self, AuthzError> {
        let schema = Arc::new(schema_of(&model)?);
        let policies = Arc::new(ArcSwap::from_pointee(read_directory(directory, &schema)?));
        if let Some(every) = reload.filter(|every| !every.is_zero()) {
            spawn_reload(
                directory.to_owned(),
                Arc::clone(&schema),
                Arc::clone(&policies),
                every,
            );
        }
        Ok(Self {
            model,
            schema,
            policies,
            authorizer: Authorizer::new(),
        })
    }

    /// Decides one combination.
    fn evaluate(
        &self,
        request: &Request<'_>,
        combination: &Combination<'_>,
    ) -> Result<(bool, Vec<String>), AuthzError> {
        let principal = principal(request, &self.model)?;
        let resource = resource(request.resource_type(), combination)?;
        let action = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Action").map_err(evaluation)?,
            EntityId::new(request.action()),
        );
        let principal_uid = principal.uid();
        let resource_uid = resource.uid();
        let entities = Entities::from_entities([principal, resource], Some(&self.schema))
            .map_err(evaluation)?;
        let context = Context::from_pairs(request.context().iter().map(|(name, value)| {
            (
                name.clone(),
                RestrictedExpression::new_string(value.clone()),
            )
        }))
        .map_err(evaluation)?;
        let cedar = cedar_policy::Request::new(
            principal_uid,
            action,
            resource_uid,
            context,
            Some(&self.schema),
        )
        .map_err(evaluation)?;
        let policies = self.policies.load();
        let response = self.authorizer.is_authorized(&cedar, &policies, &entities);
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(ToString::to_string)
            .collect();
        if !errors.is_empty() {
            return Err(AuthzError::Evaluation(errors.join("; ").into()));
        }
        let decided = response
            .diagnostics()
            .reason()
            .map(ToString::to_string)
            .collect();
        Ok((response.decision() == CedarDecision::Allow, decided))
    }
}

#[async_trait::async_trait]
impl PolicyEngine for CedarEngine {
    async fn decide(&self, request: &Request<'_>) -> Result<Decision, AuthzError> {
        let applies =
            self.model
                .actions
                .get(request.action())
                .ok_or_else(|| AuthzError::Undeclared {
                    what: "action",
                    name: request.action().to_owned(),
                })?;
        if !applies.contains(request.resource_type()) {
            return Err(AuthzError::Undeclared {
                what: "resource type",
                name: request.resource_type().to_owned(),
            });
        }
        let mut permitted = BTreeSet::new();
        for combination in request.combinations() {
            let (allow, policies) = self.evaluate(request, &combination)?;
            if !allow {
                return Ok(Decision::Deny { policies });
            }
            permitted.extend(policies);
        }
        Ok(Decision::Permit {
            policies: permitted.into_iter().collect(),
        })
    }
}

/// Wraps an evaluation failure.
fn evaluation(error: impl std::error::Error + Send + Sync + 'static) -> AuthzError {
    AuthzError::Evaluation(Box::new(error))
}

/// The schema of `model`.
fn schema_of(model: &Model) -> Result<Schema, AuthzError> {
    model
        .validate()
        .map_err(|error| AuthzError::Load(Box::new(error)))?;
    let (schema, _warnings) = Schema::from_cedarschema_str(&model.schema_source())
        .map_err(|error| AuthzError::Load(Box::new(error)))?;
    Ok(schema)
}

/// Parses `source` and validates it strictly against `schema`.
fn validated(source: &str, schema: &Schema) -> Result<PolicySet, AuthzError> {
    let policies =
        PolicySet::from_str(source).map_err(|error| AuthzError::Load(Box::new(error)))?;
    let result = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
    if result.validation_passed() {
        Ok(policies)
    } else {
        let errors: Vec<String> = result
            .validation_errors()
            .map(ToString::to_string)
            .collect();
        Err(AuthzError::Load(errors.join("; ").into()))
    }
}

/// Reads and validates every `*.cedar` file in `directory`, in file name
/// order.
fn read_directory(directory: &Path, schema: &Schema) -> Result<PolicySet, AuthzError> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(|error| AuthzError::Load(Box::new(error)))? {
        let path = entry
            .map_err(|error| AuthzError::Load(Box::new(error)))?
            .path();
        if path.extension().and_then(std::ffi::OsStr::to_str) == Some("cedar") {
            files.push(path);
        }
    }
    if files.is_empty() {
        return Err(AuthzError::Load(
            format!("no *.cedar file in {}", directory.display()).into(),
        ));
    }
    files.sort();
    let mut source = String::new();
    for path in files {
        source.push_str(
            &std::fs::read_to_string(&path).map_err(|error| AuthzError::Load(Box::new(error)))?,
        );
        source.push('\n');
    }
    validated(&source, schema)
}

/// Reads `directory` again every `every`, swapping in a set that validates.
fn spawn_reload(
    directory: PathBuf,
    schema: Arc<Schema>,
    policies: Arc<ArcSwap<PolicySet>>,
    every: Duration,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(every);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match read_directory(&directory, &schema) {
                Ok(next) => {
                    policies.store(Arc::new(next));
                    tracing::debug!("the Cedar policy set was reloaded");
                }
                Err(error) => {
                    tracing::warn!(error = %error, "a Cedar policy reload was refused; the set in force stays");
                }
            }
        }
    });
}

/// The principal entity of `request`'s subject.
fn principal(request: &Request<'_>, model: &Model) -> Result<Entity, AuthzError> {
    let subject = request.subject();
    let uid = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str(PRINCIPAL).map_err(evaluation)?,
        EntityId::new(subject.id()),
    );
    let mut attributes: HashMap<String, RestrictedExpression> = HashMap::new();
    attributes.insert(
        String::from("roles"),
        RestrictedExpression::new_set(
            subject
                .roles()
                .iter()
                .map(|role| RestrictedExpression::new_string(role.clone())),
        ),
    );
    attributes.insert(
        String::from("scopes"),
        RestrictedExpression::new_set(
            subject
                .scopes()
                .iter()
                .map(|scope| RestrictedExpression::new_string(scope.clone())),
        ),
    );
    for (name, value) in subject.attributes() {
        if model.subject_attributes.contains(name) {
            attributes.insert(
                name.clone(),
                RestrictedExpression::new_string(value.clone()),
            );
        }
    }
    Entity::new(uid, attributes, HashSet::new()).map_err(evaluation)
}

/// The resource entity of one combination.
fn resource(resource_type: &str, combination: &Combination<'_>) -> Result<Entity, AuthzError> {
    let uid = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str(resource_type).map_err(evaluation)?,
        EntityId::new(RESOURCE_ID),
    );
    let attributes: HashMap<String, RestrictedExpression> = combination
        .iter()
        .map(|(name, value)| {
            (
                (*name).to_owned(),
                RestrictedExpression::new_string((*value).to_owned()),
            )
        })
        .collect();
    Entity::new(uid, attributes, HashSet::new()).map_err(evaluation)
}
