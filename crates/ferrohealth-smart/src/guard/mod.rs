// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `tower` layer in front of every route of an `axum` router: the
//! credential check, the type-level scope check and the audit line.
//!
//! The product tells the layer what each route is ([`Classify`]): the
//! interaction it records, what it requires of the caller
//! ([`Requirement`]), which grammar that requirement is checked against
//! (SMART on FHIR or SMART on openEHR), the matched route template and the
//! name of what was addressed, which the audit line records as `addressed`.
//! A request without a valid credential answers `401`, one whose credential
//! grants no permission for the interaction `403` (RFC 6750 §3.1), and the
//! body of either is the product's ([`Render`]). What a scope reaches inside
//! a type (the patient compartment, the launch context's EHR) is checked by
//! the handler, which reads the [`Access`] the layer leaves on the request.

mod gate;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::time::Instant;

use axum::body::Body;
use axum::response::Response;
use http::Extensions;
use http::HeaderMap;
use http::HeaderName;
use http::Method;
use http::Request;
use http::Uri;
use http::request::Parts;
use tower::Layer;
use tower::Service;

use crate::audit::Actor;
use crate::audit::AuditLine;
use crate::basic::PasswordStore;
use crate::extract::HeaderOnly;
use crate::refusal::Refusal;
use crate::refusal::Schemes;
use crate::resource::Access;
use crate::resource::Caller;
use crate::resource::Honoured;
use crate::resource::Verifier;
use crate::resource::Via;
use crate::scope::Permission;

/// What a route requires of the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Requirement {
    /// No credential: a client reaches the route before it holds a token
    /// (the capability statement, the SMART discovery document).
    Public,
    /// A valid credential, whatever it grants.
    Caller,
    /// A valid credential granting `permission` on `resource_type` under the
    /// SMART on FHIR grammar (SMART App Launch 2.2.0, Scopes and Launch
    /// Context).
    Fhir {
        /// The permission the interaction needs.
        permission: Permission,
        /// The FHIR resource type the route addresses.
        resource_type: String,
    },
    /// A valid credential granting `permission` on a resource of `family`
    /// under the SMART on openEHR grammar (`master08 §Resource Scopes`);
    /// `resource` is the template id or query name the route addresses, or
    /// `None` for an operation only a bare `*` or `**` covers.
    #[cfg(feature = "openehr")]
    OpenEhr {
        /// The resource family the route addresses.
        family: openehr_sdt::smart_scopes::ResourceFamily,
        /// The permission the operation needs.
        permission: openehr_sdt::smart_scopes::Permission,
        /// The resource the route names, when the product can see it.
        resource: Option<String>,
    },
    /// A valid credential whose `scope` claim names this scope verbatim (a
    /// product's own operator or admin scope).
    Scope(String),
    /// A valid credential of a client the product lists: a bearer token's
    /// `client_id` in `client_ids`, or a Basic user-id in `basic_users`,
    /// each list matched only against its own scheme. This is how a surface
    /// no scope covers (the DEMOGRAPHIC API) is reached (no specification
    /// governs this: our own design).
    Client {
        /// The `client_id` values of the bearer clients admitted.
        client_ids: Vec<String>,
        /// The user-ids of the Basic principals admitted.
        basic_users: Vec<String>,
    },
    /// A valid credential whose caller holds this role, matched without
    /// regard to ASCII case ([`crate::roles`]).
    Role(String),
    /// A valid credential whose caller holds at least one role.
    AnyRole,
    /// A valid credential whose caller does not hold this role, matched
    /// without regard to ASCII case: a restriction, such as a read-only role
    /// on a write, which overrides every grant combined with it in
    /// [`Requirement::All`] (no specification governs role semantics: our
    /// own design).
    WithoutRole(String),
    /// Either requirement.
    Either(Box<Requirement>, Box<Requirement>),
    /// Every requirement; an empty list asks only for a valid credential.
    All(Vec<Requirement>),
    /// No caller is admitted: a route the product mounted without a
    /// classification fails closed.
    Refused,
}

impl Requirement {
    /// Returns the requirement that the caller authenticated with HTTP Basic
    /// as one of `users`, a [`Requirement::Client`] that lists no bearer
    /// client.
    #[must_use]
    pub fn basic_users<I, S>(users: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Client {
            client_ids: Vec::new(),
            basic_users: users.into_iter().map(Into::into).collect(),
        }
    }

    /// Returns whether `access` meets this requirement, `honoured` saying
    /// what the product honours for the caller beyond a `user/` grant.
    #[must_use]
    #[cfg_attr(
        not(feature = "openehr"),
        expect(
            clippy::only_used_in_recursion,
            reason = "`honoured` is read by the SMART on openEHR requirement alone"
        )
    )]
    pub fn met_by(&self, access: &Access, honoured: Honoured) -> bool {
        match self {
            Self::Public | Self::Caller => true,
            Self::Fhir {
                permission,
                resource_type,
            } => access.reach(*permission, resource_type).is_some(),
            #[cfg(feature = "openehr")]
            Self::OpenEhr {
                family,
                permission,
                resource,
            } => {
                access.caller().is_some_and(|caller| {
                    caller.admitted_without_scope()
                        || crate::openehr::granted(
                            &caller.openehr_scopes(),
                            *family,
                            *permission,
                            resource.as_deref(),
                            honoured,
                        )
                }) || matches!(access, Access::Open)
            }
            Self::Scope(scope) => access.has_scope(scope),
            Self::Client {
                client_ids,
                basic_users,
            } => access.caller().is_some_and(|caller| match caller.via() {
                Via::Bearer => caller
                    .client_id()
                    .is_some_and(|client| client_ids.iter().any(|listed| listed == client)),
                Via::Basic => basic_users.iter().any(|listed| listed == caller.subject()),
            }),
            Self::Role(role) => access.caller().is_some_and(|caller| caller.has_role(role)),
            Self::AnyRole => access
                .caller()
                .is_some_and(|caller| !caller.roles().is_empty()),
            Self::WithoutRole(role) => access.caller().is_some_and(|caller| !caller.has_role(role)),
            Self::Either(left, right) => {
                left.met_by(access, honoured) || right.met_by(access, honoured)
            }
            Self::All(requirements) => {
                access.caller().is_some()
                    && requirements
                        .iter()
                        .all(|requirement| requirement.met_by(access, honoured))
            }
            Self::Refused => false,
        }
    }
}

/// What the layer learned about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The interaction the audit line records.
    interaction: &'static str,
    /// What the route requires.
    requirement: Requirement,
    /// The matched route template the audit line records.
    route: Option<String>,
    /// The product's name for what was addressed, which the audit line
    /// records.
    addressed: Option<String>,
}

impl Target {
    /// Returns a target recorded as `interaction` with `requirement`.
    #[must_use]
    pub const fn new(interaction: &'static str, requirement: Requirement) -> Self {
        Self {
            interaction,
            requirement,
            route: None,
            addressed: None,
        }
    }

    /// Returns this target under the matched `route` template.
    #[must_use]
    pub fn route(mut self, route: impl Into<String>) -> Self {
        self.route = Some(route.into());
        self
    }

    /// Returns this target addressing `target`, the product's name for it
    /// (`Condition/c-1`, `ehr/…/composition`).
    #[must_use]
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.addressed = Some(target.into());
        self
    }

    /// Returns the interaction.
    #[must_use]
    pub const fn interaction(&self) -> &'static str {
        self.interaction
    }

    /// Returns the requirement.
    #[must_use]
    pub const fn requirement(&self) -> &Requirement {
        &self.requirement
    }

    /// Returns the matched route template.
    #[must_use]
    pub fn route_template(&self) -> Option<&str> {
        self.route.as_deref()
    }

    /// Returns the product's name for what was addressed.
    #[must_use]
    pub fn target_name(&self) -> Option<&str> {
        self.addressed.as_deref()
    }
}

/// How a product reads what a request is.
///
/// `None` is a route outside the guarded surface, which passes untouched
/// and writes no audit line.
pub trait Classify: Send + Sync + 'static {
    /// Returns what `method` on `uri` is, reading the router's extensions
    /// (the matched route template) when it needs them.
    fn classify(&self, method: &Method, uri: &Uri, extensions: &Extensions) -> Option<Target>;
}

impl<F> Classify for F
where
    F: Fn(&Method, &Uri, &Extensions) -> Option<Target> + Send + Sync + 'static,
{
    fn classify(&self, method: &Method, uri: &Uri, extensions: &Extensions) -> Option<Target> {
        self(method, uri, extensions)
    }
}

/// How a product answers a refusal: the body is its own, the status and the
/// `WWW-Authenticate` challenge are [`Refusal`]'s.
///
/// The renderer reads the refused request's parts, so a product negotiates
/// the body's format from them (the `Accept` header, a FHIR `_format`
/// parameter in the query) the way its handlers do.
pub trait Render: Send + Sync + 'static {
    /// Returns the response of `refusal` to the request `parts` head.
    fn render(&self, refusal: &Refusal, parts: &Parts) -> Response;
}

impl<F> Render for F
where
    F: Fn(&Refusal, &Parts) -> Response + Send + Sync + 'static,
{
    fn render(&self, refusal: &Refusal, parts: &Parts) -> Response {
        self(refusal, parts)
    }
}

/// The interaction a handler answered a request as, left on the response
/// when it differs from the classified one (one route serving two Bundle
/// types), which the audit line reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnsweredAs(pub &'static str);

/// The header a gate reads the credential from.
///
/// The default is `Authorization` (RFC 6750 §2.1). A product behind an edge
/// proxy that forwards the credential in a header of its own names that
/// header: schemed, carrying a scheme and a credential as `Authorization`
/// does (RFC 9110 §11.6.2), or bare, its whole value a bearer token. RFC
/// 9700 §4.13 has the proxy sanitize that header on every inbound request,
/// which is the deployment's duty once it names one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialHeader {
    /// The header's name.
    name: HeaderName,
    /// Whether the value is a bare bearer token with no scheme.
    bare: bool,
}

impl Default for CredentialHeader {
    fn default() -> Self {
        Self::authorization()
    }
}

impl CredentialHeader {
    /// Returns the `Authorization` header, the default.
    #[must_use]
    pub const fn authorization() -> Self {
        Self::schemed(http::header::AUTHORIZATION)
    }

    /// Returns the header `name`, carrying a scheme and a credential.
    #[must_use]
    pub const fn schemed(name: HeaderName) -> Self {
        Self { name, bare: false }
    }

    /// Returns the header `name`, whose whole value is a bearer token.
    #[must_use]
    pub const fn bare(name: HeaderName) -> Self {
        Self { name, bare: true }
    }

    /// Returns the header's name.
    #[must_use]
    pub const fn name(&self) -> &HeaderName {
        &self.name
    }

    /// Returns whether the value is a bare bearer token.
    #[must_use]
    pub const fn is_bare(&self) -> bool {
        self.bare
    }
}

/// What a product honours for a caller, read from its issuer or client
/// lists once the credential holds.
type Honours = Arc<dyn Fn(&Caller) -> Honoured + Send + Sync>;

/// The credentials a layer checks against: a verifier for bearer tokens,
/// the password store for Basic, or neither on an open surface.
#[derive(Clone)]
pub struct Gate {
    /// The verifier of bearer tokens, when they are admitted.
    bearer: Option<Arc<dyn Verifier>>,
    /// The password store, when Basic credentials are admitted.
    basic: Option<Arc<PasswordStore>>,
    /// The protection space the challenges name (RFC 6750 §3, RFC 7617 §2).
    realm: Option<String>,
    /// What the product honours for a caller.
    honours: Honours,
    /// The header the credential is read from.
    credential: CredentialHeader,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            bearer: None,
            basic: None,
            realm: None,
            honours: Arc::new(|_caller| Honoured::default()),
            credential: CredentialHeader::default(),
        }
    }
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gate")
            .field("bearer", &self.bearer.is_some())
            .field("basic", &self.basic)
            .field("realm", &self.realm)
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}

impl Gate {
    /// Returns the gate of a surface that authenticates no caller.
    #[must_use]
    pub fn open() -> Self {
        Self::default()
    }

    /// Returns this gate admitting the bearer tokens `verifier` checks.
    #[must_use]
    pub fn with_bearer(mut self, verifier: Arc<dyn Verifier>) -> Self {
        self.bearer = Some(verifier);
        self
    }

    /// Returns this gate admitting the Basic credentials `store` holds.
    #[must_use]
    pub fn with_basic(mut self, store: Arc<PasswordStore>) -> Self {
        self.basic = Some(store);
        self
    }

    /// Returns this gate naming `realm` on every challenge.
    #[must_use]
    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = Some(realm.into());
        self
    }

    /// Returns this gate reading what the product honours for a caller
    /// from `honours`: whether the caller is a listed backend client and
    /// whether its issuer is bound to the product's EHR space.
    #[must_use]
    pub fn with_honoured(
        mut self,
        honours: impl Fn(&Caller) -> Honoured + Send + Sync + 'static,
    ) -> Self {
        self.honours = Arc::new(honours);
        self
    }

    /// Returns this gate reading the credential from `header` in place of
    /// `Authorization`.
    ///
    /// The rules stay those of `Authorization`: one field, a bearer token in
    /// the `b64token` syntax, and the bearer challenge on every refusal. A
    /// bare header admits a bearer token alone; Basic is read from a
    /// schemed header only.
    #[must_use]
    pub fn with_credential_header(mut self, header: CredentialHeader) -> Self {
        self.credential = header;
        self
    }

    /// Returns the header the credential is read from.
    #[must_use]
    pub const fn credential_header(&self) -> &CredentialHeader {
        &self.credential
    }

    /// Returns whether the gate admits no credential at all.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.bearer.is_none() && self.basic.is_none()
    }

    /// Returns the schemes the gate admits.
    #[must_use]
    pub const fn schemes(&self) -> Schemes {
        Schemes {
            bearer: self.bearer.is_some(),
            basic: self.basic.is_some(),
        }
    }

    /// Returns the realm the challenges name.
    #[must_use]
    pub fn realm(&self) -> Option<&str> {
        self.realm.as_deref()
    }

    /// Returns what the product honours for `access`.
    #[must_use]
    pub fn honoured(&self, access: &Access) -> Honoured {
        access
            .caller()
            .map_or_else(Honoured::default, |caller| (self.honours)(caller))
    }
}

/// The layer that guards a router with a [`Gate`], classifying each request
/// with `C`.
pub struct AuthLayer<C> {
    /// The credentials admitted.
    gate: Arc<Gate>,
    /// What each request is.
    classify: Arc<C>,
    /// How a refusal is answered.
    render: Arc<dyn Render>,
    /// The header the audit line reads the request id from.
    request_id: HeaderName,
}

impl<C> Clone for AuthLayer<C> {
    fn clone(&self) -> Self {
        Self {
            gate: Arc::clone(&self.gate),
            classify: Arc::clone(&self.classify),
            render: Arc::clone(&self.render),
            request_id: self.request_id.clone(),
        }
    }
}

impl<C> std::fmt::Debug for AuthLayer<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthLayer")
            .field("gate", &self.gate)
            .field("request_id", &self.request_id)
            .finish_non_exhaustive()
    }
}

impl<C: Classify> AuthLayer<C> {
    /// Returns a layer over `gate`, classifying with `classify`.
    ///
    /// A refusal is answered with its status and challenge and no body
    /// ([`HeaderOnly`]) until [`AuthLayer::with_render`] names the product's
    /// body; the audit line reads the request id from `x-request-id`.
    #[must_use]
    pub fn new(gate: Gate, classify: C) -> Self {
        let render = match gate.realm() {
            Some(realm) => HeaderOnly::with_realm(realm),
            None => HeaderOnly::default(),
        };
        Self {
            gate: Arc::new(gate),
            classify: Arc::new(classify),
            render: Arc::new(render),
            request_id: HeaderName::from_static("x-request-id"),
        }
    }

    /// Returns this layer answering a refusal with `render`.
    #[must_use]
    pub fn with_render(mut self, render: impl Render) -> Self {
        self.render = Arc::new(render);
        self
    }

    /// Returns this layer reading the request id from `name`.
    #[must_use]
    pub fn with_request_id_header(mut self, name: HeaderName) -> Self {
        self.request_id = name;
        self
    }
}

impl<S, C> Layer<S> for AuthLayer<C> {
    type Service = AuthService<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            gate: Arc::clone(&self.gate),
            classify: Arc::clone(&self.classify),
            render: Arc::clone(&self.render),
            request_id: self.request_id.clone(),
        }
    }
}

/// The service [`AuthLayer`] wraps around `S`.
pub struct AuthService<S, C> {
    /// The guarded service.
    inner: S,
    /// The credentials admitted.
    gate: Arc<Gate>,
    /// What each request is.
    classify: Arc<C>,
    /// How a refusal is answered.
    render: Arc<dyn Render>,
    /// The header the audit line reads the request id from.
    request_id: HeaderName,
}

impl<S: Clone, C> Clone for AuthService<S, C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            gate: Arc::clone(&self.gate),
            classify: Arc::clone(&self.classify),
            render: Arc::clone(&self.render),
            request_id: self.request_id.clone(),
        }
    }
}

impl<S: std::fmt::Debug, C> std::fmt::Debug for AuthService<S, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthService")
            .field("inner", &self.inner)
            .field("gate", &self.gate)
            .finish_non_exhaustive()
    }
}

impl<S, C> Service<Request<Body>> for AuthService<S, C>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    C: Classify,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        // NOTE: tower's readiness contract, the service polled ready is the
        // one that takes the call, so the clone keeps the ready one.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let gate = Arc::clone(&self.gate);
        let classify = Arc::clone(&self.classify);
        let render = Arc::clone(&self.render);
        let request_id = self.request_id.clone();
        Box::pin(async move {
            let started = Instant::now();
            let at = jiff::Timestamp::now();
            let Some(target) =
                classify.classify(request.method(), request.uri(), request.extensions())
            else {
                return inner.call(request).await;
            };
            let method = request.method().clone();
            let request_id = request
                .headers()
                .get(&request_id)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let (mut parts, body) = request.into_parts();
            let (access, response) = match admit(&gate, &target, &parts.headers).await {
                Err((access, refusal)) => (access, render.render(&refusal, &parts)),
                Ok(access) => {
                    parts.extensions.insert(access.clone());
                    let request = Request::from_parts(parts, body);
                    (Some(access), inner.call(request).await?)
                }
            };
            let answered = response
                .extensions()
                .get::<AnsweredAs>()
                .map_or(target.interaction, |answered| answered.0);
            AuditLine::new(&method, answered, response.status())
                .timed(at, started.elapsed())
                .by(Actor::of(access.as_ref()))
                .on(target.route_template(), target.target_name())
                .request(request_id.as_deref())
                .write();
            Ok(response)
        })
    }
}

/// Returns the access of a request with `headers` to `target`, or the
/// refusal with the access it was refused under, so the audit line names a
/// caller whose credential held and whose grant did not.
///
/// A public target is admitted without a credential; a refused target is
/// refused before any credential is read.
async fn admit(
    gate: &Gate,
    target: &Target,
    headers: &HeaderMap,
) -> Result<Access, (Option<Access>, Refusal)> {
    match target.requirement() {
        Requirement::Refused => return Err((None, Refusal::Unclassified)),
        Requirement::Public => return Ok(Access::Open),
        _ => {}
    }
    let access = gate
        .authenticate(headers)
        .await
        .map_err(|denied| (None, denied.into_refusal()))?;
    let honoured = gate.honoured(&access);
    if gate.is_open() || target.requirement().met_by(&access, honoured) {
        Ok(access)
    } else {
        Err((Some(access), Refusal::Forbidden))
    }
}

#[cfg(test)]
mod tests {
    use super::{Requirement, Target};
    use crate::resource::{Access, Caller, Honoured};
    use crate::scope::Permission;
    use std::sync::Arc;

    fn access(scope: &str) -> Access {
        Access::Caller(Arc::new(Caller::new(
            String::from("sub"),
            Some(String::from("client-1")),
            scope,
            None,
            false,
        )))
    }

    fn fhir(permission: Permission) -> Requirement {
        Requirement::Fhir {
            permission,
            resource_type: String::from("Condition"),
        }
    }

    #[test]
    fn a_requirement_reads_the_permission_the_scope_the_client_or_either() {
        let none = Honoured::default();
        let read = fhir(Permission::Read);
        assert!(read.met_by(&access("system/Condition.r"), none));
        assert!(!read.met_by(&access("system/Condition.c"), none));
        let operator = Requirement::Scope(String::from("__operator"));
        assert!(operator.met_by(&access("__operator"), none));
        assert!(!operator.met_by(&access("system/*.cruds"), none));
        let either = Requirement::Either(Box::new(read), Box::new(operator));
        assert!(either.met_by(&access("__operator"), none));
        assert!(either.met_by(&access("system/Condition.r"), none));
        assert!(!either.met_by(&access("system/Condition.c"), none));
        let client = clients(&["client-1"], &[]);
        assert!(client.met_by(&access(""), none));
        assert!(!clients(&["other"], &[]).met_by(&access(""), none));
        assert!(
            !client.met_by(&Access::Open, none),
            "an open surface names no client"
        );
        assert!(!Requirement::Refused.met_by(&Access::Open, none));
        assert!(Requirement::Caller.met_by(&access(""), none));
    }

    fn holding(roles: &[&str]) -> Access {
        Access::Caller(Arc::new(
            Caller::new(String::from("sub"), None, "", None, false)
                .with_roles(roles.iter().map(|role| (*role).to_owned()).collect()),
        ))
    }

    #[test]
    fn role_requirements_judge_the_roles_the_caller_holds() {
        let none = Honoured::default();
        let admin = Requirement::Role(String::from("ADMIN"));
        assert!(admin.met_by(&holding(&["admin"]), none));
        assert!(!admin.met_by(&holding(&["clinician"]), none));
        assert!(
            !admin.met_by(&Access::Open, none),
            "an open surface holds no role"
        );
        assert!(Requirement::AnyRole.met_by(&holding(&["clinician"]), none));
        assert!(!Requirement::AnyRole.met_by(&holding(&[]), none));
        let write = Requirement::All(vec![
            Requirement::AnyRole,
            Requirement::WithoutRole(String::from("READONLY")),
        ]);
        assert!(write.met_by(&holding(&["clinician"]), none));
        assert!(
            !write.met_by(&holding(&["clinician", "readonly"]), none),
            "a restriction overrides a grant"
        );
        assert!(!write.met_by(&holding(&[]), none));
        assert!(Requirement::All(Vec::new()).met_by(&holding(&[]), none));
        assert!(!Requirement::All(Vec::new()).met_by(&Access::Open, none));
    }

    fn clients(client_ids: &[&str], basic_users: &[&str]) -> Requirement {
        Requirement::Client {
            client_ids: client_ids.iter().map(|id| (*id).to_owned()).collect(),
            basic_users: basic_users.iter().map(|user| (*user).to_owned()).collect(),
        }
    }

    fn basic(user: &str) -> Access {
        Access::Caller(Arc::new(Caller::basic(String::from(user), "")))
    }

    #[test]
    fn a_client_requirement_matches_each_list_against_its_own_scheme() {
        let none = Honoured::default();
        let demographic = clients(&["client-1"], &["etl"]);
        assert!(
            demographic.met_by(&basic("etl"), none),
            "a listed Basic user"
        );
        assert!(demographic.met_by(&access(""), none), "a listed client");
        assert!(
            !demographic.met_by(&basic("mallory"), none),
            "an unlisted Basic user"
        );
        assert!(
            !demographic.met_by(&basic("client-1"), none),
            "a Basic user-id never passes for a client id"
        );
        let by_basic_name = clients(&[], &["sub"]);
        assert!(
            !by_basic_name.met_by(&access(""), none),
            "a bearer subject never passes for a Basic user-id"
        );
    }

    #[cfg(feature = "openehr")]
    #[test]
    fn an_openehr_requirement_admits_an_allowlisted_caller_with_no_resource_scope() {
        use openehr_sdt::smart_scopes::{Permission, ResourceFamily};
        let none = Honoured::default();
        let read = Requirement::OpenEhr {
            family: ResourceFamily::Composition,
            permission: Permission::Read,
            resource: None,
        };
        let caller = |scope: &str, scopeless: bool| {
            Access::Caller(Arc::new(Caller::new(
                String::from("svc"),
                None,
                scope,
                None,
                scopeless,
            )))
        };
        assert!(read.met_by(&caller("openid", true), none), "allowlisted");
        assert!(!read.met_by(&caller("openid", false), none), "not listed");
        assert!(
            !read.met_by(&caller("system/template-*.r", true), none),
            "an openEHR scope: only its scopes"
        );
        assert!(
            !read.met_by(&caller("system/Observation.r", true), none),
            "a FHIR scope: only its scopes"
        );
        assert!(read.met_by(&caller("system/composition-*.r", false), none));
    }

    #[test]
    fn a_target_carries_what_the_path_names() {
        let target = Target::new("read", Requirement::Caller)
            .route("/fhir/{type}/{id}")
            .target("Condition/c-1");
        assert_eq!("read", target.interaction());
        assert_eq!(Some("/fhir/{type}/{id}"), target.route_template());
        assert_eq!(Some("Condition/c-1"), target.target_name());
        assert_eq!(&Requirement::Caller, target.requirement());
    }
}
