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
//! With a party binding ([`Gate::with_party`]) the layer looks each admitted
//! caller's login up and leaves the outcome on the caller; what it means is
//! the product's to answer, and a source that fails answers `503`.

mod gate;
mod layer;
mod requirement;

use std::sync::Arc;

use axum::response::Response;
use http::Extensions;
use http::HeaderName;
use http::Method;
use http::Uri;
use http::request::Parts;

use crate::basic::PasswordStore;
use crate::party::binding::PartyBinding;
use crate::refusal::Refusal;
use crate::refusal::Schemes;
use crate::resource::Access;
use crate::resource::Caller;
use crate::resource::Honoured;
use crate::resource::Verifier;
use crate::scope::Permission;
use crate::sender::proof::ProofCheck;

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
        family: crate::openehr::smart_scopes::ResourceFamily,
        /// The permission the operation needs.
        permission: crate::openehr::smart_scopes::Permission,
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
    /// The `DPoP` proof check, when `DPoP`-bound tokens are admitted.
    proof: Option<Arc<ProofCheck>>,
    /// The party binding every admitted caller is looked up in.
    party: Option<Arc<PartyBinding>>,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            bearer: None,
            basic: None,
            realm: None,
            honours: Arc::new(|_caller| Honoured::default()),
            credential: CredentialHeader::default(),
            proof: None,
            party: None,
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
            .field("proof", &self.proof)
            .field("party", &self.party)
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

    /// Returns this gate also admitting `DPoP`-bound tokens (RFC 9449 §7.1),
    /// each proof checked by `check` before the bearer verifier checks the
    /// token and its binding.
    #[must_use]
    pub fn with_dpop(mut self, check: Arc<ProofCheck>) -> Self {
        self.proof = Some(check);
        self
    }

    /// Returns this gate looking every caller it admits up in `binding`,
    /// once per request, and leaving the outcome on the caller
    /// ([`Caller::party`]).
    #[must_use]
    pub fn with_party(mut self, binding: Arc<PartyBinding>) -> Self {
        self.party = Some(binding);
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
            dpop: self.bearer.is_some() && self.proof.is_some(),
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
