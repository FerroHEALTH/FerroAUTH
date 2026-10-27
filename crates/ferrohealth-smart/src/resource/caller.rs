// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The identity one valid credential carries, and what it reaches: the
//! behaviour of [`Caller`], [`Compartment`] and [`Access`].

use crate::resource::Access;
use crate::resource::Caller;
use crate::resource::Compartment;
use crate::resource::Via;
use crate::scope::Evaluator;
use crate::scope::Permission;
use crate::scope::Reach;
use crate::scope::Scopes;

impl Caller {
    /// Returns the caller of a token whose claims say so.
    ///
    /// `scope` is the space-delimited `scope` claim (RFC 6749 §3.3), and
    /// `scopeless` is whether the deployment grants the subject system-wide
    /// access when the token names no clinical scope.
    #[must_use]
    pub fn new(
        subject: String,
        client_id: Option<String>,
        scope: &str,
        patient: Option<String>,
        scopeless: bool,
    ) -> Self {
        Self {
            subject,
            client_id,
            scope: scope
                .split(' ')
                .filter(|token| !token.is_empty())
                .map(str::to_owned)
                .collect(),
            scopes: Scopes::parse(scope),
            patient,
            scopeless,
            via: Via::Bearer,
            issuer: None,
            claims: serde_json::Map::new(),
            roles: Vec::new(),
            cached: false,
            extensions: http::Extensions::new(),
        }
    }

    /// Returns the caller a Basic credential authenticates: the user-id as
    /// the subject, no client, and the space-delimited `scope` its
    /// configuration grants it, so the same check serves a Basic caller and
    /// a bearer caller (no specification governs this: our own design).
    #[must_use]
    pub fn basic(username: String, scope: &str) -> Self {
        let mut caller = Self::new(username, None, scope, None, false);
        caller.via = Via::Basic;
        caller
    }

    /// Returns this caller with `scopes` as its clinical scopes, read under
    /// a product's resource table.
    #[must_use]
    pub fn with_scopes(mut self, scopes: Scopes) -> Self {
        self.scopes = scopes;
        self
    }

    /// Returns this caller signed by `issuer`.
    #[must_use]
    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Returns this caller carrying `claims`.
    #[must_use]
    pub fn with_claims(mut self, claims: serde_json::Map<String, serde_json::Value>) -> Self {
        self.claims = claims;
        self
    }

    /// Returns this caller holding `roles`.
    #[must_use]
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Returns the roles the caller holds, as the token's claims or the Basic
    /// user's configuration spell them ([`crate::roles`]).
    #[must_use]
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    /// Returns whether the caller holds `role`, ignoring ASCII case.
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        crate::roles::holds(&self.roles, role)
    }

    /// Returns the string at the dotted claim `path` of the token, trimmed,
    /// or `None` when it is absent, not a string, or blank; a Basic caller
    /// carries no claim.
    #[must_use]
    pub fn claim_text(&self, path: &str) -> Option<&str> {
        crate::roles::claim_text(&self.claims, path)
    }

    /// Returns this caller carrying `value`, which a handler reads with
    /// [`Caller::extension`].
    ///
    /// A product's own [`Verifier`](crate::resource::Verifier) attaches its
    /// per-issuer policy this way; the crate reads no extension (no
    /// specification governs this: our own design).
    #[must_use]
    pub fn with_extension<T: Clone + Send + Sync + 'static>(mut self, value: T) -> Self {
        self.extensions.insert(value);
        self
    }

    /// Returns this caller carrying every value of `extensions` beside its
    /// own.
    pub(crate) fn with_extensions(mut self, extensions: http::Extensions) -> Self {
        self.extensions.extend(extensions);
        self
    }

    /// Returns this caller marked as admitted from the verified-credential
    /// cache, or not.
    #[must_use]
    pub const fn with_cached(mut self, cached: bool) -> Self {
        self.cached = cached;
        self
    }

    /// Returns the product's value of type `T`, when its resource server or
    /// verifier attached one.
    #[must_use]
    pub fn extension<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.extensions.get::<T>()
    }

    /// Returns whether the caller was admitted from a cache: a Basic
    /// credential from the verified-credential cache (`[auth.basic]
    /// cache_ttl_seconds`) without the key derivation, or a bearer token
    /// from a held introspection response without a call to the endpoint.
    ///
    /// A JWT bearer caller, and a credential checked on this request, are
    /// `false`, so a product that records each fresh authentication records
    /// it once per cache lifetime (no specification governs the cache: our
    /// own design).
    #[must_use]
    pub const fn cached(&self) -> bool {
        self.cached
    }

    /// Returns the Basic user-id when the caller authenticated with HTTP
    /// Basic (RFC 7617) and its user-id is one of `users`.
    ///
    /// A bearer caller never matches, whatever its subject, the scheme rule
    /// of `guard::Requirement::Client` (no specification governs the list:
    /// our own design).
    #[must_use]
    pub fn basic_user_in<S: AsRef<str>>(&self, users: &[S]) -> Option<&str> {
        (self.via == Via::Basic && users.iter().any(|user| user.as_ref() == self.subject))
            .then_some(self.subject.as_str())
    }

    /// Returns the `acr` claim, the authentication context class the
    /// authentication event satisfied (RFC 9068 §2.2.1; RFC 9470 §6).
    #[must_use]
    pub fn acr(&self) -> Option<&str> {
        self.claims.get("acr").and_then(serde_json::Value::as_str)
    }

    /// Returns the `auth_time` claim, when the authentication event took
    /// place, in seconds since the epoch (RFC 9068 §2.2.1; RFC 9470 §6).
    #[must_use]
    pub fn auth_time(&self) -> Option<i64> {
        self.claims
            .get("auth_time")
            .and_then(serde_json::Value::as_i64)
    }

    /// Returns the subject: the token's `sub` or the Basic user-id.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the token's client, when it names one.
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    /// Returns the `patient` launch context, when the token carries one.
    #[must_use]
    pub fn patient(&self) -> Option<&str> {
        self.patient.as_deref()
    }

    /// Returns the `ehrId` of the SMART on openEHR launch context, when the
    /// token carries it as a claim.
    ///
    /// The draft places it in the token response (`master07 §Context
    /// Selection`); reading it from an `ehrId` claim is the same convention
    /// as `patient` (no specification governs it: our own design).
    #[must_use]
    pub fn ehr_id(&self) -> Option<&str> {
        self.claims.get("ehrId").and_then(serde_json::Value::as_str)
    }

    /// Returns every token of the `scope` claim read under the SMART on
    /// openEHR grammar, a token outside it as [`SmartScope::Other`].
    ///
    /// [`SmartScope::Other`]: crate::openehr::smart_scopes::SmartScope::Other
    #[cfg(feature = "openehr")]
    #[must_use]
    pub fn openehr_scopes(&self) -> Vec<crate::openehr::smart_scopes::SmartScope> {
        self.scope
            .iter()
            .map(|token| crate::openehr::smart_scopes::SmartScope::parse(token))
            .collect()
    }

    /// Returns the scheme the credential arrived with.
    #[must_use]
    pub const fn via(&self) -> Via {
        self.via
    }

    /// Returns the issuer that signed the token, when one did.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Returns whether the subject is on the deployment's
    /// `scopeless_subjects` allowlist, which grants a token that carries no
    /// resource scope of either grammar system-wide access (no
    /// specification governs the allowlist: our own design).
    #[must_use]
    pub const fn scopeless(&self) -> bool {
        self.scopeless
    }

    /// Returns whether the allowlist admits this caller everywhere: its
    /// subject is on it and its token carries no resource scope.
    pub(crate) fn admitted_without_scope(&self) -> bool {
        self.scopeless && !self.carries_resource_scope()
    }

    /// Returns whether the token carries a resource scope: a SMART on FHIR
    /// clinical scope or, with the `openehr` feature, a SMART on openEHR
    /// resource scope, the two grammars coexisting in one `scope` claim.
    fn carries_resource_scope(&self) -> bool {
        #[cfg(feature = "openehr")]
        let openehr = self
            .openehr_scopes()
            .iter()
            .any(|scope| matches!(scope, crate::openehr::smart_scopes::SmartScope::Resource(_)));
        #[cfg(not(feature = "openehr"))]
        let openehr = false;
        openehr || !self.scopes.is_empty()
    }

    /// Returns whether the `scope` claim names `scope`, compared verbatim.
    ///
    /// This is how a product reads its own scope (an operator or admin
    /// scope) that is no SMART clinical scope.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.iter().any(|granted| granted == scope)
    }

    /// Returns every token of the `scope` claim, as granted.
    #[must_use]
    pub fn scope(&self) -> &[String] {
        &self.scope
    }

    /// Returns the clinical scopes the token grants.
    #[must_use]
    pub const fn scopes(&self) -> &Scopes {
        &self.scopes
    }

    /// Returns every claim of the token, for the product's own reading.
    #[must_use]
    pub const fn claims(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.claims
    }

    /// Returns the claim `name`, when the token carries it.
    #[must_use]
    pub fn claim(&self, name: &str) -> Option<&serde_json::Value> {
        self.claims.get(name)
    }

    /// Returns which data `permission` on `resource_type` reaches, or `None`
    /// when the token does not grant it.
    ///
    /// A token with no resource scope of either grammar reaches everything
    /// when its subject is on the deployment's allowlist and nothing
    /// otherwise. A `patient/`
    /// scope reaches the patient in the `patient` claim, and nothing when the
    /// token carries no such claim. A granular scope grants nothing here;
    /// [`Caller::reach_with`] evaluates it.
    #[must_use]
    pub fn reach(&self, permission: Permission, resource_type: &str) -> Option<Compartment> {
        self.reach_with(permission, resource_type, &|_constraint| false)
    }

    /// Returns which data `permission` on `resource_type` reaches, a
    /// granular scope admitted when `evaluate` says the resource satisfies
    /// its constraint.
    #[must_use]
    pub fn reach_with(
        &self,
        permission: Permission,
        resource_type: &str,
        evaluate: Evaluator<'_>,
    ) -> Option<Compartment> {
        if self.admitted_without_scope() {
            return Some(Compartment::Any);
        }
        match self
            .scopes
            .reach_with(permission, resource_type, evaluate)?
        {
            Reach::Any => Some(Compartment::Any),
            Reach::Patient => self.patient.clone().map(Compartment::Patient),
        }
    }
}

impl Compartment {
    /// Returns whether this compartment reaches the data of `patient`, the
    /// patient a resource belongs to, or `None` when the resource belongs to
    /// no patient.
    ///
    /// "If the app has any patient-level scopes, they will be scoped to
    /// Patient 123" (SMART App Launch 2.2.0, Scopes and Launch Context,
    /// §Launch context arrives with your `access_token`), so a patient
    /// compartment reaches only that patient's resources, and a resource of
    /// no patient is outside every patient's compartment.
    #[must_use]
    pub fn admits(&self, patient: Option<&str>) -> bool {
        match self {
            Self::Any => true,
            Self::Patient(launched) => patient == Some(launched.as_str()),
        }
    }
}

impl Access {
    /// Returns the caller, or `None` on an open surface.
    #[must_use]
    pub fn caller(&self) -> Option<&Caller> {
        match self {
            Self::Open => None,
            Self::Caller(caller) => Some(caller),
        }
    }

    /// Returns whether the caller's `scope` claim names `scope`; an open
    /// surface has no caller and so no scope.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.caller().is_some_and(|caller| caller.has_scope(scope))
    }

    /// Returns the product's value of type `T` on the caller, or `None` on
    /// an open surface or when none was attached.
    #[must_use]
    pub fn extension<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.caller().and_then(Caller::extension::<T>)
    }

    /// Returns the Basic user-id when the caller authenticated with HTTP
    /// Basic and its user-id is one of `users`; an open surface has no
    /// caller and matches none.
    #[must_use]
    pub fn basic_user_in<S: AsRef<str>>(&self, users: &[S]) -> Option<&str> {
        self.caller().and_then(|caller| caller.basic_user_in(users))
    }

    /// Returns the caller's roles; none on an open surface.
    #[must_use]
    pub fn roles(&self) -> &[String] {
        self.caller().map_or(&[], Caller::roles)
    }

    /// Returns the caller's claims, or `None` on an open surface.
    #[must_use]
    pub fn claims(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
        self.caller().map(Caller::claims)
    }

    /// Returns the `ehrId` of the caller's launch context, when the token
    /// carries one.
    #[must_use]
    pub fn ehr_id(&self) -> Option<&str> {
        self.caller().and_then(Caller::ehr_id)
    }

    /// Returns which data `permission` on `resource_type` reaches.
    #[must_use]
    pub fn reach(&self, permission: Permission, resource_type: &str) -> Option<Compartment> {
        match self {
            Self::Open => Some(Compartment::Any),
            Self::Caller(caller) => caller.reach(permission, resource_type),
        }
    }

    /// Returns which data `permission` on `resource_type` reaches, a
    /// granular scope evaluated by `evaluate`.
    #[must_use]
    pub fn reach_with(
        &self,
        permission: Permission,
        resource_type: &str,
        evaluate: Evaluator<'_>,
    ) -> Option<Compartment> {
        match self {
            Self::Open => Some(Compartment::Any),
            Self::Caller(caller) => caller.reach_with(permission, resource_type, evaluate),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::resource::{Access, Caller, Compartment, Via};
    use crate::scope::Permission;

    #[test]
    fn a_scopeless_token_reaches_everything_only_when_allowlisted() {
        let allowed = Caller::new(String::from("svc"), None, "openid", None, true);
        assert_eq!(
            Some(Compartment::Any),
            allowed.reach(Permission::Create, "Condition")
        );
        assert!(allowed.has_scope("openid"));
        assert!(!allowed.has_scope("open"));
        let other = Caller::new(String::from("svc"), None, "", None, false);
        assert_eq!(None, other.reach(Permission::Read, "Condition"));
        assert_eq!(other.scope(), Vec::<String>::new());
    }

    #[test]
    fn an_allowlisted_subject_with_scopes_gets_only_its_scopes() {
        let caller = Caller::new(String::from("svc"), None, "system/Condition.r", None, true);
        assert_eq!(None, caller.reach(Permission::Create, "Condition"));
        assert!(caller.scopeless(), "the getter reads the allowlist flag");
        assert!(!Caller::basic(String::from("etl"), "").scopeless());
    }

    #[cfg(feature = "openehr")]
    #[test]
    fn an_openehr_scope_makes_a_token_scoped_on_a_fhir_route_too() {
        let caller = Caller::new(
            String::from("svc"),
            None,
            "system/composition-*.r",
            None,
            true,
        );
        assert_eq!(
            None,
            caller.reach(Permission::Read, "Condition"),
            "the two grammars share one scope claim"
        );
    }

    #[test]
    fn a_patient_scope_without_a_patient_claim_reaches_nothing() {
        let without = Caller::new(String::from("app"), None, "patient/*.rs", None, false);
        assert_eq!(None, without.reach(Permission::Read, "Condition"));
        let with = Caller::new(
            String::from("app"),
            None,
            "patient/*.rs",
            Some(String::from("123")),
            false,
        );
        assert_eq!(
            Some(Compartment::Patient(String::from("123"))),
            with.reach(Permission::Read, "Condition")
        );
    }

    #[test]
    fn a_basic_user_matches_its_list_and_a_bearer_subject_never_does() {
        let basic = Caller::basic(String::from("scrape"), "");
        assert_eq!(Some("scrape"), basic.basic_user_in(&["feed", "scrape"]));
        assert_eq!(None, basic.basic_user_in(&["feed"]), "an unlisted user");
        let bearer = Caller::new(String::from("scrape"), None, "", None, false);
        assert_eq!(
            None,
            bearer.basic_user_in(&["scrape"]),
            "a bearer subject never passes for a Basic user-id"
        );
        assert_eq!(None, Access::Open.basic_user_in(&["scrape"]));
        assert_eq!(
            Some("scrape"),
            Access::Caller(std::sync::Arc::new(basic)).basic_user_in(&[String::from("scrape")])
        );
    }

    #[test]
    fn an_extension_rides_on_the_caller_and_equality_ignores_it() {
        #[derive(Debug, Clone, PartialEq)]
        struct Policy(&'static str);
        let plain = Caller::new(String::from("svc"), None, "", None, false);
        let extended = plain.clone().with_extension(Policy("issuer-a"));
        assert_eq!(Some(&Policy("issuer-a")), extended.extension::<Policy>());
        assert_eq!(None, plain.extension::<Policy>());
        assert_eq!(plain, extended, "equality ignores the extensions");
        let access = Access::Caller(std::sync::Arc::new(extended));
        assert_eq!(Some(&Policy("issuer-a")), access.extension::<Policy>());
        assert_eq!(None, Access::Open.extension::<Policy>());
        assert!(!plain.cached(), "a bearer caller is never from the cache");
    }

    #[test]
    fn acr_and_auth_time_are_read_from_the_claims() {
        let mut claims = serde_json::Map::new();
        claims.insert(String::from("acr"), serde_json::json!("urn:acr:high"));
        claims.insert(String::from("auth_time"), serde_json::json!(1_700_000_000));
        let caller = Caller::new(String::from("svc"), None, "", None, false).with_claims(claims);
        assert_eq!(Some("urn:acr:high"), caller.acr());
        assert_eq!(Some(1_700_000_000), caller.auth_time());
        let bare = Caller::new(String::from("svc"), None, "", None, false);
        assert_eq!(None, bare.acr());
        assert_eq!(None, bare.auth_time());
    }

    #[test]
    fn a_patient_compartment_admits_its_patient_alone() {
        let compartment = Compartment::Patient(String::from("123"));
        assert!(compartment.admits(Some("123")));
        assert!(!compartment.admits(Some("124")));
        assert!(!compartment.admits(None));
        assert!(Compartment::Any.admits(None));
    }

    #[test]
    fn a_basic_caller_carries_its_configured_scope() {
        let caller = Caller::basic(String::from("alice"), "system/Condition.r");
        assert_eq!("alice", caller.subject());
        assert_eq!(None, caller.client_id());
        assert_eq!(Via::Basic, caller.via());
        assert_eq!(None, caller.issuer());
        assert_eq!(
            Some(Compartment::Any),
            caller.reach(Permission::Read, "Condition")
        );
        assert_eq!(None, caller.reach(Permission::Delete, "Condition"));
        let none = Caller::basic(String::from("bob"), "");
        assert_eq!(None, none.reach(Permission::Read, "Condition"));
    }
}
