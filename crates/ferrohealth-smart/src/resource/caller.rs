// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The identity one valid credential carries, and what it reaches: the
//! behaviour of [`Caller`], [`Compartment`] and [`Access`].

use crate::resource::Access;
use crate::resource::Caller;
use crate::resource::Compartment;
use crate::resource::PatientClaim;
use crate::resource::PersonContext;
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
    /// per-issuer policy this way; the crate reads one extension, the
    /// [`PatientClaim`] (no specification governs this: our own design).
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

    /// Returns whether the request may be the natural person's own access,
    /// the broad answer: erring toward the person is the safe direction.
    ///
    /// Regulation (EU) 2025/327 Art. 3(3) lets a Member State delay a
    /// person's access to newly registered data "until a health professional
    /// is able to properly communicate and explain" it. A product that
    /// withholds such data asks this question, and a request wrongly read as
    /// the person's is withheld from, which delays a read; one wrongly read
    /// as a professional's would show the person the data too early.
    ///
    /// A bearer token is read as the person's when its `scope` claim carries
    /// any `patient/` scope of the SMART on FHIR or the SMART on openEHR
    /// grammar, or the claim the deployment names in a [`PatientClaim`]
    /// extension, whatever `user/`
    /// or `system/` scope it carries beside them. A Basic caller never is.
    /// SMART names *what* a `patient/` scope reaches and not *who* asks
    /// (SMART App Launch 2.2.0, Scopes and Launch Context, §Patient-specific
    /// scopes), so reading it as the person's is no specification's rule:
    /// the owner's ruling of 2026-10-31 on FerroAUTH #171.
    #[must_use]
    pub fn acts_for_the_person(&self) -> bool {
        self.via == Via::Bearer
            && (self.grants_in("patient") || self.patient_claim_value().is_some())
    }

    /// Returns whether the request is the natural person's own access, the
    /// strict answer: erring toward the professional is the safe direction.
    ///
    /// Regulation (EU) 2025/327 Art. 5 has information the person inserts
    /// "clearly distinguishable as having been inserted by the natural
    /// person", who "shall not be able to directly alter" what health
    /// professionals inserted, and Art. 9(1) gives the person information on
    /// every access "through the health professional access service". A
    /// professional's request wrongly read as the person's would record a
    /// professional's write as the person's, lock professionals out of
    /// altering it, and leave their access out of the person's record of
    /// accesses, so this answer admits only a token that cannot be a
    /// professional's.
    ///
    /// A bearer token is the person's when its `scope` claim carries a
    /// `patient/` scope of either grammar and no `user/` or `system/` scope.
    /// The patient claim alone does not count, because a professional's
    /// token in a patient's context carries it too. A Basic caller never is
    /// (the owner's ruling of 2026-10-31 on FerroAUTH #171).
    #[must_use]
    pub fn is_the_person(&self) -> bool {
        self.via == Via::Bearer
            && self.grants_in("patient")
            && !self.grants_in("user")
            && !self.grants_in("system")
    }

    /// Returns the patient the request is bound to when
    /// [`Caller::acts_for_the_person`] holds, or `None` when it does not.
    ///
    /// The context carries what the token names: the `patient` launch
    /// context, the `ehrId` of the openEHR launch context, and the value of
    /// the deployment's patient claim, each `None` when absent.
    #[must_use]
    pub fn person(&self) -> Option<PersonContext<'_>> {
        self.acts_for_the_person().then(|| PersonContext {
            patient: self.patient(),
            ehr_id: self.ehr_id(),
            claim: self.patient_claim_value(),
        })
    }

    /// Returns the value of the deployment's patient claim, when it names
    /// one and the token carries it as a string that is not blank.
    fn patient_claim_value(&self) -> Option<&str> {
        self.extension::<PatientClaim>()
            .and_then(|claim| self.claim_text(claim.path()))
    }

    /// Returns whether a token of the `scope` claim names `context`, the
    /// `<context>/` prefix both SMART grammars share.
    fn grants_in(&self, context: &str) -> bool {
        self.scope.iter().any(|token| {
            token
                .strip_prefix(context)
                .is_some_and(|rest| rest.starts_with('/'))
        })
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
    use crate::resource::{Access, Caller, Compartment, PatientClaim, PatientClaimError, Via};
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

    /// A bearer caller of `scope` under a deployment whose patient claim is
    /// `patient_id`, carrying that claim when `claimed` names a value.
    fn bearer(scope: &str, claimed: Option<&str>) -> Caller {
        let mut claims = serde_json::Map::new();
        if let Some(value) = claimed {
            claims.insert(String::from("patient_id"), serde_json::json!(value));
        }
        Caller::new(
            String::from("sub-1"),
            None,
            scope,
            Some(String::from("123")),
            false,
        )
        .with_claims(claims)
        .with_extension(PatientClaim::new("patient_id").expect("a valid path"))
    }

    /// The token matrix of FerroAUTH #171, each with the broad answer
    /// (Art. 3(3)) and the strict answer (Art. 5, Art. 9) it must give.
    fn matrix() -> Vec<(&'static str, Caller, bool, bool)> {
        vec![
            (
                "a patient/ token",
                bearer("openid patient/Observation.rs", None),
                true,
                true,
            ),
            (
                "a patient-claim token",
                bearer("openid", Some("p-7")),
                true,
                false,
            ),
            (
                "a mixed patient/ and user/ token",
                bearer("patient/Observation.rs user/Practitioner.r", None),
                true,
                false,
            ),
            (
                "a mixed patient/ and system/ token",
                bearer("patient/*.rs system/Patient.r", None),
                true,
                false,
            ),
            (
                "a user/ token",
                bearer("user/Observation.rs", None),
                false,
                false,
            ),
            ("a system/ token", bearer("system/*.rs", None), false, false),
            (
                "a user/ token with the patient claim",
                bearer("user/Observation.rs", Some("p-7")),
                true,
                false,
            ),
            (
                "a Basic user",
                Caller::basic(String::from("etl"), "patient/Observation.rs"),
                false,
                false,
            ),
        ]
    }

    #[test]
    fn the_broad_answer_reads_any_patient_scope_or_the_patient_claim() {
        for (name, caller, broad, _) in matrix() {
            assert_eq!(broad, caller.acts_for_the_person(), "{name}");
            assert_eq!(broad, caller.person().is_some(), "{name}");
        }
    }

    #[test]
    fn the_strict_answer_reads_only_patient_scopes() {
        for (name, caller, _, strict) in matrix() {
            assert_eq!(strict, caller.is_the_person(), "{name}");
        }
    }

    #[test]
    fn the_strict_answer_implies_the_broad_one() {
        for (name, caller, _, _) in matrix() {
            assert!(
                !caller.is_the_person() || caller.acts_for_the_person(),
                "{name}"
            );
        }
    }

    #[cfg(feature = "openehr")]
    #[test]
    fn an_openehr_patient_scope_is_the_persons_too() {
        let alone = bearer("patient/composition-*.r patient/aql-*.s", None);
        assert!(alone.acts_for_the_person());
        assert!(alone.is_the_person());
        let mixed = bearer("patient/composition-*.r user/composition-*.r", None);
        assert!(mixed.acts_for_the_person());
        assert!(!mixed.is_the_person());
    }

    #[test]
    fn the_person_context_names_what_the_token_binds() {
        let mut claims = serde_json::Map::new();
        claims.insert(String::from("patient_id"), serde_json::json!("p-7"));
        claims.insert(String::from("ehrId"), serde_json::json!("ehr-9"));
        let caller = Caller::new(
            String::from("sub-1"),
            None,
            "patient/*.rs",
            Some(String::from("123")),
            false,
        )
        .with_claims(claims)
        .with_extension(PatientClaim::new("patient_id").expect("a valid path"));
        let person = caller.person().expect("a patient/ token is the person's");
        assert_eq!(Some("123"), person.patient);
        assert_eq!(Some("ehr-9"), person.ehr_id);
        assert_eq!(Some("p-7"), person.claim);
    }

    #[test]
    fn a_blank_or_absent_patient_claim_does_not_count() {
        assert!(!bearer("openid", None).acts_for_the_person(), "absent");
        assert!(!bearer("openid", Some("  ")).acts_for_the_person(), "blank");
        let unconfigured = Caller::new(String::from("sub-1"), None, "openid", None, false)
            .with_claims(serde_json::Map::from_iter([(
                String::from("patient_id"),
                serde_json::json!("p-7"),
            )]));
        assert!(
            !unconfigured.acts_for_the_person(),
            "a claim the deployment does not name"
        );
    }

    #[test]
    fn a_malformed_patient_claim_path_is_refused() {
        for path in ["", "person..patient_id", ".", "patient id"] {
            assert_eq!(Err(PatientClaimError), PatientClaim::new(path), "{path:?}");
        }
        assert_eq!(
            Ok("person.patient_id"),
            PatientClaim::new("person.patient_id")
                .as_ref()
                .map(PatientClaim::path)
        );
    }

    #[test]
    fn a_scope_that_only_starts_like_a_context_names_none() {
        assert!(!bearer("patients/Observation.rs", None).acts_for_the_person());
        assert!(bearer("patient/Observation.rs users/x", None).is_the_person());
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
