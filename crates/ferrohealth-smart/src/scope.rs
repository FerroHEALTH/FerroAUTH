// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The SMART App Launch 2.x clinical scopes an access token grants.
//!
//! A scope reads `<context>/<resource>.<permissions>`: the context is
//! `patient`, `user` or `system`, the resource a FHIR resource type or `*`,
//! and the permissions "a subset of the in-order string `.cruds`"
//! (SMART App Launch 2.2.0, Scopes and Launch Context, §Scopes for requesting
//! FHIR Resources). Every other scope token (`openid`, `launch/patient`,
//! `offline_access`, a product's own scope) grants no FHIR access
//! and is passed over here; [`crate::resource::Caller::has_scope`] reads
//! those.

/// One letter of the SMART v2 permission string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// `c`, the type-level `create` interaction.
    Create,
    /// `r`, the instance-level `read`, `vread` and `history` interactions.
    Read,
    /// `u`, the instance-level `update` and `patch` interactions.
    Update,
    /// `d`, the instance-level `delete` interaction.
    Delete,
    /// `s`, the type-level and system-level `search` and `history`
    /// interactions.
    Search,
}

impl Permission {
    /// The letters in the order the permission string requires.
    const ORDER: [(char, Self); 5] = [
        ('c', Self::Create),
        ('r', Self::Read),
        ('u', Self::Update),
        ('d', Self::Delete),
        ('s', Self::Search),
    ];

    /// Returns the letter of the permission string this permission is.
    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            Self::Create => 'c',
            Self::Read => 'r',
            Self::Update => 'u',
            Self::Delete => 'd',
            Self::Search => 's',
        }
    }

    /// Returns the bit this permission occupies in a [`Permissions`] set.
    const fn bit(self) -> u8 {
        match self {
            Self::Create => 1,
            Self::Read => 2,
            Self::Update => 4,
            Self::Delete => 8,
            Self::Search => 16,
        }
    }
}

/// A set of [`Permission`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Permissions(u8);

impl Permissions {
    /// Returns whether the set holds `permission`.
    const fn holds(self, permission: Permission) -> bool {
        self.0 & permission.bit() != 0
    }

    /// Returns the set a permission string names, or `None` when the string
    /// is no SMART permission string.
    ///
    /// The v1 suffixes `read`, `write` and `*` read as `rs`, `cud` and
    /// `cruds`: "servers SHOULD process v1 scopes with the following
    /// semantics in v2" (SMART App Launch 2.2.0, Scopes and Launch Context,
    /// §Scopes for requesting FHIR Resources).
    fn parse(text: &str) -> Option<Self> {
        let letters = match text {
            "read" => "rs",
            "write" => "cud",
            "*" => "cruds",
            letters => letters,
        };
        if letters.is_empty() {
            return None;
        }
        let mut bits = 0u8;
        let mut next = 0usize;
        for letter in letters.chars() {
            let offset = Permission::ORDER
                .iter()
                .skip(next)
                .position(|(candidate, _)| *candidate == letter)?;
            let position = next.checked_add(offset)?;
            let (_, permission) = Permission::ORDER.get(position)?;
            bits |= permission.bit();
            next = position.checked_add(1)?;
        }
        Some(Self(bits))
    }
}

/// The context a clinical scope is granted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Context {
    /// `patient/`: the data of the patient in the token's launch context.
    Patient,
    /// `user/`: the data the signed-in user may reach.
    User,
    /// `system/`: the data a backend service may reach.
    System,
}

/// How far one granted permission reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reach {
    /// Only the compartment of the patient in the launch context.
    Patient,
    /// Every resource of the type.
    Any,
}

/// The `?param=value&…` suffix of a granular scope (SMART App Launch 2.2.0,
/// Scopes and Launch Context, §Finer-grained resource constraints), parsed
/// as the pairs it names and nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constraint {
    /// The parameters, in the order written.
    params: Vec<(String, String)>,
}

impl Constraint {
    /// Returns the parameters, each a name and a value, in the order
    /// written.
    #[must_use]
    pub fn params(&self) -> &[(String, String)] {
        &self.params
    }

    /// Returns the constraint `suffix` names, or `None` when a pair has no
    /// `=` or an empty name.
    fn parse(suffix: &str) -> Option<Self> {
        let params = suffix
            .split('&')
            .map(|pair| {
                let (name, value) = pair.split_once('=')?;
                (!name.is_empty()).then(|| (name.to_owned(), value.to_owned()))
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self { params })
    }
}

/// An evaluator of a granular scope's constraint against the resource a
/// request addresses: `true` when the resource satisfies it.
pub type Evaluator<'a> = &'a dyn Fn(&Constraint) -> bool;

/// One clinical scope the token grants.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Grant {
    /// The context it was granted in.
    context: Context,
    /// The resource type, `None` for the `*` wildcard.
    resource_type: Option<String>,
    /// The interactions it permits.
    permissions: Permissions,
    /// The granular constraint, when the scope carries one.
    constraint: Option<Constraint>,
}

/// The clinical scopes of one access token.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scopes {
    /// Every clinical scope the `scope` claim named.
    grants: Vec<Grant>,
}

impl Scopes {
    /// Returns the clinical scopes of the space-delimited `scope` value
    /// (RFC 6749 §3.3).
    ///
    /// A token that is no clinical scope, names a resource that is not
    /// spelled like a FHIR resource type, or carries permissions out of order
    /// grants nothing: such requests "MAY be ignored" (SMART App Launch
    /// 2.2.0, Scopes and Launch Context, §Scopes for requesting FHIR
    /// Resources). A product that holds a resource table passes it to
    /// [`Scopes::parse_known`] instead.
    #[must_use]
    pub fn parse(scope: &str) -> Self {
        Self::parse_known(scope, resource_shaped)
    }

    /// Returns the clinical scopes of `scope` whose resource type `known`
    /// admits, the `*` wildcard always admitted.
    #[must_use]
    pub fn parse_known(scope: &str, known: impl Fn(&str) -> bool) -> Self {
        Self {
            grants: scope
                .split(' ')
                .filter_map(|token| grant(token, &known))
                .collect(),
        }
    }

    /// Returns whether the token names no clinical scope at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Returns how far `permission` on `resource_type` reaches, or `None`
    /// when no scope grants it.
    ///
    /// A `user/` or `system/` scope reaches every resource of the type, so it
    /// wins over a `patient/` scope for the same permission: scopes "can be
    /// combined to represent a union of access" (SMART App Launch 2.2.0,
    /// Scopes and Launch Context, §Scope Equivalence). A granular scope
    /// grants nothing here; [`Scopes::reach_with`] evaluates it.
    #[must_use]
    pub fn reach(&self, permission: Permission, resource_type: &str) -> Option<Reach> {
        self.reach_with(permission, resource_type, &|_constraint| false)
    }

    /// Returns how far `permission` on `resource_type` reaches, a granular
    /// scope admitted when `evaluate` says the resource satisfies its
    /// constraint.
    #[must_use]
    pub fn reach_with(
        &self,
        permission: Permission,
        resource_type: &str,
        evaluate: Evaluator<'_>,
    ) -> Option<Reach> {
        let mut reach = None;
        for grant in &self.grants {
            let names_type = grant
                .resource_type
                .as_deref()
                .is_none_or(|named| named == resource_type);
            if !names_type || !grant.permissions.holds(permission) {
                continue;
            }
            if let Some(constraint) = &grant.constraint
                && !evaluate(constraint)
            {
                continue;
            }
            match grant.context {
                Context::User | Context::System => return Some(Reach::Any),
                Context::Patient => reach = Some(Reach::Patient),
            }
        }
        reach
    }

    /// Returns whether any scope was granted in `context`.
    #[must_use]
    pub fn granted_in(&self, context: Context) -> bool {
        self.grants.iter().any(|grant| grant.context == context)
    }
}

/// Returns whether `name` is spelled like a FHIR resource type: an upper-case
/// ASCII letter followed by ASCII letters and digits.
///
/// No specification fixes the lexical shape outside a resource table: our
/// own design, over the names every FHIR release defines.
fn resource_shaped(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|first| first.is_ascii_uppercase())
        && chars.all(|rest| rest.is_ascii_alphanumeric())
}

/// Returns the clinical scope `token` names, or `None` for any other token.
fn grant(token: &str, known: &impl Fn(&str) -> bool) -> Option<Grant> {
    let (context, rest) = token.split_once('/')?;
    let context = match context {
        "patient" => Context::Patient,
        "user" => Context::User,
        "system" => Context::System,
        _ => return None,
    };
    let (rest, constraint) = match rest.split_once('?') {
        Some((rest, suffix)) => (rest, Some(Constraint::parse(suffix)?)),
        None => (rest, None),
    };
    let (resource, permissions) = rest.rsplit_once('.')?;
    let resource_type = match resource {
        "*" => None,
        named if known(named) => Some(named.to_owned()),
        _ => return None,
    };
    Some(Grant {
        context,
        resource_type,
        permissions: Permissions::parse(permissions)?,
        constraint,
    })
}

#[cfg(test)]
mod tests {
    use super::{Context, Permission, Reach, Scopes};

    #[test]
    fn a_v2_scope_grants_exactly_its_letters() {
        let scopes = Scopes::parse("system/Condition.crs");
        assert_eq!(
            Some(Reach::Any),
            scopes.reach(Permission::Create, "Condition")
        );
        assert_eq!(
            Some(Reach::Any),
            scopes.reach(Permission::Read, "Condition")
        );
        assert_eq!(
            Some(Reach::Any),
            scopes.reach(Permission::Search, "Condition")
        );
        assert_eq!(None, scopes.reach(Permission::Update, "Condition"));
        assert_eq!(None, scopes.reach(Permission::Delete, "Condition"));
        assert_eq!(None, scopes.reach(Permission::Read, "Observation"));
    }

    #[test]
    fn the_wildcard_names_every_type() {
        let scopes = Scopes::parse("system/*.r");
        assert_eq!(
            Some(Reach::Any),
            scopes.reach(Permission::Read, "Observation")
        );
        assert_eq!(None, scopes.reach(Permission::Create, "Observation"));
    }

    #[test]
    fn letters_out_of_order_or_repeated_grant_nothing() {
        for token in [
            "system/Condition.rc",
            "system/Condition.rr",
            "system/Condition.",
            "system/Condition.x",
        ] {
            assert!(Scopes::parse(token).is_empty(), "{token}");
        }
    }

    #[test]
    fn the_v1_suffixes_read_as_their_v2_letters() {
        let read = Scopes::parse("user/Condition.read");
        assert!(read.reach(Permission::Read, "Condition").is_some());
        assert!(read.reach(Permission::Search, "Condition").is_some());
        assert!(read.reach(Permission::Create, "Condition").is_none());
        let write = Scopes::parse("user/Condition.write");
        assert!(write.reach(Permission::Create, "Condition").is_some());
        assert!(write.reach(Permission::Update, "Condition").is_some());
        assert!(write.reach(Permission::Delete, "Condition").is_some());
        assert!(write.reach(Permission::Read, "Condition").is_none());
        let all = Scopes::parse("user/*.*");
        assert!(all.reach(Permission::Delete, "Condition").is_some());
    }

    #[test]
    fn a_patient_scope_reaches_the_compartment_and_a_system_scope_wins() {
        let patient = Scopes::parse("patient/Condition.rs");
        assert_eq!(
            Some(Reach::Patient),
            patient.reach(Permission::Read, "Condition")
        );
        assert!(patient.granted_in(Context::Patient));
        assert!(!patient.granted_in(Context::System));
        let both = Scopes::parse("patient/Condition.rs system/Condition.r");
        assert_eq!(Some(Reach::Any), both.reach(Permission::Read, "Condition"));
    }

    #[test]
    fn other_tokens_grant_nothing() {
        let scopes = Scopes::parse(
            "openid fhirUser launch/patient offline_access __operator \
             system/notAType.r system/9.r patient/Observation.rs?category",
        );
        assert!(scopes.is_empty());
    }

    #[test]
    fn a_granular_scope_grants_nothing_without_an_evaluator_and_its_pairs_with_one() {
        let scopes = Scopes::parse("patient/Observation.rs?category=laboratory&status=final");
        assert!(!scopes.is_empty(), "the constrained grant is carried");
        assert_eq!(None, scopes.reach(Permission::Read, "Observation"));
        let evaluate = |constraint: &super::Constraint| {
            constraint.params()
                == [
                    (String::from("category"), String::from("laboratory")),
                    (String::from("status"), String::from("final")),
                ]
        };
        assert_eq!(
            Some(Reach::Patient),
            scopes.reach_with(Permission::Read, "Observation", &evaluate)
        );
        assert_eq!(
            None,
            scopes.reach_with(Permission::Read, "Observation", &|_| false)
        );
    }

    #[test]
    fn a_resource_table_narrows_the_lexical_rule() {
        let scopes = Scopes::parse_known("system/Condition.r system/Imaginary.r", |name| {
            name == "Condition"
        });
        assert!(scopes.reach(Permission::Read, "Condition").is_some());
        assert!(scopes.reach(Permission::Read, "Imaginary").is_none());
    }

    #[test]
    fn a_letter_names_itself() {
        assert_eq!('c', Permission::Create.letter());
        assert_eq!('s', Permission::Search.letter());
    }
}
