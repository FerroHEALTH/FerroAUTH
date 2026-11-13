// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The product's standing through the public API: a `Standing` answering
//! each question a token's classification asks, on every request, with the
//! refusals the configured lists give; the lists refused beside it, in the
//! settings and in the `[auth]` section a product reads without them.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;

use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::ProductStandingSection;
use ferrohealth_smart::kind::Actor;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::kind::Unclassified;
use ferrohealth_smart::kind::standing::Answer;
use ferrohealth_smart::kind::standing::ClientStanding;
use ferrohealth_smart::kind::standing::Issued;
use ferrohealth_smart::kind::standing::Standing;
use ferrohealth_smart::kind::standing::StandingError;
use ferrohealth_smart::kind::standing::StandingSource;
use ferrohealth_smart::profile::Delegate;
use ferrohealth_smart::profile::Representation;
use ferrohealth_smart::resource::Caller;
use ferrohealth_smart::resource::Compartment;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::resource::ResourceError;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::Settings;
use ferrohealth_smart::scope::Permission;
use jsonwebtoken::Algorithm;
use serde_json::Value;
use serde_json::json;

use crate::support::SigningKey;
use crate::support::ec_key;
use crate::support::mint;
use crate::support::now;
use crate::support::temp_file;

/// The issuer of every case; its key set is a file, so nothing is read.
const ISSUER: &str = "https://as.example.org/realms/ferro";
/// The audience of every case.
const AUDIENCE: &str = "https://ehr.example.org/openehr";
/// The client of every person's token unless a case names another.
const PORTAL: &str = "portal";
/// The client of the machine's app-only token.
const MACHINE: &str = "machine-client";

type Outcome = Result<(), Box<dyn StdError>>;

/// A list a case sets on the settings, by the key it is refused under.
type SettingsCase = (&'static str, fn(&mut Settings));

/// A list a case sets on the section, by the key it is refused under.
type SectionCase = (&'static str, fn(&mut AuthSection));

/// One question the product was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Asked {
    /// The standing of a client, by issuer and client.
    Client(String, String),
    /// Whether an actor is a delegate, by the token's issuer and the actor.
    Delegate(String, Actor),
    /// Whether a subject is scopeless, by issuer and subject.
    Scopeless(String, String),
}

/// What the product answers, changed between requests.
#[derive(Debug, Default)]
pub(crate) struct Held {
    /// The standing of each client; any other is unlisted.
    pub(crate) clients: BTreeMap<String, ClientStanding>,
    /// The declared delegate actors.
    pub(crate) delegates: Vec<Actor>,
    /// The subjects admitted without a scope.
    pub(crate) scopeless: BTreeSet<String>,
    /// Whether the store fails.
    pub(crate) failing: bool,
    /// Every question asked, in order.
    pub(crate) asked: Vec<Asked>,
}

/// A product standing over [`Held`], answered from memory.
#[derive(Debug, Default)]
pub(crate) struct Product(Mutex<Held>);

/// The failure of a store that cannot be read.
#[derive(Debug, thiserror::Error)]
#[error("the synthetic store is down")]
struct Down;

impl Product {
    /// Returns what the product holds, to change or read.
    pub(crate) fn held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records `asked` and returns `answer`, or the store's failure.
    fn answer<T: Send + 'static>(
        &self,
        asked: Asked,
        answer: impl FnOnce(&Held) -> T,
    ) -> Answer<'_, T> {
        let mut held = self.held();
        held.asked.push(asked);
        let outcome = if held.failing {
            Err(StandingError::new(Down))
        } else {
            Ok(answer(&held))
        };
        Box::pin(std::future::ready(outcome))
    }
}

impl Standing for Product {
    fn client<'a>(&'a self, client: Issued<'a>) -> Answer<'a, ClientStanding> {
        let id = client.id.to_owned();
        self.answer(
            Asked::Client(client.issuer.to_owned(), id.clone()),
            |held| {
                held.clients
                    .get(&id)
                    .copied()
                    .unwrap_or(ClientStanding::Unlisted)
            },
        )
    }

    fn delegate<'a>(&'a self, issuer: &'a str, actor: &'a Actor) -> Answer<'a, bool> {
        let actor = actor.clone();
        self.answer(Asked::Delegate(issuer.to_owned(), actor.clone()), |held| {
            held.delegates.contains(&actor)
        })
    }

    fn scopeless<'a>(&'a self, subject: Issued<'a>) -> Answer<'a, bool> {
        let id = subject.id.to_owned();
        self.answer(
            Asked::Scopeless(subject.issuer.to_owned(), id.clone()),
            |held| held.scopeless.contains(&id),
        )
    }
}

/// A `persons` issuer whose standing is the product's.
struct Harness {
    /// The signing key, published in the key set file.
    key: SigningKey,
    /// The product's standing.
    product: Arc<Product>,
    /// The resource server.
    server: ResourceServer,
}

impl Harness {
    /// Returns the harness of an issuer of `kind` read under `tweak`.
    async fn new(kind: IssuerKind, tweak: impl FnOnce(&mut Settings)) -> Self {
        let key = ec_key("k1", Algorithm::ES256);
        let product = Arc::new(Product::default());
        let mut settings = settings(&key, kind);
        let standing: Arc<dyn Standing> = product.clone();
        settings.standing = StandingSource::Product(standing);
        tweak(&mut settings);
        let server = ResourceServer::discover(settings)
            .await
            .expect("the key set file reads");
        Self {
            key,
            product,
            server,
        }
    }

    /// Returns the caller `claims` authenticate.
    async fn admit(&self, claims: &Value) -> Result<Caller, Rejection> {
        self.server.authenticate(&mint(&self.key, claims)).await
    }

    /// Returns the questions asked so far, clearing them.
    fn asked(&self) -> Vec<Asked> {
        std::mem::take(&mut self.product.held().asked)
    }
}

/// Returns the settings of an issuer of `kind` whose key set is `key`'s.
fn settings(key: &SigningKey, kind: IssuerKind) -> Settings {
    let set = json!({ "keys": [key.jwk.clone()] }).to_string();
    let mut settings = Settings::new(ISSUER, AUDIENCE, kind);
    settings.jwks_file = Some(temp_file("standing-jwks.json", set.as_bytes()));
    settings
}

/// The claims of a person's token through `client` granting `scope`.
fn person(client: &str, scope: &str) -> Value {
    json!({
        "iss": ISSUER, "aud": AUDIENCE, "sub": "user-5ba552d67", "client_id": client,
        "iat": now(), "exp": now() + 300, "jti": "jti-person", "scope": scope,
    })
}

/// The claims of the machine's app-only token granting `scope`.
fn machine(scope: &str) -> Value {
    json!({
        "iss": ISSUER, "aud": AUDIENCE, "sub": MACHINE, "client_id": MACHINE,
        "iat": now(), "exp": now() + 300, "jti": "jti-app", "scope": scope,
    })
}

/// Returns the classification refusal of `outcome`.
fn refused(outcome: Result<Caller, Rejection>) -> Option<Unclassified> {
    match outcome {
        Err(Rejection::Unclassified { reason }) => Some(reason),
        _ => None,
    }
}

/// The actor `sub` of the token's own issuer.
fn actor(sub: &str) -> Actor {
    Actor {
        issuer: String::from(ISSUER),
        sub: String::from(sub),
    }
}

#[tokio::test]
async fn each_client_standing_classifies_a_persons_token() -> Outcome {
    let h = Harness::new(IssuerKind::Persons, |_| {}).await;
    let claims = person(PORTAL, "user/Observation.rs");
    assert_eq!(
        Some(Unclassified::UnlistedClient),
        refused(h.admit(&claims).await),
        "a client the product does not list"
    );
    assert_eq!(
        vec![Asked::Client(String::from(ISSUER), String::from(PORTAL))],
        h.asked(),
        "the product is asked by issuer and client"
    );
    h.product
        .held()
        .clients
        .insert(String::from(PORTAL), ClientStanding::FirstParty);
    let caller = h.admit(&claims).await?;
    assert_eq!(&CallerKind::Person, caller.kind());
    assert_eq!(Some(PORTAL), caller.client_id());
    h.product
        .held()
        .clients
        .insert(String::from(PORTAL), ClientStanding::Delegate);
    let caller = h.admit(&claims).await?;
    assert_eq!(&CallerKind::Delegated { actor: None }, caller.kind());
    assert_eq!(2, h.asked().len(), "one question per request, none held");
    Ok(())
}

#[tokio::test]
async fn a_representation_holds_only_through_a_first_party_client() -> Outcome {
    let h = Harness::new(IssuerKind::Persons, |settings| {
        settings.profile.representation = Some(Representation {
            claim: String::from("represents"),
            ground_claim: Some(String::from("ground")),
        });
    })
    .await;
    let mut claims = person(PORTAL, "user/Observation.rs");
    claims["represents"] = json!("represented-subject-9");
    claims["ground"] = json!("legal-guardian");
    h.product
        .held()
        .clients
        .insert(String::from(PORTAL), ClientStanding::FirstParty);
    let caller = h.admit(&claims).await?;
    assert_eq!(
        &CallerKind::Representative {
            represented: String::from("represented-subject-9"),
            ground: Some(String::from("legal-guardian")),
        },
        caller.kind()
    );
    h.product
        .held()
        .clients
        .insert(String::from(PORTAL), ClientStanding::Delegate);
    assert_eq!(
        Some(Unclassified::RepresentationThroughDelegate),
        refused(h.admit(&claims).await)
    );
    h.product.held().clients.clear();
    assert_eq!(
        Some(Unclassified::UnlistedClient),
        refused(h.admit(&claims).await)
    );
    Ok(())
}

// NOTE: RFC 8693 §4.1, `act` names the current actor by `iss` and `sub`, the
// token's own issuer when `act` names none.
#[tokio::test]
async fn an_actor_is_delegated_only_when_the_product_declares_it() -> Outcome {
    let h = Harness::new(IssuerKind::Persons, |_| {}).await;
    let mut claims = person(PORTAL, "user/Observation.rs");
    claims["act"] = json!({ "sub": "actor-1" });
    assert_eq!(
        Some(Unclassified::UnlistedActor),
        refused(h.admit(&claims).await)
    );
    assert_eq!(
        vec![Asked::Delegate(String::from(ISSUER), actor("actor-1"))],
        h.asked(),
        "only the actor is asked about, never the client"
    );
    h.product.held().delegates.push(actor("actor-1"));
    let caller = h.admit(&claims).await?;
    assert_eq!(
        &CallerKind::Delegated {
            actor: Some(actor("actor-1")),
        },
        caller.kind()
    );
    claims["act"] = json!({ "sub": "actor-1", "iss": "https://other.example.org" });
    assert_eq!(
        Some(Unclassified::UnlistedActor),
        refused(h.admit(&claims).await),
        "the actor is its issuer and its sub together"
    );
    claims["act"] = json!({ "sub": "actor-1", "act": { "sub": "prior" } });
    h.asked();
    assert_eq!(
        Some(Unclassified::ActorChain),
        refused(h.admit(&claims).await)
    );
    assert!(h.asked().is_empty(), "a chain too deep is refused unasked");
    Ok(())
}

#[tokio::test]
async fn a_scopeless_system_caller_reaches_everything_only_without_a_resource_scope() -> Outcome {
    for kind in [IssuerKind::Persons, IssuerKind::Machines] {
        let h = Harness::new(kind, |_| {}).await;
        let caller = h.admit(&machine("openid")).await?;
        assert_eq!(&CallerKind::System, caller.kind(), "{kind}");
        assert!(
            !caller.scopeless(),
            "{kind}: a subject the product does not admit"
        );
        assert_eq!(None, caller.reach(Permission::Delete, "Condition"));
        assert_eq!(
            vec![Asked::Scopeless(
                String::from(ISSUER),
                String::from(MACHINE)
            )],
            h.asked(),
            "{kind}: the product is asked by issuer and subject"
        );
        h.product.held().scopeless.insert(String::from(MACHINE));
        let caller = h.admit(&machine("openid")).await?;
        assert!(caller.scopeless(), "{kind}");
        assert_eq!(
            Some(Compartment::Any),
            caller.reach(Permission::Delete, "Condition"),
            "{kind}: a scopeless caller with no resource scope reaches everything"
        );
        let caller = h.admit(&machine("system/Observation.rs")).await?;
        assert!(caller.scopeless(), "{kind}");
        assert_eq!(
            None,
            caller.reach(Permission::Delete, "Condition"),
            "{kind}: a token carrying a resource scope gets only its scopes"
        );
        assert_eq!(
            Some(Compartment::Any),
            caller.reach(Permission::Read, "Observation"),
            "{kind}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn only_a_system_caller_is_asked_whether_it_is_scopeless() -> Outcome {
    let h = Harness::new(IssuerKind::Persons, |_| {}).await;
    {
        let mut held = h.product.held();
        held.clients
            .insert(String::from(PORTAL), ClientStanding::FirstParty);
        held.scopeless.insert(String::from("user-5ba552d67"));
    }
    let caller = h.admit(&person(PORTAL, "openid")).await?;
    assert_eq!(&CallerKind::Person, caller.kind());
    assert!(!caller.scopeless(), "a person is never scopeless");
    assert_eq!(None, caller.reach(Permission::Delete, "Condition"));
    assert_eq!(
        vec![Asked::Client(String::from(ISSUER), String::from(PORTAL))],
        h.asked()
    );
    Ok(())
}

#[tokio::test]
async fn a_standing_that_cannot_answer_refuses_the_token_as_unavailable() -> Outcome {
    let h = Harness::new(IssuerKind::Persons, |_| {}).await;
    h.product.held().failing = true;
    for claims in [person(PORTAL, "user/Observation.rs"), machine("openid")] {
        let outcome = h.admit(&claims).await;
        assert!(
            matches!(
                &outcome,
                Err(Rejection::Upstream {
                    upstream: "standing",
                    ..
                })
            ),
            "{outcome:?}"
        );
        let source = match &outcome {
            Err(error) => error.source().map(ToString::to_string),
            Ok(_) => None,
        };
        assert_eq!(Some(String::from("the synthetic store is down")), source);
    }
    Ok(())
}

#[tokio::test]
async fn a_list_beside_the_products_standing_is_refused() {
    let key = ec_key("k1", Algorithm::ES256);
    let product: Arc<dyn Standing> = Arc::new(Product::default());
    let cases: [SettingsCase; 4] = [
        ("first_party_clients", |settings| {
            settings.profile.first_party_clients = vec![String::from(PORTAL)];
        }),
        ("delegates", |settings| {
            settings.profile.delegates = vec![Delegate::Client(String::from(PORTAL))];
        }),
        ("delegates", |settings| {
            settings.profile.delegates = vec![Delegate::Actor {
                issuer: None,
                sub: String::from("actor-1"),
            }];
        }),
        ("scopeless_subjects", |settings| {
            settings.scopeless_subjects.insert(String::from(MACHINE));
        }),
    ];
    for (key_name, set) in cases {
        let mut listed = settings(&key, IssuerKind::Persons);
        set(&mut listed);
        listed.standing = StandingSource::Product(Arc::clone(&product));
        let refusal = listed.validate();
        assert!(
            matches!(refusal, Err(ResourceError::ListedBesideStanding { key }) if key == key_name),
            "{key_name}: {refusal:?}"
        );
        assert!(ResourceServer::lazy(listed.clone()).is_err(), "{key_name}");
        listed.standing = StandingSource::Lists;
        assert!(
            listed.validate().is_ok(),
            "{key_name}: the lists alone hold"
        );
    }
}

/// An `[auth]` text with one `persons` issuer and `extra` keys on it, and
/// `section` keys before it.
fn auth(section: &str, extra: &str) -> String {
    format!(
        "{section}\n[[issuer]]\nissuer = \"{ISSUER}\"\nkind = \"persons\"\naudience = [\"{AUDIENCE}\"]\n\
         jwks_file = \"/dev/null\"\n{extra}\n"
    )
}

#[test]
fn the_product_section_refuses_the_three_keys_as_unknown() {
    let refused = [
        auth("", "first_party_clients = [\"portal\"]"),
        auth("", "delegates = [{ client = \"portal\" }]"),
        auth("", "first_party_clients = []"),
        auth(
            &format!("scopeless_subjects = [{{ issuer = \"{ISSUER}\", sub = \"svc\" }}]"),
            "",
        ),
    ];
    for text in &refused {
        let error = toml::from_str::<ProductStandingSection>(text)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(error.contains("unknown field"), "{text}: {error}");
        let accepted = error.split_once("expected one of").map(|(_, list)| list);
        assert!(
            accepted.is_some_and(
                |list| ["first_party_clients", "delegates", "scopeless_subjects"]
                    .iter()
                    .all(|key| !list.contains(&format!("`{key}`")))
            ),
            "the accepted keys leave the three out: {error}"
        );
        assert!(
            toml::from_str::<AuthSection>(text).is_ok(),
            "the default section keeps the key: {text}"
        );
    }
    let other = toml::from_str::<ProductStandingSection>(&auth("", "bogus = 1"))
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(other.contains("unknown field `bogus`"), "{other}");
    assert!(
        other.contains("`audience`") && !other.contains("`delegates`"),
        "{other}"
    );
    let section_level = toml::from_str::<ProductStandingSection>(&auth("bogus = 1", ""))
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(
        section_level.contains("`realm`") && !section_level.contains("`scopeless_subjects`"),
        "{section_level}"
    );
}

#[test]
fn the_product_section_reads_and_writes_as_the_default_without_the_lists() -> Outcome {
    let text = auth("realm = \"ferro\"", "client_claims = [\"azp\"]");
    let product: ProductStandingSection = toml::from_str(&text)?;
    let plain: AuthSection = toml::from_str(&text)?;
    assert_eq!(plain, product.0);
    let written = toml::to_string(&product)?;
    assert!(!written.contains("scopeless_subjects"), "{written}");
    assert_eq!(product, toml::from_str::<ProductStandingSection>(&written)?);
    Ok(())
}

#[test]
fn the_product_section_hands_every_issuer_its_standing() -> Outcome {
    let product: Arc<dyn Standing> = Arc::new(Product::default());
    let section: ProductStandingSection = toml::from_str(&auth("", ""))?;
    let resolved = section.resolve(Arc::clone(&product))?;
    assert_eq!(1, resolved.issuers.len());
    for issuer in &resolved.issuers {
        assert_eq!(
            StandingSource::Product(Arc::clone(&product)),
            issuer.standing
        );
    }
    let plain: AuthSection = toml::from_str(&auth("", "first_party_clients = [\"portal\"]"))?;
    let resolved = plain.resolve()?;
    assert_eq!(StandingSource::Lists, resolved.issuers[0].standing);
    assert_eq!(
        vec![String::from(PORTAL)],
        resolved.issuers[0].profile.first_party_clients,
        "the default section keeps reading its lists"
    );
    Ok(())
}

#[test]
fn a_list_set_in_code_on_the_product_section_is_refused_at_resolution() -> Outcome {
    let product: Arc<dyn Standing> = Arc::new(Product::default());
    let section: ProductStandingSection = toml::from_str(&auth("", ""))?;
    let cases: [SectionCase; 3] = [
        ("auth.issuer.first_party_clients", |auth| {
            auth.issuer[0].first_party_clients = Some(Vec::new());
        }),
        ("auth.issuer.delegates", |auth| {
            auth.issuer[0].delegates = Some(vec![Delegate::Client(String::from(PORTAL))]);
        }),
        ("auth.scopeless_subjects", |auth| {
            auth.scopeless_subjects = vec![ferrohealth_smart::config::ScopelessSubject {
                issuer: ferrohealth_secret::secret_url::SecretUrl::new(ISSUER),
                sub: String::from("svc"),
            }];
        }),
    ];
    for (key_name, set) in cases {
        let mut listed = section.clone();
        set(&mut listed.0);
        let refusal = listed.resolve(Arc::clone(&product));
        assert!(
            matches!(refusal, Err(ConfigError::ListedBesideStanding { key }) if key == key_name),
            "{key_name}: {refusal:?}"
        );
    }
    Ok(())
}

#[cfg(feature = "schema")]
#[test]
fn the_product_section_schema_leaves_out_the_three_keys() {
    let product =
        serde_json::to_value(schemars::schema_for!(ProductStandingSection)).expect("the schema");
    let plain = serde_json::to_value(schemars::schema_for!(AuthSection)).expect("the schema");
    assert!(plain["properties"]["scopeless_subjects"].is_object());
    assert!(product["properties"].get("scopeless_subjects").is_none());
    assert!(product["properties"]["realm"].is_object());
    let entry = &product["properties"]["issuer"]["items"]["properties"];
    assert!(entry["audience"].is_object(), "{product}");
    assert!(entry.get("first_party_clients").is_none(), "{entry}");
    assert!(entry.get("delegates").is_none(), "{entry}");
    let defs = plain["$defs"]["IssuerEntry"]["properties"].clone();
    assert!(defs["first_party_clients"].is_object(), "{plain}");
}
