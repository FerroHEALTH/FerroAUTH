// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The records of a token request, in the form of BALP 1.1.4's
//! `IHE.IUA.71`, and of a login at the upstream provider.

use ihe_atna::balp::{
    APPLICATION, DESTINATION_ROLE, Direction, Entity, EventKind, Exchange, LOGIN, NetworkAddress,
    Outcome, Peer, SOURCE_ROLE, USER_AUTHENTICATION,
};
use ihe_atna::user::{OnBehalfOf, User};
use secrecy::SecretString;
use url::Url;

use super::{AUTHZ_OAUTH_SERVICE, IUA_71, UNIDENTIFIED_CLIENT, USER_AUTHORIZATION, WITHHELD};

/// An access token FerroSMART issued, as its record names it.
#[derive(Debug, Clone, Copy)]
pub struct Token<'a> {
    /// The issuer, the system of the token's `jti`.
    pub issuer: &'a str,
    /// The token's `jti`.
    pub jti: &'a str,
    /// The client it was issued to.
    pub client_id: &'a str,
    /// The resource server it is for.
    pub audience: &'a str,
    /// The person it was issued for, when one logged in.
    pub subject: Option<&'a str>,
}

/// A token request, as its record names it.
#[derive(Debug, Clone, Copy)]
pub struct TokenRequest<'a> {
    /// The client the request names, when it names one.
    pub client_id: Option<&'a str>,
    /// The address the request came from.
    pub from: std::net::IpAddr,
    /// The token endpoint.
    pub endpoint: &'a Url,
    /// The request's `Content-Type`, when it named one.
    pub content_type: Option<&'a str>,
    /// The request body as sent.
    pub body: &'a [u8],
}

/// Returns the request as `entity:token-request` holds it.
///
/// That is "the http request in raw form, without the `code_verifier`
/// value" (BALP 1.1.4 `IHE.IUA.71`): the request line, the `Host` and
/// `Content-Type` headers and the form, with the value of every
/// [`WITHHELD`] parameter left out.
#[must_use]
pub fn raw_request(request: &TokenRequest<'_>) -> SecretString {
    let form: String = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(
            url::form_urlencoded::parse(request.body).map(|(name, value)| {
                let shown = if WITHHELD.contains(&name.as_ref()) {
                    std::borrow::Cow::Borrowed("")
                } else {
                    value
                };
                (name, shown)
            }),
        )
        .finish();
    let mut text = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\n",
        request.endpoint.path(),
        request.endpoint.host_str().unwrap_or_default()
    );
    if let Some(content_type) = request.content_type {
        text.push_str("Content-Type: ");
        text.push_str(content_type);
        text.push_str("\r\n");
    }
    text.push_str("\r\n");
    text.push_str(&form);
    SecretString::from(text)
}

/// Returns the ITI-71 record of `request` in the form of BALP 1.1.4's
/// `IHE.IUA.71`: `issued` when a token was issued, or the OAuth `error` it
/// was refused with.
#[must_use]
pub fn token_request(request: &TokenRequest<'_>, answer: Result<Token<'_>, &str>) -> Exchange {
    let client = Peer {
        who: request
            .client_id
            .or_else(|| answer.ok().map(|token| token.client_id))
            .unwrap_or(UNIDENTIFIED_CLIENT)
            .to_owned(),
        network: NetworkAddress::Ip(request.from),
    };
    let (outcome, outcome_description, on_behalf) = match answer {
        Ok(token) => (
            Outcome::Success,
            None,
            token.subject.map_or(OnBehalfOf::System, |subject| {
                OnBehalfOf::User(
                    User::new(
                        token.issuer.to_owned(),
                        subject.to_owned(),
                        token.client_id.to_owned(),
                    )
                    .with_audience(Some(token.audience.to_owned()))
                    .with_token_id(Some(token.jti.to_owned())),
                )
            }),
        ),
        Err(error) => (
            Outcome::MinorFailure,
            Some(error.to_owned()),
            OnBehalfOf::System,
        ),
    };
    Exchange {
        kind: EventKind {
            profile: IUA_71,
            event_type: USER_AUTHENTICATION,
            subtypes: vec![USER_AUTHORIZATION],
            action: "E",
            client: APPLICATION,
            server: AUTHZ_OAUTH_SERVICE,
        },
        recorded: jiff::Timestamp::now(),
        outcome,
        outcome_description,
        direction: Direction::Received {
            client,
            endpoint: NetworkAddress::uri(request.endpoint),
        },
        on_behalf,
        entities: vec![Entity::Query(raw_request(request))],
        security: Vec::new(),
    }
}

/// A person who logged in, as the record of the login names them.
#[derive(Debug, Clone, Copy)]
pub struct Person<'a> {
    /// FerroSMART's issuer, which the subject is FerroSMART's own under.
    pub issuer: &'a str,
    /// The person's pairwise subject.
    pub subject: &'a str,
    /// Their name, when the provider gave one.
    pub name: Option<&'a str>,
    /// The client the login was for, when it was for one.
    pub client_id: Option<&'a str>,
}

/// Returns the record of a login at the provider at `provider`: the person
/// who logged in, or the reason it failed (DICOM PS3.15 A.5.3.12, User
/// Authentication, `110122` Login).
#[must_use]
pub fn login(provider: &Url, answer: Result<Person<'_>, &str>) -> Exchange {
    let (outcome, outcome_description, on_behalf) = match answer {
        Ok(person) => {
            let user = match person.client_id {
                Some(client_id) => User::new(
                    person.issuer.to_owned(),
                    person.subject.to_owned(),
                    client_id.to_owned(),
                ),
                None => User::local(person.subject.to_owned())
                    .with_issuer(Some(person.issuer.to_owned())),
            };
            (
                Outcome::Success,
                None,
                OnBehalfOf::User(user.with_name(person.name.map(str::to_owned))),
            )
        }
        Err(reason) => (
            Outcome::MinorFailure,
            Some(reason.to_owned()),
            OnBehalfOf::System,
        ),
    };
    Exchange {
        kind: EventKind {
            profile: "",
            event_type: USER_AUTHENTICATION,
            subtypes: vec![LOGIN],
            action: "E",
            client: SOURCE_ROLE,
            server: DESTINATION_ROLE,
        },
        recorded: jiff::Timestamp::now(),
        outcome,
        outcome_description,
        direction: Direction::Sent {
            server: Peer::server(provider),
        },
        on_behalf,
        entities: Vec::new(),
        security: Vec::new(),
    }
}
