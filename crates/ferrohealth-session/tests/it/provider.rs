// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The test OpenID Provider: discovery, the key set, the token endpoint,
//! revocation and end-session, with an ES256 key generated per case.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use wiremock::matchers;
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

/// The console's client id at the provider.
pub(crate) const CLIENT: &str = "synthetic-console";

/// The console's client secret.
pub(crate) const SECRET: &str = "synthetic-client-secret";

/// The console's redirection endpoint.
pub(crate) const REDIRECT: &str = "https://console.example.org/auth/callback";

/// The token endpoint's path.
pub(crate) const TOKEN: &str = "/token";

/// The revocation endpoint's path.
pub(crate) const REVOKE: &str = "/revoke";

/// The provider and its signing key.
pub(crate) struct Provider {
    pub(crate) server: MockServer,
    encoding: EncodingKey,
}

impl Provider {
    /// Starts a provider that serves its metadata and its key set.
    pub(crate) async fn start() -> Self {
        let server = MockServer::start().await;
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .expect("a key pair");
        let encoding = EncodingKey::from_ec_der(pkcs8.as_ref());
        let mut jwk = serde_json::to_value(
            Jwk::from_encoding_key(&encoding, Algorithm::ES256).expect("a JWK"),
        )
        .expect("the JWK serializes");
        if let Some(members) = jwk.as_object_mut() {
            members.insert(String::from("kid"), serde_json::json!("op-1"));
            members.insert(String::from("use"), serde_json::json!("sig"));
        }
        let uri = server.uri();
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/.well-known/oauth-authorization-server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": uri,
                "authorization_endpoint": format!("{uri}/authorize"),
                "token_endpoint": format!("{uri}{TOKEN}"),
                "jwks_uri": format!("{uri}/jwks"),
                "end_session_endpoint": format!("{uri}/logout"),
                "revocation_endpoint": format!("{uri}{REVOKE}"),
                "code_challenge_methods_supported": ["S256"]
            })))
            .mount(&server)
            .await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "keys": [jwk] })),
            )
            .mount(&server)
            .await;
        Self { server, encoding }
    }

    /// The issuer identifier.
    pub(crate) fn uri(&self) -> String {
        self.server.uri()
    }

    /// An ID Token for the console carrying `nonce`.
    pub(crate) fn id_token(&self, nonce: &str) -> String {
        let now = jiff::Timestamp::now().as_second();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(String::from("op-1"));
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({
                "iss": self.uri(),
                "aud": CLIENT,
                "sub": "synthetic-operator",
                "nonce": nonce,
                "iat": now,
                "exp": now + 300,
                "name": "Synthetic Operator"
            }),
            &self.encoding,
        )
        .expect("the ID Token signs")
    }

    /// Mounts the code exchange: `synthetic-code` with the verifier whose
    /// `S256` challenge is `challenge` answers `tokens`, once.
    pub(crate) async fn mount_exchange(&self, challenge: &str, tokens: serde_json::Value) {
        Mock::given(matchers::method("POST"))
            .and(matchers::path(TOKEN))
            .and(matchers::body_string_contains(
                "grant_type=authorization_code",
            ))
            .and(matchers::body_string_contains("code=synthetic-code"))
            .and(Verifier(challenge.to_owned()))
            .respond_with(ResponseTemplate::new(200).set_body_json(tokens))
            .expect(1)
            .mount(&self.server)
            .await;
    }

    /// Mounts the refresh grant of `refresh_token`, answering `status` and
    /// `body`, once.
    pub(crate) async fn mount_refresh(
        &self,
        refresh_token: &str,
        status: u16,
        body: serde_json::Value,
    ) {
        Mock::given(matchers::method("POST"))
            .and(matchers::path(TOKEN))
            .and(matchers::body_string_contains("grant_type=refresh_token"))
            .and(matchers::body_string_contains(format!(
                "refresh_token={refresh_token}"
            )))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .expect(1)
            .mount(&self.server)
            .await;
    }

    /// Mounts the revocation of `token` with `hint`, once.
    pub(crate) async fn mount_revoke(&self, token: &str, hint: &str) {
        Mock::given(matchers::method("POST"))
            .and(matchers::path(REVOKE))
            .and(matchers::body_string_contains(format!("token={token}")))
            .and(matchers::body_string_contains(format!(
                "token_type_hint={hint}"
            )))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&self.server)
            .await;
    }

    /// Mounts a token endpoint that fails on the provider's side.
    pub(crate) async fn mount_failing_token(&self) {
        Mock::given(matchers::method("POST"))
            .and(matchers::path(TOKEN))
            .respond_with(ResponseTemplate::new(503))
            .mount(&self.server)
            .await;
    }
}

/// A token request whose `code_verifier` derives `challenge` (RFC 7636 §4.6).
struct Verifier(String);

impl Match for Verifier {
    fn matches(&self, request: &Request) -> bool {
        url::form_urlencoded::parse(&request.body)
            .find(|(name, _)| name == "code_verifier")
            .is_some_and(|(_, verifier)| ferrohealth_smart::oidc::challenge(&verifier) == self.0)
    }
}
