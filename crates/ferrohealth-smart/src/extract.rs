// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `axum` side of the guard: the extractor of the [`Access`] the layer
//! admitted, and the renderer of a refusal that answers the status and the
//! challenge with an empty body.

use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::response::IntoResponse;
use axum::response::Response;
use http::StatusCode;
use http::header;
use http::request::Parts;

use crate::guard::Render;
use crate::refusal::Refusal;
use crate::resource::Access;

/// A handler ran outside the guard: no [`Access`] is on the request.
///
/// It answers `500`, because a route the guard does not cover is a defect
/// of the router, never a caller's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the handler runs outside the guard: no access is on the request")]
pub struct OutsideGuard;

impl IntoResponse for OutsideGuard {
    fn into_response(self) -> Response {
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Access {
    type Rejection = OutsideGuard;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> {
        std::future::ready(parts.extensions.get::<Self>().cloned().ok_or(OutsideGuard))
    }
}

/// The renderer of a refusal that sends the status and the
/// `WWW-Authenticate` challenge with an empty body, for a product that has
/// no body of its own (RFC 6750 §3 needs the header alone).
#[derive(Debug, Clone, Default)]
pub struct HeaderOnly {
    /// The realm the challenges name.
    realm: Option<String>,
}

impl HeaderOnly {
    /// Returns a renderer naming `realm` on every challenge.
    #[must_use]
    pub fn with_realm(realm: impl Into<String>) -> Self {
        Self {
            realm: Some(realm.into()),
        }
    }

    /// Returns the response of `refusal` with `body`.
    ///
    /// A product with a body of its own builds on this: the status and the
    /// challenge are the refusal's, the body the product's.
    #[must_use]
    pub fn respond(&self, refusal: &Refusal, body: Body) -> Response {
        let mut response = Response::new(body);
        *response.status_mut() = refusal.status();
        if let Some(challenge) = refusal.challenge(self.realm.as_deref())
            && let Ok(value) = header::HeaderValue::from_str(&challenge)
        {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        response
    }
}

impl Render for HeaderOnly {
    fn render(&self, refusal: &Refusal, _parts: &Parts) -> Response {
        self.respond(refusal, Body::empty())
    }
}
