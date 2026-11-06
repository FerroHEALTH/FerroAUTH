// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The behaviour of [`AuthLayer`] and the [`AuthService`] it wraps around a
//! route: classify the request, admit or refuse it, call the route, and
//! write the audit line.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::time::Instant;

use axum::body::Body;
use axum::response::Response;
use http::HeaderName;
use http::Request;
use http::request::Parts;
use tower::Layer;
use tower::Service;

use crate::audit::Actor;
use crate::audit::AuditLine;
use crate::extract::HeaderOnly;
use crate::guard::AnsweredAs;
use crate::guard::AuthLayer;
use crate::guard::AuthService;
use crate::guard::Classify;
use crate::guard::Gate;
use crate::guard::Render;
use crate::guard::Requirement;
use crate::guard::Target;
use crate::refusal::Refusal;
use crate::resource::Access;
use crate::resource::Caller;

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
            let mut binding = None;
            let (access, response) = match admit(&gate, &target, &parts).await {
                Err((access, refusal)) => {
                    if refusal == Refusal::Unavailable && access.is_some() {
                        binding = Some(crate::audit::SOURCE_UNAVAILABLE);
                    }
                    (access, render.render(&refusal, &parts))
                }
                Ok(access) => {
                    parts.extensions.insert(access.clone());
                    let request = Request::from_parts(parts, body);
                    (Some(access), inner.call(request).await?)
                }
            };
            let mut actor = Actor::of(access.as_ref());
            if let Some(binding) = binding {
                actor = actor.with_binding(binding);
            }
            let answered = response
                .extensions()
                .get::<AnsweredAs>()
                .map_or(target.interaction, |answered| answered.0);
            AuditLine::new(&method, answered, response.status())
                .timed(at, started.elapsed())
                .by(actor)
                .on(target.route_template(), target.target_name())
                .request(request_id.as_deref())
                .write();
            Ok(response)
        })
    }
}

/// Returns the access of the request `parts` to `target`, or the
/// refusal with the access it was refused under, so the audit line names a
/// caller whose credential held and whose grant did not.
///
/// A public target is admitted without a credential; a refused target is
/// refused before any credential is read.
async fn admit(
    gate: &Gate,
    target: &Target,
    parts: &Parts,
) -> Result<Access, (Option<Access>, Refusal)> {
    match target.requirement() {
        Requirement::Refused => return Err((None, Refusal::Unclassified)),
        Requirement::Public => return Ok(Access::Open),
        _ => {}
    }
    let access = gate
        .authenticate_request(parts)
        .await
        .map_err(|denied| (None, denied.into_refusal()))?;
    let honoured = gate.honoured(&access);
    if !gate.is_open() && !target.requirement().met_by(&access, honoured) {
        return Err((Some(access), Refusal::Forbidden));
    }
    let (Some(binding), Access::Caller(caller)) = (&gate.party, &access) else {
        return Ok(access);
    };
    match binding.resolve(caller).await {
        Ok(None) => Ok(access),
        Ok(Some(outcome)) => Ok(Access::Caller(Arc::new(
            Caller::clone(caller).with_party(outcome),
        ))),
        Err(error) => {
            tracing::warn!(error = %error, "the party source could not answer");
            Err((Some(access), Refusal::Unavailable))
        }
    }
}
