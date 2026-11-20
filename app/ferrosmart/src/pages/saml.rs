// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The page that carries an `AuthnRequest` to a SAML identity provider by
//! the HTTP-POST binding (saml-bindings-2.0-os §3.5.4).

use axum::response::Response;
use ferrohealth_ui::html::Html;
use ferrohealth_ui::i18n::Locale;
use ferrohealth_ui::view::button::{Variant, label};
use ferrohealth_ui::view::surface::page_card;
use http::StatusCode;
use url::Url;

use super::{CATALOG, Sources, brand_lockup, respond};
use crate::server::AppState;

/// Returns the page whose form posts `fields` to the identity provider's
/// single sign-on location `action`.
///
/// The person submits it: saml-bindings-2.0-os §3.5.4 lets the form be
/// submitted by script or by the user, and the page runs no script.
#[must_use]
pub fn post(state: &AppState, action: &Url, fields: &[(&str, &str)]) -> Response {
    let locale = Locale::default().with_catalog(&*CATALOG);
    let words = |id: &str| locale.lookup(&*CATALOG, id);
    let inputs = Html::join(fields.iter().map(|(name, value)| {
        Html::raw(format!(
            "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
            Html::text(*name),
            Html::text(*value)
        ))
    }));
    let form = Html::raw(format!(
        "<form method=\"post\" action=\"{action}\" class=\"fui-stack\">{inputs}\
         <div class=\"fui-cluster\"><button type=\"submit\" class=\"{primary}\">{go}</button></div></form>",
        action = Html::text(action.as_str()),
        primary = Variant::Primary.class(),
        go = label(None, words("saml-post-continue")),
    ));
    let body = Html::join([
        Html::raw(format!("<p>{}</p>", Html::text(words("saml-post-intro")))),
        form,
    ]);
    let title = words("saml-post-title");
    let page = page_card(Some(brand_lockup(state, &locale)), title.clone(), body);
    let reach = crate::upstream::origins_of(std::iter::once(action));
    respond(
        state,
        StatusCode::OK,
        &locale,
        title,
        page,
        Sources {
            form: &reach,
            img: &[],
        },
    )
}
