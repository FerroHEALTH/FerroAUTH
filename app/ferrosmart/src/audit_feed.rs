// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The client the audit lane's ATX: FHIR Feed sends through: FerroSMART's
//! own outbound client for `[ferrosmart.audit.feed]`, as `ihe-atna`'s
//! `FeedClient` (ITI TF-2 §3.20.4.2).
//!
//! The outbound client carries the endpoint's TLS, timeouts, credential and
//! its renewal, and the tries of one round; `ihe-atna` reads the answer's
//! status. The seam is `ihe-atna`'s own design (FerroHEALTH/FerroAUDIT#246).

use ferrohealth_smart::client::outbound::{OutboundClient, SendError};
use http::header::CONTENT_TYPE;
use http::{Method, StatusCode};
use ihe_atna::atna::feed::{FeedClient, FeedSendError};
use url::Url;

/// FerroSMART's outbound client to the Audit Record Repository.
#[derive(Debug)]
pub struct OutboundFeed(pub OutboundClient);

#[async_trait::async_trait]
impl FeedClient for OutboundFeed {
    fn authorizes(&self) -> bool {
        self.0.authorization().is_some()
    }

    async fn post(
        &self,
        url: &Url,
        content_type: &'static str,
        body: &[u8],
    ) -> Result<StatusCode, FeedSendError> {
        let answer = self
            .0
            .send(&Method::POST, url, |request| {
                request
                    .header(CONTENT_TYPE, content_type)
                    .body(body.to_vec())
            })
            .await
            .map_err(|error| match error {
                // NOTE: ihe-atna's FeedClient, an error carries no URL, so the
                // repository's userinfo and query never reach a log.
                SendError::Transport(error) => {
                    FeedSendError::Transport(Box::new(error.without_url()))
                }
                other => FeedSendError::Credentials(Box::new(other)),
            })?;
        Ok(answer.status())
    }
}
