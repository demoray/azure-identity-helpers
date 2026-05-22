// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! Authorize using the device authorization grant flow
//!
//! This flow allows users to sign in to input-constrained devices such as a smart TV, `IoT` device, or printer.
//!
//! You can learn more about this authorization flow [here](https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-device-code).
mod device_code_responses;

use azure_core::{
    error::{Error, ErrorKind},
    http::{
        ClientOptions, Context, Method, Pipeline, PipelineSendOptions, RawResponse, Request, Url,
        headers::{self, content_type},
    },
    json::from_json,
    sleep::sleep,
};
pub use device_code_responses::*;
use futures::stream::unfold;
use serde::Deserialize;
use std::pin::Pin;
use time::Duration;
use url::form_urlencoded;

/// Start the device authorization grant flow.
///
/// The user has only 15 minutes to sign in (the usual value for `expires_in`).
///
/// `pipeline` is the HTTP pipeline used to issue this request. The same
/// pipeline (and the same `tenant_id` / `client_id`) must be passed to
/// [`DeviceCodePhaseOneResponse::stream`] when polling the token endpoint
/// afterwards. Callers running the flow from a long-lived credential should
/// construct a single [`Pipeline`] once and reuse it to keep TLS sessions
/// and HTTP connections pooled across the polling loop. A pipeline built
/// with default options
/// (`Pipeline::new(None, None, ClientOptions::default(), vec![], vec![], None)`)
/// is sufficient unless custom retry, transport, or policy configuration is
/// required.
pub async fn start(
    pipeline: &Pipeline,
    tenant_id: &str,
    client_id: &str,
    scopes: &[&str],
) -> azure_core::Result<DeviceCodePhaseOneResponse> {
    let url = &format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode");

    let encoded = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", client_id)
        .append_pair("scope", &scopes.join(" "))
        .finish();

    let rsp = post_form(pipeline, url, encoded).await?;
    let rsp_status = rsp.status();
    if !rsp_status.is_success() {
        let rsp_body = rsp.into_body().into_string()?;
        // The device-code endpoint returns a structured error body that
        // matches `DeviceCodeErrorResponse`. Wrap that as the source of
        // the returned error so callers (and `format_aggregate_error`)
        // see both the phase-one context (endpoint + status) and the
        // AAD error/description/uri; fall back to embedding the raw
        // body only when the response doesn't parse as the expected
        // shape.
        return Err(
            from_json::<_, DeviceCodeErrorResponse>(&rsp_body).map_or_else(
                |_| {
                    Error::with_message(
                        ErrorKind::Credential,
                        format!("device code endpoint returned status {rsp_status}: {rsp_body}"),
                    )
                },
                |parsed| {
                    Error::with_error(
                        ErrorKind::Credential,
                        parsed,
                        format!("device code endpoint returned status {rsp_status}"),
                    )
                },
            ),
        );
    }
    rsp.into_body().json()
}

/// Contains the required information to allow a user to sign in.
///
/// The struct mirrors only the JSON fields the credential needs downstream
/// (the device code, polling interval, and pre-formatted user message);
/// other fields returned by the AAD device-code endpoint are ignored. The
/// HTTP pipeline, tenant id, and client id are passed back in to
/// [`Self::stream`] when polling rather than stored on the struct, which
/// keeps this type's serde layout faithful to the wire format.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceCodePhaseOneResponse {
    device_code: String,
    interval: i64,
    message: String,
}

pub(crate) fn default_pipeline() -> Pipeline {
    Pipeline::new(None, None, ClientOptions::default(), vec![], vec![], None)
}

impl DeviceCodePhaseOneResponse {
    /// The message containing human readable instructions for the user.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Polls the token endpoint while the user signs in.
    ///
    /// `pipeline`, `tenant_id`, and `client_id` must match what was passed
    /// to [`start`].
    ///
    /// This will continue until either success or a terminal error is
    /// returned. Per [RFC 8628 §3.5][rfc] the `authorization_pending` and
    /// `slow_down` server errors keep the poll loop alive; `slow_down`
    /// additionally requires the client to extend its polling interval by
    /// 5 seconds.
    ///
    /// [rfc]: https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
    #[must_use]
    pub fn stream<'a>(
        &'a self,
        pipeline: &'a Pipeline,
        tenant_id: &'a str,
        client_id: &'a str,
    ) -> Pin<Box<impl futures::Stream<Item = azure_core::Result<DeviceCodeAuthorization>> + 'a>>
    {
        #[derive(Debug, Clone, PartialEq, Eq)]
        enum NextState {
            /// Keep polling, sleeping `interval` seconds first.
            Continue {
                interval: i64,
            },
            Finish,
        }

        Box::pin(unfold(
            NextState::Continue {
                interval: self.interval,
            },
            move |state: NextState| async move {
                let NextState::Continue { interval } = state else {
                    return None;
                };

                let url =
                    &format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");

                // Throttle as specified by Azure. `slow_down` responses bump
                // this by 5 seconds for the next iteration (see below).
                sleep(Duration::seconds(interval)).await;

                let encoded = form_urlencoded::Serializer::new(String::new())
                    .append_pair("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                    .append_pair("client_id", client_id)
                    .append_pair("device_code", &self.device_code)
                    .finish();

                match post_form(pipeline, url, encoded).await {
                    Ok(rsp) => {
                        let rsp_status = rsp.status();
                        let rsp_body = match rsp.into_body().into_string() {
                            Ok(b) => b,
                            Err(e) => return Some((Err(e), NextState::Finish)),
                        };
                        if rsp_status.is_success() {
                            match from_json::<_, DeviceCodeAuthorization>(&rsp_body) {
                                Ok(authorization) => Some((Ok(authorization), NextState::Finish)),
                                Err(error) => Some((Err(error), NextState::Finish)),
                            }
                        } else {
                            match from_json::<_, DeviceCodeErrorResponse>(&rsp_body) {
                                Ok(error_rsp) => {
                                    let next_state = match error_rsp.error.as_str() {
                                        "authorization_pending" => NextState::Continue { interval },
                                        // Per RFC 8628 §3.5 the client must
                                        // extend its polling interval by 5s.
                                        "slow_down" => NextState::Continue {
                                            interval: interval.saturating_add(5),
                                        },
                                        _ => NextState::Finish,
                                    };
                                    Some((
                                        Err(Error::new(ErrorKind::Credential, error_rsp)),
                                        next_state,
                                    ))
                                }
                                Err(_) => Some((
                                    Err(Error::with_message(
                                        ErrorKind::Credential,
                                        format!(
                                            "device code token endpoint returned status {rsp_status}: {rsp_body}"
                                        ),
                                    )),
                                    NextState::Finish,
                                )),
                            }
                        }
                    }
                    Err(error) => Some((Err(error), NextState::Finish)),
                }
            },
        ))
    }
}

async fn post_form(
    pipeline: &Pipeline,
    url: &str,
    form_body: String,
) -> azure_core::Result<RawResponse> {
    let url = Url::parse(url)?;
    let mut req = Request::new(url, Method::Post);
    req.insert_header(
        headers::CONTENT_TYPE,
        content_type::APPLICATION_X_WWW_FORM_URLENCODED,
    );
    req.set_body(form_body);

    // The device code token endpoint signals normal flow states (notably
    // `authorization_pending` and `slow_down`) via 4xx responses with a
    // structured body. Skip the pipeline's automatic success check so that
    // we can inspect those bodies ourselves instead of having them turned
    // into opaque transport errors.
    pipeline
        .send(
            &Context::new(),
            &mut req,
            Some(PipelineSendOptions {
                skip_checks: true,
                ..PipelineSendOptions::default()
            }),
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn require_send<T: Send>(_t: T) {}

    #[test]
    fn ensure_that_start_is_send() {
        let pipeline = default_pipeline();
        require_send(start(&pipeline, "UNUSED", "UNUSED", &[]));
    }
}
