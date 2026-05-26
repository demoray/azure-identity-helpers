// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! Refresh tokens.

use azure_core::{
    credentials::Secret,
    error::{Error, ErrorKind},
    http::{
        Context, Method, Pipeline, PipelineSendOptions, Request, Url,
        headers::{self, content_type},
    },
    json::from_json,
};
use serde::Deserialize;
use std::time::Duration;
use time::OffsetDateTime;
use url::form_urlencoded;

use crate::device_code::DeviceCodeErrorResponse;

/// Exchange a refresh token for a new access token and refresh token.
///
/// `pipeline` is the HTTP pipeline used to issue the token request. Callers
/// driving repeated refreshes (for example, from inside a long-lived
/// credential instance) should construct a single [`Pipeline`] once and reuse
/// it across calls so that TLS sessions and HTTP connections are pooled
/// between requests. A pipeline built with default options
/// (`Pipeline::new(None, None, ClientOptions::default(), vec![], vec![], None)`)
/// is sufficient unless the caller needs custom retry, transport, or policy
/// configuration.
pub async fn exchange(
    pipeline: &Pipeline,
    tenant_id: &str,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &Secret,
) -> azure_core::Result<RefreshTokenResponse> {
    let ctx = Context::new();

    let encoded = {
        let mut encoded = &mut form_urlencoded::Serializer::new(String::new());
        encoded = encoded
            .append_pair("grant_type", "refresh_token")
            .append_pair("client_id", client_id)
            .append_pair("refresh_token", refresh_token.secret());
        // optionally add the client secret
        if let Some(client_secret) = client_secret {
            encoded = encoded.append_pair("client_secret", client_secret);
        }
        encoded.finish()
    };

    let url = Url::parse(&format!(
        "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    ))?;

    let mut req = Request::new(url, Method::Post);
    req.insert_header(
        headers::CONTENT_TYPE,
        content_type::APPLICATION_X_WWW_FORM_URLENCODED,
    );
    req.set_body(encoded);

    // The AAD token endpoint signals refresh-token failures via 4xx
    // responses with a structured OAuth error body. Skip the pipeline's
    // automatic success check so we can inspect those bodies ourselves
    // instead of having them turned into opaque transport errors.
    let result = pipeline
        .send(
            &ctx,
            &mut req,
            Some(PipelineSendOptions {
                skip_checks: true,
                ..PipelineSendOptions::default()
            }),
        )
        .await?;
    let status = result.status();
    if status.is_success() {
        result.into_body().json().map_err(|e| {
            Error::with_error(ErrorKind::Credential, e, "parsing refresh token response")
        })
    } else {
        let body = result.into_body().into_string()?;
        // The AAD token endpoint returns the same OAuth-shaped error body
        // for refresh-token failures that the device-code flow already
        // parses via DeviceCodeErrorResponse (RFC 6749 §5.2). Wrap that as
        // the source of the returned error so callers see the structured
        // AAD error / description / uri; fall back to embedding the raw
        // body only when the response doesn't parse as the expected shape.
        Err(from_json::<_, DeviceCodeErrorResponse>(&body).map_or_else(
            |_| {
                Error::with_message(
                    ErrorKind::Credential,
                    format!("refresh token endpoint returned status {status}: {body}"),
                )
            },
            |parsed| {
                Error::with_error(
                    ErrorKind::Credential,
                    parsed,
                    format!("refresh token endpoint returned status {status}"),
                )
            },
        ))
    }
}

/// A refresh token
#[derive(Debug, Clone, Deserialize)]
pub struct RefreshTokenResponse {
    token_type: String,
    #[serde(rename = "scope", deserialize_with = "deserialize::split")]
    scopes: Vec<String>,
    expires_in: u64,
    ext_expires_in: u64,
    access_token: Secret,
    refresh_token: Secret,
    /// Reference point used to derive [`Self::expires_on`]. Captured at
    /// deserialize time so the absolute expiry is stable across repeated
    /// reads of the same response.
    #[serde(skip, default = "OffsetDateTime::now_utc")]
    received_at: OffsetDateTime,
}

impl RefreshTokenResponse {
    /// Returns the `token_type`. Always `Bearer` for Azure AD.
    #[must_use]
    pub fn token_type(&self) -> &str {
        &self.token_type
    }
    /// The scopes that the `access_token` is valid for.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
    /// Number of seconds the `access_token` is valid for.
    #[must_use]
    pub fn expires_in(&self) -> u64 {
        self.expires_in
    }
    /// Absolute timestamp at which the `access_token` is no longer valid.
    ///
    /// Anchored to the moment the response was deserialized, so repeated
    /// reads of the same `RefreshTokenResponse` return the same expiry
    /// rather than drifting forward with the wall clock.
    #[must_use]
    pub fn expires_on(&self) -> OffsetDateTime {
        self.received_at + Duration::from_secs(self.expires_in)
    }
    /// Issued for the scopes that were requested.
    #[must_use]
    pub fn access_token(&self) -> &Secret {
        &self.access_token
    }
    /// The new refresh token and should replace old refresh token.
    #[must_use]
    pub fn refresh_token(&self) -> &Secret {
        &self.refresh_token
    }
    /// Indicates the extended lifetime of an `access_token`.
    #[must_use]
    pub fn ext_expires_in(&self) -> u64 {
        self.ext_expires_in
    }
}

mod deserialize {
    use serde::Deserializer;
    pub fn split<'de, D>(scope: D) -> Result<Vec<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string: String = serde::Deserialize::deserialize(scope)?;
        // OAuth scope is a space-separated list; use split_whitespace so
        // leading, trailing, or repeated separators never produce empty
        // scope entries.
        Ok(string.split_whitespace().map(ToOwned::to_owned).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_core::http::ClientOptions;

    fn require_send<T: Send>(_t: T) {}

    #[test]
    fn ensure_that_exchange_is_send() {
        let pipeline = Pipeline::new(None, None, ClientOptions::default(), vec![], vec![], None);
        require_send(exchange(
            &pipeline,
            "UNUSED",
            "UNUSED",
            None,
            &Secret::new("UNUSED"),
        ));
    }

    #[test]
    fn expires_on_is_stable_across_calls() -> azure_core::Result<()> {
        let body = r#"{
            "token_type": "Bearer",
            "scope": "https://example/.default",
            "expires_in": 3600,
            "ext_expires_in": 3600,
            "access_token": "a",
            "refresh_token": "r"
        }"#;
        let response: RefreshTokenResponse = azure_core::json::from_json(body)?;

        let first = response.expires_on();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let second = response.expires_on();

        assert_eq!(
            first, second,
            "expires_on must be anchored at deserialize time, not drift with wall clock",
        );
        Ok(())
    }

    #[derive(Debug)]
    struct CannedResponsePolicy {
        status: azure_core::http::StatusCode,
        body: &'static str,
    }

    #[async_trait::async_trait]
    impl azure_core::http::policies::Policy for CannedResponsePolicy {
        async fn send(
            &self,
            _ctx: &azure_core::http::Context,
            _request: &mut azure_core::http::Request,
            _next: &[std::sync::Arc<dyn azure_core::http::policies::Policy>],
        ) -> azure_core::http::policies::PolicyResult {
            use futures::FutureExt as _;
            async move {
                Ok(azure_core::http::AsyncRawResponse::from_bytes(
                    self.status,
                    azure_core::http::headers::Headers::new(),
                    azure_core::Bytes::from_static(self.body.as_bytes()),
                ))
            }
            .boxed()
            .await
        }
    }

    #[tokio::test]
    async fn non_success_response_wraps_structured_oauth_error() -> azure_core::Result<()> {
        use azure_core::http::{StatusCode, policies::Policy};
        use std::error::Error as _;
        use std::sync::Arc;

        let policy: Arc<dyn Policy> = Arc::new(CannedResponsePolicy {
            status: StatusCode::BadRequest,
            body: r#"{"error":"invalid_grant","error_description":"AADSTS70008: refresh token expired","error_uri":"https://login.microsoftonline.com/error?code=70008"}"#,
        });
        let pipeline = Pipeline::new(
            None,
            None,
            ClientOptions::default(),
            vec![policy],
            vec![],
            None,
        );

        let result = exchange(
            &pipeline,
            "tenant",
            "client",
            None,
            &Secret::new("refresh-token"),
        )
        .await;
        assert!(
            result.is_err(),
            "expected error from non-success refresh-token response",
        );
        let Err(err) = result else {
            return Ok(());
        };

        // Outer message keeps the endpoint context.
        let outer = err.to_string();
        assert!(
            outer.contains("refresh token endpoint returned status"),
            "missing endpoint context in: {outer}",
        );
        assert!(outer.contains("400"), "missing status code in: {outer}");

        // The structured OAuth error is the source of the returned Error.
        // Fold "source exists" and "source has expected content" into one
        // assertion path so we don't have to panic-unwrap: an empty
        // source_text fails both content asserts with a clear message.
        let source_text = err.source().map(ToString::to_string).unwrap_or_default();
        assert!(
            source_text.contains("invalid_grant"),
            "missing oauth error name in source (or no source attached): {source_text}",
        );
        assert!(
            source_text.contains("AADSTS70008"),
            "missing oauth error description in source: {source_text}",
        );
        Ok(())
    }
}
