// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! Refresh tokens.

use azure_core::{
    credentials::Secret,
    error::{Error, ErrorKind, ResultExt, http_response_from_body},
    http::{HttpClient, Method, Request, Url, headers, headers::content_type},
    json::from_json,
};
use serde::Deserialize;
use std::{fmt, sync::Arc};
use url::form_urlencoded;

/// Exchange a refresh token for a new access token and refresh token.
#[allow(dead_code)]
pub async fn exchange(
    http_client: Arc<dyn HttpClient>,
    tenant_id: &str,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &Secret,
) -> azure_core::Result<RefreshTokenResponse> {
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

    let rsp = http_client.execute_request(&req).await?;
    let rsp_status = rsp.status();

    if rsp_status.is_success() {
        rsp.into_body().json().await.map_kind(ErrorKind::Credential)
    } else {
        let rsp_body = rsp.into_body().collect().await?;
        let token_error: RefreshTokenError =
            from_json(&rsp_body).map_err(|_| http_response_from_body(rsp_status, &rsp_body))?;
        Err(Error::new(ErrorKind::Credential, token_error))
    }
}

/// A refresh token
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct RefreshTokenResponse {
    token_type: String,
    #[serde(rename = "scope", deserialize_with = "deserialize::split")]
    scopes: Vec<String>,
    expires_in: u64,
    ext_expires_in: u64,
    access_token: Secret,
    refresh_token: Secret,
}

#[allow(dead_code)]
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
        Ok(string.split(' ').map(ToOwned::to_owned).collect())
    }
}

// cspell:ignore suberror

/// An error response body when there is an error requesting a token
#[derive(Debug, Clone, Deserialize)]
#[allow(unused)]
pub struct RefreshTokenError {
    error: String,
    error_description: String,
    error_codes: Vec<i64>,
    timestamp: Option<String>,
    trace_id: Option<String>,
    correlation_id: Option<String>,
    suberror: Option<String>,
    claims: Option<String>,
}

impl std::error::Error for RefreshTokenError {}

impl fmt::Display for RefreshTokenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::result::Result<(), fmt::Error> {
        writeln!(f, "error: {}", self.error)?;
        if let Some(suberror) = &self.suberror {
            writeln!(f, "suberror: {suberror}")?;
        }
        writeln!(f, "description: {}", self.error_description)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn require_send<T: Send>(_t: T) {}

    #[test]
    fn ensure_that_exchange_is_send() {
        require_send(exchange(
            azure_core::http::new_http_client(),
            "UNUSED",
            "UNUSED",
            None,
            &Secret::new("UNUSED"),
        ));
    }
}
