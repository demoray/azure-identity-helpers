// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

use azure_core::credentials::Secret;
use serde::Deserialize;
use std::{fmt, time::Duration};
use time::OffsetDateTime;

/// Error response returned from the device code flow.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeviceCodeErrorResponse {
    error: String,
    // The OAuth 2.0 error response (RFC 6749 §5.2) marks
    // `error_description` and `error_uri` as OPTIONAL. Default to an
    // empty string so a body that omits either field still parses as a
    // structured error rather than getting reported as an unstructured
    // status-code-only failure.
    #[serde(default)]
    error_description: String,
    #[serde(default)]
    error_uri: String,
}

impl DeviceCodeErrorResponse {
    /// Name of the error.
    #[must_use]
    pub fn error(&self) -> &str {
        &self.error
    }
    /// Description of the error. May be empty.
    #[must_use]
    pub fn error_description(&self) -> &str {
        &self.error_description
    }
    /// Uri to get more information on this error. May be empty.
    #[must_use]
    pub fn error_uri(&self) -> &str {
        &self.error_uri
    }
}

impl std::error::Error for DeviceCodeErrorResponse {}

impl fmt::Display for DeviceCodeErrorResponse {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.error)?;
        if !self.error_description.is_empty() {
            write!(f, ". {}", self.error_description)?;
        }
        if !self.error_uri.is_empty() {
            write!(f, " ({})", self.error_uri)?;
        }
        Ok(())
    }
}

/// A successful token response.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceCodeAuthorization {
    /// Always `Bearer`.
    token_type: String,
    /// The scopes the access token is valid for.
    /// Format: Space separated strings
    scope: String,
    /// Number of seconds the included access token is valid for.
    expires_in: u64,
    /// Issued for the scopes that were requested.
    /// Format: Opaque string
    access_token: Secret,
    /// Issued if the original scope parameter included `offline_access`.
    /// Format: JWT
    refresh_token: Option<Secret>,
    /// Issued if the original scope parameter included the openid scope.
    /// Format: Opaque string
    id_token: Option<Secret>,
    /// Reference point used to derive [`Self::expires_on`]. Captured at
    /// deserialize time so the absolute expiry is stable across repeated
    /// reads of the same authorization.
    #[serde(skip, default = "OffsetDateTime::now_utc")]
    received_at: OffsetDateTime,
}

impl DeviceCodeAuthorization {
    /// The token type. Always `Bearer` for Azure AD.
    #[must_use]
    pub fn token_type(&self) -> &str {
        &self.token_type
    }
    /// The space-separated list of scopes the access token is valid for.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }
    /// Number of seconds the access token is valid for at the time the
    /// response was issued.
    #[must_use]
    pub fn expires_in(&self) -> u64 {
        self.expires_in
    }
    /// Absolute timestamp at which the `access_token` is no longer valid.
    ///
    /// Anchored to the moment the response was deserialized, so repeated
    /// reads of the same `DeviceCodeAuthorization` return the same expiry
    /// rather than drifting forward with the wall clock.
    #[must_use]
    pub fn expires_on(&self) -> OffsetDateTime {
        self.received_at + Duration::from_secs(self.expires_in)
    }
    /// Get the access token
    #[must_use]
    pub fn access_token(&self) -> &Secret {
        &self.access_token
    }
    /// Get the refresh token
    #[must_use]
    pub fn refresh_token(&self) -> Option<&Secret> {
        self.refresh_token.as_ref()
    }
    /// Get the id token
    #[must_use]
    pub fn id_token(&self) -> Option<&Secret> {
        self.id_token.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expires_on_is_stable_across_calls() -> azure_core::Result<()> {
        let body = r#"{
            "token_type": "Bearer",
            "scope": "https://example/.default",
            "expires_in": 3600,
            "access_token": "a"
        }"#;
        let auth: DeviceCodeAuthorization = azure_core::json::from_json(body)?;

        let first = auth.expires_on();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let second = auth.expires_on();

        assert_eq!(
            first, second,
            "expires_on must be anchored at deserialize time, not drift with wall clock",
        );
        Ok(())
    }

    #[test]
    fn error_response_parses_when_optional_fields_are_missing() -> azure_core::Result<()> {
        // RFC 6749 §5.2 marks error_description and error_uri as OPTIONAL.
        // A body that includes only `error` must still parse so the
        // polling loop can act on `authorization_pending` / `slow_down`.
        let body = r#"{ "error": "authorization_pending" }"#;
        let parsed: DeviceCodeErrorResponse = azure_core::json::from_json(body)?;

        assert_eq!(parsed.error(), "authorization_pending");
        assert_eq!(parsed.error_description(), "");
        assert_eq!(parsed.error_uri(), "");
        assert_eq!(parsed.to_string(), "authorization_pending");
        Ok(())
    }

    #[test]
    fn display_surfaces_error_uri_when_present() -> azure_core::Result<()> {
        let body = r#"{
            "error": "invalid_grant",
            "error_description": "AADSTS70008",
            "error_uri": "https://login.microsoftonline.com/error?code=70008"
        }"#;
        let parsed: DeviceCodeErrorResponse = azure_core::json::from_json(body)?;
        let formatted = parsed.to_string();
        assert!(formatted.contains("invalid_grant"), "{formatted}");
        assert!(formatted.contains("AADSTS70008"), "{formatted}");
        assert!(formatted.contains("error?code=70008"), "{formatted}");
        Ok(())
    }
}
