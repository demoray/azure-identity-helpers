// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! Shared OAuth 2.0 error response shape (RFC 6749 §5.2).
//!
//! Both the device-code flow and refresh-token exchange surface failures
//! through the same JSON body shape. The type lives here so neither
//! `device_code` nor `refresh_token` owns it; both depend on it instead.

use serde::Deserialize;
use std::{error::Error, fmt};

/// OAuth 2.0 error response body, per
/// [RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2).
///
/// Returned by the AAD device-code and refresh-token endpoints on failure
/// (and by the device-code polling endpoint for normal control-flow signals
/// such as `authorization_pending` and `slow_down`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OAuthErrorResponse {
    error: String,
    // RFC 6749 §5.2 marks `error_description` and `error_uri` as OPTIONAL.
    // Default to an empty string so a body that omits either field still
    // parses as a structured error rather than getting reported as an
    // unstructured status-code-only failure.
    #[serde(default)]
    error_description: String,
    #[serde(default)]
    error_uri: String,
}

impl OAuthErrorResponse {
    /// Name of the error (the OAuth `error` field).
    #[must_use]
    pub fn error(&self) -> &str {
        &self.error
    }
    /// Human-readable description of the error. May be empty.
    #[must_use]
    pub fn error_description(&self) -> &str {
        &self.error_description
    }
    /// URI with additional information about the error. May be empty.
    #[must_use]
    pub fn error_uri(&self) -> &str {
        &self.error_uri
    }
}

impl Error for OAuthErrorResponse {}

impl fmt::Display for OAuthErrorResponse {
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

#[cfg(test)]
mod tests {
    use super::*;
    use azure_core::json::from_json;

    #[test]
    fn parses_when_optional_fields_are_missing() -> azure_core::Result<()> {
        // RFC 6749 §5.2 marks error_description and error_uri as OPTIONAL.
        // A body that includes only `error` must still parse so the
        // polling loop can act on `authorization_pending` / `slow_down`.
        let body = r#"{ "error": "authorization_pending" }"#;
        let parsed: OAuthErrorResponse = from_json(body)?;

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
        let parsed: OAuthErrorResponse = from_json(body)?;
        let formatted = parsed.to_string();
        assert!(formatted.contains("invalid_grant"), "{formatted}");
        assert!(formatted.contains("AADSTS70008"), "{formatted}");
        assert!(formatted.contains("error?code=70008"), "{formatted}");
        Ok(())
    }
}
