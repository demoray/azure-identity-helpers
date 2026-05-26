// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

use azure_core::credentials::Secret;
use serde::Deserialize;
use std::time::Duration;
use time::OffsetDateTime;

/// A successful token response.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceCodeAuthorization {
    /// Always `Bearer`.
    token_type: String,
    /// The scopes the access token is valid for, parsed from the
    /// space-separated wire format.
    #[serde(rename = "scope", deserialize_with = "deserialize_scopes")]
    scopes: Vec<String>,
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

fn deserialize_scopes<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: String = serde::Deserialize::deserialize(deserializer)?;
    // OAuth scope is a space-separated list; use split_whitespace so leading,
    // trailing, or repeated separators never produce empty scope entries.
    Ok(raw.split_whitespace().map(ToOwned::to_owned).collect())
}

impl DeviceCodeAuthorization {
    /// The token type. Always `Bearer` for Azure AD.
    #[must_use]
    pub fn token_type(&self) -> &str {
        &self.token_type
    }
    /// The scopes the access token is valid for.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
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
    fn authorization_splits_space_separated_scopes() -> azure_core::Result<()> {
        let body = r#"{
            "token_type": "Bearer",
            "scope": "https://example/.default offline_access openid",
            "expires_in": 3600,
            "access_token": "a"
        }"#;
        let auth: DeviceCodeAuthorization = azure_core::json::from_json(body)?;
        assert_eq!(
            auth.scopes(),
            ["https://example/.default", "offline_access", "openid"],
        );
        Ok(())
    }

    #[test]
    fn authorization_scope_split_ignores_extra_whitespace() -> azure_core::Result<()> {
        // Real-world wire data sometimes has leading/trailing spaces or
        // doubled separators; split_whitespace must skip them so callers
        // never see empty scope entries.
        let body = r#"{
            "token_type": "Bearer",
            "scope": "  one  two  three  ",
            "expires_in": 3600,
            "access_token": "a"
        }"#;
        let auth: DeviceCodeAuthorization = azure_core::json::from_json(body)?;
        assert_eq!(auth.scopes(), ["one", "two", "three"]);
        Ok(())
    }
}
