use crate::cache::TokenCache;
use azure_core::{
    credentials::{AccessToken, Secret, TokenCredential},
    error::{Error, ErrorKind},
    json::from_json,
};
use serde::Deserialize;
use std::{str, sync::Arc};
use time::OffsetDateTime;
use tokio::process::Command;

mod unix_date_string {
    use azure_core::error::{Error, ErrorKind};
    use serde::{Deserialize, Deserializer};
    use time::OffsetDateTime;

    pub fn parse(s: &str) -> azure_core::Result<OffsetDateTime> {
        let as_i64 = s.parse().map_err(|_| {
            Error::with_message(ErrorKind::DataConversion, || {
                format!("unable to parse expiration_date '{s}")
            })
        })?;

        OffsetDateTime::from_unix_timestamp(as_i64).map_err(|_| {
            Error::with_message(ErrorKind::DataConversion, || {
                format!("unable to parse expiration_date '{s}")
            })
        })
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
struct CliTokenResponse {
    // pub user: String,
    // pub display_name: String,
    #[serde(rename = "token")]
    pub access_token: Secret,
    #[serde(with = "unix_date_string", rename = "expiration_date")]
    pub expires_on: OffsetDateTime,
}

/// Authentication Mode
///
/// Note: While the azureauth CLI supports devicecode, users wishing to use
/// devicecode should use `azure_identity::device_code_flow`
#[derive(Debug, Clone, Copy)]
pub enum AzureauthCliMode {
    All,
    IntegratedWindowsAuth,
    Broker,
    Web,
}

#[derive(Debug)]
/// Enables authentication to Azure Active Directory using Azure CLI to obtain an access token.
pub struct AzureauthCliCredential {
    tenant_id: String,
    client_id: String,
    modes: Vec<AzureauthCliMode>,
    prompt_hint: Option<String>,
    cache: TokenCache,
}

impl AzureauthCliCredential {
    /// Create a new `AzureCliCredential`
    pub fn new<T, C>(tenant_id: T, client_id: C) -> azure_core::Result<Arc<Self>>
    where
        T: Into<String>,
        C: Into<String>,
    {
        Ok(Arc::new(Self {
            tenant_id: tenant_id.into(),
            client_id: client_id.into(),
            modes: Vec::new(),
            prompt_hint: None,
            cache: TokenCache::new(),
        }))
    }

    #[must_use]
    pub fn add_mode(mut self, mode: AzureauthCliMode) -> Self {
        self.modes.push(mode);
        self
    }

    #[must_use]
    pub fn with_modes(mut self, modes: Vec<AzureauthCliMode>) -> Self {
        self.modes = modes;
        self
    }

    #[must_use]
    pub fn with_prompt_hint<S>(mut self, hint: S) -> Self
    where
        S: Into<String>,
    {
        self.prompt_hint = Some(hint.into());
        self
    }

    async fn get_access_token(&self, scopes: &[&str]) -> azure_core::Result<AccessToken> {
        let cmd_name = find_azureauth()
            .await
            .ok_or_else(|| Error::message(ErrorKind::Other, "azureauth CLI not installed"))?;
        let use_windows_features = cmd_name == "azureauth.exe";

        let mut cmd = Command::new(cmd_name);
        cmd.args([
            "aad",
            "--client",
            self.client_id.as_str(),
            "--tenant",
            self.tenant_id.as_str(),
            "--output",
            "json",
        ]);

        for scope in scopes {
            cmd.args(["--scope", scope]);
        }

        if let Some(prompt_hint) = &self.prompt_hint {
            cmd.args(["--prompt-hint", prompt_hint]);
        }

        for mode in &self.modes {
            if let Some(mode) = match mode {
                AzureauthCliMode::All => Some("all"),
                AzureauthCliMode::IntegratedWindowsAuth => use_windows_features.then_some("iwa"),
                AzureauthCliMode::Broker => use_windows_features.then_some("broker"),
                AzureauthCliMode::Web => Some("web"),
            } {
                cmd.args(["--mode", mode]);
            }
        }

        let result = cmd.output().await;

        let output = result.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                Error::message(ErrorKind::Other, "azureauth CLI not installed")
            }
            error_kind => Error::with_message(ErrorKind::Other, || {
                format!("Unknown error of kind: {error_kind:?}")
            }),
        })?;

        if !output.status.success() {
            let output = String::from_utf8_lossy(&output.stderr);
            return Err(Error::with_message(ErrorKind::Credential, || {
                format!("'azureauth' command failed: {output}")
            }));
        }

        let token_response: CliTokenResponse = from_json(output.stdout)?;
        Ok(AccessToken {
            token: token_response.access_token,
            expires_on: token_response.expires_on,
        })
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl TokenCredential for AzureauthCliCredential {
    async fn get_token(&self, scopes: &[&str]) -> azure_core::Result<AccessToken> {
        self.cache
            .get_token(scopes, self.get_access_token(scopes))
            .await
    }

    async fn clear_cache(&self) -> azure_core::Result<()> {
        // Clear internal cache only as there is no guarantee that the underlying MSAL caches will be cleared through azureauth.
        // But clearing internally will force a new call to azureauth which handles refreshing the MSAL cache and always returns a valid token.
        self.cache.clear().await
    }
}

/// Find the azureauth CLI executable
///
/// This function checks for the presence of `azureauth.exe` and `azureauth` in the system's `PATH`.
///
/// To support using azureauth within WSL, this checks for `azureauth.exe` first.
pub async fn find_azureauth() -> Option<&'static str> {
    #[cfg(target_os = "windows")]
    let which = "where";
    #[cfg(not(target_os = "windows"))]
    let which = "which";

    for &exe in &["azureauth.exe", "azureauth"] {
        if Command::new(which)
            .arg(exe)
            .output()
            .await
            .map(|x| x.status.success())
            .unwrap_or(false)
        {
            return Some(exe);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_example() -> azure_core::Result<()> {
        let src = r#"{
            "user": "example@contoso.com",
            "display_name": "Example User",
            "token": "security token here",
            "expiration_date": "1700166595"
        }"#;

        let response: CliTokenResponse = from_json(src)?;
        assert_eq!(response.access_token.secret(), "security token here");

        #[allow(clippy::expect_used)]
        let expected =
            OffsetDateTime::from_unix_timestamp(1_700_166_595).expect("known valid date");

        assert_eq!(response.expires_on, expected);

        Ok(())
    }
}
