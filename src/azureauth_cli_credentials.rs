use crate::cache::TokenCache;
use async_lock::OnceCell;
use azure_core::{
    credentials::{AccessToken, Secret, TokenCredential, TokenRequestOptions},
    error::{Error, ErrorKind},
    json::from_json,
};
use azure_identity::{Executor, new_executor};
use serde::Deserialize;
use std::{ffi::OsStr, str, sync::Arc};
use time::OffsetDateTime;

mod unix_date_string {
    use azure_core::error::{Error, ErrorKind};
    use serde::{Deserialize, Deserializer};
    use time::OffsetDateTime;

    pub fn parse(s: &str) -> azure_core::Result<OffsetDateTime> {
        let as_i64 = s.parse().map_err(|_| {
            Error::with_message(
                ErrorKind::DataConversion,
                format!("unable to parse expiration_date '{s}"),
            )
        })?;

        OffsetDateTime::from_unix_timestamp(as_i64).map_err(|_| {
            Error::with_message(
                ErrorKind::DataConversion,
                format!("unable to parse expiration_date '{s}"),
            )
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
    executor: Arc<dyn Executor>,
    cmd_name: OnceCell<&'static OsStr>,
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
            executor: new_executor(),
            cmd_name: OnceCell::new(),
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

    async fn locate_azureauth(&self) -> azure_core::Result<&'static OsStr> {
        self.cmd_name
            .get_or_try_init(|| async {
                find_azureauth(self.executor.as_ref()).await.ok_or_else(|| {
                    Error::with_message(ErrorKind::Other, "azureauth CLI not installed")
                })
            })
            .await
            .copied()
    }

    async fn get_access_token(
        &self,
        scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        let cmd_name = self.locate_azureauth().await?;
        let use_windows_features = cmd_name == "azureauth.exe";

        // self.credential_options.
        let mut cmd = vec![
            "aad",
            "--client",
            self.client_id.as_str(),
            "--tenant",
            self.tenant_id.as_str(),
            "--output",
            "json",
        ];

        for scope in scopes {
            cmd.extend(["--scope", scope]);
        }

        if let Some(prompt_hint) = &self.prompt_hint {
            cmd.extend(["--prompt-hint", prompt_hint]);
        }

        for mode in &self.modes {
            if let Some(mode) = match mode {
                AzureauthCliMode::All => Some("all"),
                AzureauthCliMode::IntegratedWindowsAuth => use_windows_features.then_some("iwa"),
                AzureauthCliMode::Broker => use_windows_features.then_some("broker"),
                AzureauthCliMode::Web => Some("web"),
            } {
                cmd.extend(["--mode", mode]);
            }
        }

        let cmd = cmd.iter().map(AsRef::as_ref).collect::<Vec<&OsStr>>();

        let result = self.executor.run(cmd_name, &cmd).await;

        let output = result.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                Error::with_message(ErrorKind::Other, "azureauth CLI not installed")
            }
            _ => Error::with_error(ErrorKind::Other, e, "running azureauth CLI"),
        })?;

        if !output.status.success() {
            let output = String::from_utf8_lossy(&output.stderr);
            return Err(Error::with_message(
                ErrorKind::Credential,
                format!("'azureauth' command failed: {output}"),
            ));
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
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        self.cache
            .get_token(scopes, options, |s, o| self.get_access_token(s, o))
            .await
    }
}

/// Find the azureauth CLI executable
///
/// This function checks for the presence of `azureauth.exe` and `azureauth` in the system's `PATH`.
///
/// To support using azureauth within WSL, this checks for `azureauth.exe` first.
pub(crate) async fn find_azureauth(executor: &dyn Executor) -> Option<&'static OsStr> {
    #[cfg(target_os = "windows")]
    let which = "where";
    #[cfg(not(target_os = "windows"))]
    let which = "which";

    for &exe in &[OsStr::new("azureauth.exe"), OsStr::new("azureauth")] {
        if executor
            .run(OsStr::new(which), &[exe])
            .await
            .is_ok_and(|x| x.status.success())
        {
            return Some(exe);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        process::Output,
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[cfg(test)]
    impl AzureauthCliCredential {
        fn new_with_executor(
            tenant_id: impl Into<String>,
            client_id: impl Into<String>,
            executor: Arc<dyn Executor>,
        ) -> Arc<Self> {
            Arc::new(Self {
                tenant_id: tenant_id.into(),
                client_id: client_id.into(),
                modes: Vec::new(),
                prompt_hint: None,
                cache: TokenCache::new(),
                executor,
                cmd_name: OnceCell::new(),
            })
        }
    }

    fn success_output() -> Output {
        Output {
            status: {
                #[cfg(windows)]
                {
                    std::os::windows::process::ExitStatusExt::from_raw(0)
                }
                #[cfg(unix)]
                {
                    std::os::unix::process::ExitStatusExt::from_raw(0)
                }
            },
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    #[derive(Debug, Default)]
    struct CountingExecutor {
        which_calls: AtomicUsize,
        azureauth_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Executor for CountingExecutor {
        async fn run(&self, program: &OsStr, _args: &[&OsStr]) -> std::io::Result<Output> {
            if program == OsStr::new("which") || program == OsStr::new("where") {
                self.which_calls.fetch_add(1, Ordering::SeqCst);
                Ok(success_output())
            } else {
                // Pretend the azureauth invocation itself fails so the
                // credential surfaces an error rather than trying to parse
                // an empty JSON body; the test only cares about how many
                // times we ran `which` / `where`.
                self.azureauth_calls.fetch_add(1, Ordering::SeqCst);
                Err(std::io::Error::other("test"))
            }
        }
    }

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

    #[tokio::test]
    async fn azureauth_binary_lookup_is_cached_across_calls() {
        let executor = Arc::new(CountingExecutor::default());
        let credential = AzureauthCliCredential::new_with_executor(
            "tenant",
            "client",
            executor.clone() as Arc<dyn Executor>,
        );

        // Two get_token calls with different scopes so the TokenCache
        // doesn't short-circuit the second one.
        let _ = credential.get_token(&["scope-a"], None).await;
        let _ = credential.get_token(&["scope-b"], None).await;

        assert_eq!(
            executor.which_calls.load(Ordering::SeqCst),
            1,
            "find_azureauth should run `which`/`where` exactly once across multiple get_token calls",
        );
        assert_eq!(
            executor.azureauth_calls.load(Ordering::SeqCst),
            2,
            "every get_token call should still reach the azureauth invocation",
        );
    }
}
