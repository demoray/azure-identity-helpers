//! [AzureAuth CLI](https://github.com/AzureAD/microsoft-authentication-cli)
//! based authentication.

use crate::cache::TokenCache;
use async_lock::OnceCell;
use azure_core::{
    credentials::{AccessToken, Secret, TokenCredential, TokenRequestOptions},
    error::{Error, ErrorKind},
    json::from_json,
};
use azure_identity::{Executor, new_executor};
use serde::Deserialize;
use std::{ffi::OsStr, io, str, sync::Arc};
use time::OffsetDateTime;

mod unix_date_string {
    use azure_core::error::{Error, ErrorKind};
    use serde::{Deserialize, Deserializer, de};
    use time::OffsetDateTime;

    fn parse(s: &str) -> azure_core::Result<OffsetDateTime> {
        let as_i64 = s.parse().map_err(|e| {
            Error::with_message(
                ErrorKind::DataConversion,
                format!("unable to parse expiration_date '{s}': {e}"),
            )
        })?;

        OffsetDateTime::from_unix_timestamp(as_i64).map_err(|e| {
            Error::with_message(
                ErrorKind::DataConversion,
                format!("expiration_date '{s}' is not a valid unix timestamp ({as_i64}): {e}"),
            )
        })
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse(&s).map_err(de::Error::custom)
    }
}

#[derive(Deserialize)]
struct CliTokenResponse {
    // pub user: String,
    // pub display_name: String,
    #[serde(rename = "token")]
    access_token: Secret,
    #[serde(with = "unix_date_string", rename = "expiration_date")]
    expires_on: OffsetDateTime,
}

/// Authentication Mode
///
/// Note: While the azureauth CLI supports devicecode, users wishing to use
/// devicecode should use `azure_identity::device_code_flow`
#[derive(Debug, Clone, Copy)]
pub enum AzureauthCliMode {
    /// All available modes.
    All,
    /// Windows-only. Silently dropped on non-Windows: the `azureauth` POSIX
    /// build does not implement this mode, only `azureauth.exe` does.
    IntegratedWindowsAuth,
    /// Windows-only. Silently dropped on non-Windows for the same reason as
    /// [`Self::IntegratedWindowsAuth`].
    Broker,
    /// Browser-based web flow.
    Web,
}

/// Optional configuration for [`AzureauthCliCredential`].
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct AzureauthCliCredentialOptions {
    /// Authentication modes to pass to the azureauth CLI via `--mode`.
    /// Empty means the CLI picks its own default.
    ///
    /// Note: [`AzureauthCliMode::IntegratedWindowsAuth`] and
    /// [`AzureauthCliMode::Broker`] are only forwarded when the located
    /// executable is `azureauth.exe`; they're silently dropped on POSIX
    /// platforms because the POSIX azureauth build doesn't implement them.
    pub modes: Vec<AzureauthCliMode>,
    /// Optional prompt hint forwarded to the CLI via `--prompt-hint`.
    pub prompt_hint: Option<String>,
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
    /// Create a new `AzureauthCliCredential`.
    ///
    /// `options` configures the auth modes and prompt hint forwarded to the
    /// azureauth CLI. Pass `None` to accept the defaults (no `--mode`
    /// flags, no `--prompt-hint`); see [`AzureauthCliCredentialOptions`] for
    /// the available knobs.
    #[must_use]
    pub fn new<T, C>(
        tenant_id: T,
        client_id: C,
        options: Option<AzureauthCliCredentialOptions>,
    ) -> Arc<Self>
    where
        T: Into<String>,
        C: Into<String>,
    {
        let options = options.unwrap_or_default();
        Arc::new(Self {
            tenant_id: tenant_id.into(),
            client_id: client_id.into(),
            modes: options.modes,
            prompt_hint: options.prompt_hint,
            cache: TokenCache::new(),
            executor: new_executor(),
            cmd_name: OnceCell::new(),
        })
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
            io::ErrorKind::NotFound => {
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
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;
    use std::{
        ffi::OsString,
        process::Output,
        sync::{
            Mutex, PoisonError,
            atomic::{AtomicUsize, Ordering},
        },
    };

    #[cfg(test)]
    impl AzureauthCliCredential {
        fn new_with_executor(
            tenant_id: impl Into<String>,
            client_id: impl Into<String>,
            options: Option<AzureauthCliCredentialOptions>,
            executor: Arc<dyn Executor>,
        ) -> Arc<Self> {
            let options = options.unwrap_or_default();
            Arc::new(Self {
                tenant_id: tenant_id.into(),
                client_id: client_id.into(),
                modes: options.modes,
                prompt_hint: options.prompt_hint,
                cache: TokenCache::new(),
                executor,
                cmd_name: OnceCell::new(),
            })
        }
    }

    fn success_output() -> Output {
        Output {
            status: ExitStatusExt::from_raw(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    #[derive(Debug, Default)]
    struct CountingExecutor {
        which_calls: AtomicUsize,
        azureauth_calls: AtomicUsize,
        // Captures the args passed to each `aad` invocation so tests can
        // assert that options.modes / options.prompt_hint actually reach
        // the command line.
        last_azureauth_args: Mutex<Vec<OsString>>,
    }

    #[async_trait::async_trait]
    impl Executor for CountingExecutor {
        async fn run(&self, program: &OsStr, args: &[&OsStr]) -> io::Result<Output> {
            if program == OsStr::new("which") || program == OsStr::new("where") {
                self.which_calls.fetch_add(1, Ordering::SeqCst);
                Ok(success_output())
            } else {
                self.azureauth_calls.fetch_add(1, Ordering::SeqCst);
                if let Ok(mut captured) = self.last_azureauth_args.lock() {
                    *captured = args.iter().map(|a| (*a).to_os_string()).collect();
                }
                // Pretend the azureauth invocation itself fails so the
                // credential surfaces an error rather than trying to parse
                // an empty JSON body.
                Err(io::Error::other("test"))
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

        let expected = OffsetDateTime::from_unix_timestamp(1_700_166_595).map_err(|e| {
            Error::with_message(
                ErrorKind::DataConversion,
                format!("hard-coded unix timestamp should be valid: {e}"),
            )
        })?;

        assert_eq!(response.expires_on, expected);

        Ok(())
    }

    #[tokio::test]
    async fn azureauth_binary_lookup_is_cached_across_calls() {
        let executor = Arc::new(CountingExecutor::default());
        let credential =
            AzureauthCliCredential::new_with_executor("tenant", "client", None, executor.clone());

        // Two get_token calls with different scopes so the TokenCache
        // doesn't short-circuit the second one.
        let _token_a = credential.get_token(&["scope-a"], None).await;
        let _token_b = credential.get_token(&["scope-b"], None).await;

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

    #[tokio::test]
    async fn options_modes_and_prompt_hint_reach_the_cli() {
        let executor = Arc::new(CountingExecutor::default());
        let credential = AzureauthCliCredential::new_with_executor(
            "tenant",
            "client",
            Some(AzureauthCliCredentialOptions {
                modes: vec![AzureauthCliMode::All, AzureauthCliMode::Web],
                prompt_hint: Some("hello-prompt".to_owned()),
            }),
            executor.clone(),
        );

        let _token_a = credential.get_token(&["scope-a"], None).await;

        let args = executor
            .last_azureauth_args
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let args_str: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        // `--prompt-hint <value>` and `--mode <value>` pairs must appear on
        // the command line. Walk the args as windows of 2 so we never index
        // past the end.
        let pairs: Vec<(&str, &str)> = args_str
            .windows(2)
            .filter_map(|w| {
                let (flag, value) = (w.first()?.as_str(), w.get(1)?.as_str());
                Some((flag, value))
            })
            .collect();

        let prompt_hints: Vec<&str> = pairs
            .iter()
            .filter_map(|(flag, value)| (*flag == "--prompt-hint").then_some(*value))
            .collect();
        assert_eq!(prompt_hints, vec!["hello-prompt"], "args were {args_str:?}");

        let mode_values: Vec<&str> = pairs
            .iter()
            .filter_map(|(flag, value)| (*flag == "--mode").then_some(*value))
            .collect();
        assert!(
            mode_values.contains(&"all"),
            "missing --mode all: {args_str:?}",
        );
        assert!(
            mode_values.contains(&"web"),
            "missing --mode web: {args_str:?}",
        );
    }
}
