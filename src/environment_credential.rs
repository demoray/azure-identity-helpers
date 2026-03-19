//! Recreates an `EnvironmentCredential`-style helper for service principal
//! authentication from environment variables.
//!
//! This helper uses the following environment variables:
//! - `AZURE_TENANT_ID`
//! - `AZURE_CLIENT_ID`
//! - `AZURE_CLIENT_SECRET`

use azure_core::{
    credentials::{AccessToken, Secret, TokenCredential, TokenRequestOptions},
    error::{Error, ErrorKind},
};
use azure_identity::{
    ClientSecretCredential, ClientSecretCredentialOptions, WorkloadIdentityCredential,
    WorkloadIdentityCredentialOptions,
};
use std::{env, path::PathBuf, sync::Arc};

const AZURE_CLIENT_ID: &str = "AZURE_CLIENT_ID";
const AZURE_CLIENT_SECRET: &str = "AZURE_CLIENT_SECRET";
const AZURE_FEDERATED_TOKEN_FILE: &str = "AZURE_FEDERATED_TOKEN_FILE";
const AZURE_TENANT_ID: &str = "AZURE_TENANT_ID";

#[derive(Debug, Clone, Default)]
pub(crate) struct EnvironmentSettings {
    client_id: Option<String>,
    client_secret: Option<String>,
    federated_token_file: Option<PathBuf>,
    tenant_id: Option<String>,
}

impl EnvironmentSettings {
    pub(crate) fn from_os_env() -> Self {
        Self {
            client_id: env::var(AZURE_CLIENT_ID).ok(),
            client_secret: env::var(AZURE_CLIENT_SECRET).ok(),
            federated_token_file: env::var_os(AZURE_FEDERATED_TOKEN_FILE).map(PathBuf::from),
            tenant_id: env::var(AZURE_TENANT_ID).ok(),
        }
    }
}

#[derive(Debug)]
enum EnvironmentCredentialSource {
    ClientSecret(Arc<ClientSecretCredential>),
}

#[derive(Debug)]
pub struct EnvironmentCredential {
    source: EnvironmentCredentialSource,
}

impl EnvironmentCredential {
    /// Create an `EnvironmentCredential` from the current process environment.
    pub fn new(
        client_secret_credential_options: Option<ClientSecretCredentialOptions>,
    ) -> azure_core::Result<Arc<Self>> {
        Self::from_settings(
            &EnvironmentSettings::from_os_env(),
            client_secret_credential_options,
        )
    }

    pub(crate) fn from_settings(
        environment: &EnvironmentSettings,
        client_secret_credential_options: Option<ClientSecretCredentialOptions>,
    ) -> azure_core::Result<Arc<Self>> {
        let credential =
            create_client_secret_credential(environment, client_secret_credential_options)?;
        Ok(Arc::new(Self {
            source: EnvironmentCredentialSource::ClientSecret(credential),
        }))
    }

    #[cfg(test)]
    fn source_name(&self) -> &'static str {
        match &self.source {
            EnvironmentCredentialSource::ClientSecret(_) => "client_secret",
        }
    }
}

pub(crate) fn create_workload_identity_credential(
    environment: &EnvironmentSettings,
    options: Option<WorkloadIdentityCredentialOptions>,
) -> azure_core::Result<Arc<WorkloadIdentityCredential>> {
    let mut options = options.unwrap_or_default();
    options.client_id = Some(
        options
            .client_id
            .take()
            .or_else(|| environment.client_id.clone())
            .ok_or_else(|| {
                Error::with_message(
                    ErrorKind::Credential,
                    format!("{AZURE_CLIENT_ID} environment variable is not set"),
                )
            })?,
    );
    options.tenant_id = Some(
        options
            .tenant_id
            .take()
            .or_else(|| environment.tenant_id.clone())
            .ok_or_else(|| {
                Error::with_message(
                    ErrorKind::Credential,
                    format!("{AZURE_TENANT_ID} environment variable is not set"),
                )
            })?,
    );
    options.token_file_path = Some(
        options
            .token_file_path
            .take()
            .or_else(|| environment.federated_token_file.clone())
            .ok_or_else(|| {
                Error::with_message(
                    ErrorKind::Credential,
                    format!("{AZURE_FEDERATED_TOKEN_FILE} environment variable is not set"),
                )
            })?,
    );

    WorkloadIdentityCredential::new(Some(options))
}

fn create_client_secret_credential(
    environment: &EnvironmentSettings,
    options: Option<ClientSecretCredentialOptions>,
) -> azure_core::Result<Arc<ClientSecretCredential>> {
    let tenant_id = required_environment_value(AZURE_TENANT_ID, environment.tenant_id.as_deref())?;
    let client_id = required_environment_value(AZURE_CLIENT_ID, environment.client_id.as_deref())?;
    let client_secret =
        required_environment_value(AZURE_CLIENT_SECRET, environment.client_secret.as_deref())?;

    ClientSecretCredential::new(
        tenant_id,
        client_id.to_owned(),
        Secret::new(client_secret.to_owned()),
        options,
    )
}

fn required_environment_value<'a>(
    variable_name: &'static str,
    value: Option<&'a str>,
) -> azure_core::Result<&'a str> {
    value.ok_or_else(|| {
        Error::with_message(
            ErrorKind::Credential,
            format!("{variable_name} environment variable is not set"),
        )
    })
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl TokenCredential for EnvironmentCredential {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        match &self.source {
            EnvironmentCredentialSource::ClientSecret(credential) => {
                credential.get_token(scopes, options).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static TEMP_FILE_COUNTER: AtomicUsize = AtomicUsize::new(0);

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(contents: &str) -> std::io::Result<Self> {
            let suffix = TEMP_FILE_COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = env::temp_dir().join(format!("azure-identity-helpers-{suffix}.tmp"));
            fs::write(&path, contents)?;
            Ok(Self { path })
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    #[test]
    fn environment_credential_uses_client_secret_even_with_federated_token()
    -> azure_core::Result<()> {
        let token_file = TempFile::new("federated token")
            .map_err(|error| Error::with_error(ErrorKind::Io, error, "creating temp token file"))?;
        let credential = EnvironmentCredential::from_settings(
            &EnvironmentSettings {
                client_id: Some(String::from("fake-client")),
                client_secret: Some(String::from("fake-secret")),
                federated_token_file: Some(token_file.path.clone()),
                tenant_id: Some(String::from("fake-tenant")),
            },
            None,
        )?;

        assert_eq!(credential.source_name(), "client_secret");
        Ok(())
    }

    #[test]
    fn workload_identity_credential_uses_federated_token_configuration() -> azure_core::Result<()> {
        let token_file = TempFile::new("federated token")
            .map_err(|error| Error::with_error(ErrorKind::Io, error, "creating temp token file"))?;
        create_workload_identity_credential(
            &EnvironmentSettings {
                client_id: Some(String::from("fake-client")),
                client_secret: None,
                federated_token_file: Some(token_file.path.clone()),
                tenant_id: Some(String::from("fake-tenant")),
            },
            None,
        )?;

        Ok(())
    }

    #[test]
    fn environment_credential_requires_client_secret_configuration() {
        let error = EnvironmentCredential::from_settings(
            &EnvironmentSettings {
                client_id: Some(String::from("fake-client")),
                client_secret: None,
                federated_token_file: None,
                tenant_id: Some(String::from("fake-tenant")),
            },
            None,
        );

        assert!(matches!(
            error,
            Err(ref error) if matches!(error.kind(), ErrorKind::Credential)
        ));
    }

    #[test]
    fn environment_credential_with_client_secret_is_valid() -> azure_core::Result<()> {
        let credential = EnvironmentCredential::from_settings(
            &EnvironmentSettings {
                client_id: Some(String::from("fake-client")),
                client_secret: Some(String::from("fake-secret")),
                federated_token_file: None,
                tenant_id: Some(String::from("fake-tenant")),
            },
            None,
        )?;

        assert_eq!(credential.source_name(), "client_secret");
        Ok(())
    }

    #[test]
    fn workload_identity_credential_requires_configuration() {
        let error = create_workload_identity_credential(&EnvironmentSettings::default(), None);

        assert!(matches!(
            error,
            Err(ref error) if matches!(error.kind(), ErrorKind::Credential)
        ));
    }
}
