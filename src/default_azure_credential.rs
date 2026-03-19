use crate::{
    chained_token_credential::{
        ChainedTokenCredential, ChainedTokenCredentialOptions, format_aggregate_error,
    },
    environment_credential::{
        EnvironmentCredential, EnvironmentSettings, create_workload_identity_credential,
    },
};
use azure_core::{
    credentials::{AccessToken, TokenCredential, TokenRequestOptions},
    error::{Error, ErrorKind},
};
#[cfg(not(target_arch = "wasm32"))]
use azure_identity::{
    AzureCliCredential, AzureCliCredentialOptions, AzureDeveloperCliCredential,
    AzureDeveloperCliCredentialOptions,
};
use azure_identity::{
    ClientSecretCredentialOptions, ManagedIdentityCredential, ManagedIdentityCredentialOptions,
    WorkloadIdentityCredentialOptions,
};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DefaultAzureCredentialSource {
    Environment,
    WorkloadIdentity,
    ManagedIdentity,
    #[cfg(not(target_arch = "wasm32"))]
    AzureCli,
    #[cfg(not(target_arch = "wasm32"))]
    AzureDeveloperCli,
}

fn default_azure_credential_sources() -> Vec<DefaultAzureCredentialSource> {
    let mut sources = vec![
        DefaultAzureCredentialSource::Environment,
        DefaultAzureCredentialSource::WorkloadIdentity,
        DefaultAzureCredentialSource::ManagedIdentity,
    ];
    #[cfg(not(target_arch = "wasm32"))]
    {
        sources.push(DefaultAzureCredentialSource::AzureCli);
        sources.push(DefaultAzureCredentialSource::AzureDeveloperCli);
    }
    sources
}

fn append_source<T>(
    credential: &mut ChainedTokenCredential,
    result: azure_core::Result<Arc<T>>,
    errors: &mut Vec<Error>,
    source_count: &mut usize,
) where
    T: TokenCredential + 'static,
{
    match result {
        Ok(source) => {
            credential.add_source(source);
            *source_count += 1;
        }
        Err(error) => errors.push(error),
    }
}

/// Builds a [`DefaultAzureCredential`] using the documented `DefaultAzureCredential` order
/// supported by the current Rust `azure_identity` dependency surface.
#[derive(Debug)]
pub struct DefaultAzureCredentialBuilder {
    sources: Vec<DefaultAzureCredentialSource>,
    chained_token_credential_options: Option<ChainedTokenCredentialOptions>,
    workload_identity_credential_options: Option<WorkloadIdentityCredentialOptions>,
    client_secret_credential_options: Option<ClientSecretCredentialOptions>,
    managed_identity_credential_options: Option<ManagedIdentityCredentialOptions>,
    #[cfg(not(target_arch = "wasm32"))]
    azure_cli_credential_options: Option<AzureCliCredentialOptions>,
    #[cfg(not(target_arch = "wasm32"))]
    azure_developer_cli_credential_options: Option<AzureDeveloperCliCredentialOptions>,
}

impl Default for DefaultAzureCredentialBuilder {
    fn default() -> Self {
        Self {
            sources: default_azure_credential_sources(),
            chained_token_credential_options: None,
            workload_identity_credential_options: None,
            client_secret_credential_options: None,
            managed_identity_credential_options: None,
            #[cfg(not(target_arch = "wasm32"))]
            azure_cli_credential_options: None,
            #[cfg(not(target_arch = "wasm32"))]
            azure_developer_cli_credential_options: None,
        }
    }
}

impl DefaultAzureCredentialBuilder {
    #[must_use]
    /// Create a new `DefaultAzureCredentialBuilder`.
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    /// Exclude the environment-backed credential source.
    pub fn exclude_environment_credential(mut self) -> Self {
        self.sources
            .retain(|source| *source != DefaultAzureCredentialSource::Environment);
        self
    }

    #[must_use]
    /// Exclude the workload identity credential source.
    pub fn exclude_workload_identity_credential(mut self) -> Self {
        self.sources
            .retain(|source| *source != DefaultAzureCredentialSource::WorkloadIdentity);
        self
    }

    #[must_use]
    /// Exclude the managed identity credential source.
    pub fn exclude_managed_identity_credential(mut self) -> Self {
        self.sources
            .retain(|source| *source != DefaultAzureCredentialSource::ManagedIdentity);
        self
    }

    #[must_use]
    /// Configure the chained credential behavior.
    pub fn with_chained_token_credential_options(
        mut self,
        options: ChainedTokenCredentialOptions,
    ) -> Self {
        self.chained_token_credential_options = Some(options);
        self
    }

    #[must_use]
    /// Configure the workload identity credential source.
    pub fn with_workload_identity_credential_options(
        mut self,
        options: WorkloadIdentityCredentialOptions,
    ) -> Self {
        self.workload_identity_credential_options = Some(options);
        self
    }

    #[must_use]
    /// Configure the environment credential source.
    pub fn with_client_secret_credential_options(
        mut self,
        options: ClientSecretCredentialOptions,
    ) -> Self {
        self.client_secret_credential_options = Some(options);
        self
    }

    #[must_use]
    /// Configure the managed identity credential source.
    pub fn with_managed_identity_credential_options(
        mut self,
        options: ManagedIdentityCredentialOptions,
    ) -> Self {
        self.managed_identity_credential_options = Some(options);
        self
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    /// Exclude the Azure CLI credential source.
    pub fn exclude_azure_cli_credential(mut self) -> Self {
        self.sources
            .retain(|source| *source != DefaultAzureCredentialSource::AzureCli);
        self
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    /// Exclude the Azure Developer CLI credential source.
    pub fn exclude_azure_developer_cli_credential(mut self) -> Self {
        self.sources
            .retain(|source| *source != DefaultAzureCredentialSource::AzureDeveloperCli);
        self
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    /// Configure the Azure CLI credential source.
    pub fn with_azure_cli_credential_options(mut self, options: AzureCliCredentialOptions) -> Self {
        self.azure_cli_credential_options = Some(options);
        self
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    /// Configure the Azure Developer CLI credential source.
    pub fn with_azure_developer_cli_credential_options(
        mut self,
        options: AzureDeveloperCliCredentialOptions,
    ) -> Self {
        self.azure_developer_cli_credential_options = Some(options);
        self
    }

    /// Build a new [`DefaultAzureCredential`].
    pub fn build(self) -> azure_core::Result<Arc<DefaultAzureCredential>> {
        let Self {
            sources,
            chained_token_credential_options,
            workload_identity_credential_options,
            client_secret_credential_options,
            managed_identity_credential_options,
            #[cfg(not(target_arch = "wasm32"))]
            azure_cli_credential_options,
            #[cfg(not(target_arch = "wasm32"))]
            azure_developer_cli_credential_options,
        } = self;

        if sources.is_empty() {
            return Err(Error::with_message(
                ErrorKind::Credential,
                "No credential sources were enabled for authentication.",
            ));
        }

        let mut credential = ChainedTokenCredential::new(chained_token_credential_options);
        let environment = EnvironmentSettings::from_os_env();
        let mut workload_identity_credential_options = workload_identity_credential_options;
        let mut client_secret_credential_options = client_secret_credential_options;
        let mut managed_identity_credential_options = managed_identity_credential_options;
        #[cfg(not(target_arch = "wasm32"))]
        let mut azure_cli_credential_options = azure_cli_credential_options;
        #[cfg(not(target_arch = "wasm32"))]
        let mut azure_developer_cli_credential_options = azure_developer_cli_credential_options;
        let mut errors = Vec::new();
        let mut source_count = 0usize;

        for source in sources {
            match source {
                DefaultAzureCredentialSource::Environment => append_source(
                    &mut credential,
                    EnvironmentCredential::from_settings(
                        &environment,
                        client_secret_credential_options.take(),
                    ),
                    &mut errors,
                    &mut source_count,
                ),
                DefaultAzureCredentialSource::WorkloadIdentity => append_source(
                    &mut credential,
                    create_workload_identity_credential(
                        &environment,
                        workload_identity_credential_options.take(),
                    ),
                    &mut errors,
                    &mut source_count,
                ),
                DefaultAzureCredentialSource::ManagedIdentity => append_source(
                    &mut credential,
                    ManagedIdentityCredential::new(managed_identity_credential_options.take()),
                    &mut errors,
                    &mut source_count,
                ),
                #[cfg(not(target_arch = "wasm32"))]
                DefaultAzureCredentialSource::AzureCli => append_source(
                    &mut credential,
                    AzureCliCredential::new(azure_cli_credential_options.take()),
                    &mut errors,
                    &mut source_count,
                ),
                #[cfg(not(target_arch = "wasm32"))]
                DefaultAzureCredentialSource::AzureDeveloperCli => append_source(
                    &mut credential,
                    AzureDeveloperCliCredential::new(azure_developer_cli_credential_options.take()),
                    &mut errors,
                    &mut source_count,
                ),
            }
        }

        if source_count == 0 {
            return Err(Error::with_message(
                ErrorKind::Credential,
                format!(
                    "No credential sources were available to be used for authentication.\n{}",
                    format_aggregate_error(&errors)
                ),
            ));
        }

        Ok(Arc::new(DefaultAzureCredential { credential }))
    }

    #[cfg(test)]
    fn included(&self) -> Vec<DefaultAzureCredentialSource> {
        self.sources.clone()
    }
}

/// Recreates `DefaultAzureCredential` using the currently supported Rust credential types.
///
/// The following credential sources are attempted in order:
/// - environment-backed authentication (`ClientSecretCredential`)
/// - `WorkloadIdentityCredential`
/// - `ManagedIdentityCredential`
/// - `AzureCliCredential`
/// - `AzureDeveloperCliCredential`
///
/// `AzurePowerShellCredential` is not currently implemented in this crate.
#[derive(Debug)]
pub struct DefaultAzureCredential {
    credential: ChainedTokenCredential,
}

impl DefaultAzureCredential {
    /// Create a `DefaultAzureCredential` with the default chain order.
    pub fn new() -> azure_core::Result<Arc<Self>> {
        DefaultAzureCredentialBuilder::new().build()
    }

    #[must_use]
    /// Create a builder for a customized `DefaultAzureCredential`.
    pub fn builder() -> DefaultAzureCredentialBuilder {
        DefaultAzureCredentialBuilder::new()
    }
}

/// Create a default credential as a trait object.
pub fn create_default_credential() -> azure_core::Result<Arc<dyn TokenCredential>> {
    let credential = DefaultAzureCredential::new()?;
    Ok(credential)
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl TokenCredential for DefaultAzureCredential {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        TokenCredential::get_token(&self.credential, scopes, options).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_builder_included_credential_types() {
        let builder = DefaultAzureCredentialBuilder::new();
        #[cfg(not(target_arch = "wasm32"))]
        assert_eq!(
            builder.included(),
            vec![
                DefaultAzureCredentialSource::Environment,
                DefaultAzureCredentialSource::WorkloadIdentity,
                DefaultAzureCredentialSource::ManagedIdentity,
                DefaultAzureCredentialSource::AzureCli,
                DefaultAzureCredentialSource::AzureDeveloperCli,
            ]
        );
        #[cfg(target_arch = "wasm32")]
        assert_eq!(
            builder.included(),
            vec![
                DefaultAzureCredentialSource::Environment,
                DefaultAzureCredentialSource::WorkloadIdentity,
                DefaultAzureCredentialSource::ManagedIdentity,
            ]
        );
    }

    #[test]
    fn excluded_credential_types() {
        let builder = DefaultAzureCredentialBuilder::new()
            .exclude_environment_credential()
            .exclude_workload_identity_credential()
            .exclude_managed_identity_credential();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder
            .exclude_azure_cli_credential()
            .exclude_azure_developer_cli_credential();

        assert!(builder.included().is_empty());
    }
}
