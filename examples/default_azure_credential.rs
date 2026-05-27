//! Example for using [`DefaultAzureCredential`].
//!
//! Tries each credential source in the default order — environment-backed
//! authentication, workload identity, managed identity, Azure CLI, Azure
//! Developer CLI — and uses whichever one first produces a token. This is
//! the "just give me a credential that works" entry point and the recommended
//! starting place for new applications.
//!
//! Usage:
//!
//! ```sh
//! # Request an Azure Resource Manager token using whichever credential
//! # source is available in the local environment.
//! cargo run --example default_azure_credential
//!
//! # Override the scope.
//! AZURE_SCOPE=https://graph.microsoft.com/.default \
//!     cargo run --example default_azure_credential
//! ```
//!
//! Set `RUST_LOG=azure_identity_helpers=debug` to see which source the
//! `ChainedTokenCredential` underneath actually picked.

use azure_core::credentials::TokenCredential;
use azure_identity_helpers::default_azure_credential::DefaultAzureCredential;
use std::{env, error::Error};
use tracing::info;

const DEFAULT_SCOPE: &str = "https://management.core.windows.net/.default";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let scope = env::var("AZURE_SCOPE").unwrap_or_else(|_| DEFAULT_SCOPE.to_owned());

    info!(%scope, "acquiring token via DefaultAzureCredential");

    let credential = DefaultAzureCredential::new()?;
    let token = credential.get_token(&[scope.as_str()], None).await?;

    info!(
        expires_on = %token.expires_on,
        token_len = token.token.secret().len(),
        "received access token",
    );

    Ok(())
}
