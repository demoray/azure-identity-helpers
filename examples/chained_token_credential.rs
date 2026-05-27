//! Example for composing a custom [`ChainedTokenCredential`].
//!
//! Builds a two-source chain explicitly: Azure CLI first, environment-backed
//! authentication second. The chain tries each source in order and returns
//! the first successful token; by default it then sticks to that source for
//! subsequent calls (set `ChainedTokenCredentialOptions { retry_sources: true }`
//! to walk the chain on every request).
//!
//! Use this when [`DefaultAzureCredential`]'s built-in order isn't what you
//! want or you only want a subset of sources.
//!
//! Usage:
//!
//! ```sh
//! cargo run --example chained_token_credential
//!
//! # Override the scope.
//! AZURE_SCOPE=https://graph.microsoft.com/.default \
//!     cargo run --example chained_token_credential
//! ```

use azure_core::credentials::TokenCredential;
use azure_identity::AzureCliCredential;
use azure_identity_helpers::{
    chained_token_credential::ChainedTokenCredential, environment_credential::EnvironmentCredential,
};
use std::{env, error::Error, sync::Arc};
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

    // Add sources before sharing the credential — add_source() takes
    // &mut self, so once the value is wrapped in an Arc no further sources
    // can be appended (without an Arc::get_mut detour).
    let mut chain = ChainedTokenCredential::new(None);
    chain.add_source(AzureCliCredential::new(None)?);
    if let Ok(env_cred) = EnvironmentCredential::new(None) {
        chain.add_source(env_cred);
    }
    let credential = Arc::new(chain);

    info!(%scope, "acquiring token via custom ChainedTokenCredential");

    let token = credential.get_token(&[scope.as_str()], None).await?;

    info!(
        expires_on = %token.expires_on,
        token_len = token.token.secret().len(),
        "received access token",
    );

    Ok(())
}
