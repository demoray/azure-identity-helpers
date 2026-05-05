//! Example for using [`DeviceCodeCredential`].
//!
//! Usage:
//!
//! ```sh
//! # Default: authenticate against the `common` tenant using the Azure CLI's
//! # public client id and request an Azure Resource Manager token.
//! cargo run --example device_code
//!
//! # Override any of the inputs via environment variables.
//! AZURE_TENANT_ID=<tenant>            \
//! AZURE_CLIENT_ID=<app-registration>  \
//! AZURE_SCOPE=https://graph.microsoft.com/.default \
//!     cargo run --example device_code
//! ```
//!
//! Set `RUST_LOG=azure_identity_helpers=debug` to see the per-poll diagnostics
//! emitted by the credential.

use azure_core::credentials::TokenCredential;
use azure_identity_helpers::devicecode_credentials::DeviceCodeCredential;
use std::env;
use tracing::info;

// The Azure CLI's well-known public client id. It works against any tenant
// without requiring a per-app registration, which makes it convenient for
// manual exercises like this one.
const AZURE_CLI_CLIENT_ID: &str = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
const DEFAULT_SCOPE: &str = "https://management.core.windows.net/.default";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let tenant_id = env::var("AZURE_TENANT_ID").unwrap_or_else(|_| "common".to_string());
    let client_id = env::var("AZURE_CLIENT_ID").unwrap_or_else(|_| AZURE_CLI_CLIENT_ID.to_string());
    let scope = env::var("AZURE_SCOPE").unwrap_or_else(|_| DEFAULT_SCOPE.to_string());

    info!(%tenant_id, %client_id, %scope, "starting device code flow");

    let credential = DeviceCodeCredential::new(tenant_id, client_id)?;
    let token = credential.get_token(&[scope.as_str()], None).await?;

    info!(
        expires_on = %token.expires_on,
        token_len = token.token.secret().len(),
        "received access token",
    );

    Ok(())
}
