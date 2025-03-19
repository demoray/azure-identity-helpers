//! # Azure Identity Helpers
//!
//! `azure-identity-helpers` provides unofficial utility components for handling
//! Azure authentication and identity management in Rust applications.
//!
//! This crate offers helper components for Azure authentication scenarios,
//! including [AzureAuth CLI](https://github.com/AzureAD/microsoft-authentication-cli)
//! integration, credential chaining, device code authentication, and refresh
//! token handling.
//!
//! ## Modules
//!
//! - `azureauth_cli_credentials`: Implements [AzureAuth CLI](https://github.com/AzureAD/microsoft-authentication-cli) based authentication.  Originally from `azure_identity` 0.20.0.
//! - `cache`: Re-implements the azure-identity caching provider
//! - `chained_token_credential`: Implements credential chaining to try multiple authentication methods.  This method has been added to an unreleased version of the upstream `azure_identity` crate.  This will be removed once the updated upstream crate is released.
//! - `device_code`: Provides device code flow authentication support for Azure services.  Originally from `azure_identity` 0.20.0.
//! - `refresh_token`: Handles refresh token operations for maintaining authentication sessions.  Originally from `azure_identity` 0.20.0.
//!

#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::manual_assert,
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used
)]

pub mod azureauth_cli_credentials;
pub mod cache;
pub mod chained_token_credential;
pub mod device_code;
pub mod refresh_token;
