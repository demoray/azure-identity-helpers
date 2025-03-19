//! # Azure Identity Helpers
//!
//! `azure-identity-helpers` provides unofficial utility components for handling Azure authentication
//! and identity management in Rust applications.
//!
//! This crate offers helper components for Azure authentication scenarios, including [AzureAuth CLI](https://github.com/AzureAD/microsoft-authentication-cli) integration and credential chaining.
//!
//! ## Modules
//!
//! - `azureauth_cli_credentials`: Implements [AzureAuth CLI](https://github.com/AzureAD/microsoft-authentication-cli) based authentication
//! - `cache`: Re-implements the azure-identity caching provider
//! - `chained_token_credential`: Implements credential chaining to try multiple authentication methods.  This method has been added to an unreleased version of the upstream azure-identity crate.  This will be removed once the updated upstream crate is released.
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
