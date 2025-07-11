// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

use crate::cache::TokenCache;
use async_lock::RwLock;
use azure_core::{
    credentials::{AccessToken, TokenCredential, TokenRequestOptions},
    error::{Error, ErrorKind},
};
use azure_identity::TokenCredentialOptions;
use std::sync::Arc;
use tracing::debug;

#[derive(Debug, Default)]
/// [`ChainedTokenCredentialOptions`] contains optional parameters for [`ChainedTokenCredential`].
pub struct ChainedTokenCredentialOptions {
    pub retry_sources: bool,
    pub credential_options: TokenCredentialOptions,
}

impl From<TokenCredentialOptions> for ChainedTokenCredentialOptions {
    fn from(credential_options: TokenCredentialOptions) -> Self {
        Self {
            retry_sources: Default::default(),
            credential_options,
        }
    }
}

/// Provides a user-configurable [`TokenCredential`] authentication flow for applications that will be deployed to Azure.
///
/// The credential types are tried in the order specified by the user.
#[derive(Debug)]
pub struct ChainedTokenCredential {
    #[allow(dead_code)]
    options: ChainedTokenCredentialOptions,
    sources: Vec<Arc<dyn TokenCredential>>,
    cache: TokenCache,
    successful_credential: RwLock<Option<Arc<dyn TokenCredential>>>,
}

impl ChainedTokenCredential {
    #[must_use]
    /// Create a `ChainedTokenCredential` with options.
    pub fn new(options: Option<ChainedTokenCredentialOptions>) -> Self {
        Self {
            options: options.unwrap_or_default(),
            sources: Vec::new(),
            cache: TokenCache::new(),
            successful_credential: RwLock::new(None),
        }
    }

    /// Add a credential source to the chain.
    pub fn add_source(&mut self, source: Arc<dyn TokenCredential>) {
        self.sources.push(source);
    }

    async fn get_token_impl(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions>,
    ) -> azure_core::Result<(Arc<dyn TokenCredential>, AccessToken)> {
        let mut errors = Vec::new();
        for source in &self.sources {
            debug!("Attempting to get token from source: {source:?}");
            let token_res = source.get_token(scopes, options.clone()).await;

            match token_res {
                Ok(token) => return Ok((source.clone(), token)),
                Err(error) => errors.push(error),
            }
        }
        Err(Error::with_message(ErrorKind::Credential, || {
            format!(
                "Multiple errors were encountered while attempting to authenticate:\n{}",
                format_aggregate_error(&errors)
            )
        }))
    }

    /// Try to fetch a token using each of the credential sources until one succeeds
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions>,
    ) -> azure_core::Result<AccessToken> {
        if self.options.retry_sources {
            // if we are retrying sources, we don't need to cache the successful credential
            Ok(self.get_token_impl(scopes, options).await?.1)
        } else {
            if let Some(entry) = self.successful_credential.read().await.as_ref() {
                return entry.get_token(scopes, options).await;
            }
            let mut lock = self.successful_credential.write().await;
            // if after getting the write lock, we find that another thread has already found a credential, use that.
            if let Some(entry) = lock.as_ref() {
                return entry.get_token(scopes, options).await;
            }
            let (entry, token) = self.get_token_impl(scopes, options).await?;
            *lock = Some(entry);
            Ok(token)
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl TokenCredential for ChainedTokenCredential {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions>,
    ) -> azure_core::Result<AccessToken> {
        self.cache
            .get_token(scopes, options, |s, o| self.get_token(s, o))
            .await
    }
}

fn format_aggregate_error(errors: &[Error]) -> String {
    use std::error::Error;
    errors
        .iter()
        .map(|e| {
            let mut current: Option<&dyn Error> = Some(e);
            let mut stack = vec![];
            while let Some(err) = current.take() {
                stack.push(err.to_string());
                current = err.source();
            }
            stack.join(" - ")
        })
        .collect::<Vec<String>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_identity::AzureCliCredential;

    #[test]
    fn test_adding_azure_cli() -> azure_core::Result<()> {
        let mut credential = ChainedTokenCredential::new(None);
        #[cfg(not(target_arch = "wasm32"))]
        {
            let cli = AzureCliCredential::new(None)?;
            credential.add_source(cli);
        }

        Ok(())
    }
}
