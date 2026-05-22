// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

use crate::cache::TokenCache;
use async_lock::RwLock;
use azure_core::{
    credentials::{AccessToken, TokenCredential, TokenRequestOptions},
    error::{Error, ErrorKind},
};
use std::sync::Arc;
use tracing::debug;

#[derive(Debug, Default, Clone, Copy)]
/// [`ChainedTokenCredentialOptions`] contains optional parameters for [`ChainedTokenCredential`].
pub struct ChainedTokenCredentialOptions {
    pub retry_sources: bool,
}

/// Provides a user-configurable [`TokenCredential`] authentication flow for applications that will be deployed to Azure.
///
/// The credential types are tried in the order specified by the user.
#[derive(Debug)]
pub struct ChainedTokenCredential {
    options: ChainedTokenCredentialOptions,
    sources: Vec<Arc<dyn TokenCredential>>,
    cache: TokenCache,
    successful_credential: RwLock<Option<Arc<dyn TokenCredential>>>,
}

impl ChainedTokenCredential {
    #[must_use]
    /// Create a `ChainedTokenCredential` with options.
    ///
    /// Returns the credential by value so callers can configure it with
    /// [`Self::add_source`] before wrapping it in an [`Arc`]. Once wrapped,
    /// the chain is immutable; further sources cannot be added because
    /// [`Self::add_source`] takes `&mut self`.
    pub fn new(options: Option<ChainedTokenCredentialOptions>) -> Self {
        Self {
            options: options.unwrap_or_default(),
            sources: Vec::new(),
            cache: TokenCache::new(),
            successful_credential: RwLock::new(None),
        }
    }

    /// Add a credential source to the chain.
    ///
    /// Sources are tried in the order they are added. Must be called before
    /// the credential is shared (e.g. wrapped in an [`Arc`]); after sharing,
    /// `&mut self` is no longer available and the chain is effectively
    /// frozen.
    pub fn add_source(&mut self, source: Arc<dyn TokenCredential>) {
        self.sources.push(source);
    }

    async fn get_token_impl(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions<'_>>,
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
        Err(Error::with_message(
            ErrorKind::Credential,
            format!(
                "Multiple errors were encountered while attempting to authenticate:\n{}",
                format_aggregate_error(&errors)
            ),
        ))
    }

    /// Try to fetch a token using each of the credential sources until one succeeds
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions<'_>>,
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
        options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        self.cache
            .get_token(scopes, options, |s, o| self.get_token(s, o))
            .await
    }
}

pub(crate) fn format_aggregate_error(errors: &[Error]) -> String {
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
    use azure_core::credentials::Secret;
    use azure_identity::AzureCliCredential;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use time::OffsetDateTime;

    #[cfg(not(target_arch = "wasm32"))]
    fn require_send<T: Send>(_t: T) {}

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn ensure_that_get_token_is_send() {
        let credential = ChainedTokenCredential::new(None);
        require_send(async move { TokenCredential::get_token(&credential, &[], None).await });
    }

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

    #[derive(Debug)]
    struct MockCredential {
        name: &'static str,
        succeed: bool,
        calls: AtomicUsize,
    }

    impl MockCredential {
        fn ok(name: &'static str) -> Arc<Self> {
            Arc::new(Self {
                name,
                succeed: true,
                calls: AtomicUsize::new(0),
            })
        }

        fn err(name: &'static str) -> Arc<Self> {
            Arc::new(Self {
                name,
                succeed: false,
                calls: AtomicUsize::new(0),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl TokenCredential for MockCredential {
        async fn get_token(
            &self,
            _scopes: &[&str],
            _options: Option<TokenRequestOptions<'_>>,
        ) -> azure_core::Result<AccessToken> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.succeed {
                Ok(AccessToken {
                    token: Secret::new(self.name.to_string()),
                    expires_on: OffsetDateTime::now_utc() + Duration::from_hours(1),
                })
            } else {
                Err(Error::with_message(
                    ErrorKind::Credential,
                    format!("mock {} failed", self.name),
                ))
            }
        }
    }

    #[tokio::test]
    async fn first_source_success_short_circuits_chain() -> azure_core::Result<()> {
        let first = MockCredential::ok("first");
        let second = MockCredential::ok("second");
        let mut chain = ChainedTokenCredential::new(None);
        chain.add_source(first.clone());
        chain.add_source(second.clone());

        let token = chain.get_token(&["scope-a"], None).await?;
        assert_eq!(token.token.secret(), "first");
        assert_eq!(first.calls(), 1);
        assert_eq!(second.calls(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn falls_back_to_later_source_on_failure() -> azure_core::Result<()> {
        let first = MockCredential::err("first");
        let second = MockCredential::ok("second");
        let mut chain = ChainedTokenCredential::new(None);
        chain.add_source(first.clone());
        chain.add_source(second.clone());

        let token = chain.get_token(&["scope-a"], None).await?;
        assert_eq!(token.token.secret(), "second");
        assert_eq!(first.calls(), 1);
        assert_eq!(second.calls(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn all_sources_failing_aggregates_their_errors() {
        let first = MockCredential::err("first");
        let second = MockCredential::err("second");
        let mut chain = ChainedTokenCredential::new(None);
        chain.add_source(first);
        chain.add_source(second);

        let result = chain.get_token(&["scope-a"], None).await;
        assert!(matches!(
            &result,
            Err(error) if matches!(error.kind(), ErrorKind::Credential)
        ));
        if let Err(error) = result {
            let message = error.to_string();
            assert!(
                message.contains("mock first failed"),
                "missing first source error in: {message}",
            );
            assert!(
                message.contains("mock second failed"),
                "missing second source error in: {message}",
            );
        }
    }

    #[tokio::test]
    async fn successful_credential_is_sticky_across_scopes() -> azure_core::Result<()> {
        let first = MockCredential::err("first");
        let second = MockCredential::ok("second");
        let mut chain = ChainedTokenCredential::new(None);
        chain.add_source(first.clone());
        chain.add_source(second.clone());

        // First scope: chain walks both sources.
        let _ = chain.get_token(&["scope-a"], None).await?;
        assert_eq!(first.calls(), 1);
        assert_eq!(second.calls(), 1);

        // Different scope: cache miss, but `successful_credential` should
        // route straight to `second` without re-trying `first`.
        let _ = chain.get_token(&["scope-b"], None).await?;
        assert_eq!(first.calls(), 1, "failing source should not be retried");
        assert_eq!(second.calls(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn retry_sources_re_walks_chain_on_every_request() -> azure_core::Result<()> {
        let first = MockCredential::err("first");
        let second = MockCredential::ok("second");
        let mut chain = ChainedTokenCredential::new(Some(ChainedTokenCredentialOptions {
            retry_sources: true,
        }));
        chain.add_source(first.clone());
        chain.add_source(second.clone());

        let _ = chain.get_token(&["scope-a"], None).await?;
        let _ = chain.get_token(&["scope-b"], None).await?;
        assert_eq!(first.calls(), 2, "failing source should be retried");
        assert_eq!(second.calls(), 2);
        Ok(())
    }

    #[test]
    fn format_aggregate_error_walks_source_chain() {
        // Wrap an inner cause as the source of an outer azure_core::Error.
        // format_aggregate_error should follow Error::source() and surface
        // the inner message, not just the outer one.
        let inner = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "inner-cause");
        let outer = Error::with_error(ErrorKind::Credential, inner, "outer-context");

        let formatted = format_aggregate_error(&[outer]);

        assert!(
            formatted.contains("outer-context"),
            "missing outer message in: {formatted}",
        );
        assert!(
            formatted.contains("inner-cause"),
            "source chain was not walked; output was: {formatted}",
        );
        assert!(
            formatted.contains(" - "),
            "missing chain separator in: {formatted}",
        );
    }

    #[test]
    fn format_aggregate_error_joins_multiple_errors_with_newlines() {
        let first = Error::with_message(ErrorKind::Credential, "first-failure");
        let second = Error::with_message(ErrorKind::Credential, "second-failure");

        let formatted = format_aggregate_error(&[first, second]);

        assert!(formatted.contains("first-failure"), "missing: {formatted}");
        assert!(formatted.contains("second-failure"), "missing: {formatted}");
        assert!(
            formatted.contains('\n'),
            "missing per-error newline in: {formatted}",
        );
    }
}
