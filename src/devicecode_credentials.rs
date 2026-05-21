use crate::{
    cache::TokenCache,
    device_code::{default_pipeline, start},
    refresh_token::exchange,
};
use async_lock::Mutex;
use azure_core::{
    credentials::{AccessToken, Secret, TokenCredential, TokenRequestOptions},
    error::{Error, ErrorKind},
    http::Pipeline,
};
use futures::stream::StreamExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use time::OffsetDateTime;
use tracing::debug;

/// Future returned by a [`DeviceCodeMessageHandler`].
///
/// The future is allowed to borrow from the message slice it was handed,
/// so simple handlers (e.g. ones that just `write!` the message somewhere
/// before returning) don't have to allocate to take an owned copy.
pub type DeviceCodeMessageFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Async callback invoked with the device-code instruction message.
///
/// The handler receives the human-readable string telling the user which
/// URL to visit and which code to enter, and returns a future the
/// credential awaits before it starts polling for the token. The callback
/// fires once per `get_token` call that has to start a fresh device-code
/// flow; cached and refresh-token paths skip it.
pub type DeviceCodeMessageHandler =
    Arc<dyn for<'a> Fn(&'a str) -> DeviceCodeMessageFuture<'a> + Send + Sync>;

/// Optional configuration for [`DeviceCodeCredential`].
#[derive(Default)]
#[non_exhaustive]
pub struct DeviceCodeCredentialOptions {
    /// Handler invoked with the device-code instruction message. When
    /// `None`, the message is written to stderr via `eprintln!`.
    pub message_handler: Option<DeviceCodeMessageHandler>,
    /// HTTP pipeline used for the device-code and refresh-token requests.
    /// When `None`, a pipeline built with default options is used. Supply a
    /// custom pipeline to plug in retry, transport, proxy, or logging
    /// policies, or to share a single pipeline across multiple credentials.
    pub pipeline: Option<Pipeline>,
}

impl fmt::Debug for DeviceCodeCredentialOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceCodeCredentialOptions")
            .field(
                "message_handler",
                &self.message_handler.as_ref().map(|_| "<callback>"),
            )
            .field("pipeline", &self.pipeline)
            .finish()
    }
}

/// Enables authentication to an Azure Client using a Device Code workflow.
pub struct DeviceCodeCredential {
    tenant_id: String,
    client_id: String,
    cache: TokenCache,
    refresh_tokens: Mutex<BTreeMap<BTreeSet<String>, Secret>>,
    pipeline: Pipeline,
    message_handler: Option<DeviceCodeMessageHandler>,
}

impl fmt::Debug for DeviceCodeCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceCodeCredential")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("cache", &self.cache)
            .field("refresh_tokens", &self.refresh_tokens)
            .field("pipeline", &self.pipeline)
            .field(
                "message_handler",
                &self.message_handler.as_ref().map(|_| "<callback>"),
            )
            .finish()
    }
}

impl DeviceCodeCredential {
    /// Create a new `DeviceCodeCredential` with the specified tenant ID,
    /// client ID, and options.
    pub fn new<T, C>(
        tenant_id: T,
        client_id: C,
        options: Option<DeviceCodeCredentialOptions>,
    ) -> azure_core::Result<Arc<Self>>
    where
        T: Into<String>,
        C: Into<String>,
    {
        let options = options.unwrap_or_default();
        Ok(Arc::new(Self {
            tenant_id: tenant_id.into(),
            client_id: client_id.into(),
            cache: TokenCache::new(),
            refresh_tokens: Mutex::new(BTreeMap::new()),
            pipeline: options.pipeline.unwrap_or_else(default_pipeline),
            message_handler: options.message_handler,
        }))
    }

    async fn emit_message(&self, message: &str) {
        if let Some(handler) = &self.message_handler {
            handler(message).await;
        } else {
            eprintln!("{message}");
        }
    }

    async fn get_access_token(
        &self,
        scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        let scopes_owned = scopes
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();

        // Take any cached refresh token for this scope set under a brief lock
        // and drop the guard immediately. Holding it across the HTTP call (or,
        // worse, across `emit_message`) would block every other concurrent
        // `get_token` and would let a user-supplied message handler re-enter
        // the credential under a held lock.
        let existing_refresh = {
            let mut refresh_tokens = self.refresh_tokens.lock().await;
            refresh_tokens.remove(&scopes_owned)
        };

        if let Some(refresh_token) = existing_refresh {
            let response = exchange(
                &self.pipeline,
                self.tenant_id.as_str(),
                &self.client_id,
                None,
                &refresh_token,
            )
            .await?;
            let token = AccessToken {
                token: response.access_token().to_owned(),
                expires_on: convert_expires_in(response.expires_in()),
            };
            self.refresh_tokens
                .lock()
                .await
                .insert(scopes_owned, response.refresh_token().to_owned());
            return Ok(token);
        }

        let flow = start(
            &self.pipeline,
            self.tenant_id.clone(),
            self.client_id.as_str(),
            scopes,
        )
        .await?;

        self.emit_message(flow.message()).await;

        let mut stream = flow.stream();
        let mut last_error: Option<Error> = None;
        let auth = loop {
            let Some(response) = stream.next().await else {
                // The polling stream ended without yielding a successful
                // authorization. Surface the most recent error from the
                // server (e.g. `expired_token`, `access_denied`) instead
                // of a generic message — that's almost always what the
                // caller actually needs to see.
                return Err(last_error.unwrap_or_else(|| {
                    Error::with_message(
                        ErrorKind::Credential,
                        "device code did not return a response",
                    )
                }));
            };
            match response {
                Ok(auth) => break auth,
                Err(err) => {
                    debug!("device code poll returned error, will continue if recoverable: {err}");
                    last_error = Some(err);
                }
            }
        };

        let token = AccessToken {
            token: auth.access_token().to_owned(),
            expires_on: convert_expires_in(auth.expires_in),
        };

        if let Some(refresh_token) = auth.refresh_token() {
            self.refresh_tokens
                .lock()
                .await
                .insert(scopes_owned, refresh_token.to_owned());
        }
        Ok(token)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl TokenCredential for DeviceCodeCredential {
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

fn convert_expires_in(seconds: u64) -> OffsetDateTime {
    OffsetDateTime::now_utc() + Duration::new(seconds, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    fn require_send<T: Send>(_t: T) {}

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn ensure_that_get_token_is_send() -> azure_core::Result<()> {
        let credential = DeviceCodeCredential::new("UNUSED", "UNUSED", None)?;
        require_send(async move { credential.get_token(&[], None).await });
        Ok(())
    }

    #[tokio::test]
    async fn message_handler_receives_emitted_messages() -> azure_core::Result<()> {
        let captured: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_for_handler = captured.clone();
        let credential = DeviceCodeCredential::new(
            "UNUSED",
            "UNUSED",
            Some(DeviceCodeCredentialOptions {
                message_handler: Some(Arc::new(move |message: &str| {
                    let captured = captured_for_handler.clone();
                    // The handler is allowed to borrow `message` for the
                    // lifetime of the returned future, so callers that just
                    // need to inspect it don't have to allocate. This test
                    // exercises that path by formatting via the borrow.
                    Box::pin(async move {
                        if let Ok(mut log) = captured.lock() {
                            log.push(format!("seen:{message}"));
                        }
                    })
                })),
                ..Default::default()
            }),
        )?;

        credential.emit_message("hello").await;
        credential.emit_message("world").await;

        let log = captured.lock().map_err(|_| {
            Error::with_message(ErrorKind::Other, "captured-message log mutex poisoned")
        })?;
        assert_eq!(
            *log,
            vec!["seen:hello".to_string(), "seen:world".to_string()]
        );
        Ok(())
    }

    #[tokio::test]
    async fn default_options_emit_to_stderr() -> azure_core::Result<()> {
        // No handler configured: the default branch in `emit_message` is the
        // `eprintln!` fallback. We can't easily capture stderr from inside
        // the process, but exercising the branch confirms it doesn't panic
        // and the handler-less path stays wired up.
        let credential = DeviceCodeCredential::new("UNUSED", "UNUSED", None)?;
        credential.emit_message("default-path message").await;
        Ok(())
    }

    #[test]
    fn custom_pipeline_is_accepted_by_options() -> azure_core::Result<()> {
        let _credential = DeviceCodeCredential::new(
            "UNUSED",
            "UNUSED",
            Some(DeviceCodeCredentialOptions {
                pipeline: Some(default_pipeline()),
                ..Default::default()
            }),
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn refresh_token_scope_order_is_irrelevant() -> azure_core::Result<()> {
        // A refresh token stored under one ordering of the scopes must be
        // found by a lookup using the same scopes in a different order; the
        // AAD token endpoint treats scopes as unordered, and the cache
        // should too.
        let credential = DeviceCodeCredential::new("UNUSED", "UNUSED", None)?;
        let key_first: BTreeSet<String> =
            ["alpha", "beta"].iter().map(|s| (*s).to_string()).collect();
        let key_permuted: BTreeSet<String> =
            ["beta", "alpha"].iter().map(|s| (*s).to_string()).collect();
        assert_eq!(key_first, key_permuted, "BTreeSet keys must compare equal");

        credential
            .refresh_tokens
            .lock()
            .await
            .insert(key_first, Secret::new("token"));
        let found = credential.refresh_tokens.lock().await.remove(&key_permuted);
        assert!(
            found.is_some(),
            "permuted scope set should hit the same refresh-token entry",
        );
        Ok(())
    }

    #[derive(Debug)]
    struct RecordingPolicy {
        hits: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl azure_core::http::policies::Policy for RecordingPolicy {
        async fn send(
            &self,
            _ctx: &azure_core::http::Context,
            _request: &mut azure_core::http::Request,
            _next: &[Arc<dyn azure_core::http::policies::Policy>],
        ) -> azure_core::http::policies::PolicyResult {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Short-circuit the pipeline so no real HTTP traffic leaves the
            // process. The credential will surface this error to its caller;
            // we only care that the policy was reached.
            Err(Error::with_message(
                ErrorKind::Other,
                "recording-policy short circuit",
            ))
        }
    }

    #[tokio::test]
    async fn custom_pipeline_is_actually_used_for_requests() -> azure_core::Result<()> {
        // Build a pipeline whose first per-call policy records every send
        // and short-circuits. If the credential were ignoring our pipeline
        // and using its own, the recorder would never fire.
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let recorder: Arc<dyn azure_core::http::policies::Policy> =
            Arc::new(RecordingPolicy { hits: hits.clone() });
        let pipeline = azure_core::http::Pipeline::new(
            None,
            None,
            azure_core::http::ClientOptions::default(),
            vec![recorder],
            vec![],
            None,
        );

        let credential = DeviceCodeCredential::new(
            "UNUSED",
            "UNUSED",
            Some(DeviceCodeCredentialOptions {
                pipeline: Some(pipeline),
                ..Default::default()
            }),
        )?;

        // Trigger a request path. The recorder will short-circuit so this
        // call necessarily fails; the test only inspects the hit counter.
        let _ = credential.get_token(&["scope"], None).await;
        assert!(
            hits.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "the caller-supplied pipeline was never invoked",
        );
        Ok(())
    }
}
