use crate::{cache::TokenCache, device_code::start, refresh_token::exchange};
use async_lock::Mutex;
use azure_core::{
    credentials::{AccessToken, Secret, TokenCredential, TokenRequestOptions},
    error::{Error, ErrorKind},
};
use azure_identity::TokenCredentialOptions;
use futures::stream::StreamExt;
use std::{collections::BTreeMap, str, sync::Arc, time::Duration};
use time::OffsetDateTime;

#[derive(Debug)]
/// Enables authentication to an Azure Client using a Device Code workflow.
pub struct DeviceCodeCredential {
    tenant_id: String,
    client_id: String,
    cache: TokenCache,
    refresh_tokens: Mutex<BTreeMap<Vec<String>, Secret>>,
    options: TokenCredentialOptions,
}

impl DeviceCodeCredential {
    /// Create a new `DeviceCodeCredential` with the specified tenant ID, client ID, and options.
    pub fn new<T, C>(
        tenant_id: T,
        client_id: C,
        options: TokenCredentialOptions,
    ) -> azure_core::Result<Arc<Self>>
    where
        T: Into<String>,
        C: Into<String>,
    {
        Ok(Arc::new(Self {
            tenant_id: tenant_id.into(),
            client_id: client_id.into(),
            cache: TokenCache::new(),
            refresh_tokens: Mutex::new(BTreeMap::new()),
            options,
        }))
    }

    async fn get_access_token(
        &self,
        scopes: &[&str],
        _options: Option<TokenRequestOptions>,
    ) -> azure_core::Result<AccessToken> {
        let scopes_owned = scopes.iter().map(ToString::to_string).collect::<Vec<_>>();
        let mut refresh_tokens = self.refresh_tokens.lock().await;
        if let Some(refresh_token) = refresh_tokens.remove(&scopes_owned) {
            let response = exchange(
                self.options.http_client(),
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
            refresh_tokens.insert(scopes_owned, response.refresh_token().to_owned());
            return Ok(token);
        }

        let flow = start(
            self.options.http_client(),
            self.tenant_id.to_string(),
            self.client_id.as_str(),
            scopes,
        )
        .await?;

        eprintln!("{}", flow.message());

        let mut stream = flow.stream();
        let auth = loop {
            let Some(response) = stream.next().await else {
                return Err(Error::message(
                    ErrorKind::Credential,
                    "device code did not return a response",
                ));
            };
            if let Ok(auth) = response {
                break auth;
            }
        };

        let token = AccessToken {
            token: auth.access_token().to_owned(),
            expires_on: convert_expires_in(auth.expires_in),
        };

        if let Some(refresh_token) = auth.refresh_token() {
            refresh_tokens.insert(scopes_owned, refresh_token.to_owned());
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
        options: Option<TokenRequestOptions>,
    ) -> azure_core::Result<AccessToken> {
        self.cache
            .get_token(scopes, options, |s, o| self.get_access_token(s, o))
            .await
    }
}

fn convert_expires_in(seconds: u64) -> OffsetDateTime {
    OffsetDateTime::now_utc() + Duration::new(seconds, 0)
}
