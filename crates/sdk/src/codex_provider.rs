use std::path::Path;

use hellas_executor::{
    FetchProvider, FetchProviderError, FetchProviderFuture, FetchProviderResponse,
    PreparedFetchRequest,
};
use hellas_providers::{CODEX_RESPONSES_ENDPOINT, codex_responses_contract};
use reqwest::Url;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue};

use crate::codex_auth::CodexAuthStore;

use hellas_providers::{execute_responses_request, responses_http_client};

const CODEX_ORIGINATOR: &str = "codex_cli_rs";

#[derive(Clone)]
pub struct CodexResponsesFetchProvider {
    client: reqwest::Client,
    auth: CodexAuthStore,
    account_id: String,
    endpoint: Url,
    environment: hellas_rpc::ContentId,
}

impl CodexResponsesFetchProvider {
    pub fn new(auth_path: Option<&Path>) -> anyhow::Result<Self> {
        let auth = CodexAuthStore::new(auth_path)?;
        let account_id = auth.account_id()?;
        Ok(Self {
            environment: codex_responses_contract()?.manifest_id(),
            client: codex_http_client(&account_id, None)?,
            account_id,
            auth,
            endpoint: Url::parse(CODEX_RESPONSES_ENDPOINT)?,
        })
    }

    #[cfg(test)]
    fn with_store(endpoint: Url, auth: CodexAuthStore) -> Self {
        let account_id = auth.account_id().expect("test account id");
        Self {
            account_id,
            environment: codex_responses_contract().unwrap().manifest_id(),
            client: codex_http_client(&auth.account_id().expect("test account id"), None)
                .expect("Codex HTTP client"),
            auth,
            endpoint,
        }
    }

    async fn execute(
        &self,
        request: PreparedFetchRequest,
    ) -> Result<FetchProviderResponse, FetchProviderError> {
        if let Some(policy) = &request.upstream {
            policy
                .permits_host(
                    self.endpoint
                        .host_str()
                        .ok_or_else(|| FetchProviderError::failed("missing Codex host"))?,
                )
                .map_err(FetchProviderError::failed)?;
        }
        let client = if request.upstream.is_some() {
            codex_http_client(&self.account_id, request.upstream.as_ref())
                .map_err(|_| FetchProviderError::failed("Codex TLS policy invalid"))?
        } else {
            self.client.clone()
        };
        let credentials = self.auth.credentials().await.map_err(|error| {
            FetchProviderError::failed(format!("Codex authentication failed: {error}"))
        })?;
        if credentials.account_id != self.account_id {
            return Err(FetchProviderError::failed(
                "Codex account changed; restart the provider with the intended account",
            ));
        }
        execute_responses_request(
            &client,
            self.endpoint.clone(),
            request.upstream.as_ref(),
            &credentials.access_token,
            request.body.as_bytes().to_vec(),
            &request.idempotency_key(),
            "Codex Responses",
        )
        .await
    }
}

fn codex_http_client(
    account_id: &str,
    upstream: Option<&hellas_rpc::upstream::UpstreamPolicy>,
) -> anyhow::Result<reqwest::Client> {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("text/event-stream"));
    headers.insert("ChatGPT-Account-ID", HeaderValue::from_str(account_id)?);
    headers.insert("Originator", HeaderValue::from_static(CODEX_ORIGINATOR));
    Ok(responses_http_client(headers, upstream)?)
}

impl FetchProvider for CodexResponsesFetchProvider {
    fn execution_environment(&self) -> hellas_rpc::ContentId {
        self.environment
    }

    fn run(&self, request: PreparedFetchRequest) -> FetchProviderFuture<'_> {
        Box::pin(async move { self.execute(request).await })
    }
}

#[cfg(test)]
mod tests;
