//! One persistent account budget below every grant/paid provider invocation.
//! Stores counts only. Each bounded call costs its full reservation for the window,
//! including on failure/cancellation. There are no asynchronous token refunds.
mod quota;
use futures::StreamExt;
use hellas_authority::model::http_usage::{AccountingProfile, unique_json};
use hellas_executor::{
    FetchProvider, FetchProviderError, FetchProviderFuture, PreparedFetchRequest,
};
pub use quota::{QuotaSource, Reserve};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, OnceCell, OwnedSemaphorePermit, Semaphore};

type Result<T> = std::result::Result<T, AccountError>;
#[derive(Debug, thiserror::Error)]
#[error("upstream account refused: {0}")]
pub struct AccountError(&'static str);
impl From<AccountError> for FetchProviderError {
    fn from(value: AccountError) -> Self {
        Self::failed(value.to_string())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    pub ledger: PathBuf,
    pub window_seconds: u32,
    pub max_requests: u32,
    /// Conservative output-token allowance; every call charges its full cap.
    pub max_tokens: u64,
    pub max_concurrency: u32,
    pub max_request_bytes: u32,
    pub max_output_tokens: u32,
    pub accounting: AccountingProfile,
    pub quota: QuotaSource,
}
impl AccountConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.ledger.is_absolute()
            || self.window_seconds == 0
            || self.window_seconds > RETENTION
            || self.max_requests == 0
            || self.max_tokens == 0
            || self.max_tokens > i64::MAX as u64
            || self.max_concurrency == 0
            || self.max_request_bytes == 0
            || self.max_output_tokens == 0
            || self.max_tokens < u64::from(self.max_output_tokens)
            || self.accounting == AccountingProfile::None
        {
            return Err(AccountError("invalid account limits"));
        }
        self.quota.validate()
    }
}
const RETENTION: u32 = 31 * 24 * 3600;
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| AccountError("clock unavailable"))
}
struct Ledger {
    pool: sqlx::SqlitePool,
    _lock: std::fs::File,
}
struct AccountLimiter {
    config: AccountConfig,
    permits: Arc<Semaphore>,
    ledger: OnceCell<Ledger>,
    serial: Mutex<()>,
    client: reqwest::Client,
}
impl AccountLimiter {
    fn new(config: AccountConfig, client: reqwest::Client) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(config.max_concurrency as usize)),
            config,
            ledger: OnceCell::new(),
            serial: Mutex::new(()),
            client,
        }
    }
    async fn ledger(&self) -> Result<&Ledger> {
        self.ledger.get_or_try_init(|| async {
            let path = &self.config.ledger;
            let parent = path.parent().ok_or(AccountError("invalid ledger path"))?;
            hellas_private::create_dir_all_durable(parent).map_err(|_| AccountError("ledger directory unavailable"))?;
            let lock = hellas_private::open_lock_beside(path).map_err(|_| AccountError("ledger lock unavailable"))?;
            lock.try_lock().map_err(|_| AccountError("account ledger is already in use"))?;
            if !path.try_exists().map_err(|_| AccountError("ledger inaccessible"))? {
                let temporary = hellas_private::private_tempfile(parent, ".account-", ".sqlite")
                    .map_err(|_| AccountError("ledger creation failed"))?;
                temporary.persist_noclobber(path).map_err(|_| AccountError("ledger creation failed"))?;
                hellas_private::sync_directory(parent).map_err(|_| AccountError("ledger sync failed"))?;
            }
            let file = hellas_private::open_regular_file_nofollow_rw(path).map_err(|_| AccountError("invalid ledger file"))?;
            if !hellas_private::is_private(&file).map_err(|_| AccountError("ledger permissions unavailable"))? {
                return Err(AccountError("account ledger must be private"));
            }
            hellas_private::restrict_directory(parent).map_err(|_| AccountError("ledger directory must be private"))?;
            // DELETE journaling keeps SQLite sidecars transient; parent is private.
            let pool = SqlitePoolOptions::new().max_connections(1).connect_with(
                SqliteConnectOptions::new().filename(path).create_if_missing(false)
                    .journal_mode(sqlx::sqlite::SqliteJournalMode::Delete)
                    .synchronous(sqlx::sqlite::SqliteSynchronous::Full)
            ).await.map_err(|_| AccountError("ledger open failed"))?;
            sqlx::query("CREATE TABLE IF NOT EXISTS calls (id INTEGER PRIMARY KEY, at INTEGER NOT NULL, tokens INTEGER NOT NULL)")
                .execute(&pool).await.map_err(|_| AccountError("ledger schema failed"))?;
            Ok(Ledger { pool, _lock: lock })
        }).await
    }
    async fn reserve(&self, tokens: u64) -> Result<OwnedSemaphorePermit> {
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| AccountError("account concurrency exhausted"))?;
        let quota_deadline = self.config.quota.check(&self.client, now()?).await?;
        let _serial = self.serial.lock().await;
        let pool = &self.ledger().await?.pool;
        let now = i64::try_from(now()?).map_err(|_| AccountError("clock overflow"))?;
        let mut tx = pool
            .begin()
            .await
            .map_err(|_| AccountError("ledger transaction failed"))?;
        let (count, used, newest): (i64, i64, i64) = sqlx::query_as("SELECT COUNT(*), COALESCE(SUM(tokens),0), COALESCE(MAX(at),0) FROM calls WHERE at >= ?")
            .bind(now - i64::from(self.config.window_seconds)).fetch_one(&mut *tx).await
            .map_err(|_| AccountError("ledger read failed"))?;
        if newest > now {
            return Err(AccountError("account ledger clock moved backwards"));
        }
        if used < 0
            || count >= i64::from(self.config.max_requests)
            || (used as u64)
                .checked_add(tokens)
                .is_none_or(|v| v > self.config.max_tokens)
        {
            return Err(AccountError("account request/token window exhausted"));
        }
        sqlx::query("INSERT INTO calls (at,tokens) VALUES (?,?)")
            .bind(now)
            .bind(tokens as i64)
            .execute(&mut *tx)
            .await
            .map_err(|_| AccountError("ledger reservation failed"))?;
        sqlx::query("DELETE FROM calls WHERE at < ?")
            .bind(now - i64::from(RETENTION))
            .execute(&mut *tx)
            .await
            .map_err(|_| AccountError("ledger prune failed"))?;
        tx.commit()
            .await
            .map_err(|_| AccountError("ledger commit failed"))?;
        if crate::account::now()? > quota_deadline {
            return Err(AccountError("quota expired during admission"));
        }
        Ok(permit)
    }
}
/// Pure schema/uniqueness validation; no clients, files or runtime objects.
pub fn validate_accounts(configs: &BTreeMap<String, AccountConfig>) -> Result<()> {
    let mut paths = std::collections::BTreeSet::new();
    let mut identities = std::collections::BTreeSet::new();
    for (name, config) in configs {
        config.validate()?;
        if name.is_empty()
            || !paths.insert(&config.ledger)
            || !identities.insert((&config.quota.upstream, &config.quota.account))
        {
            return Err(AccountError("duplicate or empty account/ledger"));
        }
    }
    Ok(())
}
/// Construct once per host. All route/credential aliases clone the same limiter.
pub struct AccountRegistry {
    accounts: BTreeMap<String, Arc<AccountLimiter>>,
}
impl AccountRegistry {
    pub fn new(configs: &BTreeMap<String, AccountConfig>) -> Result<Self> {
        validate_accounts(configs)?;
        let mut accounts = BTreeMap::new();
        if !configs.is_empty() {
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .map_err(|_| AccountError("quota HTTP client unavailable"))?;
            for (name, config) in configs {
                accounts.insert(
                    name.clone(),
                    Arc::new(AccountLimiter::new(config.clone(), client.clone())),
                );
            }
        }
        Ok(Self { accounts })
    }
    pub fn bind(
        &self,
        provider: Arc<dyn FetchProvider>,
        account: Option<&str>,
        aliases: &BTreeMap<String, String>,
        http: bool,
    ) -> Result<Arc<dyn FetchProvider>> {
        let lookup = |name: &str| {
            self.accounts
                .get(name)
                .cloned()
                .ok_or(AccountError("unknown upstream account"))
        };
        let account = account.map(lookup).transpose()?;
        let aliases = aliases
            .iter()
            .map(|(alias, name)| Ok((alias.clone(), lookup(name)?)))
            .collect::<Result<_>>()?;
        Ok(Arc::new(AccountProvider {
            provider,
            account,
            aliases,
            http,
        }))
    }
}
struct AccountProvider {
    provider: Arc<dyn FetchProvider>,
    account: Option<Arc<AccountLimiter>>,
    aliases: BTreeMap<String, Arc<AccountLimiter>>,
    http: bool,
}
impl FetchProvider for AccountProvider {
    fn execution_environment(&self) -> hellas_rpc::ContentId {
        self.provider.execution_environment()
    }
    fn run(&self, request: PreparedFetchRequest) -> FetchProviderFuture<'_> {
        Box::pin(async move {
            let http = if self.http {
                Some(
                    hellas_rpc::http_fetch::HttpFetchRequest::decode(request.body.as_bytes())
                        .map_err(|_| AccountError("invalid HTTP account request"))?,
                )
            } else {
                None
            };
            let account = match http.as_ref().and_then(|r| r.credential.as_ref()) {
                Some(alias) => Some(
                    self.aliases
                        .get(alias)
                        .ok_or(AccountError("credential has no account binding"))?,
                ),
                None => self.account.as_ref(),
            };
            let Some(account) = account else {
                return self.provider.run(request).await;
            };
            let body = match &http {
                Some(r) => r.body().map_err(|_| AccountError("invalid HTTP body"))?,
                None => request.body.as_bytes().to_vec(),
            };
            let tokens = if http
                .as_ref()
                .is_some_and(|r| matches!(r.method.as_str(), "GET" | "HEAD") && body.is_empty())
            {
                0 // Account health/read requests still consume request/concurrency/quota admission.
            } else {
                request_reservation(&body, &account.config)?
            };
            let permit = account.reserve(tokens).await?;
            let mut response = self.provider.run(request).await?;
            let mut upstream = response.stream;
            response.stream = Box::pin(async_stream::stream! {
                // Own the permit even if this stream is never polled.
                let _permit = permit;
                while let Some(chunk) = upstream.next().await { yield chunk; }
            });
            Ok(response)
        })
    }
}
fn request_reservation(body: &[u8], config: &AccountConfig) -> Result<u64> {
    if body.len() > config.max_request_bytes as usize {
        return Err(AccountError("account request byte cap exceeded"));
    }
    let value =
        unique_json(body).map_err(|_| AccountError("account request requires unambiguous JSON"))?;
    let keys = ["max_output_tokens", "max_completion_tokens", "max_tokens"];
    let mut caps = keys.iter().filter_map(|k| value.get(k));
    let cap = caps
        .next()
        .and_then(serde_json::Value::as_u64)
        .filter(|v| *v > 0 && *v <= u64::from(config.max_output_tokens))
        .ok_or(AccountError(
            "account request requires a bounded output token cap",
        ))?;
    if caps.next().is_some() || value.get("n").is_some_and(|v| v.as_u64() != Some(1)) {
        return Err(AccountError("ambiguous or multiple account generations"));
    }
    Ok(cap)
}

#[cfg(test)]
mod tests;
