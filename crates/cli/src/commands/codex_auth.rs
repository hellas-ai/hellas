use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
#[cfg(feature = "node")]
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(feature = "node")]
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use reqwest::Url;
use reqwest::header::{CONTENT_TYPE, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::commands::http_client;

const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const ISSUER: &str = "https://auth.openai.com";
const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const AUTH_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const AUTH_FILE_LOCK_TIMEOUT: Duration = Duration::from_secs(35);
#[cfg(feature = "node")]
const REFRESH_SKEW_SECONDS: u64 = 120;
#[cfg(feature = "node")]
const MAX_REFRESH_RESPONSE_BYTES: usize = 64 * 1024;
#[cfg(feature = "node")]
const MAX_REFRESH_ERROR_MESSAGE_BYTES: usize = 2 * 1024;

pub(crate) async fn login(auth_path: Option<&Path>) -> anyhow::Result<()> {
    let store = CodexAuthStore::new(auth_path)?;
    let client = CodexAuthClient::new(
        Url::parse(ISSUER).expect("Codex auth issuer URL is valid"),
        Url::parse(TOKEN_URL).expect("Codex auth token URL is valid"),
    );
    let tokens = client.device_login().await?;
    store.save(&CodexAuthState::new(tokens, None))?;
    eprintln!("Codex auth saved: {}", store.path().display());
    Ok(())
}

pub(crate) fn status(auth_path: Option<&Path>) -> anyhow::Result<()> {
    let store = CodexAuthStore::new(auth_path)?;
    match store.load() {
        Ok(state) => {
            let expires_at = access_token_expires_at(&state.tokens.access_token);
            println!("logged_in: true");
            println!("auth_path: {}", store.path().display());
            println!(
                "last_refresh: {}",
                state.last_refresh.as_deref().unwrap_or("unknown")
            );
            println!(
                "refresh_token_blocked: {}",
                state.refresh_token_blocked.is_some()
            );
            if let Some(expires_at) = expires_at {
                println!("access_token_expires_at: {expires_at}");
            }
        }
        Err(CodexAuthError::Missing) => {
            println!("logged_in: false");
            println!("auth_path: {}", store.path().display());
        }
        Err(err) => return Err(err.into()),
    }
    Ok(())
}

pub(crate) fn import_codex_cli(
    auth_path: Option<&Path>,
    source_path: Option<&Path>,
) -> anyhow::Result<()> {
    let source_path = match source_path {
        Some(path) => path.to_path_buf(),
        None => default_codex_cli_auth_path()?,
    };
    let bytes = fs::read(&source_path)
        .map_err(|err| CodexAuthError::CodexCliAuthRead(source_path.clone(), err))?;
    let value: JsonValue =
        serde_json::from_slice(&bytes).map_err(CodexAuthError::CodexCliAuthInvalidJson)?;
    let tokens = tokens_from_codex_cli_json(&value)?;
    let last_refresh = required_string(&value, "last_refresh");

    let store = CodexAuthStore::new(auth_path)?;
    store.save(&CodexAuthState::new(tokens, last_refresh))?;
    eprintln!("Codex auth imported: {}", store.path().display());
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct CodexAuthStore {
    path: PathBuf,
    #[cfg(feature = "node")]
    token_url: Url,
    /// Prevent many callers in this process from occupying Tokio blocking
    /// threads on the cross-process file lock while one refresh awaits HTTP.
    #[cfg(feature = "node")]
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

impl CodexAuthStore {
    pub(crate) fn new(path: Option<&Path>) -> Result<Self, CodexAuthError> {
        let path = match path {
            Some(path) => path.to_path_buf(),
            None => default_auth_path()?,
        };
        Ok(Self {
            path,
            #[cfg(feature = "node")]
            token_url: Url::parse(TOKEN_URL).expect("Codex auth token URL is valid"),
            #[cfg(feature = "node")]
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    #[cfg(all(test, feature = "node"))]
    pub(crate) fn with_token_url(path: PathBuf, token_url: Url) -> Self {
        Self {
            path,
            token_url,
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn load(&self) -> Result<CodexAuthState, CodexAuthError> {
        self.load_unlocked()
    }

    #[cfg(feature = "node")]
    pub(crate) fn account_id(&self) -> Result<String, CodexAuthError> {
        self.load_unlocked()?
            .tokens
            .account_id
            .ok_or(CodexAuthError::MissingAccountId)
    }

    fn load_unlocked(&self) -> Result<CodexAuthState, CodexAuthError> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(CodexAuthError::InvalidJson),
            Err(err) if err.kind() == ErrorKind::NotFound => Err(CodexAuthError::Missing),
            Err(err) => Err(CodexAuthError::Io(err)),
        }
    }

    #[cfg(feature = "node")]
    pub(crate) async fn access_token(&self) -> Result<String, CodexAuthError> {
        if !self.path.exists() {
            return Err(CodexAuthError::Missing);
        }
        let _process_guard = self.refresh_lock.lock().await;
        let auth_path = self.path.clone();
        let _file_guard = tokio::task::spawn_blocking(move || FileLock::lock(&auth_path))
            .await
            .map_err(|error| CodexAuthError::LockTask(error.to_string()))??;
        let mut state = self.load_unlocked()?;
        if let Some(blocked) = &state.refresh_token_blocked {
            return Err(CodexAuthError::RefreshBlocked(blocked.message.clone()));
        }
        if access_token_expiring(&state.tokens.access_token, REFRESH_SKEW_SECONDS) {
            let client = http_client(AUTH_HTTP_TIMEOUT);
            let refreshed = refresh_tokens(&client, self.token_url.clone(), &state.tokens).await;
            match refreshed {
                Ok(tokens) => {
                    state.tokens = tokens;
                    state.last_refresh = Some(now_timestamp());
                    state.refresh_token_blocked = None;
                    self.save_unlocked(&state)?;
                }
                Err(err) if err.is_terminal() => {
                    state.refresh_token_blocked = Some(BlockedRefreshToken {
                        message: bounded_diagnostic(&err.to_string()),
                        blocked_at: now_timestamp(),
                    });
                    self.save_unlocked(&state)?;
                    return Err(err);
                }
                Err(err) => return Err(err),
            }
        }
        Ok(state.tokens.access_token)
    }

    pub(crate) fn save(&self, state: &CodexAuthState) -> Result<(), CodexAuthError> {
        let dir = self
            .path
            .parent()
            .ok_or_else(|| CodexAuthError::InvalidPath(self.path.clone()))?;
        create_dir_restricted(dir).map_err(CodexAuthError::Io)?;
        let _guard = FileLock::lock(&self.path)?;
        self.save_unlocked(state)
    }

    fn save_unlocked(&self, state: &CodexAuthState) -> Result<(), CodexAuthError> {
        let bytes = serde_json::to_vec_pretty(state).map_err(CodexAuthError::Encode)?;
        // Private from creation on every platform, including an
        // operator-supplied path whose directory ACL we did not choose.
        hellas_private::write_atomically(&self.path, ".tmp", &bytes).map_err(CodexAuthError::Io)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct CodexAuthState {
    version: u8,
    tokens: CodexTokens,
    last_refresh: Option<String>,
    refresh_token_blocked: Option<BlockedRefreshToken>,
}

impl CodexAuthState {
    pub(crate) fn new(tokens: CodexTokens, last_refresh: Option<String>) -> Self {
        Self {
            version: 1,
            tokens,
            last_refresh,
            refresh_token_blocked: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct CodexTokens {
    access_token: String,
    refresh_token: String,
    #[serde(default, deserialize_with = "deserialize_optional_account_id")]
    account_id: Option<String>,
}

#[cfg(all(test, feature = "node"))]
pub(crate) fn test_tokens_with_account_id(
    access_token: &str,
    refresh_token: &str,
    account_id: &str,
) -> CodexTokens {
    CodexTokens {
        access_token: access_token.to_string(),
        refresh_token: refresh_token.to_string(),
        account_id: Some(validate_account_id(account_id).expect("valid test account id")),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BlockedRefreshToken {
    message: String,
    blocked_at: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CodexAuthError {
    #[error("no Codex credentials found; run `hellas codex-auth login`")]
    Missing,
    #[cfg(feature = "node")]
    #[error("Codex auth refresh token is blocked: {0}")]
    RefreshBlocked(String),
    #[cfg(feature = "node")]
    #[error("Codex auth lock task failed: {0}")]
    LockTask(String),
    #[error("Codex auth path has no parent directory: {0}")]
    InvalidPath(PathBuf),
    #[error("Codex auth file is invalid JSON: {0}")]
    InvalidJson(serde_json::Error),
    #[error("failed to encode Codex auth file: {0}")]
    Encode(serde_json::Error),
    #[error("Codex auth IO error: {0}")]
    Io(std::io::Error),
    #[error("HOME environment variable is not set; pass --auth-path")]
    MissingHome,
    #[error("failed to read Codex CLI auth file {0}: {1}")]
    CodexCliAuthRead(PathBuf, std::io::Error),
    #[error("Codex CLI auth file is invalid JSON: {0}")]
    CodexCliAuthInvalidJson(serde_json::Error),
    #[error("Codex CLI auth file is missing tokens.access_token or tokens.refresh_token")]
    CodexCliAuthShape,
    #[cfg(feature = "node")]
    #[error("Codex ChatGPT credentials have no account id; re-import Codex CLI credentials")]
    MissingAccountId,
    #[error("Codex account id must be 1 to {MAX_ACCOUNT_ID_BYTES} valid HTTP-header bytes")]
    InvalidAccountId,
    #[error("failed to request Codex device code: {0}")]
    DeviceCodeRequest(reqwest::Error),
    #[error("Codex device auth response is invalid JSON: {0}")]
    DeviceCodeJson(serde_json::Error),
    #[error("Codex device code request returned HTTP {0}")]
    DeviceCodeStatus(reqwest::StatusCode),
    #[error("Codex device code response is missing required fields")]
    DeviceCodeShape,
    #[error("Codex login timed out")]
    DeviceCodeTimeout,
    #[error("Codex device auth polling returned HTTP {0}")]
    DevicePollStatus(reqwest::StatusCode),
    #[error("Codex device auth response is missing authorization_code or code_verifier")]
    DevicePollShape,
    #[error("Codex token exchange failed: {0}")]
    TokenExchange(reqwest::Error),
    #[error("Codex token exchange response is invalid JSON: {0}")]
    TokenExchangeJson(serde_json::Error),
    #[error("Codex token exchange returned HTTP {0}")]
    TokenExchangeStatus(reqwest::StatusCode),
    #[error("Codex token response is missing access_token")]
    TokenMissingAccessToken,
    #[error("Codex token response is missing refresh_token")]
    TokenMissingRefreshToken,
    #[cfg(feature = "node")]
    #[error("Codex token refresh failed: {message}")]
    RefreshFailed { message: String, terminal: bool },
}

impl CodexAuthError {
    #[cfg(feature = "node")]
    fn is_terminal(&self) -> bool {
        matches!(self, Self::RefreshFailed { terminal: true, .. })
    }
}

struct CodexAuthClient {
    http: reqwest::Client,
    issuer: Url,
    token_url: Url,
}

impl CodexAuthClient {
    fn new(issuer: Url, token_url: Url) -> Self {
        Self {
            http: http_client(AUTH_HTTP_TIMEOUT),
            issuer,
            token_url,
        }
    }

    async fn device_login(&self) -> Result<CodexTokens, CodexAuthError> {
        let device = self.request_device_code().await?;
        eprintln!("To continue, open this URL:");
        eprintln!("  {}codex/device", self.issuer);
        eprintln!("Enter this code:");
        eprintln!("  {}", device.user_code);
        eprintln!("Waiting for sign-in...");

        let exchange = self.poll_device_code(&device).await?;
        self.exchange_device_code(exchange).await
    }

    async fn request_device_code(&self) -> Result<DeviceCode, CodexAuthError> {
        let response = self
            .http
            .post(
                self.issuer
                    .join("api/accounts/deviceauth/usercode")
                    .expect("valid path"),
            )
            .header(CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_vec(&serde_json::json!({ "client_id": CLIENT_ID }))
                    .expect("valid JSON"),
            )
            .send()
            .await
            .map_err(CodexAuthError::DeviceCodeRequest)?;
        let status = response.status();
        if !status.is_success() {
            return Err(CodexAuthError::DeviceCodeStatus(status));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(CodexAuthError::DeviceCodeRequest)?;
        let value: JsonValue =
            serde_json::from_slice(&bytes).map_err(CodexAuthError::DeviceCodeJson)?;
        let user_code =
            required_string(&value, "user_code").ok_or(CodexAuthError::DeviceCodeShape)?;
        let device_auth_id =
            required_string(&value, "device_auth_id").ok_or(CodexAuthError::DeviceCodeShape)?;
        let interval = value
            .get("interval")
            .and_then(JsonValue::as_u64)
            .unwrap_or(5)
            .max(3);
        Ok(DeviceCode {
            user_code,
            device_auth_id,
            interval,
        })
    }

    async fn poll_device_code(
        &self,
        device: &DeviceCode,
    ) -> Result<DeviceExchange, CodexAuthError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15 * 60);
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_secs(device.interval)).await;
            let response = self
                .http
                .post(
                    self.issuer
                        .join("api/accounts/deviceauth/token")
                        .expect("valid path"),
                )
                .header(CONTENT_TYPE, "application/json")
                .body(
                    serde_json::to_vec(&serde_json::json!({
                        "device_auth_id": device.device_auth_id,
                        "user_code": device.user_code,
                    }))
                    .expect("valid JSON"),
                )
                .send()
                .await
                .map_err(CodexAuthError::DeviceCodeRequest)?;
            match response.status().as_u16() {
                200 => {
                    let bytes = response
                        .bytes()
                        .await
                        .map_err(CodexAuthError::DeviceCodeRequest)?;
                    let value: JsonValue =
                        serde_json::from_slice(&bytes).map_err(CodexAuthError::DeviceCodeJson)?;
                    let authorization_code = required_string(&value, "authorization_code")
                        .ok_or(CodexAuthError::DevicePollShape)?;
                    let code_verifier = required_string(&value, "code_verifier")
                        .ok_or(CodexAuthError::DevicePollShape)?;
                    return Ok(DeviceExchange {
                        authorization_code,
                        code_verifier,
                    });
                }
                403 | 404 => {}
                _ => return Err(CodexAuthError::DevicePollStatus(response.status())),
            }
        }
        Err(CodexAuthError::DeviceCodeTimeout)
    }

    async fn exchange_device_code(
        &self,
        exchange: DeviceExchange,
    ) -> Result<CodexTokens, CodexAuthError> {
        let response = self
            .http
            .post(self.token_url.clone())
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form_body(&[
                ("grant_type", "authorization_code"),
                ("code", exchange.authorization_code.as_str()),
                (
                    "redirect_uri",
                    "https://auth.openai.com/deviceauth/callback",
                ),
                ("client_id", CLIENT_ID),
                ("code_verifier", exchange.code_verifier.as_str()),
            ]))
            .send()
            .await
            .map_err(CodexAuthError::TokenExchange)?;
        let status = response.status();
        if !status.is_success() {
            return Err(CodexAuthError::TokenExchangeStatus(status));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(CodexAuthError::TokenExchange)?;
        let value: JsonValue =
            serde_json::from_slice(&bytes).map_err(CodexAuthError::TokenExchangeJson)?;
        tokens_from_json(value)
    }
}

struct DeviceCode {
    user_code: String,
    device_auth_id: String,
    interval: u64,
}

struct DeviceExchange {
    authorization_code: String,
    code_verifier: String,
}

#[cfg(feature = "node")]
async fn refresh_tokens(
    client: &reqwest::Client,
    token_url: Url,
    tokens: &CodexTokens,
) -> Result<CodexTokens, CodexAuthError> {
    if tokens.refresh_token.trim().is_empty() {
        return Err(CodexAuthError::RefreshFailed {
            message: "missing refresh_token".to_string(),
            terminal: true,
        });
    }
    let response = client
        .post(token_url)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form_body(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", tokens.refresh_token.as_str()),
            ("client_id", CLIENT_ID),
        ]))
        .send()
        .await
        .map_err(|err| CodexAuthError::RefreshFailed {
            message: err.to_string(),
            terminal: false,
        })?;
    let status = response.status();
    let bytes = bounded_refresh_body(response).await?;
    if !status.is_success() {
        let body = String::from_utf8_lossy(&bytes);
        let (message, terminal) = refresh_error(status, &body);
        return Err(CodexAuthError::RefreshFailed { message, terminal });
    }
    // Deliberately non-terminal: a 2xx with an unparseable or incomplete
    // body means the *response* was bad, not the refresh token. Terminal
    // would persist `refresh_token_blocked` and brick a likely-valid
    // credential until a human re-logs-in; non-terminal retries at the
    // caller's pace and self-heals when the server recovers. Only the
    // explicit auth-error codes and 401/403 in `refresh_error` are terminal.
    let value: JsonValue =
        serde_json::from_slice(&bytes).map_err(|err| CodexAuthError::RefreshFailed {
            message: format!("invalid JSON: {err}"),
            terminal: false,
        })?;
    let access_token =
        required_string(&value, "access_token").ok_or_else(|| CodexAuthError::RefreshFailed {
            message: "missing access_token".to_string(),
            terminal: false,
        })?;
    let refresh_token =
        required_string(&value, "refresh_token").unwrap_or_else(|| tokens.refresh_token.clone());
    Ok(CodexTokens {
        access_token,
        refresh_token,
        account_id: tokens.account_id.clone(),
    })
}

#[cfg(feature = "node")]
async fn bounded_refresh_body(mut response: reqwest::Response) -> Result<Vec<u8>, CodexAuthError> {
    let mut body = Vec::new();
    while let Some(chunk) =
        response
            .chunk()
            .await
            .map_err(|error| CodexAuthError::RefreshFailed {
                message: format!("body read failed: {error}"),
                terminal: false,
            })?
    {
        let Some(next_len) = body.len().checked_add(chunk.len()) else {
            return Err(refresh_body_too_large());
        };
        if next_len > MAX_REFRESH_RESPONSE_BYTES {
            return Err(refresh_body_too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(feature = "node")]
fn refresh_body_too_large() -> CodexAuthError {
    CodexAuthError::RefreshFailed {
        message: format!("response body exceeds the {MAX_REFRESH_RESPONSE_BYTES}-byte limit"),
        terminal: false,
    }
}

fn tokens_from_json(value: JsonValue) -> Result<CodexTokens, CodexAuthError> {
    let access_token =
        required_string(&value, "access_token").ok_or(CodexAuthError::TokenMissingAccessToken)?;
    let refresh_token =
        required_string(&value, "refresh_token").ok_or(CodexAuthError::TokenMissingRefreshToken)?;
    Ok(CodexTokens {
        access_token,
        refresh_token,
        account_id: optional_account_id(&value)?,
    })
}

const MAX_ACCOUNT_ID_BYTES: usize = 256;

fn optional_account_id(value: &JsonValue) -> Result<Option<String>, CodexAuthError> {
    match value.get("account_id") {
        None | Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::String(value)) => validate_account_id(value).map(Some),
        Some(_) => Err(CodexAuthError::InvalidAccountId),
    }
}

fn deserialize_optional_account_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?.map_or(Ok(None), |value| {
        validate_account_id(&value)
            .map(Some)
            .map_err(serde::de::Error::custom)
    })
}

fn validate_account_id(value: &str) -> Result<String, CodexAuthError> {
    if value.is_empty()
        || value.len() > MAX_ACCOUNT_ID_BYTES
        || HeaderValue::from_str(value).is_err()
    {
        return Err(CodexAuthError::InvalidAccountId);
    }
    Ok(value.to_string())
}

fn tokens_from_codex_cli_json(value: &JsonValue) -> Result<CodexTokens, CodexAuthError> {
    let Some(tokens) = value.get("tokens") else {
        return Err(CodexAuthError::CodexCliAuthShape);
    };
    let access_token =
        required_string(tokens, "access_token").ok_or(CodexAuthError::CodexCliAuthShape)?;
    let refresh_token =
        required_string(tokens, "refresh_token").ok_or(CodexAuthError::CodexCliAuthShape)?;
    Ok(CodexTokens {
        access_token,
        refresh_token,
        account_id: optional_account_id(tokens)?,
    })
}

#[cfg(feature = "node")]
fn refresh_error(status: reqwest::StatusCode, body: &str) -> (String, bool) {
    let mut code = None;
    let mut message = None;
    if let Ok(JsonValue::Object(object)) = serde_json::from_str::<JsonValue>(body)
        && let Some(error) = object.get("error")
    {
        match error {
            JsonValue::String(value) => code = Some(value.clone()),
            JsonValue::Object(error) => {
                code = error
                    .get("code")
                    .or_else(|| error.get("type"))
                    .and_then(JsonValue::as_str)
                    .map(ToString::to_string);
                message = error
                    .get("message")
                    .and_then(JsonValue::as_str)
                    .map(ToString::to_string);
            }
            _ => {}
        }
        message = message.or_else(|| {
            object
                .get("error_description")
                .or_else(|| object.get("message"))
                .and_then(JsonValue::as_str)
                .map(ToString::to_string)
        });
    }

    let terminal = matches!(
        code.as_deref(),
        Some("invalid_grant" | "invalid_token" | "invalid_request" | "refresh_token_reused")
    ) || matches!(status.as_u16(), 401 | 403);
    let message = message.unwrap_or_else(|| format!("HTTP {status}"));
    let message = bounded_diagnostic(&message);
    (message, terminal)
}

#[cfg(feature = "node")]
fn bounded_diagnostic(message: &str) -> String {
    let mut output = String::with_capacity(message.len().min(MAX_REFRESH_ERROR_MESSAGE_BYTES));
    for character in message.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if output.len() + character.len_utf8() > MAX_REFRESH_ERROR_MESSAGE_BYTES {
            break;
        }
        output.push(character);
    }
    if output.is_empty() {
        "upstream returned an empty error".to_string()
    } else {
        output
    }
}

fn form_body(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", form_escape(key), form_escape(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn form_escape(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

fn required_string(value: &JsonValue, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

#[cfg(feature = "node")]
fn access_token_expiring(token: &str, skew_seconds: u64) -> bool {
    let Some(expires_at) = access_token_expiry_seconds(token) else {
        return true;
    };
    let now = unix_seconds();
    expires_at <= now.saturating_add(skew_seconds)
}

fn access_token_expires_at(token: &str) -> Option<u64> {
    access_token_expiry_seconds(token)
}

fn access_token_expiry_seconds(token: &str) -> Option<u64> {
    let payload = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.as_bytes())
        .ok()?;
    let value: JsonValue = serde_json::from_slice(&decoded).ok()?;
    value.get("exp").and_then(JsonValue::as_u64)
}

#[cfg(feature = "node")]
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(feature = "node")]
fn now_timestamp() -> String {
    unix_seconds().to_string()
}

/// The user's home directory. Windows does not set `HOME`; the Codex CLI
/// itself uses `%USERPROFILE%` there.
fn home_dir() -> Result<PathBuf, CodexAuthError> {
    std::env::var_os("HOME")
        .or_else(|| {
            if cfg!(windows) {
                std::env::var_os("USERPROFILE")
            } else {
                None
            }
        })
        .map(PathBuf::from)
        .ok_or(CodexAuthError::MissingHome)
}

fn default_auth_path() -> Result<PathBuf, CodexAuthError> {
    Ok(home_dir()?.join(".hellas").join("codex-auth.json"))
}

fn default_codex_cli_auth_path() -> Result<PathBuf, CodexAuthError> {
    Ok(home_dir()?.join(".codex").join("auth.json"))
}

fn create_dir_restricted(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

/// Exclusive advisory lock beside the auth file (flock on Unix, LockFileEx
/// on Windows), released when the file is dropped.
struct FileLock {
    _file: fs::File,
}

impl FileLock {
    fn lock(path: &Path) -> Result<Self, CodexAuthError> {
        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            // Lock files carry no content; never clobber what's there.
            .truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(path.with_extension("lock"))
            .map_err(CodexAuthError::Io)?;
        let deadline = Instant::now() + AUTH_FILE_LOCK_TIMEOUT;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { _file: file }),
                Err(fs::TryLockError::WouldBlock) => {}
                Err(fs::TryLockError::Error(error)) => return Err(CodexAuthError::Io(error)),
            }
            if Instant::now() >= deadline {
                return Err(CodexAuthError::Io(std::io::Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "timed out after {} seconds waiting for Codex auth file lock",
                        AUTH_FILE_LOCK_TIMEOUT.as_secs()
                    ),
                )));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

#[cfg(test)]
mod tests;
