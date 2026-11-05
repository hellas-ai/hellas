//! Read-only access to the Codex CLI's native auth.json. The Codex CLI is the
//! sole login/refresh owner; this module has no HTTP client or write operation.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct CodexAuthStore {
    path: PathBuf,
}

#[derive(Deserialize)]
struct NativeAuth {
    tokens: NativeTokens,
    // Reject the deleted Hellas document even though native Codex may add
    // unrelated metadata fields. Never parse or retain refresh_token.
    version: Option<serde::de::IgnoredAny>,
}
#[derive(Deserialize)]
struct NativeTokens {
    access_token: String,
    account_id: String,
}

pub struct CodexCredentials {
    pub account_id: String,
    pub access_token: zeroize::Zeroizing<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum CodexAuthError {
    #[error("native Codex auth.json unavailable: {0}; sign in or refresh using the Codex CLI")]
    Io(#[from] std::io::Error),
    #[error(
        "expected the Codex CLI's native OAuth auth.json with tokens.access_token and tokens.account_id; no Hellas token format is supported"
    )]
    Invalid,
    #[error(
        "Codex access token is expired or its expiry cannot be verified; refresh it with the Codex CLI; Hellas never refreshes or rewrites auth.json"
    )]
    Expired,
    #[error("Codex account ID is missing or invalid")]
    Account,
    #[error("CODEX_HOME or HOME must select the Codex CLI credential directory")]
    Home,
}

impl CodexAuthStore {
    pub fn new(path: Option<&Path>) -> Result<Self, CodexAuthError> {
        let path = match path {
            Some(path) => path.to_owned(),
            None => match std::env::var_os("CODEX_HOME") {
                Some(directory) => PathBuf::from(directory).join("auth.json"),
                None => PathBuf::from(std::env::var_os("HOME").ok_or(CodexAuthError::Home)?)
                    .join(".codex/auth.json"),
            },
        };
        Ok(Self { path })
    }

    fn read(&self) -> Result<NativeTokens, CodexAuthError> {
        let file = hellas_private::open_regular_file_nofollow(&self.path)?;
        let bytes = hellas_private::read_private_bounded(file, 1024 * 1024)?;
        let auth: NativeAuth =
            serde_json::from_slice(&bytes).map_err(|_| CodexAuthError::Invalid)?;
        if auth.version.is_some() {
            return Err(CodexAuthError::Invalid);
        }
        let account = &auth.tokens.account_id;
        if account.is_empty()
            || account.len() > 256
            || !account
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        {
            return Err(CodexAuthError::Account);
        }
        Ok(auth.tokens)
    }

    pub fn account_id(&self) -> Result<String, CodexAuthError> {
        Ok(self.read()?.account_id)
    }

    pub async fn credentials(&self) -> Result<CodexCredentials, CodexAuthError> {
        // Re-read every request: an atomic refresh by Codex becomes visible
        // immediately. Never lock beside, refresh, create, or rewrite this file.
        let tokens = self.read()?;
        let expiry = tokens
            .access_token
            .split('.')
            .nth(1)
            .and_then(|part| URL_SAFE_NO_PAD.decode(part).ok())
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|value| value.get("exp").and_then(serde_json::Value::as_u64))
            .ok_or(CodexAuthError::Expired)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CodexAuthError::Expired)?
            .as_secs();
        if expiry <= now.saturating_add(30) {
            return Err(CodexAuthError::Expired);
        }
        Ok(CodexCredentials {
            account_id: tokens.account_id,
            access_token: zeroize::Zeroizing::new(tokens.access_token),
        })
    }
}

#[cfg(test)]
mod tests;
