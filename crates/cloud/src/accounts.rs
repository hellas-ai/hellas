use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

/// Profiles contain references to credentials, never API keys.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accounts {
    pub runpod: BTreeMap<String, CredentialSource>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum CredentialSource {
    Env(String),
    Command(Vec<String>),
}

impl CredentialSource {
    pub async fn token(&self) -> Result<String> {
        let token = match self {
            Self::Env(name) => std::env::var(name).with_context(|| format!("set {name}"))?,
            Self::Command(args) => {
                let (program, args) = args.split_first().context("empty credential command")?;
                let output = tokio::time::timeout(
                    Duration::from_secs(30),
                    tokio::process::Command::new(program)
                        .args(args)
                        .stdin(std::process::Stdio::null())
                        .kill_on_drop(true)
                        .output(),
                )
                .await
                .context("credential command timed out")?
                .context("could not start credential command")?;
                ensure!(
                    output.status.success(),
                    "credential command failed; output withheld"
                );
                ensure!(
                    output.stdout.len() <= 65536,
                    "credential command output too large"
                );
                String::from_utf8(output.stdout)
                    .context("credential command returned invalid UTF-8")?
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            }
        };
        let token = token.trim().to_owned();
        ensure!(
            !token.is_empty() && token.len() <= 4096 && token.bytes().all(|b| b.is_ascii_graphic()),
            "credential must be a nonempty API token"
        );
        Ok(token)
    }
}

pub fn runpod(account: Option<&str>) -> Result<CredentialSource> {
    let Some(account) = account else {
        return Ok(CredentialSource::Env("RUNPOD_API_KEY".into()));
    };
    validate_name(account)?;
    let path = match std::env::var_os("HELLAS_CLOUD_ACCOUNTS") {
        Some(path) => PathBuf::from(path),
        None => {
            let root = match std::env::var_os("XDG_CONFIG_HOME") {
                Some(root) => PathBuf::from(root),
                None => PathBuf::from(
                    std::env::var_os("HOME").context("set HOME or HELLAS_CLOUD_ACCOUNTS")?,
                )
                .join(".config"),
            };
            root.join("hellas/cloud-accounts.json")
        }
    };
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let accounts: Accounts = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid account configuration in {}", path.display()))?;
    accounts
        .runpod
        .get(account)
        .cloned()
        .with_context(|| format!("unknown Runpod account {account:?} in {}", path.display()))
}

pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 48
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
        "account name must contain 1..48 ASCII letters, digits, hyphens, or underscores"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn credential_commands_use_first_line_and_withhold_failure_output() {
        let source = CredentialSource::Command(vec![
            "sh".into(),
            "-c".into(),
            "printf 'test-token\\nextra pass metadata\\n'".into(),
        ]);
        assert_eq!(source.token().await.unwrap(), "test-token");
        let failed = CredentialSource::Command(vec![
            "sh".into(),
            "-c".into(),
            "printf do-not-leak; printf do-not-leak >&2; exit 1".into(),
        ]);
        let error = format!("{:#}", failed.token().await.unwrap_err());
        assert!(error.contains("output withheld"));
        assert!(!error.contains("do-not-leak"));
    }
}
