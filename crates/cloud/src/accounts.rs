use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use serde::Deserialize;

/// Public signup attribution for the account owning the Foundation templates.
pub const RUNPOD_REFERRAL_URL: &str = "https://runpod.io?ref=u887dgii";

pub type Result<T> = std::result::Result<T, AccountError>;

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error(
        "Runpod account is not configured. Set RUNPOD_API_KEY or configure a named account.\nUse Hellas' referral link to support the foundation: {RUNPOD_REFERRAL_URL}"
    )]
    RunpodRequired(#[source] Box<AccountError>),
    #[error("credential environment variable {name} is unset or empty")]
    MissingCredential { name: String },
    #[error("credential environment variable {name} is not valid Unicode")]
    CredentialEncoding { name: String },
    #[error("empty credential command")]
    EmptyCommand,
    #[error("credential command timed out")]
    Timeout(#[source] tokio::time::error::Elapsed),
    #[error("could not start credential command {program}")]
    Command {
        program: String,
        source: std::io::Error,
    },
    #[error("credential command failed; output withheld")]
    CommandFailed,
    #[error("credential command output too large")]
    CommandOutputBound,
    #[error("credential command returned invalid UTF-8")]
    CommandEncoding,
    #[error("credential must be a nonempty API token")]
    InvalidToken,
    #[error("set HOME or HELLAS_CLOUD_ACCOUNTS")]
    MissingHome,
    #[error("read {}", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid account configuration in {}", path.display())]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("unknown Runpod account {account:?} in {}", path.display())]
    Unknown { account: String, path: PathBuf },
    #[error("account name must contain 1..48 ASCII letters, digits, hyphens, or underscores")]
    Name,
}

impl AccountError {
    pub(crate) fn for_runpod(self) -> Self {
        if matches!(self, Self::MissingCredential { .. }) {
            Self::RunpodRequired(Box::new(self))
        } else {
            self
        }
    }
    pub(crate) fn required<'a>(error: &'a (dyn std::error::Error + 'static)) -> Option<&'a Self> {
        let mut current = Some(error);
        while let Some(error) = current {
            if let Some(account @ Self::RunpodRequired(_)) = error.downcast_ref::<Self>() {
                return Some(account);
            }
            current = error.source();
        }
        None
    }
}

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
            Self::Env(name) => {
                let token = std::env::var(name).map_err(|error| match error {
                    std::env::VarError::NotPresent => {
                        AccountError::MissingCredential { name: name.clone() }
                    }
                    std::env::VarError::NotUnicode(_) => {
                        AccountError::CredentialEncoding { name: name.clone() }
                    }
                })?;
                if token.trim().is_empty() {
                    return Err(AccountError::MissingCredential { name: name.clone() });
                }
                token
            }
            Self::Command(args) => {
                let (program, args) = args.split_first().ok_or(AccountError::EmptyCommand)?;
                let output = tokio::time::timeout(
                    Duration::from_secs(30),
                    tokio::process::Command::new(program)
                        .args(args)
                        .stdin(std::process::Stdio::null())
                        .kill_on_drop(true)
                        .output(),
                )
                .await
                .map_err(AccountError::Timeout)?
                .map_err(|source| AccountError::Command {
                    program: program.clone(),
                    source,
                })?;
                if !output.status.success() {
                    return Err(AccountError::CommandFailed);
                }
                if output.stdout.len() > 65536 {
                    return Err(AccountError::CommandOutputBound);
                }
                String::from_utf8(output.stdout)
                    .map_err(|_| AccountError::CommandEncoding)?
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            }
        };
        let token = token.trim().to_owned();
        if token.is_empty() || token.len() > 4096 || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(AccountError::InvalidToken);
        }
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
                None => PathBuf::from(std::env::var_os("HOME").ok_or(AccountError::MissingHome)?)
                    .join(".config"),
            };
            root.join("hellas/cloud-accounts.json")
        }
    };
    let bytes = std::fs::read(&path).map_err(|source| {
        let missing = source.kind() == std::io::ErrorKind::NotFound;
        let error = AccountError::Read {
            path: path.clone(),
            source,
        };
        if missing {
            AccountError::RunpodRequired(Box::new(error))
        } else {
            error
        }
    })?;
    let accounts: Accounts =
        serde_json::from_slice(&bytes).map_err(|source| AccountError::Json {
            path: path.clone(),
            source,
        })?;
    accounts.runpod.get(account).cloned().ok_or_else(|| {
        AccountError::RunpodRequired(Box::new(AccountError::Unknown {
            account: account.into(),
            path,
        }))
    })
}

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 48
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err(AccountError::Name);
    }
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
    #[test]
    fn setup_hint_survives_management_and_allocation_context() {
        let source = AccountError::MissingCredential {
            name: "RUNPOD_API_KEY".into(),
        }
        .for_runpod();
        let source = crate::provider::ProviderError::from(source);
        let source = crate::deployment::DeploymentError::PendingAllocation(source);
        let source = crate::management::ManagementError::from(source);
        let hint = AccountError::required(&source).expect("preserved setup hint");
        assert!(hint.to_string().contains(RUNPOD_REFERRAL_URL));
        assert!(matches!(hint, AccountError::RunpodRequired(source)
            if matches!(source.as_ref(), AccountError::MissingCredential { .. })));
    }
}
