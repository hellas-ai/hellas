//! Operator-owned account aliases reference environment variables or private
//! credential files; route configuration contains no secret values.
use super::{HttpCredential, HttpEgressPolicy, HttpFetchProvider};
use hellas_executor::{FetchProviderError, FetchRouteEntry, FetchRoutePolicy};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::{
    io::Read,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpProviderConfig {
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub allow_private_addresses: bool,
    #[serde(default)]
    pub credentials: BTreeMap<String, HttpCredentialConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpCredentialConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub header_name: String,
    pub secret_env: Option<String>,
    /// A private JSON credential file maintained by the account's login tool.
    pub secret_file: Option<PathBuf>,
    pub secret_field: Option<String>,
    pub refresh: Option<CredentialRefresh>,
    #[serde(default)]
    pub prefix: String,
}

/// An operator-owned login tool updates the same private JSON file. It receives
/// no customer data, and its output is never forwarded to clients or logs.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRefresh {
    pub command: Vec<String>,
    pub expires_field: String,
    #[serde(skip)]
    lock: Arc<tokio::sync::Mutex<Option<std::time::Instant>>>,
}

impl CredentialRefresh {
    fn due(&self, object: &serde_json::Value) -> Result<bool, FetchProviderError> {
        let expiry = credential_field(object, &self.expires_field)
            .and_then(serde_json::Value::as_f64)
            .filter(|value| value.is_finite())
            .ok_or_else(|| super::fault("credential expiry unavailable"))?;
        Ok(expiry
            <= SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64()
                + 30.)
    }
    async fn run(&self) -> Result<(), FetchProviderError> {
        use tracing::Instrument;
        let span = hellas_rpc::request_span!(target: "hellas_request", "credential.refresh",
            otel.kind = "internal", otel.status_code = tracing::field::Empty, error.type = tracing::field::Empty);
        let Some((program, args)) = self.command.split_first() else {
            return Err(super::fault("empty credential refresh command"));
        };
        let mut command = tokio::process::Command::new(program);
        command
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let result = tokio::time::timeout(Duration::from_secs(30), command.status())
            .instrument(span.clone())
            .await;
        if !matches!(result, Ok(Ok(status)) if status.success()) {
            span.record("otel.status_code", "ERROR");
            span.record("error.type", "refresh_failed");
            return Err(super::fault("credential refresh failed"));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub enum HttpSecret {
    Value(String),
    JsonFile {
        path: PathBuf,
        field: String,
        prefix: String,
        refresh: Option<CredentialRefresh>,
    },
}

impl From<String> for HttpSecret {
    fn from(value: String) -> Self {
        Self::Value(value)
    }
}
impl From<&str> for HttpSecret {
    fn from(value: &str) -> Self {
        Self::Value(value.into())
    }
}

impl HttpSecret {
    pub(super) async fn resolve(&self) -> Result<String, FetchProviderError> {
        match self {
            Self::Value(value) => Ok(value.clone()),
            Self::JsonFile {
                path,
                field,
                prefix,
                refresh,
            } => {
                let mut guard = match refresh {
                    Some(refresh) => Some(refresh.lock.lock().await),
                    None => None,
                };
                let mut object = read_credential(path.clone()).await?;
                if let Some(refresh) = refresh {
                    if refresh.due(&object)? {
                        let retry_at = guard.as_mut().expect("refresh holds its account lock");
                        if retry_at.is_some_and(|deadline| deadline > std::time::Instant::now()) {
                            return Err(super::fault("credential refresh is cooling down"));
                        }
                        **retry_at = Some(std::time::Instant::now() + Duration::from_secs(30));
                        refresh.run().await?;
                        object = read_credential(path.clone()).await?;
                        if refresh.due(&object)? {
                            return Err(super::fault("credential refresh did not renew the token"));
                        }
                        **retry_at = None;
                    }
                }
                let secret = credential_field(&object, field)
                    .and_then(serde_json::Value::as_str)
                    .filter(|secret| !secret.is_empty())
                    .ok_or_else(|| super::fault("credential field unavailable"))?;
                Ok(format!("{prefix}{secret}"))
            }
        }
    }
}

fn credential_field<'a>(
    object: &'a serde_json::Value,
    field: &str,
) -> Option<&'a serde_json::Value> {
    if field.starts_with('/') {
        object.pointer(field)
    } else {
        object.get(field)
    }
}

async fn read_credential(path: PathBuf) -> Result<serde_json::Value, FetchProviderError> {
    tokio::task::spawn_blocking(move || {
        let file = hellas_private::open_nofollow(&path)
            .map_err(|_| super::fault("credential file unavailable"))?;
        if !hellas_private::is_private(&file).unwrap_or(false) {
            return Err(super::fault("credential file must be owner-only"));
        }
        let mut bytes = Vec::new();
        file.take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| super::fault("credential file read failed"))?;
        if bytes.len() > 65536 {
            return Err(super::fault("credential file exceeds limit"));
        }
        let object: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| super::fault("credential file is not JSON"))?;
        Ok(object)
    })
    .await
    .map_err(|_| super::fault("credential loader failed"))?
}

impl HttpProviderConfig {
    pub fn into_entry(
        self,
        capabilities: FetchRoutePolicy,
    ) -> Result<FetchRouteEntry, FetchProviderError> {
        let mut credentials = BTreeMap::new();
        for (alias, config) in self.credentials {
            if config.refresh.as_ref().is_some_and(|refresh| {
                refresh.command.is_empty() || refresh.expires_field.is_empty()
            }) {
                return Err(super::fault(
                    "credential refresh requires a command and expiry field",
                ));
            }
            let header_value = match (config.secret_env, config.secret_file, config.secret_field) {
                (Some(name), None, None) if config.refresh.is_none() => {
                    let secret = std::env::var(name).map_err(|_| {
                        super::fault("account secret environment variable is unavailable")
                    })?;
                    if secret.is_empty() {
                        return Err(super::fault("account secret is empty"));
                    }
                    HttpSecret::Value(format!("{}{secret}", config.prefix))
                }
                (None, Some(path), Some(field)) if !field.is_empty() => HttpSecret::JsonFile {
                    path,
                    field,
                    prefix: config.prefix,
                    refresh: config.refresh,
                },
                _ => {
                    return Err(super::fault(
                        "configure either secret_env or secret_file with secret_field",
                    ));
                }
            };
            credentials.insert(
                alias,
                HttpCredential {
                    allowed_origins: config.allowed_origins,
                    allowed_paths: config.allowed_paths,
                    allowed_methods: config.allowed_methods,
                    header_name: config.header_name,
                    header_value,
                },
            );
        }
        let provider = HttpFetchProvider::new(
            HttpEgressPolicy {
                allowed_hosts: self.allowed_hosts,
                allow_private_addresses: self.allow_private_addresses,
            },
            credentials,
        )?;
        FetchRouteEntry::new(
            std::sync::Arc::new(provider),
            std::sync::Arc::new(super::HttpFetchAdaptorFactory),
            capabilities,
        )
        .map_err(|_| super::fault("invalid HTTP Fetch route"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn nested_file_credentials_follow_rotation_and_reject_missing_fields() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("account.json");
        let source = HttpSecret::JsonFile {
            path: path.clone(),
            field: "/tokens/access_token".into(),
            prefix: "Bearer ".into(),
            refresh: None,
        };
        for token in ["first", "rotated"] {
            hellas_private::write_atomically(
                &path,
                ".tmp",
                &serde_json::to_vec(&serde_json::json!({"tokens":{"access_token":token}})).unwrap(),
            )
            .unwrap();
            assert_eq!(source.resolve().await.unwrap(), format!("Bearer {token}"));
        }
        hellas_private::write_atomically(
            &path,
            ".tmp",
            b"{\"tokens\":{\"refresh_token\":\"private\"}}",
        )
        .unwrap();
        assert!(source.resolve().await.is_err());
        let refresh = CredentialRefresh {
            command: vec!["unused".into()],
            expires_field: "/tokens/expires_at".into(),
            lock: Default::default(),
        };
        assert!(
            refresh
                .due(&serde_json::json!({"tokens":{"expires_at":0}}))
                .unwrap()
        );
        assert!(
            !refresh
                .due(&serde_json::json!({"tokens":{"expires_at":4102444800_u64}}))
                .unwrap()
        );
        assert!(refresh.due(&serde_json::json!({"tokens":{}})).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_refresh_is_not_repeated_by_waiting_requests() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("account.json");
        let counter = directory.path().join("count");
        hellas_private::write_atomically(
            &path,
            ".tmp",
            b"{\"access_token\":\"old\",\"expires_at\":0}",
        )
        .unwrap();
        let source = HttpSecret::JsonFile {
            path,
            field: "access_token".into(),
            prefix: String::new(),
            refresh: Some(CredentialRefresh {
                command: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "printf 'attempt\\n' >> \"$1\"; exit 1".into(),
                    "refresh-test".into(),
                    counter.to_string_lossy().into(),
                ],
                expires_field: "expires_at".into(),
                lock: Default::default(),
            }),
        };
        let (a, b) = tokio::join!(source.resolve(), source.resolve());
        assert!(a.is_err() && b.is_err());
        assert_eq!(std::fs::read_to_string(counter).unwrap(), "attempt\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn concurrent_reads_refresh_once_and_verify_the_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("account.json");
        let counter = directory.path().join("count");
        hellas_private::write_atomically(
            &path,
            ".tmp",
            b"{\"access_token\":\"old\",\"expires_at\":0}",
        )
        .unwrap();
        let refresh = CredentialRefresh {
            command: vec!["/bin/sh".into(), "-c".into(),
                "printf '%s' '{\"access_token\":\"new\",\"expires_at\":4102444800}' > \"$1\"; printf 'one\\n' >> \"$2\"".into(),
                "refresh-test".into(), path.to_string_lossy().into(), counter.to_string_lossy().into()],
            expires_field: "expires_at".into(), lock: Default::default(),
        };
        let source = HttpSecret::JsonFile {
            path,
            field: "access_token".into(),
            prefix: "Bearer ".into(),
            refresh: Some(refresh),
        };
        let (a, b) = tokio::join!(source.resolve(), source.resolve());
        assert_eq!(a.unwrap(), "Bearer new");
        assert_eq!(b.unwrap(), "Bearer new");
        assert_eq!(std::fs::read_to_string(counter).unwrap(), "one\n");
    }
    #[tokio::test]
    async fn file_credentials_follow_atomic_rotation_and_reject_missing_or_public_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("account.json");
        let source = HttpSecret::JsonFile {
            path: path.clone(),
            field: "access_token".into(),
            prefix: "Bearer ".into(),
            refresh: None,
        };
        assert!(source.resolve().await.is_err());
        for value in ["first", "rotated"] {
            hellas_private::write_atomically(
                &path,
                ".tmp",
                &serde_json::to_vec(&serde_json::json!({"access_token":value})).unwrap(),
            )
            .unwrap();
            assert_eq!(source.resolve().await.unwrap(), format!("Bearer {value}"));
        }
        hellas_private::write_atomically(&path, ".tmp", b"{\"refresh_token\":\"DO-NOT-LEAK\"}")
            .unwrap();
        let error = source.resolve().await.unwrap_err().to_string();
        assert!(!error.contains("DO-NOT-LEAK"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(source.resolve().await.is_err());
        }
    }
}
