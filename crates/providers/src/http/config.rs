//! Operator-owned account aliases reference environment variables, private
//! credential files or secret stores; route configuration contains no secret values.
use super::{HttpCredential, HttpEgressPolicy, HttpFetchProvider};
use hellas_auth::authority::UnixMillis;
use hellas_executor::{FetchProviderError, FetchRouteEntry, FetchRoutePolicy};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::{io::Read, path::PathBuf, sync::Arc, time::Duration};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpProviderConfig {
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub allow_private_addresses: bool,
    #[serde(default)]
    pub credentials: BTreeMap<String, HttpCredentialConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpCredentialConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub allowed_methods: Vec<String>,
    /// Defaults to public WebPKI. Private roots must be explicitly operator-owned.
    #[serde(default)]
    pub trust_roots: Option<hellas_rpc::http_fetch::HttpTrustRoots>,
    pub header_name: String,
    #[serde(flatten)]
    pub source: HttpSecretConfig,
}

/// The one operator-owned credential source used by HTTP routes and provisioning.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSecretConfig {
    pub secret_env: Option<String>,
    pub secret_store: Option<HttpSecretStore>,
    /// A private JSON credential file maintained by the account's login tool.
    pub secret_file: Option<PathBuf>,
    pub secret_field: Option<String>,
    pub refresh: Option<CredentialRefresh>,
    #[serde(default)]
    pub prefix: String,
}

/// A reference, never a secret value. Headless files require explicit selection.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum HttpSecretStore {
    Native {
        service: String,
        key: String,
    },
    HeadlessFiles {
        directory: PathBuf,
        service: String,
        key: String,
    },
}
impl HttpSecretStore {
    fn into_entry(self) -> Result<(hellas_private::SecretStore, String), FetchProviderError> {
        let (store, key) = match self {
            Self::Native { service, key } => (hellas_private::SecretStore::native(service), key),
            Self::HeadlessFiles {
                directory,
                service,
                key,
            } => (
                hellas_private::SecretStore::headless_files(directory, service),
                key,
            ),
        };
        let store = store.map_err(|_| super::fault("invalid secret store reference"))?;
        store
            .validate_key(&key)
            .map_err(|_| super::fault("invalid secret store key"))?;
        Ok((store, key))
    }
}

/// An operator-owned login tool updates the same private JSON file. It receives
/// no customer data, and its output is never forwarded to clients or logs.
#[derive(Clone, Debug, Deserialize, Serialize)]
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
        Ok(expiry <= (UnixMillis::now().unwrap_or_default().0 as f64 / 1_000.) + 30.)
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
    Store {
        store: hellas_private::SecretStore,
        key: String,
        prefix: String,
    },
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
    pub async fn resolve(&self) -> Result<String, FetchProviderError> {
        match self {
            Self::Value(value) => Ok(value.clone()),
            Self::Store { store, key, prefix } => {
                let store = store.clone();
                let key = key.clone();
                let bytes = tokio::task::spawn_blocking(move || store.get(&key))
                    .await
                    .map_err(|_| super::fault("secret store reader failed"))?
                    .map_err(|_| super::fault("secret store unavailable or access denied"))?
                    .ok_or_else(|| super::fault("secret store entry unavailable"))?;
                let secret = std::str::from_utf8(&bytes)
                    .ok()
                    .filter(|secret| !secret.is_empty())
                    .ok_or_else(|| super::fault("secret store entry must be nonempty UTF-8"))?;
                Ok(format!("{prefix}{secret}"))
            }
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
                if let Some(refresh) = refresh
                    && refresh.due(&object)?
                {
                    let Some(retry_at) = guard.as_mut() else {
                        return Err(super::fault("credential refresh lock unavailable"));
                    };
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

impl HttpSecretConfig {
    pub fn into_secret(self) -> Result<HttpSecret, FetchProviderError> {
        if self
            .refresh
            .as_ref()
            .is_some_and(|refresh| refresh.command.is_empty() || refresh.expires_field.is_empty())
        {
            return Err(super::fault(
                "credential refresh requires a command and expiry field",
            ));
        }
        let secret = match (
            self.secret_env,
            self.secret_file,
            self.secret_field,
            self.secret_store,
        ) {
            (Some(name), None, None, None) if self.refresh.is_none() => {
                let secret = std::env::var(name).map_err(|_| {
                    super::fault("account secret environment variable is unavailable")
                })?;
                if secret.is_empty() {
                    return Err(super::fault("account secret is empty"));
                }
                HttpSecret::Value(format!("{}{secret}", self.prefix))
            }
            (None, Some(path), Some(field), None) if !field.is_empty() => HttpSecret::JsonFile {
                path,
                field,
                prefix: self.prefix,
                refresh: self.refresh,
            },
            (None, None, None, Some(reference)) if self.refresh.is_none() => {
                let (store, key) = reference.into_entry()?;
                HttpSecret::Store {
                    store,
                    key,
                    prefix: self.prefix,
                }
            }
            _ => {
                return Err(super::fault(
                    "configure exactly one of secret_env, secret_file with secret_field, or secret_store",
                ));
            }
        };
        Ok(secret)
    }
}

impl HttpProviderConfig {
    pub fn into_entry(
        self,
        capabilities: FetchRoutePolicy,
    ) -> Result<FetchRouteEntry, FetchProviderError> {
        let mut credentials = BTreeMap::new();
        for (alias, config) in self.credentials {
            let header_value = config.source.into_secret()?;
            credentials.insert(
                alias,
                HttpCredential {
                    allowed_origins: config.allowed_origins,
                    allowed_paths: config.allowed_paths,
                    allowed_methods: config.allowed_methods,
                    trust_roots: config
                        .trust_roots
                        .unwrap_or(hellas_rpc::http_fetch::HttpTrustRoots::WebPki),
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
            std::sync::Arc::new(
                super::HttpFetchAdaptorFactory::new()
                    .map_err(|_| super::fault("invalid HTTP execution contract"))?,
            ),
            capabilities,
        )
        .map_err(|_| super::fault("invalid HTTP Fetch route"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_credentials_resolve_rotation_and_refuse_invalid_values() {
        let directory = tempfile::tempdir().unwrap();
        hellas_private::restrict_directory(directory.path()).unwrap();
        let store =
            hellas_private::SecretStore::headless_files(directory.path().into(), "http-test")
                .unwrap();
        let value = serde_json::json!({"secret_store": {"backend":"headless_files", "directory":directory.path(), "service":"http-test", "key":"token"}, "prefix":"Bearer "});
        let source = serde_json::from_value::<HttpSecretConfig>(value.clone())
            .unwrap()
            .into_secret()
            .unwrap();
        assert!(source.resolve().await.is_err());
        for token in ["first", "rotated"] {
            store.set("token", token.as_bytes()).unwrap();
            assert_eq!(source.resolve().await.unwrap(), format!("Bearer {token}"));
        }
        for invalid in [b"".as_slice(), b"\xffPRIVATE-PAYLOAD".as_slice()] {
            store.set("token", invalid).unwrap();
            let error = source.resolve().await.unwrap_err().to_string();
            assert!(!error.contains("PRIVATE-PAYLOAD"));
        }
        store.delete("token").unwrap();
        assert!(source.resolve().await.is_err());
        for (name, extra) in [
            ("secret_env", serde_json::json!("IGNORED")),
            ("secret_file", serde_json::json!("ignored")),
            ("secret_field", serde_json::json!("token")),
            (
                "refresh",
                serde_json::json!({"command":["unused"],"expires_field":"expiry"}),
            ),
        ] {
            let mut ambiguous = value.clone();
            ambiguous[name] = extra;
            assert!(
                serde_json::from_value::<HttpSecretConfig>(ambiguous)
                    .unwrap()
                    .into_secret()
                    .is_err()
            );
        }
        let mut unknown = value;
        unknown["secret_store"]["fallback"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HttpSecretConfig>(unknown).is_err());
    }

    #[tokio::test]
    #[ignore = "requires an explicitly prepared disposable native secret-store session"]
    async fn native_store_source_resolves_on_current_thread_runtime() {
        let service = std::env::var("HELLAS_SECRET_TEST_SERVICE").unwrap();
        assert!(service.starts_with("hellas-secret-test-"));
        let store = hellas_private::SecretStore::native(&service).unwrap();
        let writer = store.clone();
        tokio::task::spawn_blocking(move || writer.set("http-token", b"native-token"))
            .await
            .unwrap()
            .unwrap();
        let source = serde_json::from_value::<HttpSecretConfig>(serde_json::json!({"secret_store":{"backend":"native","service":service,"key":"http-token"},"prefix":"Bearer "})).unwrap().into_secret().unwrap();
        let result = source.resolve().await;
        tokio::task::spawn_blocking(move || store.delete("http-token"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.unwrap(), "Bearer native-token");
    }

    #[test]
    fn flattened_source_preserves_http_scope_and_rejects_ambiguous_sources() {
        let value = serde_json::json!({
            "allowed_origins":["https://example.com"], "allowed_paths":["/exact"],
            "allowed_methods":["POST"], "header_name":"authorization",
            "secret_file":"account.json", "secret_field":"token", "prefix":"Bearer "
        });
        let config: HttpCredentialConfig = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(config.allowed_paths, ["/exact"]);
        assert!(matches!(
            config.source.into_secret().unwrap(),
            HttpSecret::JsonFile { .. }
        ));
        let mut unknown = value.clone();
        unknown["implicit_fallback"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HttpCredentialConfig>(unknown).is_err());
        let mut ambiguous = value;
        ambiguous["secret_env"] = serde_json::json!("EXPLICIT_ACCOUNT_TOKEN");
        let config: HttpCredentialConfig = serde_json::from_value(ambiguous).unwrap();
        assert!(config.source.into_secret().is_err());
        let missing: HttpSecretConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(missing.into_secret().is_err());
    }

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
