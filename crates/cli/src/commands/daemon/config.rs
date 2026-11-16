//! TOML and foreground shorthand compile into the same daemon document.
use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    #[serde(default)]
    models: Vec<String>,
    #[serde(default)]
    upstreams: std::collections::BTreeMap<String, Upstream>,
    #[serde(default)]
    paid_policy: Option<hellas_channel::model::paid_policy::PaidPolicy>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upstream {
    url: String,
    key_file: PathBuf,
}
pub(super) struct Resolved {
    pub document: Document,
    pub paid_policy: Option<hellas_channel::model::paid_policy::PaidPolicy>,
}
pub(super) struct State {
    pub document: Document,
    models: Vec<String>,
    upstreams: std::collections::BTreeMap<String, Upstream>,
    pub paid_policy: Option<hellas_channel::model::paid_policy::PaidPolicy>,
}
impl State {
    pub fn gateway(
        models: Vec<String>,
        upstreams: Vec<String>,
        bind: Option<std::net::SocketAddr>,
    ) -> Result<Self> {
        let mut document = Document::default();
        document.listeners.insert(
            "api".into(),
            Listener::http(bind.unwrap_or_else(|| "127.0.0.1:8080".parse().unwrap())),
        );
        let mut named = std::collections::BTreeMap::new();
        for upstream in upstreams {
            let (definition, key_file) = upstream
                .rsplit_once(",key-file=")
                .context("upstream is NAME=HTTPS_API_URL,key-file=PATH")?;
            let (name, url) = definition
                .split_once('=')
                .context("upstream is NAME=HTTPS_API_URL,key-file=PATH")?;
            ensure!(
                named
                    .insert(
                        name.into(),
                        Upstream {
                            url: url.into(),
                            key_file: key_file.into()
                        }
                    )
                    .is_none(),
                "duplicate upstream {name}"
            );
        }
        Ok(Self {
            document,
            models,
            upstreams: named,
            paid_policy: None,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = hellas_private::read_bounded_regular_file(path, 512 * 1024)?;
        Self::parse(std::str::from_utf8(&bytes)?)
            .with_context(|| format!("configuration {}", path.display()))
    }
    fn parse(text: &str) -> Result<Self> {
        let diagnostic = |error: toml::de::Error| {
            let offset = error.span().map_or(0, |span| span.start).min(text.len());
            let prefix = &text.as_bytes()[..offset];
            let line = prefix.iter().filter(|byte| **byte == b'\n').count() + 1;
            let column = prefix
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(offset + 1, |newline| offset - newline);
            anyhow::anyhow!("invalid daemon TOML at line {line}, column {column} (byte {offset})")
        };
        let mut table: toml::Table = toml::from_str(text).map_err(diagnostic)?;
        let mut inputs = toml::Table::new();
        for key in ["models", "upstreams", "paid_policy"] {
            if let Some(value) = table.remove(key) {
                inputs.insert(key.into(), value);
            }
        }
        let schema_error = |error: toml::de::Error| {
            let message = error.message();
            let safe = if let Some((_, expected)) = message.split_once(", expected ") {
                format!("expected {expected}")
            } else if message.starts_with("missing field `") {
                message.to_owned()
            } else {
                "unknown or invalid field".into()
            };
            anyhow::anyhow!("invalid configuration schema: {safe}")
        };
        let inputs: Inputs = toml::Value::Table(inputs)
            .try_into()
            .map_err(schema_error)?;
        let document: Document = toml::Value::Table(table).try_into().map_err(schema_error)?;
        if let Some(policy) = &inputs.paid_policy {
            policy.check()?;
        }
        Ok(Self {
            document,
            models: inputs.models,
            upstreams: inputs.upstreams,
            paid_policy: inputs.paid_policy,
        })
    }
    pub async fn resolve(self, context: &ModelContext) -> Result<Resolved> {
        let mut document = self.document;
        for (name, upstream) in self.upstreams {
            expand_upstream(&mut document, &name, &upstream.url, &upstream.key_file)?;
        }
        for model in self.models {
            context.add(&mut document, &model).await?;
        }
        document.validate().map_err(anyhow::Error::msg)?;
        Ok(Resolved {
            document,
            paid_policy: self.paid_policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn compilation_preserves_selection_and_matches_foreground_defaults() {
        let root = tempfile::tempdir().unwrap();
        let key = root.path().join("key");
        std::fs::write(&key, "runtime-secret").unwrap();
        let context = ModelContext {
            home: root.path().into(),
            content: None,
            principal: None,
            holder: NodeKey::from_public_key(
                hellas_auth::ProducerSigningKey::from_secret_bytes([1; 32])
                    .unwrap()
                    .public_key(),
            )
            .unwrap(),
        };
        let shorthand = format!("remote=https://example.com/v1,key-file={}", key.display());
        let flags = State::gateway(vec!["model@remote".into()], vec![shorthand], None)
            .unwrap()
            .resolve(&context)
            .await
            .unwrap();
        let text = format!(
            "models = ['model@remote']\n[listeners.api]\nkind = 'http'\nbind = '127.0.0.1:8080'\n[upstreams.remote]\nurl = 'https://example.com/v1'\nkey_file = '{}'\n",
            key.display()
        );
        let file = State::parse(&text)
            .unwrap()
            .resolve(&context)
            .await
            .unwrap();
        assert!(flags.document == file.document);
        let selected = format!(
            "{text}\n[backends.local]\nkind = 'local'\nmax_in_flight = 1\n[listeners.work]\nkind = 'iroh'\nport = 0\nbackends = ['local']\n"
        );
        let file = State::parse(&selected)
            .unwrap()
            .resolve(&context)
            .await
            .unwrap();
        assert!(
            matches!(&file.document.listeners["work"], Listener::Iroh { backends, .. } if backends == &["local"])
        );
        let explicit =
            State::parse(&text.replace("kind = 'http'", "kind = 'http'\nzdr = false")).unwrap();
        assert!(matches!(
            explicit.document.listeners["api"],
            Listener::Http { zdr: false, .. }
        ));
        let schema = State::parse("models = 'private-key-material'")
            .err()
            .unwrap()
            .to_string();
        assert!(
            schema.contains("schema")
                && schema.contains("expected")
                && !schema.contains("line 1")
                && !schema.contains("private-key-material")
        );
        let error = State::parse("models = [\n'private-key-material'\nBAD")
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("line")
                && error.contains("column")
                && !error.contains("private-key-material")
        );
    }

    #[test]
    fn shared_toml_supports_multiple_models_and_runtime_keys() {
        let state = State::parse(
            r#"
models = ["/srv/qwen.gguf", "/srv/flux"]
[listeners.work]
kind = "iroh"
port = 31145
backends = ["local"]
[listeners.api]
kind = "http"
bind = "127.0.0.1:8080"
[upstreams.remote]
url = "https://example.com/v1"
key_file = "/run/secrets/upstream"
"#,
        )
        .unwrap();
        assert_eq!(state.models.len(), 2);
        assert_eq!(
            state.upstreams["remote"].key_file,
            Path::new("/run/secrets/upstream")
        );
        assert!(State::parse("unknown = true").is_err());
        let bounds = State::parse("[execution]\nqueue_capacity = 1\nsession_programs = 1\nsession_asset_bytes = 1516744736").unwrap();
        assert_eq!(
            bounds.document.execution.session_asset_bytes.unwrap().get(),
            1516744736
        );
        assert!(State::parse("[execution]\nqueue_capacity = 0").is_ok());
        assert!(State::parse("[listeners.api]\nkind = 'http'\nbind = 'invalid'").is_err());
        assert!(State::parse("[paid_policy]\njobs_per_channel = 0").is_err());
    }
}
