//! TOML and foreground shorthand compile into the same daemon document.
use super::*;
use hellas_channel::model::paid_policy::PaidPolicy;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upstream {
    url: String,
    key_file: PathBuf,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    #[serde(flatten)]
    pub document: Document,
    #[serde(default)]
    models: Vec<String>,
    #[serde(default)]
    upstreams: std::collections::BTreeMap<String, Upstream>,
    #[serde(default)]
    pub paid_policy: Option<PaidPolicy>,
}
impl Config {
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
        let config: Self = toml::from_str(text).map_err(|error: toml::de::Error| {
            let message = error.message();
            let cause = if let Some((_, expected)) = message.split_once(", expected ") {
                format!("configuration schema: expected {expected}")
            } else if message.starts_with("missing field `") {
                format!("configuration schema: {message}")
            } else {
                "unknown configuration field or invalid TOML syntax".into()
            };
            let location = error
                .span()
                .map(|span| {
                    let prefix = &text.as_bytes()[..span.start.min(text.len())];
                    let line = prefix.iter().filter(|byte| **byte == b'\n').count() + 1;
                    let column = prefix
                        .iter()
                        .rposition(|byte| *byte == b'\n')
                        .map_or(prefix.len() + 1, |newline| prefix.len() - newline);
                    format!(
                        " at line {line}, column {column} (bytes {}..{})",
                        span.start, span.end
                    )
                })
                .unwrap_or_default();
            anyhow::anyhow!("{cause}{location}")
        })?;
        if let Some(policy) = &config.paid_policy {
            policy.check()?;
        }
        Ok(config)
    }
    pub async fn resolve(self, context: &ModelContext) -> Result<(Document, Option<PaidPolicy>)> {
        let mut document = self.document;
        for (name, upstream) in self.upstreams {
            expand_upstream(&mut document, &name, &upstream.url, &upstream.key_file)?;
        }
        for model in self.models {
            context.add(&mut document, &model).await?;
        }
        document.validate().map_err(anyhow::Error::msg)?;
        Ok((document, self.paid_policy))
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
        let context = super::super::tests::model_context(root.path());
        let shorthand = format!("remote=https://example.com/v1,key-file={}", key.display());
        let flags = Config::gateway(
            vec!["model@remote".into(), "second@remote".into()],
            vec![shorthand],
            None,
        )
        .unwrap()
        .resolve(&context)
        .await
        .unwrap();
        let text = format!(
            "models = ['model@remote', 'second@remote']\n[listeners.api]\nkind = 'http'\nbind = '127.0.0.1:8080'\n[upstreams.remote]\nurl = 'https://example.com/v1'\nkey_file = '{}'\n",
            key.display()
        );
        let file = Config::parse(&text)
            .unwrap()
            .resolve(&context)
            .await
            .unwrap();
        assert!(flags.0 == file.0);
        let selected = format!(
            "{text}\n[backends.local]\nkind = 'local'\nmax_in_flight = 1\n[listeners.work]\nkind = 'iroh'\nport = 0\nbackends = ['local']\n"
        );
        let file = Config::parse(&selected)
            .unwrap()
            .resolve(&context)
            .await
            .unwrap();
        assert!(
            matches!(&file.0.listeners["work"], Listener::Iroh { backends, .. } if backends == &["local"])
        );
        assert!(Config::parse("unknown = true").is_err());
        let explicit =
            Config::parse(&text.replace("kind = 'http'", "kind = 'http'\nzdr = false")).unwrap();
        assert!(matches!(
            explicit.document.listeners["api"],
            Listener::Http { zdr: false, .. }
        ));
        let schema = Config::parse("models = 'private-key-material'")
            .err()
            .unwrap()
            .to_string();
        assert!(
            schema.contains("schema")
                && schema.contains("expected")
                && !schema.contains("private-key-material")
        );
        let error = Config::parse("models = [\n'private-key-material'\nBAD")
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("line")
                && error.contains("column")
                && !error.contains("private-key-material")
        );
    }
}
