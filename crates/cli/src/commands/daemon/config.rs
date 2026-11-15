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
            Listener::Http {
                bind: bind.unwrap_or_else(|| "127.0.0.1:8080".parse().unwrap()),
                zdr: true,
            },
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
    }
    fn parse(text: &str) -> Result<Self> {
        let mut table: toml::Table =
            toml::from_str(text).map_err(|_| anyhow::anyhow!("invalid daemon TOML syntax"))?;
        let mut inputs = toml::Table::new();
        for key in ["models", "upstreams", "paid_policy"] {
            if let Some(value) = table.remove(key) {
                inputs.insert(key.into(), value);
            }
        }
        let inputs: Inputs = toml::Value::Table(inputs).try_into()?;
        let document: Document = toml::Value::Table(table).try_into()?;
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
            ensure!(
                !document.backends.contains_key(&name),
                "duplicate backend {name}"
            );
            apply(
                &mut document,
                Edit::Backend(BackendCommand::Add {
                    name,
                    url: upstream.url,
                    key_file: upstream.key_file,
                }),
                context,
            )
            .await?;
        }
        for model in self.models {
            apply(
                &mut document,
                Edit::Route(RouteCommand::Add { model }),
                context,
            )
            .await?;
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
        assert!(State::parse("[execution]\nqueue_capacity = 0").is_err());
        assert!(State::parse("[listeners.api]\nkind = 'http'\nbind = 'invalid'").is_err());
        assert!(State::parse("[paid_policy]\njobs_per_channel = 0").is_err());
    }
}
