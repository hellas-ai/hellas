//! One versioned host configuration shared by native applications and the CLI.
use anyhow::{Context, bail, ensure};
use hellas_channel::model::{
    paid_policy::{OfferPolicy, PaidPolicy},
    work::{JobPaymentPolicyV2, PaidChannelPolicyV1},
};
use hellas_executor::{FetchRoute, FetchRouteEntry, FetchRoutePolicy, FetchRouteRegistry};
use hellas_kernel::{EdgeValues, Fees};
use hellas_rpc::protocol::invocation::{Admission, InvocationPolicy};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServeConfig {
    pub version: u32,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub routes: Vec<Route>,
    pub grants: Option<crate::grant_config::GrantSettings>,
    pub paid: Option<PaidTerms>,
    pub port: Option<u16>,
}
impl ServeConfig {
    pub fn empty() -> Self {
        Self {
            version: 1,
            revision: 0,
            routes: Vec::new(),
            grants: None,
            paid: None,
            port: None,
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let config: Self = serde_json::from_slice(bytes)?;
        config.validate()?;
        Ok(config)
    }
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        Self::from_bytes(&hellas_private::read_bounded_regular_file(path, 8 << 20)?)
            .with_context(|| format!("invalid host configuration {}", path.display()))
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.version == 1,
            "unsupported host configuration version {}",
            self.version
        );
        let mut names = BTreeSet::new();
        for route in &self.routes {
            ensure!(
                !route.service.trim().is_empty() && !route.method.trim().is_empty(),
                "route service and method must be non-empty"
            );
            ensure!(
                names.insert((&route.service, &route.method)),
                "duplicate Fetch route"
            );
            route.capabilities.clone().into_policy()?;
        }
        if let Some(paid) = &self.paid {
            paid.policy()?;
            for admission in &paid.invocation_policy.admissions {
                if let Admission::Fetch { admission } = admission {
                    use hellas_rpc::protocol::invocation::fetch::FetchRoutePolicy;
                    let (service, method) = match &admission.route {
                        FetchRoutePolicy::SealedRoute { service, method } => {
                            (service.as_str(), method.as_str())
                        }
                        FetchRoutePolicy::OpenFetch { .. } => ("http", "request"),
                    };
                    let route = self
                        .routes
                        .iter()
                        .find(|r| r.service == service && r.method == method)
                        .context("paid Fetch route is not configured")?;
                    ensure!(
                        route.destination.contract()? == admission.contract,
                        "paid Fetch contract differs from the configured driver"
                    );
                }
            }
        }
        Ok(())
    }
    pub fn routes(&self) -> anyhow::Result<FetchRouteRegistry> {
        self.validate()?;
        let mut routes = FetchRouteRegistry::new();
        for route in &self.routes {
            routes.register(
                FetchRoute::new(&route.service, &route.method),
                route
                    .destination
                    .clone()
                    .into_entry(route.capabilities.clone().into_policy()?)?,
            )?;
        }
        Ok(routes)
    }
    pub fn paid_policy(&self) -> anyhow::Result<Option<PaidPolicy>> {
        self.validate()?;
        self.paid.as_ref().map(PaidTerms::policy).transpose()
    }
    pub fn grants(
        &self,
        default_root: Option<&Path>,
    ) -> anyhow::Result<Option<crate::grant_config::GrantConfig>> {
        self.grants
            .clone()
            .map(|g| {
                crate::grant_config::GrantConfig::from_settings(g, default_root).map_err(Into::into)
            })
            .transpose()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub service: String,
    pub method: String,
    /// One sealed, compiled destination plus provider-local credentials. This
    /// one selection constructs both the HTTP driver and the projector whose
    /// manifest is quoted; a URL or separate identity cannot be supplied.
    pub destination: Destination,
    #[serde(default)]
    pub capabilities: RouteLimits,
    #[serde(default)]
    pub credential_metadata: std::collections::BTreeMap<String, CredentialMetadata>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Destination {
    /// Caller-signed HTTPS URL and TLS settings with operator-owned account aliases.
    Http {
        config: hellas_providers::HttpProviderConfig,
    },
    /// Official Codex Responses, authenticated by the local Codex OAuth store.
    OpenAiResponses {
        credential: String,
        credentials: std::collections::BTreeMap<String, hellas_providers::HttpSecretConfig>,
    },
    CodexResponses {
        #[serde(default)]
        auth_path: Option<PathBuf>,
    },
}

impl Destination {
    /// The sealed contract this destination's trusted adaptor implements.
    pub fn contract(&self) -> anyhow::Result<hellas_rpc::FetchContract> {
        match self {
            Self::Http { .. } => Ok(hellas_rpc::FetchContract::http()?),
            Self::OpenAiResponses { .. } => Ok(hellas_providers::responses_contract()?),
            Self::CodexResponses { .. } => Ok(hellas_providers::codex_responses_contract()?),
        }
    }

    pub fn into_entry(self, capabilities: FetchRoutePolicy) -> anyhow::Result<FetchRouteEntry> {
        match self {
            Self::Http { config } => Ok(config.into_entry(capabilities)?),
            Self::OpenAiResponses {
                credential,
                mut credentials,
            } => Ok(FetchRouteEntry::new(
                Arc::new(hellas_providers::OpenAiResponsesFetchProvider::with_secret(
                    credentials
                        .remove(&credential)
                        .context("unknown OpenAI credential alias")?
                        .into_secret()?,
                )?),
                Arc::new(hellas_providers::OpenAiResponsesAdaptorFactory::new()?),
                capabilities,
            )?),
            Self::CodexResponses { auth_path } => {
                let cap: u32 = capabilities
                    .max_output_units
                    .context("Codex route requires capabilities.max_output_tokens")?
                    .try_into()
                    .context("Codex output cap exceeds u32")?;
                Ok(FetchRouteEntry::new(
                    Arc::new(crate::codex_provider::CodexResponsesFetchProvider::new(
                        auth_path.as_deref(),
                    )?),
                    Arc::new(hellas_providers::CodexResponsesAdaptorFactory::new(cap)?),
                    capabilities,
                )?)
            }
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteLimits {
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub max_output_tokens: Option<u64>,
}

impl RouteLimits {
    pub fn into_policy(self) -> anyhow::Result<FetchRoutePolicy> {
        let allowed_models = if self.models.is_empty() {
            None
        } else {
            let mut models = BTreeSet::new();
            for model in self.models {
                let model = model.trim();
                if model.is_empty() {
                    bail!("fetch config model names must be non-empty");
                }
                models.insert(model.to_string());
            }
            Some(models)
        };
        Ok(FetchRoutePolicy {
            allowed_models,
            max_output_units: self.max_output_tokens,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaidTerms {
    /// JSON chain configuration for a custom network; omit for the shipped devnet.
    pub chain: Option<crate::work_config::WorkConfigFile>,
    pub jobs_per_channel: u64,
    pub min_omit_response_blocks: u64,
    pub payment: JobPaymentPolicyV2,
    pub channel: PaidChannelPolicyV1,
    pub offers: OfferPolicy,
    pub invocation_policy: InvocationPolicy,
}

impl PaidTerms {
    pub fn policy(&self) -> anyhow::Result<PaidPolicy> {
        let capacity = self
            .payment
            .fixed_price
            .checked_mul(self.jobs_per_channel)
            .context("paid channel capacity overflow")?;
        let value = capacity
            .checked_add(self.offers.omission_bond)
            .context("paid funding overflow")?;
        let policy = PaidPolicy {
            channel_policy: self.channel,
            invocation_policy: self.invocation_policy.clone(),
            payment_policy: self.payment,
            expected_payment_values: EdgeValues::new(value, 0, Fees::ZERO),
            min_omit_response_blocks: self.min_omit_response_blocks,
            jobs_per_channel: self.jobs_per_channel,
            offers: self.offers.clone(),
        };
        policy.check()?;
        Ok(policy)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialMetadata {
    pub fingerprint: String,
    pub last_use: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unversioned_old_or_unknown_host_documents() {
        for bytes in [
            br#"{"routes":[]}"#.as_slice(),
            br#"{"version":2,"routes":[]}"#,
            br#"{"version":1,"endpoints":{}}"#,
        ] {
            assert!(ServeConfig::from_bytes(bytes).is_err());
        }
    }
    #[test]
    fn duplicate_routes_are_refused_before_host_startup() {
        let route = serde_json::json!({"service":"http","method":"request","destination":{"type":"http","config":{}}});
        let bytes =
            serde_json::to_vec(&serde_json::json!({"version":1,"routes":[route.clone(),route]}))
                .unwrap();
        assert!(
            ServeConfig::from_bytes(&bytes)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }
    #[test]
    fn one_document_retains_grants_and_secret_references() {
        let bytes=br#"{"version":1,"revision":7,"routes":[{"service":"deepseek","method":"request","destination":{"type":"http","config":{"allowed_hosts":["api.deepseek.com"],"credentials":{"main":{"allowed_origins":["https://api.deepseek.com"],"allowed_paths":["/chat/completions"],"allowed_methods":["POST"],"header_name":"authorization","secret_env":"DEEPSEEK_API_KEY","prefix":"Bearer "}}}}}],"grants":{"max_job_millis":10000,"resources":[]}}"#;
        let config = ServeConfig::from_bytes(bytes).unwrap();
        assert_eq!(config.revision, 7);
        let serialized = serde_json::to_string(&config).unwrap();
        assert!(serialized.contains("DEEPSEEK_API_KEY"));
        assert!(
            config
                .grants(Some(Path::new("/tmp/serve-v1")))
                .unwrap()
                .is_some()
        );
    }
}
