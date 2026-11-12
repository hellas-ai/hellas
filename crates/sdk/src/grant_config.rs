//! A node's own configuration: its listeners, the budget tree down to accounts,
//! and the resources it serves, sharing exactly the paid InvocationPolicy parser.
//! Pools, subjects, allowances, grants and their counters remain runtime state
//! in the provider journal.
use crate::resource_config::ResourceConfigError;
use hellas_auth::authority::{ResourceId, Revision};
use hellas_authority::model::grant::{
    budget::Limit,
    configuration::{ConfiguredBudget, NodeConfiguration},
    records::{GrantError, GrantPolicy},
    resource::HttpsResource,
    responses::ResponsesResource,
};
use hellas_private::StoreLocation;
use serde::Deserialize;
use std::{
    num::NonZeroU64,
    path::{Path, PathBuf},
};

#[derive(Debug, thiserror::Error)]
pub enum GrantConfigError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Policy(#[from] ResourceConfigError),
    #[error(transparent)]
    Grant(#[from] GrantError),
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceFile {
    resource: ResourceId,
    account: ResourceId,
    revision: Revision,
    name: String,
    invocation_policy: hellas_rpc::protocol::invocation::InvocationPolicy,
    https: Option<HttpsResource>,
    responses: Option<ResponsesResource>,
    pricing: hellas_authority::model::grant::pricing::Pricing,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountFile {
    account: ResourceId,
    max_in_flight: std::num::NonZeroU16,
    limits: Vec<Limit>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    remote_control_peers: Vec<iroh::EndpointId>,
    #[serde(default)]
    remote_control: bool,
    max_job_millis: NonZeroU64,
    machine: Option<ConfiguredBudget>,
    #[serde(default)]
    accounts: Vec<AccountFile>,
    resources: Vec<ResourceFile>,
}
pub struct GrantConfig {
    provider_dir: StoreLocation,
    pub remote_control: crate::node_control::RemoteControlAdmission,
    pub max_job_millis: NonZeroU64,
    pub configuration: NodeConfiguration,
}
impl GrantConfig {
    pub fn provider_dir(home: &StoreLocation) -> StoreLocation {
        home.child("provider")
    }
    pub fn journal_dir(home: &StoreLocation) -> StoreLocation {
        Self::provider_dir(home).child("authority")
    }
    pub fn journal_root(&self) -> StoreLocation {
        self.provider_dir.child("authority")
    }
    pub fn control_socket(&self) -> PathBuf {
        self.provider_dir.join("control.sock")
    }
    pub fn control_certificate(&self) -> PathBuf {
        self.provider_dir.join("control.cert.der")
    }
    pub fn control_private_key(&self) -> PathBuf {
        self.provider_dir.join("control.key.der")
    }

    /// Serves no resources and configures no budgets; never supplies permissions.
    pub fn unconfigured(root: &StoreLocation) -> Self {
        Self {
            provider_dir: Self::provider_dir(root),
            remote_control: Default::default(),
            max_job_millis: NonZeroU64::MIN.saturating_add(1_799_999), // 30 minutes
            configuration: NodeConfiguration::default(),
        }
    }

    /// One generic Compute resource, `compute`, under the given admission, with
    /// fixed job bounds and one job at a time. Owners narrow it with
    /// `--grant-config`; nothing here knows what a program computes.
    pub fn compute(
        home: &StoreLocation,
        admission: hellas_rpc::protocol::invocation::Admission,
    ) -> Result<Self, GrantConfigError> {
        use hellas_rpc::protocol::invocation::{InvocationPolicy, Limits};
        let account = ResourceId(hellas_auth::Digest::hash(b"hellas.compute.account.v1"));
        let policy = GrantPolicy {
            resource: ResourceId(hellas_auth::Digest::hash(b"hellas.compute.resource.v1")),
            account,
            revision: Revision(1),
            name: "compute".into(),
            invocation_policy: InvocationPolicy {
                admissions: vec![admission],
                limits: Limits {
                    max_upload_bytes: 8 << 20,
                    max_output_bytes: 4 << 20,
                    max_steps: 4096,
                    execution_timeout_ms: 900_000,
                },
            },
            https: None,
            responses: None,
            pricing: hellas_authority::model::grant::pricing::Pricing {
                revision: Revision(1),
                rates: Some(vec![]),
            },
        };
        let budget = ConfiguredBudget {
            max_in_flight: std::num::NonZeroU16::MIN,
            limits: vec![],
        };
        let mut config = Self::unconfigured(home);
        config.configuration = NodeConfiguration::new(
            Some(budget.clone()),
            [(account, budget)].into(),
            vec![policy],
        )?;
        Ok(config)
    }

    /// Provider authority state is fixed under the selected home.
    pub fn load(path: &Path, home: &StoreLocation) -> Result<Self, GrantConfigError> {
        let bytes = hellas_private::read_bounded_regular_file(path, 1 << 20)?;
        let file: ConfigFile = serde_json::from_slice(&bytes)?;
        let remote_control = if file.remote_control && file.remote_control_peers.is_empty() {
            crate::node_control::RemoteControlAdmission::credential_gated()
        } else {
            crate::node_control::RemoteControlAdmission::new(file.remote_control_peers)
                .map_err(|_| GrantError::Limits)?
        };
        let resources = file
            .resources
            .into_iter()
            .map(|p| GrantPolicy {
                resource: p.resource,
                account: p.account,
                revision: p.revision,
                name: p.name,
                invocation_policy: p.invocation_policy,
                https: p.https,
                responses: p.responses,
                pricing: p.pricing,
            })
            .collect();
        let mut accounts = std::collections::BTreeMap::new();
        for account in file.accounts {
            let budget = ConfiguredBudget {
                max_in_flight: account.max_in_flight,
                limits: account.limits,
            };
            if accounts.insert(account.account, budget).is_some() {
                return Err(GrantError::Malformed.into());
            }
        }
        let configuration = NodeConfiguration::new(file.machine, accounts, resources)?;
        let mut config = Self::unconfigured(home);
        config.remote_control = remote_control;
        config.max_job_millis = file.max_job_millis;
        config.configuration = configuration;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_channel::test_support::assert_err;
    use hellas_private::StoreLocation;
    use serde_json::json;

    #[test]
    fn resource_configuration_cannot_override_budgets() {
        let policy = hellas_authority::test_support::policy();
        let baseline = json!({"resource":policy.resource, "account":policy.account, "revision":policy.revision, "name":policy.name, "pricing":policy.pricing, "invocation_policy":policy.invocation_policy});
        serde_json::from_value::<ResourceFile>(baseline.clone()).unwrap();
        for field in ["budget", "limits", "allowances", "permissions"] {
            let mut resource = baseline.clone();
            resource[field] = json!([]);
            let error = serde_json::from_value::<ResourceFile>(resource).unwrap_err();
            assert_eq!(error.classify(), serde_json::error::Category::Data);
            assert!(
                error
                    .to_string()
                    .contains(&format!("unknown field `{field}`")),
                "{error}"
            );
        }
    }

    #[test]
    fn configuration_cannot_install_authority_or_budgets() {
        let baseline = json!({"max_job_millis":10000,"resources":[]});
        serde_json::from_value::<ConfigFile>(baseline.clone()).unwrap();
        for field in [
            "grants",
            "allowances",
            "budgets",
            "machine_limits",
            "credentials",
        ] {
            let mut config = baseline.clone();
            config[field] = json!([]);
            let error = serde_json::from_value::<ConfigFile>(config).unwrap_err();
            assert_eq!(error.classify(), serde_json::error::Category::Data);
            assert!(
                error
                    .to_string()
                    .contains(&format!("unknown field `{field}`")),
                "{error}"
            );
        }
    }

    #[test]
    fn one_hundred_twenty_eight_distinct_remote_peers_are_accepted() {
        let peers: Vec<_> = (0..128)
            .map(|seed| iroh::SecretKey::from_bytes(&[seed; 32]).public())
            .collect();
        let config = json!({"max_job_millis":10000,"resources":[],"remote_control_peers":peers});
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resources.json");
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let location = StoreLocation::for_test(directory.path());
        let config = GrantConfig::load(&path, &location).unwrap();
        assert!(config.remote_control.enabled());
    }

    #[test]
    fn provider_authority_paths_are_fixed_under_home() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resources.json");
        let config = json!({"max_job_millis":10000,"resources":[]});
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let location = StoreLocation::for_test(directory.path());
        let loaded = GrantConfig::load(&path, &location).unwrap();
        let other_location = StoreLocation::for_test(&directory.path().join("provider/authority"));
        assert_eq!(loaded.journal_root(), other_location.clone());
        assert_eq!(
            loaded.control_private_key(),
            directory.path().join("provider/control.key.der")
        );
    }

    #[test]
    fn remote_control_requires_explicit_bounded_endpoint_keys() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resources.json");
        let mut config = json!({"max_job_millis":10000,"resources":[]});
        let load = |value: &serde_json::Value| {
            std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
            let location = StoreLocation::for_test(directory.path());
            GrantConfig::load(&path, &location)
        };
        assert!(!load(&config).unwrap().remote_control.enabled());
        let peer = iroh::SecretKey::from_bytes(&[1; 32]).public().to_string();
        config["remote_control_peers"] = json!([peer]);
        assert!(load(&config).unwrap().remote_control.enabled());
        let too_many: Vec<_> = (0..129)
            .map(|seed| {
                iroh::SecretKey::from_bytes(&[seed; 32])
                    .public()
                    .to_string()
            })
            .collect();
        for invalid in [json!([peer, peer]), json!(too_many)] {
            config["remote_control_peers"] = invalid;
            assert_err!(load(&config), GrantConfigError::Grant(GrantError::Limits));
        }
        config["remote_control_peers"] = json!(["invalid"]);
        assert_err!(load(&config), GrantConfigError::Json(error) if error.classify() == serde_json::error::Category::Data);
    }

    #[test]
    fn responses_configuration_preserves_explicit_constraints_and_rejects_unbounded_resources() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resources.json");
        let mut expected = hellas_authority::test_support::policy();
        expected.pricing.rates = Some(vec![hellas_authority::model::grant::pricing::UnitPrice {
            meter: hellas_authority::model::grant::budget::Meter::OutputTokens,
            usd_micros: 3,
            units: NonZeroU64::new(4).unwrap(),
        }]);
        let account = json!({"account":expected.account,"max_in_flight":4,"limits":[]});
        let config = json!({"max_job_millis":10000,
        "machine":{"max_in_flight":8,"limits":[]},"accounts":[account],
        "resources":[{
            "resource":expected.resource,"account":expected.account,"revision":expected.revision,
            "name":expected.name,"responses":expected.responses,"pricing":expected.pricing,
            "invocation_policy":expected.invocation_policy
        }]});
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let location = StoreLocation::for_test(directory.path());
        let parsed = GrantConfig::load(&path, &location).unwrap();
        assert_eq!(parsed.configuration.resources(), [expected.clone()]);
        assert_eq!(
            parsed.configuration.machine().unwrap().max_in_flight.get(),
            8
        );
        assert!(!parsed.journal_root().exists());
        // The configuration owns the budget tree above pools, completely: a
        // resource needs a machine and a declared account, and every declared
        // account is used exactly once.
        let load = |value: &serde_json::Value| {
            std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
            let location = StoreLocation::for_test(directory.path());
            GrantConfig::load(&path, &location)
        };
        let other = hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"other account"));
        for (field, value) in [
            ("machine", serde_json::Value::Null),
            ("accounts", json!([])),
            (
                "accounts",
                json!([account, {"account":other,"max_in_flight":1,"limits":[]}]),
            ),
        ] {
            let mut invalid = config.clone();
            invalid[field] = value;
            assert_err!(load(&invalid), GrantConfigError::Grant(GrantError::Limits));
        }
        let mut duplicated = config.clone();
        duplicated["accounts"] = json!([account, account]);
        assert_err!(
            load(&duplicated),
            GrantConfigError::Grant(GrantError::Malformed)
        );
        let unconfigured = load(&json!({"max_job_millis":10000,"resources":[]})).unwrap();
        assert_eq!(unconfigured.configuration, NodeConfiguration::default());
        let mut missing = config.clone();
        missing["resources"][0]
            .as_object_mut()
            .unwrap()
            .remove("pricing");
        std::fs::write(&path, serde_json::to_vec(&missing).unwrap()).unwrap();
        assert_err!(GrantConfig::load(&path, &location), GrantConfigError::Json(error) if error.classify() == serde_json::error::Category::Data);
        for invalid in [
            json!(null),
            json!({"revision":0,"rates":[]}),
            json!({"revision":1,"rates":[{"meter":"InputTokens","usd_micros":1,"units":1}]}),
            json!({"revision":1,"rates":[{"meter":"UsdMicros","usd_micros":1,"units":1}]}),
        ] {
            let mut changed = config.clone();
            let malformed_json = invalid.is_null();
            changed["resources"][0]["pricing"] = invalid;
            std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
            if malformed_json {
                let location = StoreLocation::for_test(directory.path());
                assert_err!(GrantConfig::load(&path, &location), GrantConfigError::Json(error) if error.classify() == serde_json::error::Category::Data);
            } else {
                let location = StoreLocation::for_test(directory.path());
                assert_err!(
                    GrantConfig::load(&path, &location),
                    GrantConfigError::Grant(GrantError::Limits)
                );
            }
        }

        for invalid in [
            serde_json::Value::Null,
            json!({"model":"fixture","max_output_tokens":0}),
            json!({"model":"fixture","max_output_tokens":8,"settings":{"output_formats":[]}}),
        ] {
            let mut changed = config.clone();
            changed["resources"][0]["responses"] = invalid;
            // Isolate resource validation from unsupported priced meters.
            changed["resources"][0]["pricing"]["rates"] = json!(null);
            std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
            let location = StoreLocation::for_test(directory.path());
            assert_err!(
                GrantConfig::load(&path, &location),
                GrantConfigError::Grant(GrantError::Malformed)
            );
        }
    }
}
