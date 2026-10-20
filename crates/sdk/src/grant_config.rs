//! Local resource configuration shares exactly the paid WorkPolicy parser.
//! Grants and their counters remain runtime state in the provider journal.
use crate::resource_config::{ExecutionPolicyFile, FetchPolicyFile, ResourceConfigError};
use hellas_auth::authority::{ResourceId, Revision};
use hellas_work::model::grant::{
    records::{GrantError, GrantPolicy},
    resource::HttpsResource,
    responses::ResponsesResource,
};
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
    #[error("grant config must name {0} when no default data root applies")]
    MissingPath(&'static str),
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceFile {
    resource: ResourceId,
    account: ResourceId,
    revision: Revision,
    name: String,
    execution: Option<ExecutionPolicyFile>,
    fetch: Option<FetchPolicyFile>,
    https: Option<HttpsResource>,
    responses: Option<ResponsesResource>,
    pricing: hellas_work::model::grant::pricing::Pricing,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    journal_root: Option<PathBuf>,
    control_socket: Option<PathBuf>,
    control_certificate: Option<PathBuf>,
    control_private_key: Option<PathBuf>,
    #[serde(default)]
    remote_control_peers: Vec<iroh::EndpointId>,
    #[serde(default)]
    remote_control: bool,
    max_job_millis: NonZeroU64,
    resources: Vec<ResourceFile>,
}
pub struct GrantConfig {
    pub journal_root: PathBuf,
    pub control_socket: PathBuf,
    pub control_certificate: PathBuf,
    pub control_private_key: PathBuf,
    pub remote_control: crate::node_control::RemoteControlAdmission,
    pub max_job_millis: NonZeroU64,
    pub resources: Vec<GrantPolicy>,
}
impl GrantConfig {
    /// Listener and resource configuration never supplies permissions or budgets.
    pub fn unconfigured(root: &Path) -> Self {
        Self {
            journal_root: root.join("provider"),
            control_socket: root.join("control.sock"),
            control_certificate: root.join("control.cert.der"),
            control_private_key: root.join("control.key.der"),
            remote_control: Default::default(),
            max_job_millis: NonZeroU64::MIN.saturating_add(1_799_999), // 30 minutes
            resources: vec![],
        }
    }

    /// Unnamed paths default under `default_root`; without one, the config
    /// must name every path.
    pub fn load(path: &Path, default_root: Option<&Path>) -> Result<Self, GrantConfigError> {
        let bytes = hellas_private::read_bounded_regular_file(path, 1 << 20)?;
        let file: ConfigFile = serde_json::from_slice(&bytes)?;
        let remote_control = if file.remote_control && file.remote_control_peers.is_empty() {
            crate::node_control::RemoteControlAdmission::credential_gated()
        } else {
            crate::node_control::RemoteControlAdmission::new(file.remote_control_peers)
                .map_err(|_| GrantError::Limits)?
        };
        let journal_root = match (file.journal_root, default_root) {
            (Some(path), _) => path,
            (None, Some(root)) => root.join("provider"),
            (None, None) => return Err(GrantConfigError::MissingPath("journal_root")),
        };
        let control_socket = match (file.control_socket, default_root) {
            (Some(path), _) => path,
            (None, Some(root)) => root.join("control.sock"),
            (None, None) => return Err(GrantConfigError::MissingPath("control_socket")),
        };
        let control_certificate = match (file.control_certificate, default_root) {
            (Some(path), _) => path,
            (None, Some(root)) => root.join("control.cert.der"),
            (None, None) => return Err(GrantConfigError::MissingPath("control_certificate")),
        };
        let control_private_key = match (file.control_private_key, default_root) {
            (Some(path), _) => path,
            (None, Some(root)) => root.join("control.key.der"),
            (None, None) => return Err(GrantConfigError::MissingPath("control_private_key")),
        };
        if !journal_root.is_absolute()
            || !control_socket.is_absolute()
            || !control_certificate.is_absolute()
            || !control_private_key.is_absolute()
            || file.resources.len() > 16
        {
            return Err(GrantError::Limits.into());
        }
        let resources = file
            .resources
            .into_iter()
            .map(|p| {
                let work = match (p.execution, p.fetch) {
                    (Some(execution), None) => execution.into_policy()?.into(),
                    (None, Some(fetch)) => fetch.into_policy()?,
                    _ => return Err(GrantConfigError::Grant(GrantError::Malformed)),
                };
                let policy = GrantPolicy {
                    resource: p.resource,
                    account: p.account,
                    revision: p.revision,
                    name: p.name,
                    work,
                    https: p.https,
                    responses: p.responses,
                    pricing: p.pricing,
                };
                policy.validate()?;
                Ok(policy)
            })
            .collect::<Result<Vec<_>, GrantConfigError>>()?;
        let mut names = std::collections::BTreeSet::new();
        let mut ids = std::collections::BTreeSet::new();
        for resource in &resources {
            if !names.insert(&resource.name) || !ids.insert(resource.resource) {
                return Err(GrantError::Malformed.into());
            }
        }
        Ok(Self {
            journal_root,
            control_socket,
            control_certificate,
            control_private_key,
            remote_control,
            max_job_millis: file.max_job_millis,
            resources,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_work::test_support::assert_err;
    use serde_json::json;

    #[test]
    fn resource_configuration_cannot_override_budgets() {
        let policy = hellas_work::test_support::policy();
        let baseline = json!({"resource":policy.resource, "account":policy.account, "revision":policy.revision, "name":policy.name, "pricing":policy.pricing});
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
        let config = GrantConfig::load(&path, Some(directory.path())).unwrap();
        assert!(config.remote_control.enabled());
    }

    #[test]
    fn without_a_default_root_every_path_is_named() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resources.json");
        let named = |key: &str| directory.path().join(key);
        let mut config = json!({"max_job_millis":10000,"resources":[],
            "journal_root":named("journal"),"control_socket":named("control.sock"),
            "control_certificate":named("control.cert.der")});
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert_err!(
            GrantConfig::load(&path, None),
            GrantConfigError::MissingPath("control_private_key")
        );
        config["control_private_key"] = json!(named("control.key.der"));
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let config = GrantConfig::load(&path, None).unwrap();
        assert_eq!(config.control_private_key, named("control.key.der"));
    }

    #[test]
    fn remote_control_requires_explicit_bounded_endpoint_keys() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resources.json");
        let mut config = json!({"max_job_millis":10000,"resources":[]});
        let load = |value: &serde_json::Value| {
            std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
            GrantConfig::load(&path, Some(directory.path()))
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
        let mut expected = hellas_work::test_support::policy();
        expected.pricing.rates = Some(vec![hellas_work::model::grant::pricing::UnitPrice {
            meter: hellas_work::model::grant::budget::Meter::OutputTokens,
            usd_micros: 3,
            units: NonZeroU64::new(4).unwrap(),
        }]);
        let hellas_work::model::profile::WorkPolicy::Fetch {
            policy, contract, ..
        } = &expected.work
        else {
            panic!("Fetch fixture");
        };
        let config = json!({"max_job_millis":10000,"resources":[{
            "resource":expected.resource,"account":expected.account,"revision":expected.revision,
            "name":expected.name,"responses":expected.responses,"pricing":expected.pricing,
            "fetch":{
                "contract":contract,
                "allowed_environment":policy.allowed_environment.to_string(),
                "service":"openai","method":"responses",
                "max_request_body_bytes":policy.max_request_body_bytes,
                "max_output_events":policy.max_output_events,"max_output_bytes":policy.max_output_bytes,
                "max_spool_bytes":policy.max_spool_bytes,
                "max_encoded_result_frame":policy.max_encoded_result_frame,
                "max_encoded_prepared_input":policy.max_encoded_prepared_input
            }
        }]});
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let parsed = GrantConfig::load(&path, Some(directory.path())).unwrap();
        assert_eq!(parsed.resources, vec![expected]);
        assert!(!parsed.journal_root.exists());
        let mut missing = config.clone();
        missing["resources"][0]
            .as_object_mut()
            .unwrap()
            .remove("pricing");
        std::fs::write(&path, serde_json::to_vec(&missing).unwrap()).unwrap();
        assert_err!(GrantConfig::load(&path, Some(directory.path())), GrantConfigError::Json(error) if error.classify() == serde_json::error::Category::Data);
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
                assert_err!(GrantConfig::load(&path, Some(directory.path())), GrantConfigError::Json(error) if error.classify() == serde_json::error::Category::Data);
            } else {
                assert_err!(
                    GrantConfig::load(&path, Some(directory.path())),
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
            assert_err!(
                GrantConfig::load(&path, Some(directory.path())),
                GrantConfigError::Grant(GrantError::Malformed)
            );
        }
    }
}
