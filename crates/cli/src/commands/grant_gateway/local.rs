use crate::{commands::CliResult, identity::LocalIdentity};
use anyhow::Context;
use hellas_executor::{Executor, ExecutorSpawnConfig, FetchRouteRegistry, GpuConfig};
use hellas_rpc::{
    Assurance, CausalLmEnvironment,
    protocol::{
        artifacts::{BoundTermId, Canonical as _, TextArtifact, TextPolicy},
        work::{EvaluatePolicyV2, generation_policy_digest, identity_source_digest},
        work_grant::{grant_network, owner_grant_id, records::GrantPolicy},
    },
};
use hellas_sdk::{
    grant_client::{GrantSessionOptions, GrantTarget, GrantTransport},
    grant_config::GrantConfig,
    grant_gateway::GrantGateway,
};
use std::{path::PathBuf, sync::Arc, time::Duration};

pub struct LocalContent {
    pub paths: Vec<PathBuf>,
    pub roots: Vec<PathBuf>,
    pub index: Option<PathBuf>,
    pub queue_size: usize,
}

fn policy(environment: &CausalLmEnvironment, stops: &[u32]) -> CliResult<GrantPolicy> {
    let capacity = environment
        .generation_schedule()
        .fixed_capacity
        .min(GpuConfig::default().max_generation_capacity());
    anyhow::ensure!(capacity > 1, "local environment has no room for generation");
    let max_new_tokens = u32::try_from(capacity - 1)?;
    anyhow::ensure!(
        stops.len() <= hellas_rpc::MAX_STOP_TOKEN_IDS,
        "too many local stop token IDs"
    );
    anyhow::ensure!(
        stops
            .iter()
            .all(|id| u64::from(*id) < environment.vocabulary_size()),
        "local stop token ID is outside the vocabulary"
    );
    let manifest = environment.manifest().content_id();
    let identity = TextArtifact::identity(BoundTermId::from_digest(manifest.digest()));
    let generation = TextPolicy::from_u32_stop_tokens(max_new_tokens, stops.to_vec());
    let policy = GrantPolicy {
        name: "local".into(),
        work: EvaluatePolicyV2 {
            allowed_environment: manifest,
            generation_policy_digest: generation_policy_digest(&generation.canonical_bytes())?,
            identity_source_digest: identity_source_digest(&identity.canonical_bytes())?,
            max_prompt_tokens: max_new_tokens,
            max_new_tokens,
            max_stop_token_ids: u16::try_from(stops.len())?,
            max_spool_bytes: 32 << 20,
            max_encoded_result_frame: 4 << 20,
            max_encoded_prepared_input: 4 << 20,
        }
        .into(),
        https: None,
    };
    policy.validate()?;
    Ok(policy)
}

pub async fn open(
    environment: &CausalLmEnvironment,
    stops: &[u32],
    content: LocalContent,
    identity: &LocalIdentity,
) -> CliResult<Arc<GrantGateway>> {
    let principal = crate::commands::contributions::principal(identity)?;
    let root = crate::commands::contributions::data_root(&principal)?;
    let index = content
        .index
        .map(Ok)
        .unwrap_or_else(crate::identity::default_content_index_path)?;
    let content_store =
        crate::commands::environment::index_content(&content.paths, &content.roots, &index)?;
    let mut config = GrantConfig::unconfigured(&root);
    // Preserve the existing machine allowance while explicitly selecting the
    // local owner's current environment. Opening the same provider twice fails
    // on the common journal lease, including a simultaneous `serve` process.
    config.resources = vec![policy(environment, stops)?];
    config.max_job_millis = std::num::NonZeroU64::new(90_000).expect("positive");
    let (_, store) =
        crate::commands::serve::prepare_grants(crate::commands::serve::GrantNodeConfig {
            config,
            provider: principal.clone(),
            owner: Some(principal.clone()),
        })?;
    let signer = Arc::new(identity.producer_key.clone());
    let mut executor = ExecutorSpawnConfig::fetch_only(
        signer.clone(),
        Assurance::ProducerSigned,
        FetchRouteRegistry::default(),
    );
    executor.content_store = content_store;
    executor.queue_capacity = content.queue_size;
    let backend = Executor::spawn_configured(executor)
        .await
        .context("start local Work executor")?;
    let service = hellas_work::grant_service::GrantService::new(
        store,
        signer.clone(),
        backend,
        vec![],
        Arc::new(hellas_work::grant_service::wall_clock),
    )?;
    let network = grant_network();
    let transport = GrantTransport::Local(service);
    let target = GrantTarget {
        network,
        grant: owner_grant_id(network, principal.bundle().content_id(), principal.id()),
        provider: principal.bundle().clone(),
        generation: 0,
        addresses: vec![],
    }
    .discover(
        &principal,
        &signer,
        &transport,
        &hellas_client::ProviderTrustAnchor {
            expected_genesis: principal.bundle().content_id(),
            required_assurance: Assurance::ProducerSigned,
            apple_app_attest: None,
        },
        Duration::from_secs(90),
    )
    .await?;
    Ok(GrantGateway::open(
        GrantSessionOptions {
            target,
            client: principal.clone(),
            signer,
            journal_root: crate::commands::contributions::client_journal_root(&principal)?,
            timeout: Duration::from_secs(90),
        },
        transport,
        Some("local".into()),
    )
    .await?)
}
