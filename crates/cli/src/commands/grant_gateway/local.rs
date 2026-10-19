use crate::{commands::CliResult, identity::LocalIdentity};
use anyhow::Context;
use hellas_executor::{Executor, ExecutorSpawnConfig, FetchRouteRegistry};
use hellas_rpc::Assurance;
use hellas_sdk::grant_client::{GrantSessionOptions, GrantTarget, GrantTransport};
use hellas_work::model::grant::grant_network;
use std::{path::PathBuf, sync::Arc, time::Duration};

pub struct LocalContent {
    pub grant: Option<String>,
    pub paths: Vec<PathBuf>,
    pub roots: Vec<PathBuf>,
    pub index: Option<PathBuf>,
    pub queue_size: usize,
}

pub async fn prepare(
    content: LocalContent,
    identity: &LocalIdentity,
    application: Arc<hellas_sdk::node_control::profile::ClientProfile>,
    trust: hellas_client::ProviderTrustAnchor,
) -> CliResult<(GrantSessionOptions, GrantTransport)> {
    let principal = crate::commands::contributions::principal(identity)?;
    let root = crate::commands::contributions::data_root(&principal)?;
    let index = content
        .index
        .map(Ok)
        .unwrap_or_else(crate::identity::default_content_index_path)?;
    let grant = content
        .grant
        .context("--local-grant is required")?
        .parse()
        .context("--local-grant must be a 16-byte hexadecimal ID")?;
    let store = hellas_work::work_store::grant::NodeStore::open(
        &root.join("provider"),
        grant_network(),
        Some(identity.enrollment.clone()),
        hellas_auth::authority::UnixMillis::now().unwrap_or_default(),
    )
    .await?;
    let generation = store
        .state()
        .generation(grant)
        .context("local allowance is not configured")?;
    let content_store =
        crate::commands::environment::index_content(&content.paths, &content.roots, &index)?;

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
        Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
    )?;
    let network = grant_network();
    let transport = GrantTransport::Local(service);
    let target = GrantTarget {
        network,
        grant,
        provider: identity.enrollment.clone(),
        generation,
        addresses: vec![],
    }
    .discover(
        principal,
        &signer,
        &transport,
        &trust,
        &application,
        Duration::from_secs(90),
    )
    .await?;
    Ok((
        GrantSessionOptions {
            target,
            principal,
            signer,
            application,
            journal_root: crate::commands::contributions::client_journal_root(&principal)?,
            timeout: Duration::from_secs(90),
        },
        transport,
    ))
}
