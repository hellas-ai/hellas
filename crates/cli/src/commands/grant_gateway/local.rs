//! `gateway --local-grant`: run granted Work on this machine, in process.
//! Uses the same grant channel as a remote allowance; no chain is involved.
use crate::{commands::CliResult, compute::ServeArgs, identity::LocalIdentity};
use anyhow::Context as _;
use hellas_authority::model::grant::grant_network;
use hellas_executor::{Executor, ExecutorSpawnConfig, FetchRouteRegistry};
use hellas_sdk::grant_client::{GrantSessionOptions, GrantTarget, GrantTransport};
use std::{sync::Arc, time::Duration};

/// Opens this node's own provider store and serves `grant` from an in-process
/// executor. The allowance must already be configured on this node.
pub async fn prepare(
    grant: &str,
    native: ServeArgs,
    identity: &LocalIdentity,
    principal: hellas_auth::authority::PrincipalId,
    application: Arc<hellas_sdk::node_control::profile::ClientProfile>,
    trust: hellas_client::ProviderTrustAnchor,
) -> CliResult<(GrantSessionOptions, GrantTransport)> {
    let grant = grant
        .parse()
        .context("--local-grant must be a 16-byte hexadecimal ID")?;
    let root = crate::commands::contributions::data_root(&principal)?;
    let store = hellas_authority::work_store::grant::NodeStore::open(
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
    let signer = Arc::new(identity.node_key.clone());
    let mut executor = ExecutorSpawnConfig::new(
        signer.clone(),
        hellas_rpc::Assurance::ProducerSigned,
        FetchRouteRegistry::default(),
    );
    native.configure(&mut executor)?;
    let content = executor.content_store.clone();
    let backend = Executor::spawn_configured(executor)
        .await
        .context("start local Work executor")?;
    let service = hellas_authority::grant_service::GrantService::new(
        store,
        signer.clone(),
        backend,
        vec![],
        Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
    )?
    .with_content_store(content);
    let transport = GrantTransport::Local(service);
    let timeout = Duration::from_secs(90);
    let target = GrantTarget {
        network: grant_network(),
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
        timeout,
    )
    .await?;
    Ok((
        GrantSessionOptions {
            target,
            principal,
            signer,
            application,
            journal_root: crate::commands::contributions::client_journal_root(&principal)?,
            timeout,
        },
        transport,
    ))
}
