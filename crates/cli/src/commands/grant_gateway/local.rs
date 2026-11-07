//! `gateway --local-grant`: run granted Work on this machine, in process.
//! Uses the same grant channel as a remote allowance; no chain is involved.
use crate::{commands::CliResult, compute::ServeArgs, identity::LocalIdentity};
use anyhow::Context as _;
use hellas_authority::model::grant::grant_network;
use hellas_executor::{Executor, ExecutorSpawnConfig, FetchRouteRegistry};
use hellas_private::StoreLocation;
use hellas_sdk::grant_client::{GrantSessionOptions, GrantTarget, GrantTransport};
use std::{sync::Arc, time::Duration};

/// Opens this node's own provider store and serves `grant` from an in-process
/// executor. The allowance must already be configured on this node.
pub async fn prepare(
    home: &StoreLocation,
    grant: &str,
    native: ServeArgs,
    identity: &LocalIdentity,
    principal: hellas_auth::authority::PrincipalId,
    application: Arc<hellas_sdk::node_control::profile::ClientProfile>,
    trust: hellas_client::ProviderTrustAnchor,
) -> CliResult<(
    (GrantSessionOptions, GrantTransport),
    crate::content_configuration::ContentReload,
)> {
    let grant = grant
        .parse()
        .context("--local-grant must be a 16-byte hexadecimal ID")?;
    let store = hellas_authority::work_store::grant::NodeStore::open(
        &hellas_sdk::grant_config::GrantConfig::journal_dir(home),
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
    let (content, reload) = prepare_content(home, native, &mut executor).await?;
    let backend = Executor::spawn_configured(executor)
        .await
        .context("start local Work executor")?;
    let service = hellas_authority::grant_service::GrantService::new(
        store,
        signer.clone(),
        backend,
        vec![],
        Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
        content,
    )?;
    let transport = GrantTransport::Local(service);
    let control_timeout = Duration::from_secs(90);
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
        control_timeout,
    )
    .await?;
    Ok((
        (
            GrantSessionOptions {
                target,
                principal,
                signer,
                application,
                journal_root: crate::commands::contributions::client_journal_root(
                    home, &principal,
                )?,
                control_timeout,
            },
            transport,
        ),
        reload,
    ))
}

async fn prepare_content(
    home: &StoreLocation,
    native: ServeArgs,
    executor: &mut ExecutorSpawnConfig,
) -> CliResult<(
    hellas_store::content::DiskStore,
    crate::content_configuration::ContentReload,
)> {
    let configuration = native.configure(executor)?.with_default_upper(
        hellas_sdk::grant_config::GrantConfig::provider_dir(home).join("content"),
    );
    let content = configuration
        .config()
        .open(
            home,
            hellas_store::content::Reservations::ram(
                hellas_channel::content::DEFAULT_MAX_STAGING_BYTES,
            ),
            true,
        )
        .await?;
    // Grant jobs are ephemeral; this host has no paid channel journals.
    content.finish_recovery().await?;
    let reload = configuration.start(content.clone()).await?;
    Ok((content, reload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use hellas_store::content::{JobContent, JobId};

    fn native(config: Option<&std::path::Path>) -> ServeArgs {
        let mut args = vec!["hellas".to_owned(), "serve".to_owned()];
        if let Some(path) = config {
            args.extend(["--content-config".into(), path.display().to_string()]);
        }
        let crate::Commands::Serve { native, .. } =
            crate::Cli::try_parse_from(args).unwrap().command
        else {
            panic!("serve");
        };
        native
    }
    fn executor() -> ExecutorSpawnConfig {
        ExecutorSpawnConfig::new(
            Arc::new(hellas_auth::ProducerSigningKey::from_secret_bytes([23; 32]).unwrap()),
            hellas_rpc::Assurance::ProducerSigned,
            FetchRouteRegistry::default(),
        )
    }
    #[tokio::test]
    async fn dedicated_local_upper_restarts_after_ram_work_and_refuses_paid_owned_reuse() {
        let root = tempfile::tempdir().unwrap();
        let (store, reload) = prepare_content(
            &StoreLocation::for_test(root.path()),
            native(None),
            &mut executor(),
        )
        .await
        .unwrap();
        assert!(
            root.path()
                .join("provider/content/content.sqlite")
                .is_file()
        );
        let job = JobId {
            channel: hellas_auth::Digest::hash(b"grant"),
            id: hellas_auth::Digest::hash(b"work"),
        };
        let object = hellas_rpc::ContentRef::for_bytes(b"ephemeral grant bytes");
        let content = JobContent::new(&store, job, vec![object], object.bytes())
            .await
            .unwrap();
        hellas_channel::content::upload_bytes(
            content.store(),
            content.scope(),
            b"ephemeral grant bytes",
            None,
        )
        .await
        .unwrap();
        content.end().await.unwrap();
        reload.shutdown().await.unwrap();
        store.close().await;
        drop(content);
        drop(store);
        let (store, reload) = prepare_content(
            &StoreLocation::for_test(root.path()),
            native(None),
            &mut executor(),
        )
        .await
        .unwrap();
        let scope = store.open_work(job, vec![], 0).await.unwrap();
        store.end_work(&scope).await.unwrap();
        reload.shutdown().await.unwrap();
        store.close().await;
        drop(store);
        assert!(matches!(
            prepare_content(
                &StoreLocation::for_test(root.path()),
                native(None),
                &mut executor()
            )
            .await
            .err()
            .unwrap()
            .downcast_ref::<hellas_store::content::Error>(),
            Some(hellas_store::content::Error::WorkOwned)
        ));
        let other = tempfile::tempdir().unwrap();
        let config = other.path().join("content.toml");
        std::fs::write(
            &config,
            format!(
                "[content]\nupper = {:?}\n",
                root.path().join("provider/content")
            ),
        )
        .unwrap();
        let error = prepare_content(
            &StoreLocation::for_test(other.path()),
            native(Some(&config)),
            &mut executor(),
        )
        .await
        .err()
        .unwrap();
        assert!(
            error
                .to_string()
                .contains("run the command against the daemon")
        );
    }
}
