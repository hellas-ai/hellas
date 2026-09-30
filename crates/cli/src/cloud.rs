//! Thin adapter between the main CLI identity and the machine management library.
use super::{Commands, identity};
use anyhow::{Context, Result};
use hellas_cloud::management::Service;
use std::path::Path;

pub(super) async fn run(command: Commands, identity_path: Option<&Path>) -> Result<()> {
    let needs_identity = match &command {
        Commands::Cloud(args) => args.needs_identity() || identity_path.is_some(),
        _ => true,
    };
    let service = if needs_identity {
        let identity = identity::load_existing(identity_path)?;
        Some(Service::open(identity.transport_key)?.with_owner_enrollment(identity.enrollment)?)
    } else {
        None
    };
    match command {
        Commands::Cloud(args) => args.run_owned(service.as_ref()).await,
        Commands::Machines(args) => args.run(service.context("owner identity required")?).await,
        Commands::Admin(args) => {
            #[cfg(feature = "node")]
            anyhow::ensure!(
                args.node_contact.is_none()
                    && args.control_socket.is_none()
                    && args.addresses.is_empty(),
                "admin serve starts a local management service; use --socket to select its listener"
            );
            let socket = match args.command {
                crate::commands::admin::AdminCommand::Serve { socket } => socket,
                #[cfg(feature = "node")]
                _ => unreachable!("only management commands reach this adapter"),
            };
            let service = service.context("owner identity required")?;
            let socket = socket
                .map(Ok)
                .unwrap_or_else(|| hellas_cloud::internal_rpc::default_socket(&service.owner()))?;
            eprintln!(
                "management owner: {}\nmanagement socket: {}",
                service.owner(),
                socket.display()
            );
            hellas_cloud::internal_rpc::serve(service, &socket).await
        }
        _ => unreachable!("only management commands reach this adapter"),
    }
}

#[cfg(feature = "gateway")]
pub(super) async fn machine_target(
    name: &str,
    identity: &identity::LocalIdentity,
    addresses: Vec<std::net::SocketAddr>,
) -> Result<hellas_sdk::grant_client::PinnedOffer> {
    use hellas_rpc::protocol::work_grant::{grant_network, owner_grant_id};
    let enrollment = Service::open(identity.transport_key.clone())?
        .resolve(name)
        .await?;
    let provider = enrollment.principal()?;
    let owner = crate::commands::contributions::principal(identity)?;
    let network = grant_network();
    let target = hellas_sdk::grant_client::GrantTarget {
        grant: owner_grant_id(network, provider.bundle().content_id(), owner.id()),
        network,
        provider: provider.bundle().clone(),
        generation: 0,
        addresses,
    };
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(identity.transport_key.clone())
        .bind()
        .await?;
    let result = target
        .discover(
            &owner,
            &identity.producer_key,
            &hellas_sdk::grant_client::GrantTransport::Remote(endpoint.clone()),
            &hellas_client::ProviderTrustAnchor {
                expected_genesis: provider.bundle().content_id(),
                required_assurance: hellas_rpc::Assurance::ProducerSigned,
                apple_app_attest: None,
            },
            std::time::Duration::from_secs(90),
        )
        .await;
    endpoint.close().await;
    Ok(result?)
}
