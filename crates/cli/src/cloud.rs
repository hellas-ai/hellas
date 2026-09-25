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
        Some(Service::open(
            identity::load_existing(identity_path)?.transport_key,
        )?)
    } else {
        None
    };
    match command {
        Commands::Cloud(args) => args.run_owned(service.as_ref()).await,
        Commands::Machines(args) => args.run(service.context("owner identity required")?).await,
        Commands::Control(args) => args.run(service.context("owner identity required")?).await,
        _ => unreachable!("only management commands reach this adapter"),
    }
}

pub(super) async fn machine_route(
    machine: Option<&str>,
    key: &iroh::SecretKey,
    node_id: Option<iroh::EndpointId>,
    mut trust: super::RemoteTrustArgs,
) -> Result<(Option<iroh::EndpointId>, super::RemoteTrustArgs)> {
    let Some(machine) = machine else {
        return Ok((node_id, trust));
    };
    anyhow::ensure!(
        trust.assurance == hellas_rpc::Assurance::ProducerSigned,
        "owned machine currently supports producer-signed assurance only"
    );
    let enrollment = Service::open(key.clone())?.resolve(machine).await?;
    trust.provider_genesis =
        Some(super::parse_content_id_hex(&enrollment.enrollment_id).map_err(anyhow::Error::msg)?);
    Ok((Some(enrollment.node_id.parse()?), trust))
}
