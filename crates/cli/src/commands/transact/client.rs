use super::{ClientArgs, Context};
use anyhow::Context as _;
use hellas_chain::{
    ConsensusInfo, FinalizedBlockQuery, FinalizedBlockView, LightClient as _,
    client::RemoteLightClient,
};
use hellas_sdk::{
    paid_client::{finalized_channel_settlement, retained_settlement_channels, settle_channel},
    work_config::{ChainCrossCheck, WorkConfig},
};
use std::path::Path;
type CliResult<T> = super::super::CliResult<T>;

async fn read_chain(
    validators: &[String],
    trust_path: &Path,
    genesis_path: Option<&Path>,
) -> CliResult<(ConsensusInfo, [u8; 32])> {
    anyhow::ensure!(
        validators.len() == 6,
        "--validator must be passed exactly six times, got {}",
        validators.len(),
    );
    let trust = serde_json::from_slice(&std::fs::read(trust_path)?)?;
    let genesis_json = match genesis_path {
        Some(path) => std::fs::read(path)?,
        None => hellas_chain::genesis::HELLAS_DEVNET_1_JSON
            .as_bytes()
            .to_vec(),
    };
    let mut observed: Option<(ConsensusInfo, [u8; 32])> = None;
    for url in validators {
        let client = RemoteLightClient::connect(url.clone())
            .await
            .with_context(|| format!("failed to connect to validator {url}"))?;
        let info = client
            .get_consensus_info()
            .await
            .with_context(|| format!("failed to read consensus info from {url}"))?;
        let first = client
            .get_finalized_block(FinalizedBlockQuery::Height(1))
            .await
            .with_context(|| format!("failed to read finalized block 1 from {url}"))?
            .ok_or_else(|| {
                hellas_chain::QueryError::StateUnavailable(format!(
                    "validator {url} has no finalized block 1"
                ))
            })?;
        hellas_sdk::client_chain::pinned_consensus_verifier(&trust, &genesis_json, &info)?
            .verify_snapshot(&first.snapshot, &first.block)
            .with_context(|| format!("validator {url} returned an unauthenticated block 1"))?;
        let first = FinalizedBlockView::decode(&first)
            .with_context(|| format!("validator {url} returned malformed finalized block 1"))?;
        anyhow::ensure!(
            first.height() == 1,
            "validator {url} answered the height-1 query with finalized height {}",
            first.height(),
        );
        let genesis: [u8; 32] = first.parent().into();
        match &observed {
            None => observed = Some((info, genesis)),
            Some((expected, payload)) => {
                anyhow::ensure!(
                    info.network_id == expected.network_id
                        && info.threshold_identity == expected.threshold_identity,
                    "validator {url} reports a different consensus identity",
                );
                anyhow::ensure!(
                    genesis == *payload,
                    "validator {url} reports a different genesis payload",
                );
            }
        }
    }
    observed.context("validators produced no observation")
}

pub(super) async fn config(args: &ClientArgs, root: &Path) -> CliResult<WorkConfig> {
    let mut config = hellas_sdk::client_chain::devnet(root)?;
    config.journal_root = root.join("chain-reads");
    if !args.validators.is_empty() {
        config.validators = args.validators.clone();
    }
    if let Some(trust) = &args.trust {
        let (info, genesis_payload) = loop {
            match read_chain(&config.validators, trust, args.genesis.as_deref()).await {
                Err(error)
                    if matches!(
                        error.downcast_ref::<hellas_chain::QueryError>(),
                        Some(
                            hellas_chain::QueryError::StateUnavailable(_)
                                | hellas_chain::QueryError::Connect(_)
                                | hellas_chain::QueryError::ChannelClosed
                        )
                    ) =>
                {
                    tokio::time::sleep(config.poll).await;
                }
                result => break result?,
            }
        };
        let genesis = match &args.genesis {
            Some(path) => serde_json::from_slice(&std::fs::read(path)?)?,
            None => serde_json::from_str(hellas_chain::genesis::HELLAS_DEVNET_1_JSON)?,
        };
        config.chain = ChainCrossCheck {
            network: hellas_kernel::NetworkId::new(&info.network_id)
                .context("invalid chain network")?,
            genesis_payload_digest: genesis_payload.into(),
            threshold_identity: info.threshold_identity,
            genesis: Some(genesis),
        };
    } else {
        anyhow::ensure!(
            args.genesis.is_none(),
            "--genesis requires independently authenticated --trust"
        );
    }
    config.validate().map_err(Into::into)
}

pub(super) async fn settle(args: &ClientArgs, context: &Context) -> CliResult<()> {
    let root = args.root(context);
    let config = config(args, &root).await?;
    let journals = args.journals(&root);
    if !journals.exists() {
        println!("no open channels with {}", args.provider.address);
        return Ok(());
    }
    let owner = hellas_auth::authority::PrincipalId::from_public_key(
        hellas_auth::PublicKey::P256(context.owner.party_key().to_bytes()),
    )?;
    let channels = retained_settlement_channels(
        &journals,
        config.chain.network,
        args.provider.address,
        owner,
        context.settlement.party_key(),
    )
    .await?;
    let mut closed = 0;
    for channel in channels {
        let options =
            args.options_with_config(context, channel.price, channel.assurance, config.clone())?;
        if finalized_channel_settlement(
            &options,
            channel.bond,
            owner,
            context.settlement.party_key(),
        )
        .await?
        .is_some()
        {
            continue;
        }
        let receipt = settle_channel(&options, channel.bond, owner, &context.settlement).await?;
        println!(
            "settled channel {}: provider payout {}",
            receipt.channel, receipt.provider_payout
        );
        closed += 1;
    }
    println!("settled {closed} channels with {}", args.provider.address);
    Ok(())
}
