use super::{ClientArgs, Context};
use hellas_sdk::paid_client::{
    finalized_channel_settlement, retained_settlement_channels, settle_channel,
};
use hellas_sdk::work_config::WorkConfig;
type CliResult<T> = super::super::CliResult<T>;

pub(super) async fn config(args: &ClientArgs, context: &Context) -> CliResult<WorkConfig> {
    let mut chain = context.chain.clone();
    if !args.validators.is_empty() {
        chain = chain.with_validators(args.validators.clone())?;
    }
    Ok(WorkConfig::from_chain_dir(chain)?)
}

pub(super) async fn settle(args: &ClientArgs, context: &Context) -> CliResult<()> {
    let provider = args.paid_provider()?;
    let config = config(args, context).await?;
    let journals = context.chain.client_journals(&provider.address.to_string());
    if !journals.exists() {
        println!("no open channels with {}", provider.address);
        return Ok(());
    }
    let owner = hellas_auth::authority::PrincipalId::from_public_key(
        hellas_auth::PublicKey::P256(context.owner.party_key().to_bytes()),
    )?;
    let channels = retained_settlement_channels(
        &journals,
        config.network(),
        provider.address,
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
    println!("settled {closed} channels with {}", provider.address);
    Ok(())
}
