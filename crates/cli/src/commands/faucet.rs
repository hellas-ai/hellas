//! Devnet coins for this principal from a public faucet account.
use super::CliResult;
use anyhow::{Context as _, anyhow, ensure};
use hellas_authority::authenticator::{Authenticator as _, kernel_auth};
use hellas_chain::LightClient as _;
use hellas_chain::domain::{ObjectKey, SettlementKey, Transaction};
use hellas_chain::genesis::{ChainProfile, FaucetAccount};
use hellas_kernel::{CoinId, MAX_EDGE_INPUTS, NetworkId, SoftPasskey};
use std::time::Duration;

/// Coins `faucet` sends by default: enough to pay for jobs or stake offers
/// under the shipped example terms.
pub const DEFAULT_AMOUNT: u64 = 1000;

/// Sends `amount` from a random public faucet account of the selected chain
/// to `principal`, waits until the payment is final, and prints the
/// principal's balance.
pub async fn faucet(amount: u64, principal: &SoftPasskey, profile: &ChainProfile) -> CliResult {
    ensure!(amount > 0, "amount must be positive");
    let account = faucet_account(profile, rand::random_range(0..100))?;
    eprintln!(
        "devnet faucet account {}: {}",
        account.index, account.address
    );
    let balance = pay(amount, &faucet_passkey(&account)?, principal, profile)
        .await
        .with_context(|| format!("devnet faucet account {}", account.index))?;
    println!(
        "received {amount}; {} now holds {balance}",
        SettlementKey::from(principal.party_key())
    );
    Ok(())
}

/// Pays `amount` from `faucet`'s coins to `principal` and returns the
/// principal's balance once the payment is final.
async fn pay(
    amount: u64,
    faucet: &SoftPasskey,
    principal: &SoftPasskey,
    profile: &ChainProfile,
) -> CliResult<u64> {
    let network = NetworkId::new(profile.network_id()).expect("validated profile");
    let client = super::chain::connect_with_verified_snapshots(None, profile).await?;
    let source = SettlementKey::from(faucet.party_key());
    let recipient = SettlementKey::from(principal.party_key());
    // The account's largest coins first, as few as cover the amount.
    let mut coins = owned_coins(&client, source).await?;
    coins.sort_by_key(|(_, value)| std::cmp::Reverse(*value));
    let mut selected = Vec::new();
    let mut covered = 0_u64;
    for (id, value) in coins.into_iter().take(MAX_EDGE_INPUTS) {
        if covered >= amount {
            break;
        }
        selected.push(id);
        covered = covered.saturating_add(value);
    }
    ensure!(
        covered >= amount,
        "the faucet account holds less than {amount}"
    );
    let plan = hellas_sdk::coin_owner::OwnerReshape::pay(
        &client,
        network,
        faucet.party_key(),
        &selected,
        principal.party_key(),
        amount,
    )
    .await?;
    let paid = plan.output_ids().as_slice()[0];
    let auth = kernel_auth(
        &faucet.public_key()?,
        &faucet
            .assert(hellas_auth::Digest::from(*plan.payload_hash().as_bytes()))
            .await?,
    )?;
    let outcome = client
        .submit_tx(Transaction::Kernel(plan.authorize(auth)?))
        .await?;
    ensure!(
        matches!(
            outcome,
            hellas_rpc::SubmitTxOutcome::Enqueued | hellas_rpc::SubmitTxOutcome::Duplicate
        ),
        "the chain refused the faucet payment: {outcome}"
    );
    // Final once the payment exists; refused if another request spent its coins.
    loop {
        let keys = std::iter::once(paid)
            .chain(selected.iter().copied())
            .map(ObjectKey::Coin)
            .collect();
        let snapshot = client
            .get_objects(keys)
            .await?
            .context("the chain has no finalized snapshot")?;
        if snapshot.coin(paid)?.is_some() {
            break;
        }
        for input in &selected {
            ensure!(
                snapshot.coin(*input)?.is_some(),
                "another request spent the faucet account's coins first; run `hellas faucet` again"
            );
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "polls finalized state until the payment lands"
        )]
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(owned_coins(&client, recipient)
        .await?
        .into_iter()
        .map(|(_, value)| value)
        .sum())
}

/// Every coin `owner` holds, with its value.
async fn owned_coins(
    client: &hellas_chain::client::RemoteLightClient,
    owner: SettlementKey,
) -> CliResult<Vec<(CoinId, u64)>> {
    let mut coins = Vec::new();
    let mut after = None;
    while let Some(page) = client.get_holdings(owner, after).await? {
        coins.extend(
            page.owned_coins(owner)
                .into_iter()
                .map(|(id, coin)| (id, coin.value)),
        );
        after = page.next_holdings();
        if after.is_none() {
            break;
        }
    }
    Ok(coins)
}

fn faucet_account(chain: &ChainProfile, index: u8) -> anyhow::Result<FaucetAccount> {
    let faucet_json = chain
        .faucet_json()
        .ok_or_else(|| anyhow!("selected chain has no faucet accounts"))?;
    let accounts: Vec<FaucetAccount> = serde_json::from_str(faucet_json)?;
    accounts
        .into_iter()
        .find(|account| account.index == index)
        .ok_or_else(|| anyhow!("devnet faucet account must be from 0 through 99"))
}

fn faucet_passkey(account: &FaucetAccount) -> anyhow::Result<SoftPasskey> {
    let scalar: [u8; 32] = hex::decode(&account.secret_scalar)?
        .try_into()
        .map_err(|_| anyhow!("invalid faucet secret length"))?;
    SoftPasskey::from_secret_scalar(scalar)
        .map_err(|_| anyhow!("invalid faucet P-256 scalar"))
        .with_context(|| format!("devnet faucet account {}", account.index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_chain::genesis::Chain;

    #[test]
    fn every_faucet_passkey_controls_its_genesis_allocation() {
        let chain = ChainProfile::known(Chain::Devnet);
        let genesis: hellas_chain::genesis::Genesis =
            serde_json::from_str(hellas_chain::genesis::HELLAS_DEVNET_3_JSON).unwrap();
        for index in 0..100 {
            let account = faucet_account(&chain, index).unwrap();
            let key = faucet_passkey(&account).unwrap();
            let address = SettlementKey::from(key.party_key()).to_string();
            let allocation = genesis
                .allocations
                .iter()
                .find(|a| a.address == address)
                .unwrap();
            assert!(allocation.balance >= DEFAULT_AMOUNT);
            assert_eq!(address, account.address);
        }
        assert!(faucet_account(&chain, 100).is_err());
    }

    #[test]
    fn the_faucet_pays_the_principal_and_waits_until_the_payment_is_final() {
        use hellas_chain::test_support::devnet::{Devnet, DevnetConfig, GenesisOwner, run};
        run(|runtime| async move {
            let faucet = GenesisOwner::faucet(7);
            let mut devnet = Devnet::start(
                runtime,
                DevnetConfig {
                    name: "cli_faucet",
                    owners: vec![faucet],
                    full_nodes: 0,
                },
            )
            .await;
            devnet.seal().await;
            let profile = devnet.profile(0);
            let source = SoftPasskey::from_secret_scalar(faucet.secret_scalar).unwrap();
            let principal = SoftPasskey::from_secret_scalar([0x52; 32]).unwrap();
            let payment = tokio::spawn({
                let profile = profile.clone();
                async move { pay(1000, &source, &principal, &profile).await }
            });
            while !payment.is_finished() {
                devnet.seal().await;
            }
            assert_eq!(payment.await.unwrap().unwrap(), 1000);
            // Everything the faucet holds is too much for one payment.
            let source = SoftPasskey::from_secret_scalar(faucet.secret_scalar).unwrap();
            let principal = SoftPasskey::from_secret_scalar([0x52; 32]).unwrap();
            assert!(pay(931_145, &source, &principal, &profile).await.is_err());
        });
    }
}
