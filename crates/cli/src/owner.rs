//! One software-passkey selection for the whole invocation.
use anyhow::{Context as _, anyhow};
use clap::Args;
use hellas_chain::genesis::{FaucetAccount, HELLAS_DEVNET_1_FAUCET_JSON};
use hellas_kernel::SoftPasskey;
use std::path::PathBuf;

#[derive(Args, Debug, Default)]
pub(crate) struct OwnerArgs {
    /// Software passkey of the principal: 32 raw bytes or 64 hex digits.
    #[arg(long, global = true, conflicts_with_all = ["faucet", "faucet_account"])]
    passkey: Option<PathBuf>,
    /// Act as a random public devnet faucet account (unsafe for anything of value).
    #[arg(long, global = true, conflicts_with = "faucet_account")]
    faucet: bool,
    /// Act as public devnet faucet account N, from 0 through 99.
    #[arg(long, global = true, value_name = "N", value_parser = clap::value_parser!(u8).range(0..100))]
    faucet_account: Option<u8>,
}

impl OwnerArgs {
    pub(crate) fn load(&self) -> anyhow::Result<Option<SoftPasskey>> {
        let index = self
            .faucet_account
            .or_else(|| self.faucet.then(|| rand::random_range(0..100)));
        if let Some(index) = index {
            let account = faucet_account(index)?;
            let key = faucet_passkey(&account)?;
            eprintln!(
                "devnet faucet account {}: {}",
                account.index, account.address
            );
            Ok(Some(key))
        } else {
            self.passkey
                .as_deref()
                .map(crate::commands::chain::passkey)
                .transpose()
        }
    }
}

fn faucet_account(index: u8) -> anyhow::Result<FaucetAccount> {
    let accounts: Vec<FaucetAccount> = serde_json::from_str(HELLAS_DEVNET_1_FAUCET_JSON)?;
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
    use clap::Parser as _;
    use hellas_chain::domain::SettlementKey;

    #[test]
    fn every_selected_faucet_passkey_controls_its_genesis_allocation() {
        let genesis: hellas_chain::genesis::Genesis =
            serde_json::from_str(hellas_chain::genesis::HELLAS_DEVNET_1_JSON).unwrap();
        for index in 0..100 {
            let options = OwnerArgs {
                faucet_account: Some(index),
                ..Default::default()
            };
            let key = options.load().unwrap().unwrap();
            let address = SettlementKey::from(key.party_key()).to_string();
            let allocation = genesis
                .allocations
                .iter()
                .find(|a| a.address == address)
                .unwrap();
            assert_eq!(allocation.balance, 931_145);
            assert_eq!(address, faucet_account(index).unwrap().address);
        }
        assert!(faucet_account(100).is_err());
    }

    #[test]
    fn random_selection_is_funded_and_explicit_credentials_are_exclusive() {
        let options = OwnerArgs {
            faucet: true,
            ..Default::default()
        };
        let key = options.load().unwrap().unwrap();
        let accounts: Vec<FaucetAccount> =
            serde_json::from_str(HELLAS_DEVNET_1_FAUCET_JSON).unwrap();
        assert!(
            accounts
                .iter()
                .any(|account| account.address == SettlementKey::from(key.party_key()).to_string())
        );
        for args in [
            vec!["hellas", "serve", "--faucet", "--passkey", "owner.key"],
            vec!["hellas", "serve", "--faucet", "--faucet-account", "0"],
            vec![
                "hellas",
                "serve",
                "--faucet-account",
                "0",
                "--passkey",
                "owner.key",
            ],
            vec!["hellas", "serve", "--faucet-account", "100"],
        ] {
            assert!(crate::Cli::try_parse_from(args).is_err());
        }
        assert!(crate::Cli::try_parse_from(["hellas", "serve", "--faucet"]).is_ok());
        assert!(crate::Cli::try_parse_from(["hellas", "--faucet-account", "99", "serve"]).is_ok());
    }
}
