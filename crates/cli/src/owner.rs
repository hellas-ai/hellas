//! One software-passkey selection for the whole invocation.
use anyhow::{Context as _, anyhow};
use clap::Args;
use hellas_chain::genesis::{ChainProfile, FaucetAccount};
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
    pub(crate) fn is_faucet(&self) -> bool {
        self.faucet || self.faucet_account.is_some()
    }

    /// Keep the selected public owner with this identity across restarts.
    pub(crate) fn load_persistent(
        &self,
        home: &hellas_private::StoreLocation,
        chain: &ChainProfile,
    ) -> anyhow::Result<Option<SoftPasskey>> {
        if !self.is_faucet() {
            return self.load(chain);
        }
        let path = hellas_chain::chain_dir::ChainDir::open(home, chain)?.faucet_account();
        let root = path.parent().expect("faucet account has a chain directory");
        if !path.try_exists()? {
            let index = self
                .faucet_account
                .unwrap_or_else(|| rand::random_range(0..100));
            let temporary = hellas_private::private_tempfile(root, ".account-", ".new")?;
            match hellas_sdk::node_control::profile::publish_private(temporary, &path, &[index]) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let bytes = hellas_private::read_bounded_regular_file(&path, 1)?;
        let [index] = bytes.as_slice() else {
            anyhow::bail!("invalid saved faucet account");
        };
        anyhow::ensure!(
            self.faucet_account
                .is_none_or(|requested| requested == *index),
            "this provider already uses a different faucet account"
        );
        let account = faucet_account(chain, *index)?;
        eprintln!(
            "devnet faucet account {}: {}",
            account.index, account.address
        );
        Ok(Some(faucet_passkey(&account)?))
    }

    pub(crate) fn load(&self, chain: &ChainProfile) -> anyhow::Result<Option<SoftPasskey>> {
        let index = self
            .faucet_account
            .or_else(|| self.faucet.then(|| rand::random_range(0..100)));
        if let Some(index) = index {
            let account = faucet_account(chain, index)?;
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
    use clap::Parser as _;
    use hellas_chain::domain::SettlementKey;
    use hellas_chain::genesis::Chain;

    #[test]
    fn every_selected_faucet_passkey_controls_its_genesis_allocation() {
        let chain = ChainProfile::known(Chain::Devnet);
        let genesis: hellas_chain::genesis::Genesis =
            serde_json::from_str(hellas_chain::genesis::HELLAS_DEVNET_3_JSON).unwrap();
        for index in 0..100 {
            let options = OwnerArgs {
                faucet_account: Some(index),
                ..Default::default()
            };
            let key = options.load(&chain).unwrap().unwrap();
            let address = SettlementKey::from(key.party_key()).to_string();
            let allocation = genesis
                .allocations
                .iter()
                .find(|a| a.address == address)
                .unwrap();
            assert_eq!(allocation.balance, 931_145);
            assert_eq!(address, faucet_account(&chain, index).unwrap().address);
        }
        assert!(faucet_account(&chain, 100).is_err());
    }

    #[test]
    fn a_selected_account_stays_with_its_identity() {
        let chain = ChainProfile::known(Chain::Devnet);
        let root = tempfile::tempdir().unwrap();
        let load = |args: &[&str]| {
            crate::Cli::try_parse_from(args)
                .unwrap()
                .owner
                .load_persistent(
                    &hellas_private::StoreLocation::for_test(root.path()),
                    &chain,
                )
        };
        let first = load(&["hellas", "serve", "--faucet-account", "7"])
            .unwrap()
            .unwrap();
        let again = load(&["hellas", "serve", "--faucet"]).unwrap().unwrap();
        assert_eq!(again.party_key(), first.party_key());
        assert!(load(&["hellas", "serve", "--faucet-account", "8"]).is_err());
    }

    #[test]
    fn random_selection_is_funded_and_explicit_credentials_are_exclusive() {
        let chain = ChainProfile::known(Chain::Devnet);
        let options = OwnerArgs {
            faucet: true,
            ..Default::default()
        };
        let key = options.load(&chain).unwrap().unwrap();
        let accounts: Vec<FaucetAccount> =
            serde_json::from_str(chain.faucet_json().unwrap()).unwrap();
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
