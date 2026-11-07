//! Native storage paths for one validated chain profile.
use crate::genesis::{ChainProfile, ChainProfileError};
use hellas_private::StoreLocation;
use std::{io, path::Path};

/// The one chain-owned directory under a process home.
#[derive(Clone, Debug)]
pub struct ChainDir {
    home: StoreLocation,
    root: StoreLocation,
    profile: ChainProfile,
}

impl ChainDir {
    /// Chain stores inherit `home`'s durability.
    pub fn open(home: &StoreLocation, profile: &ChainProfile) -> io::Result<Self> {
        let root = home.child("chains").child(profile.state_key());
        hellas_private::create_dir_all_durable(&root)?;
        Ok(Self {
            home: home.clone(),
            root,
            profile: profile.clone(),
        })
    }

    pub fn as_path(&self) -> &Path {
        &self.root
    }
    pub fn home(&self) -> &StoreLocation {
        &self.home
    }
    pub fn profile(&self) -> &ChainProfile {
        &self.profile
    }
    pub fn with_validators(mut self, validators: Vec<String>) -> Result<Self, ChainProfileError> {
        self.profile = self.profile.with_validators(validators)?;
        Ok(self)
    }
    pub fn rotate_validators(&mut self) {
        self.profile.rotate_validators();
    }
    pub fn node(&self) -> StoreLocation {
        self.root.child("node")
    }
    pub fn client(&self) -> StoreLocation {
        self.root.child("client")
    }
    /// `provider` is the canonical display form of a typed ProviderAddress.
    pub fn client_journals(&self, provider: &str) -> StoreLocation {
        self.client().child("channels").child(provider)
    }
    pub fn provider(&self) -> StoreLocation {
        self.root.child("provider")
    }
    pub fn provider_journals(&self) -> StoreLocation {
        self.provider().child("channels")
    }
    /// `provider` is the canonical display form of a typed endpoint ID.
    pub fn gateway(&self, provider: &str) -> StoreLocation {
        self.root.child("gateway").child(provider)
    }
    pub fn indexer(&self) -> StoreLocation {
        self.root.child("indexer")
    }
    pub fn validator(&self) -> StoreLocation {
        self.root.child("validator")
    }
    pub fn faucet_account(&self) -> StoreLocation {
        self.root.child("faucet-account")
    }
}

impl std::ops::Deref for ChainDir {
    type Target = ChainProfile;
    fn deref(&self) -> &Self::Target {
        &self.profile
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::{Chain, CustomChainFile, Genesis};
    use hellas_private::Durability::Crash;
    use sha2::{Digest as _, Sha256};

    #[test]
    fn store_locations_keep_the_selected_durability() {
        use hellas_private::Durability;
        let home = tempfile::tempdir().unwrap();
        let profile = ChainProfile::known(Chain::Devnet);
        for durability in [Durability::Crash, Durability::Power] {
            let home = StoreLocation::from_home(home.path(), durability);
            let chain = ChainDir::open(&home, &profile).unwrap();
            for location in [
                chain.home().clone(),
                chain.node(),
                chain.client_journals("client"),
                chain.provider_journals(),
                chain.gateway("provider"),
                chain.indexer(),
                chain.validator(),
            ] {
                assert_eq!(location.durability(), durability);
            }
        }
    }

    #[test]
    fn same_genesis_with_another_initial_authority_cannot_read_state() {
        let directory = tempfile::tempdir().unwrap();
        let home = StoreLocation::from_home(directory.path(), Crash);
        let known = ChainProfile::known(Chain::Devnet);
        let mut genesis: Genesis = known.genesis().clone();
        genesis.network_id = "custom-1".into();
        let genesis_json = serde_json::to_string(&genesis).unwrap();
        let mut trust = known.trust().clone();
        trust.network_id = genesis.network_id.clone();
        trust.genesis_sha256 = hex::encode(Sha256::digest(&genesis_json));
        let make = |trust| {
            ChainProfile::custom(CustomChainFile {
                trust,
                validators: vec!["ws://127.0.0.1:9080".into()],
                genesis_json: genesis_json.clone(),
            })
            .unwrap()
        };
        let first = make(trust.clone());
        let a = ChainDir::open(&home, &first).unwrap();
        std::fs::create_dir_all(a.client()).unwrap();
        std::fs::write(a.client().join("wallet.json"), b"a-only").unwrap();

        let mut changed = trust.clone();
        let mut key = hex::decode(&changed.epochs[0].threshold_identity).unwrap();
        key[0] ^= 1;
        changed.epochs[0].threshold_identity = hex::encode(key);
        let b = ChainDir::open(&home, &make(changed)).unwrap();
        assert_ne!(a.as_path(), b.as_path());
        assert!(!b.client().join("wallet.json").exists());

        trust.epochs[0].end_height = Some(10);
        let mut next = trust.epochs[0].clone();
        next.epoch += 1;
        next.start_height = 10;
        next.end_height = None;
        trust.epochs.push(next);
        let resumed = ChainDir::open(&home, &make(trust)).unwrap();
        assert_eq!(resumed.as_path(), a.as_path());
        assert_eq!(
            std::fs::read(resumed.client().join("wallet.json")).unwrap(),
            b"a-only"
        );
    }
}
