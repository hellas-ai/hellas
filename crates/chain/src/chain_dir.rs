//! Native storage paths for one validated chain profile.
use crate::genesis::{ChainProfile, ChainProfileError, CustomChainFile};
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
        let directory = Self::prepare(home, profile)?;
        directory.persist()?;
        Ok(directory)
    }

    /// Validate a directory descriptor without creating or changing its files.
    pub fn prepare(home: &StoreLocation, profile: &ChainProfile) -> io::Result<Self> {
        let directory = Self {
            home: home.clone(),
            root: home.child("chains").child(profile.state_key()),
            profile: profile.clone(),
        };
        directory.profile_bytes()?;
        Ok(directory)
    }

    /// Publish the validated profile when its owning configuration commits.
    pub fn persist(&self) -> io::Result<()> {
        let bytes = self.profile_bytes()?;
        self.root.durability().create_dir_all(&self.root)?;
        self.root
            .durability()
            .write_atomically(&self.root.join("profile.json"), ".profile", &bytes)
    }

    fn profile_bytes(&self) -> io::Result<Vec<u8>> {
        let bytes = serde_json::to_vec(&self.profile.to_file()).map_err(invalid_profile)?;
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(invalid_profile("chain profile is too large"));
        }
        Ok(bytes)
    }

    /// Read every retained chain without creating directories or rewriting profiles.
    /// Missing or malformed profiles refuse recovery.
    pub fn discover(home: &StoreLocation) -> io::Result<Vec<Self>> {
        directories(&home.child("chains"))?
            .into_iter()
            .map(|root| {
                let bytes = hellas_private::read_bounded_regular_file(
                    &root.join("profile.json"),
                    MAX_PROFILE_BYTES,
                )
                .map_err(|error| {
                    if error.kind() == io::ErrorKind::NotFound {
                        invalid_profile(format!(
                            "chain directory {} predates chain profiles and must be removed",
                            root.display()
                        ))
                    } else {
                        error
                    }
                })?;
                let file: CustomChainFile =
                    serde_json::from_slice(&bytes).map_err(invalid_profile)?;
                let profile = ChainProfile::custom(file).map_err(invalid_profile)?;
                if root.file_name() != Some(std::ffi::OsStr::new(&profile.state_key())) {
                    return Err(invalid_profile(format!(
                        "chain profile does not match directory {}",
                        root.display()
                    )));
                }
                Ok(Self {
                    home: home.clone(),
                    root,
                    profile,
                })
            })
            .collect()
    }

    /// All provider roots sharing this chain's client content store.
    pub fn client_journal_roots(&self) -> io::Result<Vec<StoreLocation>> {
        directories(&self.client().child("channels"))
    }

    pub fn as_path(&self) -> &Path {
        &self.root
    }
    pub fn home(&self) -> &StoreLocation {
        &self.home
    }
    pub fn network(&self) -> hellas_kernel::NetworkId {
        hellas_kernel::NetworkId::new(self.profile.network_id()).expect("validated chain profile")
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
    pub fn indexer(&self) -> StoreLocation {
        self.root.child("indexer")
    }
    pub fn validator(&self) -> StoreLocation {
        self.root.child("validator")
    }
}

impl std::ops::Deref for ChainDir {
    type Target = ChainProfile;
    fn deref(&self) -> &Self::Target {
        &self.profile
    }
}

const MAX_PROFILE_BYTES: usize = 4 << 20;

fn invalid_profile(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn directories(root: &StoreLocation) -> io::Result<Vec<StoreLocation>> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        Err(error) => return Err(error),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            return Err(invalid_profile(format!(
                "expected directory: {}",
                entry.path().display()
            )));
        }
        paths.push(root.child(entry.file_name()));
    }
    paths.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::{Chain, CustomChainFile, Genesis};
    use hellas_private::Durability::Crash;
    use sha2::{Digest as _, Sha256};

    #[test]
    fn discovery_preserves_the_profile_and_refuses_missing_or_malformed_identity() {
        let directory = tempfile::tempdir().unwrap();
        let home = StoreLocation::from_home(&directory.path().join("home"), Crash);
        assert!(ChainDir::discover(&home).unwrap().is_empty());
        assert!(!home.exists(), "discovery must not create a home");
        let profile = ChainProfile::known(Chain::Devnet)
            .with_validators(vec!["wss://example.com/chain".into()])
            .unwrap();
        let chain = ChainDir::open(&home, &profile).unwrap();
        let file = chain.as_path().join("profile.json");
        let found = ChainDir::discover(&home).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(
            serde_json::to_vec(&found[0].to_file()).unwrap(),
            serde_json::to_vec(&profile.to_file()).unwrap()
        );
        assert!(chain.client_journal_roots().unwrap().is_empty());
        assert!(!chain.client().exists());
        std::fs::remove_file(&file).unwrap();
        let error = ChainDir::discover(&home).unwrap_err().to_string();
        assert!(error.contains(&chain.as_path().display().to_string()));
        assert!(error.contains("predates chain profiles and must be removed"));
        std::fs::write(&file, b"invalid").unwrap();
        assert!(ChainDir::discover(&home).is_err());
        let mut swapped = profile.to_file();
        let mut genesis = profile.genesis().clone();
        genesis.network_id = "swapped-chain".into();
        swapped.genesis_json = serde_json::to_string(&genesis).unwrap();
        swapped.trust.network_id = genesis.network_id;
        swapped.trust.genesis_sha256 = hex::encode(Sha256::digest(&swapped.genesis_json));
        let swapped = ChainProfile::custom(swapped).unwrap();
        assert_ne!(swapped.state_key(), profile.state_key());
        std::fs::write(&file, serde_json::to_vec(&swapped.to_file()).unwrap()).unwrap();
        assert!(
            ChainDir::discover(&home)
                .unwrap_err()
                .to_string()
                .contains("does not match directory")
        );
    }

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
