use crate::{Chain, Genesis, TrustDocument};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    io,
    path::{Path, PathBuf},
};

/// One authenticated chain identity and its untrusted transport routes.
#[derive(Clone, Debug)]
pub struct ChainProfile {
    known: Option<Chain>,
    consensus_digest: [u8; 32],
    trust: TrustDocument,
    validators: Vec<String>,
    genesis: Option<Genesis>,
    /// Exact authenticated bytes when full-node execution is requested.
    genesis_json: Option<String>,
    genesis_payload: Option<[u8; 32]>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChainProfileError {
    #[error("validator routes need at least one ws:// or wss:// URL with a host")]
    Routes,
    #[error("validator routes must be distinct")]
    DuplicateRoute,
    #[error("invalid chain trust: {0}")]
    Trust(#[from] crate::TrustError),
    #[error("invalid chain genesis: {0}")]
    Genesis(#[from] crate::GenesisError),
    #[error("invalid chain digest")]
    Digest,
    #[error("invalid chain genesis payload")]
    Payload,
    #[error("this binary is out of date for {0}; please update")]
    OutOfDate(&'static str),
    #[error("this chain needs full genesis for execution")]
    MissingExecution,
    #[error("this role requires one open trusted epoch beginning at zero")]
    UnsupportedSchedule,
}

/// Complete authenticated light input; execution fields are needed only by full nodes.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomChainFile {
    pub consensus_digest: String,
    pub trust: TrustDocument,
    pub validators: Vec<String>,
    pub genesis_json: Option<String>,
    pub genesis_payload: Option<String>,
}

fn digest_hex(value: &str) -> Result<[u8; 32], ChainProfileError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ChainProfileError::Digest);
    }
    hex::decode(value)
        .map_err(|_| ChainProfileError::Digest)?
        .try_into()
        .map_err(|_| ChainProfileError::Digest)
}

fn canonical_digest(genesis: &Genesis) -> [u8; 32] {
    Sha256::digest(serde_json::to_vec(genesis).expect("genesis serializes")).into()
}

fn validate_routes(routes: Vec<String>) -> Result<Vec<String>, ChainProfileError> {
    if routes.is_empty() {
        return Err(ChainProfileError::Routes);
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(routes.len());
    for route in routes {
        let parsed = url::Url::parse(route.trim()).map_err(|_| ChainProfileError::Routes)?;
        if parsed.host_str().is_none() || !matches!(parsed.scheme(), "ws" | "wss") {
            return Err(ChainProfileError::Routes);
        }
        let normalized = parsed.to_string();
        if !seen.insert(normalized.clone()) {
            return Err(ChainProfileError::DuplicateRoute);
        }
        out.push(normalized);
    }
    Ok(out)
}

impl ChainProfile {
    #[must_use]
    pub const fn known_chain(&self) -> Option<Chain> {
        self.known
    }

    #[must_use]
    pub fn network_id(&self) -> &str {
        &self.trust.network_id
    }

    #[must_use]
    pub const fn consensus_digest(&self) -> [u8; 32] {
        self.consensus_digest
    }

    #[must_use]
    pub fn state_key(&self) -> String {
        hex::encode(self.consensus_digest)
    }

    #[must_use]
    pub const fn trust(&self) -> &TrustDocument {
        &self.trust
    }

    pub fn static_threshold_identity(&self) -> Result<Vec<u8>, ChainProfileError> {
        let [epoch] = self.trust.epochs.as_slice() else {
            return Err(ChainProfileError::UnsupportedSchedule);
        };
        if epoch.epoch != 0 || epoch.start_height != 0 || epoch.end_height.is_some() {
            return Err(ChainProfileError::UnsupportedSchedule);
        }
        Ok(hex::decode(&epoch.threshold_identity).expect("validated trust identity"))
    }

    #[must_use]
    pub fn validators(&self) -> &[String] {
        &self.validators
    }

    #[must_use]
    pub fn faucet_json(&self) -> Option<&'static str> {
        self.known.and_then(|chain| chain.network().faucet_json)
    }

    #[must_use]
    pub fn genesis_json(&self) -> Option<&str> {
        self.genesis_json.as_deref()
    }

    #[must_use]
    pub fn genesis(&self) -> Option<&Genesis> {
        self.genesis.as_ref()
    }

    #[must_use]
    pub fn has_execution(&self) -> bool {
        self.genesis.is_some()
    }

    pub fn with_validators(mut self, routes: Vec<String>) -> Result<Self, ChainProfileError> {
        self.validators = validate_routes(routes)?;
        Ok(self)
    }

    pub fn rotate_validators(&mut self) {
        self.validators.rotate_left(1);
    }

    pub fn known(chain: Chain) -> Self {
        let network = chain.network();
        let genesis: Genesis = serde_json::from_str(network.json).expect("shipped genesis decodes");
        genesis.validate().expect("shipped genesis validates");
        let trust: TrustDocument =
            serde_json::from_str(network.trust_json).expect("shipped trust decodes");
        trust.validate().expect("shipped trust validates");
        assert_eq!(
            trust.network_id, genesis.network_id,
            "shipped network mismatch"
        );
        assert_eq!(
            trust.genesis_sha256,
            hex::encode(Sha256::digest(network.json)),
            "shipped genesis file mismatch"
        );
        Self {
            known: Some(chain),
            consensus_digest: canonical_digest(&genesis),
            trust,
            validators: validate_routes(
                network
                    .validators
                    .iter()
                    .map(|route| (*route).to_owned())
                    .collect(),
            )
            .expect("shipped validator routes"),
            genesis: Some(genesis),
            genesis_json: Some(network.json.to_owned()),
            genesis_payload: Some(
                digest_hex(network.genesis_payload_hex.trim())
                    .expect("shipped genesis payload decodes"),
            ),
        }
    }

    pub fn custom(file: CustomChainFile) -> Result<Self, ChainProfileError> {
        file.trust.validate()?;
        let network_id = file.trust.network_id.clone();
        let consensus_digest = digest_hex(&file.consensus_digest)?;
        let genesis = file
            .genesis_json
            .as_ref()
            .map(|json| -> Result<Genesis, ChainProfileError> {
                let parsed: Genesis =
                    serde_json::from_str(json).map_err(|_| ChainProfileError::Digest)?;
                parsed.validate()?;
                if parsed.network_id != network_id
                    || canonical_digest(&parsed) != consensus_digest
                    || hex::encode(Sha256::digest(json)) != file.trust.genesis_sha256
                {
                    return Err(ChainProfileError::Digest);
                }
                Ok(parsed)
            })
            .transpose()?;
        let genesis_payload = file
            .genesis_payload
            .as_deref()
            .map(|raw| digest_hex(raw).map_err(|_| ChainProfileError::Payload))
            .transpose()?;
        for chain in [Chain::Devnet] {
            if network_id == chain.network().id {
                let shipped = Self::known(chain);
                if consensus_digest != shipped.consensus_digest
                    || file.trust != shipped.trust
                    || genesis
                        .as_ref()
                        .is_some_and(|value| Some(value) != shipped.genesis.as_ref())
                    || genesis_payload.is_some_and(|value| Some(value) != shipped.genesis_payload)
                {
                    return Err(ChainProfileError::OutOfDate(chain.name()));
                }
                return shipped.with_validators(file.validators);
            }
        }
        Ok(Self {
            known: None,
            consensus_digest,
            trust: file.trust,
            validators: validate_routes(file.validators)?,
            genesis,
            genesis_json: file.genesis_json,
            genesis_payload,
        })
    }

    pub fn execution(&self) -> Result<(&Genesis, Option<[u8; 32]>), ChainProfileError> {
        Ok((
            self.genesis
                .as_ref()
                .ok_or(ChainProfileError::MissingExecution)?,
            self.genesis_payload,
        ))
    }
}

/// The one directory owned by a selected chain under a process home.
#[derive(Clone, Debug)]
pub struct ChainDir {
    home: PathBuf,
    root: PathBuf,
    profile: ChainProfile,
}

impl ChainDir {
    pub fn open(home: &Path, profile: &ChainProfile) -> io::Result<Self> {
        let root = home.join("chains").join(profile.state_key());
        hellas_private::create_dir_all_durable(&root)?;
        Ok(Self {
            home: home.to_path_buf(),
            root,
            profile: profile.clone(),
        })
    }

    pub fn as_path(&self) -> &Path {
        &self.root
    }
    pub fn home(&self) -> &Path {
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
    pub fn node(&self) -> PathBuf {
        self.root.join("node")
    }
    pub fn head(&self) -> PathBuf {
        self.root.join("head")
    }
    pub fn client(&self) -> PathBuf {
        self.root.join("client")
    }
    pub fn provider(&self) -> PathBuf {
        self.root.join("provider")
    }
    pub fn gateway(&self, provider: &str) -> io::Result<PathBuf> {
        if provider.is_empty()
            || !provider
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid provider key",
            ));
        }
        Ok(self.root.join("gateway").join(provider))
    }
    pub fn indexer(&self) -> PathBuf {
        self.root.join("indexer")
    }
    pub fn validator(&self) -> PathBuf {
        self.root.join("validator")
    }
    pub fn faucet_account(&self) -> PathBuf {
        self.root.join("faucet-account")
    }
}

impl std::ops::Deref for ChainDir {
    type Target = ChainProfile;
    fn deref(&self) -> &Self::Target {
        &self.profile
    }
}

#[cfg(test)]
mod namespace_tests {
    use super::*;

    #[test]
    fn canonical_digest_separates_same_id_and_rejects_traversal_before_open() {
        let home = tempfile::tempdir().unwrap();
        let known = ChainProfile::known(Chain::Devnet);
        let mut trust = known.trust().clone();
        trust.network_id = "custom-1".into();
        let make = |digest: &str, trust: TrustDocument| {
            ChainProfile::custom(CustomChainFile {
                consensus_digest: digest.into(),
                trust,
                validators: vec!["ws://127.0.0.1:9080".into()],
                genesis_json: None,
                genesis_payload: None,
            })
        };
        let first = make(&"01".repeat(32), trust.clone()).unwrap();
        let second = make(&("01".repeat(31) + "02"), trust.clone()).unwrap();
        let a = ChainDir::open(home.path(), &first).unwrap();
        let b = ChainDir::open(home.path(), &second).unwrap();
        assert_eq!(a.profile().network_id(), b.profile().network_id());
        assert_ne!(a.as_path(), b.as_path());
        assert_eq!(
            a.as_path().file_name().unwrap().to_str().unwrap(),
            "01".repeat(32)
        );
        assert_eq!(a.state_key().len(), 64);
        assert!(a.as_path().is_dir() && b.as_path().is_dir());

        trust.network_id = "../../escape".into();
        assert!(make(&"03".repeat(32), trust).is_err());
        assert!(!home.path().join("escape").exists());
        assert!(a.gateway("../escape").is_err());
    }
}
