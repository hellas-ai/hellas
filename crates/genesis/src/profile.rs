use crate::{Chain, Genesis, TrustDocument};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

const STATE_KEY_DOMAIN: &[u8] = b"hellas.chain-state.v1\0";

/// One authenticated chain identity and its untrusted transport routes.
#[derive(Clone, Debug)]
pub struct ChainProfile {
    known: Option<Chain>,
    consensus_digest: [u8; 32],
    state_key: [u8; 32],
    trust: TrustDocument,
    validators: Vec<String>,
    genesis: Genesis,
    /// Exact authenticated bytes when full-node execution is requested.
    genesis_json: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ChainProfileError {
    #[error("validator routes need at least one ws:// or wss:// URL with a host")]
    Routes,
    #[error("invalid chain trust: {0}")]
    Trust(#[from] crate::TrustError),
    #[error("invalid chain genesis: {0}")]
    Genesis(#[from] crate::GenesisError),
    #[error("invalid chain genesis JSON: {0}")]
    GenesisJson(#[from] serde_json::Error),
    #[error("chain trust does not bind the supplied genesis JSON")]
    Binding,
    #[error("this binary is out of date for {0}; please update")]
    OutOfDate(&'static str),
    #[error("this role requires one open trusted epoch beginning at zero")]
    UnsupportedSchedule,
}

/// Complete authenticated chain input, including the genesis document.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomChainFile {
    pub trust: TrustDocument,
    pub validators: Vec<String>,
    pub genesis_json: String,
}

fn canonical_digest(genesis: &Genesis) -> [u8; 32] {
    Sha256::digest(serde_json::to_vec(genesis).expect("genesis serializes")).into()
}

fn state_key(consensus_digest: [u8; 32], trust: &TrustDocument) -> [u8; 32] {
    // Validation makes epoch zero and its fixed-width hexadecimal identity mandatory.
    // Later epochs deliberately do not change a directory's initial authority.
    let initial = hex::decode(&trust.epochs[0].threshold_identity).expect("validated epoch zero");
    let mut hash = Sha256::new();
    hash.update(STATE_KEY_DOMAIN);
    hash.update(consensus_digest);
    hash.update(initial);
    hash.finalize().into()
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
            return Err(ChainProfileError::Routes);
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
        hex::encode(self.state_key)
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
    pub fn genesis_json(&self) -> &str {
        &self.genesis_json
    }

    #[must_use]
    pub fn genesis(&self) -> &Genesis {
        &self.genesis
    }

    #[must_use]
    pub fn known_genesis_payload_pin(&self) -> Option<[u8; 32]> {
        self.known.map(|chain| {
            hex::decode(chain.network().genesis_payload_hex.trim())
                .expect("shipped genesis payload decodes")
                .try_into()
                .expect("shipped genesis payload is 32 bytes")
        })
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
        let trust: TrustDocument =
            serde_json::from_str(network.trust_json).expect("shipped trust decodes");
        let consensus_digest = canonical_digest(&genesis);
        Self {
            known: Some(chain),
            consensus_digest,
            state_key: state_key(consensus_digest, &trust),
            trust,
            validators: network
                .validators
                .iter()
                .map(|route| (*route).to_owned())
                .collect(),
            genesis,
            genesis_json: network.json.to_owned(),
        }
    }

    pub fn custom(file: CustomChainFile) -> Result<Self, ChainProfileError> {
        file.trust.validate()?;
        let genesis: Genesis = serde_json::from_str(&file.genesis_json)?;
        genesis.validate()?;
        let consensus_digest = canonical_digest(&genesis);
        let file_digest = hex::encode(Sha256::digest(&file.genesis_json));
        for network in crate::KNOWN_NETWORKS {
            let chain = network.chain;
            if genesis.network_id == chain.network().id {
                let shipped = Self::known(chain);
                if consensus_digest != shipped.consensus_digest
                    || file.trust != shipped.trust
                    || file_digest != file.trust.genesis_sha256
                {
                    return Err(ChainProfileError::OutOfDate(chain.name()));
                }
                return shipped.with_validators(file.validators);
            }
        }
        if genesis.network_id != file.trust.network_id || file_digest != file.trust.genesis_sha256 {
            return Err(ChainProfileError::Binding);
        }
        let state_key = state_key(consensus_digest, &file.trust);
        Ok(Self {
            known: None,
            consensus_digest,
            state_key,
            trust: file.trust,
            validators: validate_routes(file.validators)?,
            genesis,
            genesis_json: file.genesis_json,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A custom network whose trust document binds its genesis bytes.
    fn custom_file(trust_edit: impl FnOnce(&mut TrustDocument)) -> CustomChainFile {
        let known = ChainProfile::known(Chain::Devnet);
        let mut genesis = known.genesis().clone();
        genesis.network_id = "custom-1".into();
        let genesis_json = serde_json::to_string(&genesis).unwrap();
        let mut trust = known.trust().clone();
        trust.network_id = genesis.network_id;
        trust.genesis_sha256 = hex::encode(Sha256::digest(&genesis_json));
        trust_edit(&mut trust);
        CustomChainFile {
            trust,
            validators: vec!["ws://127.0.0.1:9080".into()],
            genesis_json,
        }
    }

    #[test]
    fn custom_trust_must_bind_the_genesis_bytes_and_name() {
        assert!(ChainProfile::custom(custom_file(|_| {})).is_ok());
        let mut reformatted = custom_file(|_| {});
        reformatted.genesis_json.push('\n');
        let renamed = custom_file(|trust| trust.network_id = "custom-2".into());
        for file in [reformatted, renamed] {
            assert!(matches!(
                ChainProfile::custom(file),
                Err(ChainProfileError::Binding)
            ));
        }
    }

    #[test]
    fn routes_must_be_distinct_websocket_urls_with_a_host() {
        let profile = ChainProfile::known(Chain::Devnet);
        let accepted = profile
            .clone()
            .with_validators(vec![
                " wss://a.example/ws ".into(),
                "ws://b.example:9".into(),
            ])
            .unwrap();
        assert_eq!(
            accepted.validators(),
            ["wss://a.example/ws", "ws://b.example:9/"]
        );
        for routes in [
            vec![],
            vec!["not a url"],
            vec!["https://a.example"],
            vec!["ws://"],
            vec!["ws://a.example:9", "ws://a.example:9/"],
        ] {
            let routes: Vec<String> = routes.into_iter().map(String::from).collect();
            assert!(
                matches!(
                    profile.clone().with_validators(routes.clone()),
                    Err(ChainProfileError::Routes)
                ),
                "{routes:?}"
            );
        }
    }

    #[test]
    fn static_identity_needs_one_open_epoch_from_zero() {
        let open = ChainProfile::custom(custom_file(|_| {})).unwrap();
        assert_eq!(
            open.static_threshold_identity().unwrap(),
            hex::decode(&open.trust().epochs[0].threshold_identity).unwrap()
        );
        let closed = custom_file(|trust| trust.epochs[0].end_height = Some(10));
        let renumbered = custom_file(|trust| trust.epochs[0].epoch = 5);
        for file in [closed, renumbered] {
            let profile = ChainProfile::custom(file).unwrap();
            assert!(matches!(
                profile.static_threshold_identity(),
                Err(ChainProfileError::UnsupportedSchedule)
            ));
        }
    }

    #[test]
    fn custom_profile_requires_genesis_bytes_and_rejects_a_foreign_name() {
        let known = ChainProfile::known(Chain::Devnet);
        let without_genesis = serde_json::json!({
            "trust": known.trust(),
            "validators": ["ws://127.0.0.1:9080"]
        });
        assert!(serde_json::from_value::<CustomChainFile>(without_genesis).is_err());

        let mut trust = known.trust().clone();
        trust.network_id = "unrelated-1".into();
        assert!(matches!(
            ChainProfile::custom(CustomChainFile {
                trust,
                validators: vec!["ws://127.0.0.1:9080".into()],
                genesis_json: known.genesis_json().to_owned(),
            }),
            Err(ChainProfileError::OutOfDate("devnet"))
        ));
    }
}
