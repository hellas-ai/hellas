//! Authenticated light-client configuration, distributed independently of an RPC origin.
use crate::HELLAS_DEVNET_1_ID;
use serde::{Deserialize, Serialize};

pub const TRUST_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustDocument {
    pub schema_version: u16,
    pub network_id: String,
    /// Lowercase SHA-256 of the exact genesis document bytes.
    pub genesis_sha256: String,
    pub epochs: Vec<TrustEpoch>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustEpoch {
    /// Consensus round epoch, not the position in this list.
    pub epoch: u64,
    pub start_height: u64,
    /// Exclusive end; only the last epoch may be open-ended.
    pub end_height: Option<u64>,
    /// Canonical compressed BLS12-381 MinPk public key, lowercase hex.
    pub threshold_identity: String,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    #[error("unsupported trust schema version")]
    Schema,
    #[error("only the shipped devnet network is supported")]
    Network,
    #[error("invalid genesis digest")]
    Genesis,
    #[error("trust epochs must cover height zero onward without gaps or overlaps")]
    Schedule,
    #[error("invalid threshold identity encoding")]
    Identity,
    #[error("height is outside the configured trust epochs")]
    UnknownHeight,
}

impl TrustDocument {
    pub fn validate(&self) -> Result<(), TrustError> {
        if self.schema_version != TRUST_SCHEMA_VERSION {
            return Err(TrustError::Schema);
        }
        if self.network_id != HELLAS_DEVNET_1_ID {
            return Err(TrustError::Network);
        }
        if !canonical_hex(&self.genesis_sha256, 64) {
            return Err(TrustError::Genesis);
        }
        if self.epochs.is_empty() {
            return Err(TrustError::Schedule);
        }
        let mut next = Some(0);
        let mut previous_epoch = None;
        for epoch in &self.epochs {
            if next != Some(epoch.start_height)
                || epoch
                    .end_height
                    .is_some_and(|end| end <= epoch.start_height)
                || previous_epoch.is_some_and(|previous| epoch.epoch <= previous)
            {
                return Err(TrustError::Schedule);
            }
            if !canonical_hex(&epoch.threshold_identity, 96) {
                return Err(TrustError::Identity);
            }
            previous_epoch = Some(epoch.epoch);
            next = epoch.end_height;
        }
        Ok(())
    }

    pub fn epoch_at(&self, height: u64) -> Result<&TrustEpoch, TrustError> {
        self.validate()?;
        self.epochs
            .iter()
            .find(|epoch| {
                height >= epoch.start_height && epoch.end_height.is_none_or(|end| height < end)
            })
            .ok_or(TrustError::UnknownHeight)
    }
}

fn canonical_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn document() -> TrustDocument {
        TrustDocument {
            schema_version: 1,
            network_id: HELLAS_DEVNET_1_ID.into(),
            genesis_sha256: "ab".repeat(32),
            epochs: vec![
                TrustEpoch {
                    epoch: 0,
                    start_height: 0,
                    end_height: Some(10),
                    threshold_identity: "ab".repeat(48),
                },
                TrustEpoch {
                    epoch: 1,
                    start_height: 10,
                    end_height: None,
                    threshold_identity: "cd".repeat(48),
                },
            ],
        }
    }
    #[test]
    fn boundaries_and_unknown_height() {
        let mut trust = document();
        assert_eq!(trust.epoch_at(9).unwrap().epoch, 0);
        assert_eq!(trust.epoch_at(10).unwrap().epoch, 1);
        trust.epochs[1].end_height = Some(20);
        assert_eq!(trust.epoch_at(20), Err(TrustError::UnknownHeight));
    }
    #[test]
    fn rejects_ambiguous_schedule_and_identity() {
        for height in [0, 9, 11] {
            let mut trust = document();
            trust.epochs[1].start_height = height;
            assert_eq!(trust.validate(), Err(TrustError::Schedule));
        }
        let mut trust = document();
        trust.epochs[0].end_height = None;
        assert_eq!(trust.validate(), Err(TrustError::Schedule));
        let mut trust = document();
        trust.epochs[1].epoch = 0;
        assert_eq!(trust.validate(), Err(TrustError::Schedule));
        let mut trust = document();
        trust.epochs[0].threshold_identity = "AB".repeat(48);
        assert_eq!(trust.validate(), Err(TrustError::Identity));
    }
    #[test]
    fn rejects_wrong_network_and_schema() {
        let mut trust = document();
        trust.network_id = "another-network".into();
        assert_eq!(trust.validate(), Err(TrustError::Network));
        let mut trust = document();
        trust.schema_version = 2;
        assert_eq!(trust.validate(), Err(TrustError::Schema));
    }
}
