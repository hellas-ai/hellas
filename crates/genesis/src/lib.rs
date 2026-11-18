//! Portable network identity and genesis configuration.
//!
//! This crate intentionally contains no consensus engine, transport, or key
//! implementation. It is the small document shared by validators, relays,
//! indexers, browsers, and deployment tooling. Cryptographic consumers decode
//! and validate the key strings at their own boundary.
//!
//! It is `std` and it is a crate, because the document is `String`s, `Vec`s
//! and a `BTreeSet` of them, and because the readers are not all nodes: a
//! `wasm32-unknown-unknown` browser build and a relay in another repository
//! read operator-supplied documents. `hellas-chain`
//! re-exports it whole as `hellas_chain::genesis`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const GENESIS_SCHEMA_VERSION: u16 = 1;

/// One public development account. Cryptographic consumers validate its key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaucetAccount {
    pub index: u8,
    /// Base58-encoded compressed P-256 settlement key.
    pub address: String,
    /// Hex-encoded, big-endian 32-byte P-256 secret scalar.
    pub secret_scalar: String,
}

const PUBLIC_KEY_HEX_BYTES: usize = 64;
const MAX_NETWORK_ID_BYTES: usize = 63;
const MAX_LABEL_BYTES: usize = 63;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub schema_version: u16,
    pub network_id: String,
    pub validators: Vec<GenesisValidator>,
    #[serde(default)]
    pub allocations: Vec<GenesisAllocation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisValidator {
    /// Canonical lowercase hex-encoded 32-byte Ed25519 public key.
    pub public_key: String,
    /// Stable human-facing route label; it is never an authentication secret.
    pub label: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisAllocation {
    pub address: String,
    pub balance: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GenesisError {
    #[error("unsupported genesis schema version {0}")]
    UnsupportedSchema(u16),
    #[error("network id must be 1..={MAX_NETWORK_ID_BYTES} lowercase ASCII token bytes")]
    InvalidNetworkId,
    #[error("genesis must contain at least one validator")]
    EmptyCommittee,
    #[error("validator public key must be exactly 64 lowercase hexadecimal characters")]
    InvalidValidatorKey,
    #[error("duplicate validator public key {0}")]
    DuplicateValidatorKey(String),
    #[error("validator label must be 1..={MAX_LABEL_BYTES} lowercase ASCII token bytes")]
    InvalidValidatorLabel,
    #[error("duplicate validator label {0}")]
    DuplicateValidatorLabel(String),
    #[error("genesis allocation address must not be empty")]
    EmptyAllocationAddress,
    #[error("duplicate genesis allocation address {0}")]
    DuplicateAllocationAddress(String),
}

impl Genesis {
    pub fn validate(&self) -> Result<(), GenesisError> {
        if self.schema_version != GENESIS_SCHEMA_VERSION {
            return Err(GenesisError::UnsupportedSchema(self.schema_version));
        }
        if !is_token(&self.network_id, MAX_NETWORK_ID_BYTES) {
            return Err(GenesisError::InvalidNetworkId);
        }
        if self.validators.is_empty() {
            return Err(GenesisError::EmptyCommittee);
        }

        let mut keys = BTreeSet::new();
        let mut labels = BTreeSet::new();
        for validator in &self.validators {
            if validator.public_key.len() != PUBLIC_KEY_HEX_BYTES
                || !validator
                    .public_key
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(GenesisError::InvalidValidatorKey);
            }
            if !keys.insert(validator.public_key.as_str()) {
                return Err(GenesisError::DuplicateValidatorKey(
                    validator.public_key.clone(),
                ));
            }
            if !is_token(&validator.label, MAX_LABEL_BYTES) {
                return Err(GenesisError::InvalidValidatorLabel);
            }
            if !labels.insert(validator.label.as_str()) {
                return Err(GenesisError::DuplicateValidatorLabel(
                    validator.label.clone(),
                ));
            }
        }

        let mut allocations = BTreeSet::new();
        for allocation in &self.allocations {
            if allocation.address.is_empty() {
                return Err(GenesisError::EmptyAllocationAddress);
            }
            if !allocations.insert(allocation.address.as_str()) {
                return Err(GenesisError::DuplicateAllocationAddress(
                    allocation.address.clone(),
                ));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn validator(&self, public_key: &str) -> Option<&GenesisValidator> {
        self.validators
            .iter()
            .find(|validator| validator.public_key == public_key)
    }
}

fn is_token(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod tests;

mod trust;
pub use trust::{TRUST_SCHEMA_VERSION, TrustDocument, TrustEpoch, TrustError};
mod profile;
pub use profile::{ChainFile, ChainProfile, ChainProfileError};

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
