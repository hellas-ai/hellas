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
//! read the same shipped bytes as the validator does. `hellas-chain`
//! re-exports it whole as `hellas_chain::genesis`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const GENESIS_SCHEMA_VERSION: u16 = 1;

/// The in-tree development network's document.
pub const HELLAS_DEVNET_1_JSON: &str = include_str!("../networks/hellas-devnet-1/genesis.json");

/// The id that document names.
pub const HELLAS_DEVNET_1_ID: &str = "hellas-devnet-1";

/// A network whose genesis document ships inside the binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KnownNetwork {
    /// Short name to select it by, e.g. `devnet`.
    pub name: &'static str,
    /// Full network id the document declares, e.g. `hellas-devnet-1`.
    pub id: &'static str,
    /// The document itself.
    pub json: &'static str,
}

/// Every network this binary can join without being handed a file.
///
/// Compiled in on purpose: operators should not have to ship genesis
/// JSON around to talk to a network everyone already agrees on, and a
/// document passed by path is a document that can be swapped.
///
/// This is a *registry selected by name*, which is a different thing
/// from the constant it replaced. That one presented itself as "the
/// network", so editing one string silently re-domained every
/// signature in the tree — a mistake this repository has already made
/// once. Adding a network here adds an entry; it never moves an
/// existing one. Nothing reads this list to decide what network it is
/// on: a caller names one, or hands over a document.
pub const KNOWN_NETWORKS: &[KnownNetwork] = &[KnownNetwork {
    name: "devnet",
    id: HELLAS_DEVNET_1_ID,
    json: HELLAS_DEVNET_1_JSON,
}];

/// Looks up a shipped network by its short name (`devnet`) or its full
/// id (`hellas-devnet-1`).
#[must_use]
pub fn known_network(selector: &str) -> Option<&'static KnownNetwork> {
    KNOWN_NETWORKS
        .iter()
        .find(|network| network.name == selector || network.id == selector)
}

/// The short names a caller may pass, for help text and error messages.
#[must_use]
pub fn known_network_names() -> Vec<&'static str> {
    KNOWN_NETWORKS.iter().map(|network| network.name).collect()
}

const PUBLIC_KEY_HEX_BYTES: usize = 64;
const MAX_NETWORK_ID_BYTES: usize = 63;
const MAX_LABEL_BYTES: usize = 63;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    #[serde(default = "default_schema_version")]
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

const fn default_schema_version() -> u16 {
    GENESIS_SCHEMA_VERSION
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
