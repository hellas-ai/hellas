//! JSON adapters and structural validation for the generated EdgeIndex contract.
//! Consensus verification belongs to the chain client, not this transport module.
use serde::{Deserialize, Serialize};
include!(concat!(env!("OUT_DIR"), "/hellas_edge_index_aliases.rs"));
pub const SCHEMA_VERSION: u32 = 2;
pub const PROOF_SCHEMA_VERSION: u32 = 1;

pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let value = raw.parse::<u64>().map_err(serde::de::Error::custom)?;
        if value.to_string() != raw {
            return Err(serde::de::Error::custom("noncanonical decimal u64"));
        }
        Ok(value)
    }
}
pub mod base64_bytes {
    use base64ct::{Base64, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&Base64::encode_string(value))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let value = Base64::decode_vec(&raw).map_err(serde::de::Error::custom)?;
        if Base64::encode_string(&value) != raw {
            return Err(serde::de::Error::custom("noncanonical base64"));
        }
        Ok(value)
    }
}
pub mod optional_base64_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    #[derive(Serialize, Deserialize)]
    struct Bytes(#[serde(with = "super::base64_bytes")] Vec<u8>);
    pub fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .as_ref()
            .map(|v| Bytes(v.clone()))
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Ok(Option::<Bytes>::deserialize(deserializer)?.map(|v| v.0))
    }
}
pub mod base58_address {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&bs58::encode(value).into_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let value = bs58::decode(&raw)
            .into_vec()
            .map_err(serde::de::Error::custom)?;
        if value.len() != hellas_kernel::Key::LENGTH || bs58::encode(&value).into_string() != raw {
            return Err(serde::de::Error::custom("noncanonical settlement key"));
        }
        Ok(value)
    }
}
pub mod optional_base58_address {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    #[derive(Serialize, Deserialize)]
    struct Address(#[serde(with = "super::base58_address")] Vec<u8>);
    pub fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .as_ref()
            .map(|v| Address(v.clone()))
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Ok(Option::<Address>::deserialize(deserializer)?.map(|v| v.0))
    }
}
/// Reuses ProofBundle's exact protobuf schema while applying EdgeIndex's explicit JSON mapping.
pub mod proof_json {
    use super::*;
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct JsonProof {
        schema_version: u32,
        network_id: String,
        trust_sha256: String,
        #[serde(with = "decimal_u64")]
        height: u64,
        payload: String,
        state_root: String,
        #[serde(with = "base64_bytes")]
        finalization: Vec<u8>,
        #[serde(with = "base64_bytes")]
        canonical_block: Vec<u8>,
        #[serde(with = "decimal_u64")]
        observed_at_ms: u64,
        #[serde(with = "decimal_u64")]
        epoch: u64,
    }
    pub fn serialize<S: serde::Serializer>(v: &ProofBundle, s: S) -> Result<S::Ok, S::Error> {
        JsonProof {
            schema_version: v.schema_version,
            network_id: v.network_id.clone(),
            trust_sha256: v.trust_sha256.clone(),
            height: v.height,
            payload: v.payload.clone(),
            state_root: v.state_root.clone(),
            finalization: v.finalization.clone(),
            canonical_block: v.canonical_block.clone(),
            observed_at_ms: v.observed_at_ms,
            epoch: v.epoch,
        }
        .serialize(s)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<ProofBundle, D::Error> {
        let v = JsonProof::deserialize(d)?;
        Ok(ProofBundle {
            schema_version: v.schema_version,
            network_id: v.network_id,
            trust_sha256: v.trust_sha256,
            height: v.height,
            payload: v.payload,
            state_root: v.state_root,
            finalization: v.finalization,
            canonical_block: v.canonical_block,
            observed_at_ms: v.observed_at_ms,
            epoch: v.epoch,
        })
    }
}

/// EdgeIndex's explicit JSON mapping for the deduplicated historical evidence set.
pub mod proofs_json {
    use super::*;
    #[derive(Serialize, Deserialize)]
    struct Proof(#[serde(with = "proof_json")] ProofBundle);
    pub fn serialize<S: serde::Serializer>(
        proofs: &[ProofBundle],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        proofs
            .iter()
            .cloned()
            .map(Proof)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<ProofBundle>, D::Error> {
        Ok(Vec::<Proof>::deserialize(deserializer)?
            .into_iter()
            .map(|v| v.0)
            .collect())
    }
}

impl Provenance {
    pub fn reported() -> Self {
        Self {
            block: "proof-supplied".into(),
            discovery: "indexer-reported".into(),
            current_objects: "indexer-reported".into(),
            completeness: "indexer-reported".into(),
        }
    }
}
impl EdgeIndexMetadata {
    /// Resolve a transaction's payload to the one canonical proof in this response.
    pub fn proof(&self, payload: &str) -> Result<&ProofBundle, &'static str> {
        if self.snapshot.payload == payload {
            return Ok(&self.snapshot.block_proof);
        }
        self.evidence
            .binary_search_by(|proof| proof.payload.as_str().cmp(payload))
            .map(|index| &self.evidence[index])
            .map_err(|_| "referenced block evidence is missing")
    }

    /// Structural binding only. Consensus trust verification is a separate consumer operation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != SCHEMA_VERSION || self.index.schema_version != SCHEMA_VERSION {
            return Err("unsupported schema version");
        }
        for hash in [
            &self.genesis_sha256,
            &self.trust_sha256,
            &self.snapshot.payload,
            &self.snapshot.state_root,
            &self.index.indexed_through_payload,
        ] {
            validate_id(hash)?;
        }
        let proof = &self.snapshot.block_proof;
        if proof.schema_version != PROOF_SCHEMA_VERSION
            || proof.network_id != self.network_id
            || proof.trust_sha256 != self.trust_sha256
            || proof.height != self.snapshot.height
            || proof.payload != self.snapshot.payload
            || proof.state_root != self.snapshot.state_root
        {
            return Err("snapshot does not match block proof");
        }
        if self.evidence.len() > 4
            || !self
                .evidence
                .windows(2)
                .all(|v| v[0].payload < v[1].payload)
        {
            return Err("evidence must be distinct and sorted by payload");
        }
        for proof in &self.evidence {
            validate_id(&proof.payload)?;
            validate_id(&proof.state_root)?;
            if proof.schema_version != PROOF_SCHEMA_VERSION
                || proof.network_id != self.network_id
                || proof.trust_sha256 != self.trust_sha256
                || proof.height > self.snapshot.height
                || proof.payload == self.snapshot.payload
            {
                return Err("historical evidence does not match snapshot identity");
            }
        }
        if self.provenance != Provenance::reported() {
            return Err("unsupported provenance");
        }
        if !self.index.complete_through_snapshot
            || self.index.indexed_from_height != 0
            || self.index.indexed_through_height < self.snapshot.height
            || (self.index.indexed_through_height == self.snapshot.height
                && self.index.indexed_through_payload != self.snapshot.payload)
            || self.index.retained_from_height > self.snapshot.height
        {
            return Err("incomplete snapshot coverage");
        }
        if let Some(head) = &self.index.observed_head {
            validate_id(&head.payload)?;
        }
        Ok(())
    }
}
pub fn validate_id(id: &str) -> Result<(), &'static str> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected canonical lowercase 32-byte hex identifier");
    }
    Ok(())
}
pub fn validate_limit(limit: Option<u32>) -> Result<u32, &'static str> {
    let limit = limit.unwrap_or(32);
    if !(1..=64).contains(&limit) {
        return Err("limit must be 1..64");
    }
    Ok(limit)
}
impl ListEdgesRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported schema version");
        }
        if let Some(payload) = &self.payload {
            validate_id(payload)?;
        }
        validate_limit(self.limit)?;
        if !matches!(
            self.state.as_deref().unwrap_or("open"),
            "open" | "closed" | "all"
        ) {
            return Err("unknown state");
        }
        if !matches!(
            self.kind.as_deref(),
            None | Some("basic" | "work-payment" | "work-stake-bond")
        ) {
            return Err("unknown kind");
        }
        if !matches!(
            self.role.as_deref().unwrap_or("any"),
            "any" | "maker" | "taker"
        ) {
            return Err("unknown role");
        }
        if self.role.is_some() && self.party.is_none() {
            return Err("role requires party");
        }
        if self
            .party
            .as_ref()
            .is_some_and(|v| v.len() != hellas_kernel::Key::LENGTH)
        {
            return Err("invalid party");
        }
        Ok(())
    }
}
