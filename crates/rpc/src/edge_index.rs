//! JSON adapters and structural validation for the generated EdgeIndex contract.
//! Consensus verification belongs to the chain client, not this transport module.
include!(concat!(env!("OUT_DIR"), "/hellas_edge_index_aliases.rs"));
pub use crate::pb::chain::{
    edge_index_lease_answer::Answer as LeaseState, edge_index_object_answer::Answer as ObjectState,
    edge_index_pending_answer::Answer as PendingState, edge_index_public_terms::Terms as TermsKind,
};
pub const SCHEMA_VERSION: u32 = 3;
pub const PROOF_SCHEMA_VERSION: u32 = 1;

pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(crate) mod decimal_u64 {
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
pub(crate) mod base64_bytes {
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
pub(crate) mod optional_base64_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    #[derive(Serialize, Deserialize)]
    struct Bytes(#[serde(with = "super::base64_bytes")] Vec<u8>);
    pub fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct BytesRef<'a>(#[serde(with = "super::base64_bytes")] &'a [u8]);
        value.as_deref().map(BytesRef).serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Ok(Option::<Bytes>::deserialize(deserializer)?.map(|v| v.0))
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
    /// Structural binding only. Consensus trust verification is a separate consumer operation.
    pub fn validate(&self) -> Result<(), &'static str> {
        let snapshot = self.snapshot.as_ref().ok_or("missing snapshot")?;
        let index = self.index.as_ref().ok_or("missing coverage")?;
        if self.schema_version != SCHEMA_VERSION || index.schema_version != SCHEMA_VERSION {
            return Err("unsupported schema version");
        }
        for hash in [
            &self.genesis_sha256,
            &self.trust_sha256,
            &snapshot.payload,
            &snapshot.state_root,
            &index.indexed_through_payload,
        ] {
            validate_id(hash)?;
        }
        let proof = snapshot
            .block_proof
            .as_ref()
            .ok_or("missing snapshot proof")?;
        if proof.schema_version != PROOF_SCHEMA_VERSION
            || proof.network_id != self.network_id
            || proof.trust_sha256 != self.trust_sha256
            || proof.height != snapshot.height
            || proof.payload != snapshot.payload
            || proof.state_root != snapshot.state_root
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
                || proof.height > snapshot.height
                || proof.payload == snapshot.payload
            {
                return Err("historical evidence does not match snapshot identity");
            }
        }
        if self.provenance.as_ref() != Some(&Provenance::reported()) {
            return Err("unsupported provenance");
        }
        if !index.complete_through_snapshot
            || index.indexed_from_height != 0
            || index.indexed_through_height < snapshot.height
            || (index.indexed_through_height == snapshot.height
                && index.indexed_through_payload != snapshot.payload)
            || index.retained_from_height > snapshot.height
        {
            return Err("incomplete snapshot coverage");
        }
        if let Some(head) = &index.observed_head {
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
