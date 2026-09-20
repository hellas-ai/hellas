//! Public EdgeIndex transport models. Discovery and current objects remain indexer-reported.
use crate::verified_explorer::ProofBundle;
use serde::{Deserialize, Serialize};
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct IndexError {
    #[prost(uint32, tag = "1")]
    pub schema_version: u32,
    #[prost(string, tag = "2")]
    pub code: String,
    #[prost(string, tag = "3")]
    pub message: String,
    #[prost(message, optional, tag = "4")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope: Option<EdgeIndexMetadata>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    #[test]
    fn json_preserves_u64_max_and_canonical_bytes() {
        let fees = CloseFees {
            base: u64::MAX,
            slot: 1,
            proof: 2,
            lifetime: 3,
        };
        let json = serde_json::to_value(&fees).unwrap();
        assert_eq!(json["base"], u64::MAX.to_string());
        assert_eq!(serde_json::from_value::<CloseFees>(json).unwrap(), fees);
        for bad in [
            r#"{"base":1,"slot":"1","proof":"2","lifetime":"3"}"#,
            r#"{"base":"01","slot":"1","proof":"2","lifetime":"3"}"#,
        ] {
            assert!(serde_json::from_str::<CloseFees>(bad).is_err());
        }
        let slot = RegistrySlot {
            object_id: "ab".repeat(32),
            chunk: Some(vec![0, 255, 1]),
        };
        let json = serde_json::to_value(&slot).unwrap();
        assert_eq!(json["chunk"], "AP8B");
        assert_eq!(serde_json::from_value::<RegistrySlot>(json).unwrap(), slot);
        assert_ne!(
            RegistrySlot {
                object_id: slot.object_id.clone(),
                chunk: None
            }
            .encode_to_vec(),
            RegistrySlot {
                object_id: slot.object_id,
                chunk: Some(vec![])
            }
            .encode_to_vec()
        );
    }
    #[test]
    fn generated_proto_and_explicit_json_share_fields_and_presence() {
        let request = GetWorkChannelDetailRequest {
            payment_edge_id: "a1".repeat(32),
            payload: Some("b2".repeat(32)),
            funding: Some(FundingQuery { coins: vec![] }),
            schema_version: 1,
        };
        let generated = hellas_rpc::pb::chain::EdgeIndexGetWorkChannelDetailRequest::decode(
            request.encode_to_vec().as_slice(),
        )
        .unwrap();
        assert!(generated.funding.is_some());
        assert_eq!(
            GetWorkChannelDetailRequest::decode(generated.encode_to_vec().as_slice()).unwrap(),
            request
        );
        let response = ListEdgesResponse {
            envelope: EdgeIndexMetadata {
                schema_version: 1,
                network_id: "hellas-devnet-1".into(),
                genesis_sha256: "a1".repeat(32),
                trust_sha256: "b2".repeat(32),
                snapshot: Snapshot {
                    height: u64::MAX,
                    payload: "c3".repeat(32),
                    state_root: "d4".repeat(32),
                    block_proof: ProofBundle {
                        height: u64::MAX,
                        canonical_block: vec![0, 255],
                        ..Default::default()
                    },
                },
                index: IndexCoverage {
                    indexed_through_height: u64::MAX,
                    ..Default::default()
                },
                provenance: Provenance::reported(),
            },
            data: ListEdgesPage {
                items: vec![],
                next_cursor: None,
            },
        };
        let generated = hellas_rpc::pb::chain::EdgeIndexListEdgesResponse::decode(
            response.encode_to_vec().as_slice(),
        )
        .unwrap();
        assert_eq!(
            ListEdgesResponse::decode(generated.encode_to_vec().as_slice()).unwrap(),
            response
        );
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("envelope").is_none());
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["snapshot"]["height"], u64::MAX.to_string());
        assert_eq!(json["snapshot"]["block_proof"]["canonical_block"], "AP8=");
        assert_eq!(
            serde_json::from_value::<ListEdgesResponse>(json).unwrap(),
            response
        );
    }
    #[test]
    fn object_and_parser_absence_are_explicit() {
        let absent = ObjectAnswer {
            answer: Some(ObjectState::Absent(AbsentObject {
                provenance: "indexer-reported".into(),
            })),
        };
        let json = serde_json::to_value(&absent).unwrap();
        assert_eq!(json["state"], "absent");
        assert_eq!(
            serde_json::from_value::<ObjectAnswer>(json).unwrap(),
            absent
        );
        let invalid = PendingAnswer {
            answer: Some(PendingState::Invalid(ParserInvalid {
                reason: "wrong edge".into(),
            })),
        };
        let json = serde_json::to_value(&invalid).unwrap();
        assert_eq!(json["state"], "invalid");
        assert_eq!(
            serde_json::from_value::<PendingAnswer>(json).unwrap(),
            invalid
        );
    }
    #[test]
    fn invalid_filters_schema_and_noncanonical_ids_are_rejected() {
        let mut request = ListEdgesRequest {
            schema_version: 1,
            ..Default::default()
        };
        assert!(request.validate().is_ok());
        request.limit = Some(0);
        assert!(request.validate().is_err());
        request.limit = None;
        request.kind = Some("unknown".into());
        assert!(request.validate().is_err());
        request.kind = None;
        request.role = Some("maker".into());
        assert!(request.validate().is_err());
        request.role = None;
        request.schema_version = 2;
        assert!(request.validate().is_err());
        for id in ["A1".repeat(32), "00".repeat(31), "0g".repeat(32)] {
            assert!(validate_id(&id).is_err());
        }
    }
}

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
        if proof.schema_version != crate::verified_explorer::PROOF_SCHEMA_VERSION
            || proof.network_id != self.network_id
            || proof.trust_sha256 != self.trust_sha256
            || proof.height != self.snapshot.height
            || proof.payload != self.snapshot.payload
            || proof.state_root != self.snapshot.state_root
        {
            return Err("snapshot does not match block proof");
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct TransactionRef {
    #[prost(uint64, tag = "1")]
    #[serde(with = "decimal_u64")]
    pub height: u64,
    #[prost(string, tag = "2")]
    pub payload: String,
    #[prost(string, tag = "3")]
    pub transaction_digest: String,
    #[prost(uint32, tag = "4")]
    pub transaction_index: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    #[prost(uint64, tag = "1")]
    #[serde(with = "decimal_u64")]
    pub height: u64,
    #[prost(string, tag = "2")]
    pub payload: String,
    #[prost(string, tag = "3")]
    pub state_root: String,
    #[prost(message, required, tag = "4")]
    #[serde(with = "proof_json")]
    pub block_proof: ProofBundle,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct ObservedHead {
    #[prost(uint64, tag = "1")]
    #[serde(with = "decimal_u64")]
    pub height: u64,
    #[prost(string, tag = "2")]
    pub payload: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct IndexCoverage {
    #[prost(uint32, tag = "1")]
    pub schema_version: u32,
    #[prost(uint64, tag = "2")]
    #[serde(with = "decimal_u64")]
    pub indexed_from_height: u64,
    #[prost(uint64, tag = "3")]
    #[serde(with = "decimal_u64")]
    pub indexed_through_height: u64,
    #[prost(string, tag = "4")]
    pub indexed_through_payload: String,
    #[prost(bool, tag = "5")]
    pub complete_through_snapshot: bool,
    #[prost(message, optional, tag = "6")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_head: Option<ObservedHead>,
    #[prost(uint64, tag = "7")]
    #[serde(with = "decimal_u64")]
    pub observed_at_ms: u64,
    #[prost(uint64, tag = "8")]
    #[serde(with = "decimal_u64")]
    pub retained_from_height: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    #[prost(string, tag = "1")]
    pub block: String,
    #[prost(string, tag = "2")]
    pub discovery: String,
    #[prost(string, tag = "3")]
    pub current_objects: String,
    #[prost(string, tag = "4")]
    pub completeness: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct EdgeIndexMetadata {
    #[prost(uint32, tag = "1")]
    pub schema_version: u32,
    #[prost(string, tag = "2")]
    pub network_id: String,
    #[prost(string, tag = "3")]
    pub genesis_sha256: String,
    #[prost(string, tag = "4")]
    pub trust_sha256: String,
    #[prost(message, required, tag = "5")]
    pub snapshot: Snapshot,
    #[prost(message, required, tag = "6")]
    pub index: IndexCoverage,
    #[prost(message, required, tag = "7")]
    pub provenance: Provenance,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct ListEdgesRequest {
    #[prost(string, optional, tag = "1")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[prost(string, optional, tag = "2")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[prost(uint32, optional, tag = "3")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[prost(string, optional, tag = "4")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[prost(string, optional, tag = "5")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[prost(bytes = "vec", optional, tag = "6")]
    #[serde(with = "optional_base58_address")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party: Option<Vec<u8>>,
    #[prost(string, optional, tag = "7")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[prost(uint32, tag = "8")]
    pub schema_version: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct GetEdgeDetailRequest {
    #[prost(string, tag = "1")]
    pub edge_id: String,
    #[prost(string, optional, tag = "2")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[prost(uint32, tag = "3")]
    pub schema_version: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct ListEdgeEventsRequest {
    #[prost(string, tag = "1")]
    pub edge_id: String,
    #[prost(string, optional, tag = "2")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[prost(string, optional, tag = "3")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[prost(uint32, optional, tag = "4")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[prost(uint32, tag = "5")]
    pub schema_version: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct FundingQuery {
    #[prost(string, repeated, tag = "1")]
    pub coins: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct GetWorkChannelDetailRequest {
    #[prost(string, tag = "1")]
    pub payment_edge_id: String,
    #[prost(string, optional, tag = "2")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[prost(message, optional, tag = "3")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding: Option<FundingQuery>,
    #[prost(uint32, tag = "4")]
    pub schema_version: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct EdgeLinks {
    #[prost(string, tag = "1")]
    pub edge: String,
    #[prost(string, optional, tag = "2")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[prost(string, tag = "3")]
    pub maker: String,
    #[prost(string, tag = "4")]
    pub taker: String,
    #[prost(string, tag = "5")]
    pub opening_transaction: String,
    #[prost(string, tag = "6")]
    pub opening_block: String,
    #[prost(string, tag = "7")]
    pub evidence: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct EdgeSummary {
    #[prost(string, tag = "1")]
    pub edge_id: String,
    #[prost(string, tag = "2")]
    pub kind: String,
    #[prost(bytes = "vec", tag = "3")]
    #[serde(with = "base58_address")]
    pub maker: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    #[serde(with = "base58_address")]
    pub taker: Vec<u8>,
    #[prost(message, required, tag = "5")]
    pub opened: TransactionRef,
    #[prost(message, optional, tag = "6")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed: Option<TransactionRef>,
    #[prost(string, tag = "7")]
    pub lifecycle: String,
    #[prost(string, tag = "8")]
    pub terms_hash: String,
    #[prost(string, optional, tag = "9")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_edge_id: Option<String>,
    #[prost(string, optional, tag = "10")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_edge_id: Option<String>,
    #[prost(message, required, tag = "11")]
    pub links: EdgeLinks,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct ListEdgesPage {
    #[prost(message, repeated, tag = "1")]
    pub items: Vec<EdgeSummary>,
    #[prost(string, optional, tag = "2")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct CloseFees {
    #[prost(uint64, tag = "1")]
    #[serde(with = "decimal_u64")]
    pub base: u64,
    #[prost(uint64, tag = "2")]
    #[serde(with = "decimal_u64")]
    pub slot: u64,
    #[prost(uint64, tag = "3")]
    #[serde(with = "decimal_u64")]
    pub proof: u64,
    #[prost(uint64, tag = "4")]
    #[serde(with = "decimal_u64")]
    pub lifetime: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct EdgeProjection {
    #[prost(uint64, tag = "1")]
    #[serde(with = "decimal_u64")]
    pub value: u64,
    #[prost(uint64, tag = "2")]
    #[serde(with = "decimal_u64")]
    pub reserve: u64,
    #[prost(message, required, tag = "3")]
    pub close_fees: CloseFees,
    #[prost(uint64, tag = "4")]
    #[serde(with = "decimal_u64")]
    pub timeout: u64,
    #[prost(bytes = "vec", tag = "5")]
    #[serde(with = "base58_address")]
    pub maker: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    #[serde(with = "base58_address")]
    pub taker: Vec<u8>,
    #[prost(string, tag = "7")]
    pub terms_hash: String,
    #[prost(string, repeated, tag = "8")]
    pub allowed_close_kinds: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct PresentEdge {
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "base64_bytes")]
    pub canonical: Vec<u8>,
    #[prost(message, required, tag = "2")]
    pub decoded: EdgeProjection,
    #[prost(string, tag = "3")]
    pub provenance: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct AbsentObject {
    #[prost(string, tag = "1")]
    pub provenance: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct PublicPayout {
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "base58_address")]
    pub owner: Vec<u8>,
    #[prost(uint64, tag = "2")]
    #[serde(with = "decimal_u64")]
    pub value: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct BasicTerms {
    #[prost(uint32, tag = "1")]
    pub protocol: u32,
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "base58_address")]
    pub maker: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    #[serde(with = "base58_address")]
    pub taker: Vec<u8>,
    #[prost(uint64, tag = "4")]
    #[serde(with = "decimal_u64")]
    pub timeout: u64,
    #[prost(message, repeated, tag = "5")]
    pub timeout_payouts: Vec<PublicPayout>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct WorkStakeBondTerms {
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "base58_address")]
    pub maker: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "base58_address")]
    pub taker: Vec<u8>,
    #[prost(uint64, tag = "3")]
    #[serde(with = "decimal_u64")]
    pub timeout: u64,
    #[prost(message, repeated, tag = "4")]
    pub timeout_payouts: Vec<PublicPayout>,
    #[prost(uint64, tag = "5")]
    #[serde(with = "decimal_u64")]
    pub max_job_price: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct WorkPaymentTerms {
    #[prost(string, tag = "1")]
    pub bond_edge_id: String,
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "base64_bytes")]
    pub canonical_bond_terms: Vec<u8>,
    #[prost(message, required, tag = "3")]
    pub bond_terms: WorkStakeBondTerms,
    #[prost(string, tag = "4")]
    pub bond_terms_hash: String,
    #[prost(bytes = "vec", tag = "5")]
    #[serde(with = "base58_address")]
    pub maker: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    #[serde(with = "base58_address")]
    pub taker: Vec<u8>,
    #[prost(uint64, tag = "7")]
    #[serde(with = "decimal_u64")]
    pub admission_horizon: u64,
    #[prost(string, tag = "8")]
    pub private_policy_commitment: String,
    #[prost(uint64, tag = "9")]
    #[serde(with = "decimal_u64")]
    pub omission_bond: u64,
    #[prost(uint64, tag = "10")]
    #[serde(with = "decimal_u64")]
    pub omit_response_blocks: u64,
    #[prost(uint64, tag = "11")]
    #[serde(with = "decimal_u64")]
    pub start_validity_blocks: u64,
    #[prost(string, repeated, tag = "12")]
    pub allowed_close_kinds: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct Opening {
    #[prost(message, required, tag = "1")]
    pub transaction: TransactionRef,
    #[prost(message, required, tag = "2")]
    #[serde(with = "proof_json")]
    pub proof: ProofBundle,
    #[prost(string, repeated, tag = "3")]
    pub funding_maker: Vec<String>,
    #[prost(string, repeated, tag = "4")]
    pub funding_taker: Vec<String>,
    #[prost(bytes = "vec", tag = "5")]
    #[serde(with = "base64_bytes")]
    pub canonical_terms: Vec<u8>,
    #[prost(message, required, tag = "6")]
    pub terms: PublicTerms,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct Closing {
    #[prost(message, required, tag = "1")]
    pub transaction: TransactionRef,
    #[prost(message, required, tag = "2")]
    #[serde(with = "proof_json")]
    pub proof: ProofBundle,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct RelatedEdges {
    #[prost(string, optional, tag = "1")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_edge_id: Option<String>,
    #[prost(string, optional, tag = "2")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_edge_id: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct EventsLink {
    #[prost(string, tag = "1")]
    pub href: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct EdgeDetail {
    #[prost(message, required, tag = "1")]
    pub summary: EdgeSummary,
    #[prost(message, required, tag = "2")]
    pub object_at_snapshot: ObjectAnswer,
    #[prost(message, required, tag = "3")]
    pub opening: Opening,
    #[prost(message, optional, tag = "4")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closing: Option<Closing>,
    #[prost(message, required, tag = "5")]
    pub related: RelatedEdges,
    #[prost(message, required, tag = "6")]
    pub events: EventsLink,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct EdgeEvent {
    #[prost(string, tag = "1")]
    pub kind: String,
    #[prost(message, required, tag = "2")]
    pub transaction: TransactionRef,
    #[prost(bytes = "vec", tag = "3")]
    #[serde(with = "base64_bytes")]
    pub canonical_transaction: Vec<u8>,
    #[prost(string, tag = "4")]
    pub evidence_href: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct EdgeEventsPage {
    #[prost(message, repeated, tag = "1")]
    pub items: Vec<EdgeEvent>,
    #[prost(string, optional, tag = "2")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct RegistrySlot {
    #[prost(string, tag = "1")]
    pub object_id: String,
    #[prost(bytes = "vec", optional, tag = "2")]
    #[serde(with = "optional_base64_bytes")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct LeaseProjection {
    #[prost(string, tag = "1")]
    pub bond_edge_id: String,
    #[prost(string, tag = "2")]
    pub payment_edge_id: String,
    #[prost(string, tag = "3")]
    pub payment_terms_hash: String,
    #[prost(string, tag = "4")]
    pub private_policy_commitment: String,
    #[prost(uint64, tag = "5")]
    #[serde(with = "decimal_u64")]
    pub admission_horizon: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct PendingProjection {
    #[prost(string, tag = "1")]
    pub payment_edge_id: String,
    #[prost(string, tag = "2")]
    pub opener_role: String,
    #[prost(string, tag = "3")]
    pub start_id: String,
    #[prost(uint64, tag = "4")]
    #[serde(with = "decimal_u64")]
    pub response_deadline: u64,
    #[prost(uint64, tag = "5")]
    #[serde(with = "decimal_u64")]
    pub start_cumulative: u64,
    #[prost(uint64, tag = "6")]
    #[serde(with = "decimal_u64")]
    pub final_cumulative: u64,
    #[prost(bool, tag = "7")]
    pub responded: bool,
    #[prost(bool, tag = "8")]
    pub penalty_due: bool,
    #[prost(uint64, tag = "9")]
    #[serde(with = "decimal_u64")]
    pub penalty_amount: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct ParserAbsent {}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct ParserInvalid {
    #[prost(string, tag = "1")]
    pub reason: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct WorkChannelDetail {
    #[prost(message, required, tag = "1")]
    pub payment: EdgeDetail,
    #[prost(message, required, tag = "2")]
    pub bond: EdgeDetail,
    #[prost(string, repeated, tag = "3")]
    pub funding_query: Vec<String>,
    #[prost(string, repeated, tag = "4")]
    pub live_funding: Vec<String>,
    #[prost(message, repeated, tag = "5")]
    pub lease_slots: Vec<RegistrySlot>,
    #[prost(message, required, tag = "6")]
    pub pending_slot: RegistrySlot,
    #[prost(message, required, tag = "7")]
    pub lease: LeaseAnswer,
    #[prost(message, required, tag = "8")]
    pub pending: PendingAnswer,
    #[prost(string, tag = "9")]
    pub admission: String,
    #[prost(string, tag = "10")]
    pub bond_state: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
pub struct ListEdgesResponse {
    #[prost(message, required, tag = "1")]
    #[serde(flatten)]
    pub envelope: EdgeIndexMetadata,
    #[prost(message, required, tag = "2")]
    pub data: ListEdgesPage,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
pub struct GetEdgeDetailResponse {
    #[prost(message, required, tag = "1")]
    #[serde(flatten)]
    pub envelope: EdgeIndexMetadata,
    #[prost(message, required, tag = "2")]
    pub data: EdgeDetail,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
pub struct ListEdgeEventsResponse {
    #[prost(message, required, tag = "1")]
    #[serde(flatten)]
    pub envelope: EdgeIndexMetadata,
    #[prost(message, required, tag = "2")]
    pub data: EdgeEventsPage,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
pub struct GetWorkChannelDetailResponse {
    #[prost(message, required, tag = "1")]
    #[serde(flatten)]
    pub envelope: EdgeIndexMetadata,
    #[prost(message, required, tag = "2")]
    pub data: WorkChannelDetail,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
pub struct ObjectAnswer {
    #[prost(oneof = "ObjectState", tags = "1, 2")]
    #[serde(flatten)]
    pub answer: Option<ObjectState>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Oneof)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum ObjectState {
    #[prost(message, tag = "1")]
    Present(PresentEdge),
    #[prost(message, tag = "2")]
    Absent(AbsentObject),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
pub struct PublicTerms {
    #[prost(oneof = "TermsKind", tags = "1, 2, 3")]
    #[serde(flatten)]
    pub terms: Option<TermsKind>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Oneof)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TermsKind {
    #[prost(message, tag = "1")]
    Basic(BasicTerms),
    #[prost(message, tag = "2")]
    WorkPayment(WorkPaymentTerms),
    #[prost(message, tag = "3")]
    WorkStakeBond(WorkStakeBondTerms),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
pub struct LeaseAnswer {
    #[prost(oneof = "LeaseState", tags = "1, 2, 3")]
    #[serde(flatten)]
    pub answer: Option<LeaseState>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Oneof)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum LeaseState {
    #[prost(message, tag = "1")]
    Present(LeaseProjection),
    #[prost(message, tag = "2")]
    Absent(ParserAbsent),
    #[prost(message, tag = "3")]
    Invalid(ParserInvalid),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
pub struct PendingAnswer {
    #[prost(oneof = "PendingState", tags = "1, 2, 3")]
    #[serde(flatten)]
    pub answer: Option<PendingState>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Oneof)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum PendingState {
    #[prost(message, tag = "1")]
    Present(PendingProjection),
    #[prost(message, tag = "2")]
    Absent(ParserAbsent),
    #[prost(message, tag = "3")]
    Invalid(ParserInvalid),
}
