//! Private, connection-bound standing queries. The stable locator admits stale
//! generations for discovery only; it grants no execution or result authority.
use super::{budget::*, records::*, *};
use crate::protocol::value::{canonical_dag_cbor, decode_canonical_dag_cbor};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandingLocator {
    pub provider: ContentId,
    pub grant: GrantId,
    pub client: PrincipalId,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct StandingQuery {
    pub locator: StandingLocator,
    pub signature: crate::Signature,
}
impl StandingLocator {
    pub const SIZE: usize = 88;
    pub fn channel(self, network: NetworkId) -> ChannelId {
        grant_channel_id(
            network,
            self.provider,
            self.grant,
            self.client,
            self.generation,
        )
    }
    pub fn encode(self) -> [u8; Self::SIZE] {
        let mut bytes = [0; Self::SIZE];
        bytes[..32].copy_from_slice(self.provider.as_bytes());
        bytes[32..48].copy_from_slice(&self.grant.0);
        bytes[48..80].copy_from_slice(self.client.0.as_bytes());
        bytes[80..].copy_from_slice(&self.generation.to_be_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        let bytes: &[u8; Self::SIZE] = bytes.try_into().map_err(|_| GrantError::Malformed)?;
        Ok(Self {
            provider: ContentId::from_bytes(bytes[..32].try_into().expect("fixed slice")),
            grant: GrantId(bytes[32..48].try_into().expect("fixed slice")),
            client: PrincipalId(ContentId::from_bytes(
                bytes[48..80].try_into().expect("fixed slice"),
            )),
            generation: u64::from_be_bytes(bytes[80..].try_into().expect("fixed slice")),
        })
    }
    pub fn digest(self, network: NetworkId, exporter: &[u8; 32]) -> Digest {
        xh(
            b"hellas.work.get-standing.v1",
            &[
                EncodedNetwork::new(network).as_slice(),
                self.channel(network).0.as_bytes(),
                &self.encode(),
                exporter,
            ],
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Standing {
    pub offer: SignedOffer,
    pub now: UnixMillis,
    pub nodes: Vec<NodeAllowance>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAllowance {
    pub node: BudgetNode,
    pub concurrent_limit: u16,
    pub active: u16,
    /// Includes hidden ancestor constraints, without disclosing their usage.
    pub concurrent_remaining: u16,
    pub counters: Vec<CounterAllowance>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterAllowance {
    pub meter: Meter,
    pub window: Window,
    pub window_id: u64,
    pub used: u64,
    pub reserved: u64,
    pub limit: Option<u64>,
    /// Minimum remaining allowance across all ancestors; None is unlimited.
    pub remaining: Option<u64>,
}
impl Standing {
    pub const MAX_BYTES: usize = MAX_OFFER_BYTES + 16_384;
    pub fn encode(&self) -> Result<Vec<u8>, GrantError> {
        let bytes = canonical_dag_cbor(self).map_err(|_| GrantError::Malformed)?;
        if bytes.len() > Self::MAX_BYTES {
            return Err(GrantError::StateCapacity);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], client: PrincipalId, now: UnixMillis) -> Result<Self, GrantError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(GrantError::StateCapacity);
        }
        let value: Self = decode_canonical_dag_cbor(bytes).map_err(|_| GrantError::Malformed)?;
        SignedOffer::decode(&value.offer.encode()?, client, now)?;
        let own = BudgetNode::Grant(value.offer.offer().grant.id);
        let owner = matches!(value.offer.offer().grant.kind, GrantKind::Owner(_));
        let mut nodes = std::collections::BTreeSet::new();
        for node in &value.nodes {
            if !nodes.insert(node.node)
                || (node.node != own && !(owner && node.node == BudgetNode::Machine))
                || node.counters.len() != 16
                || node.concurrent_limit == 0
                || node.concurrent_remaining > node.concurrent_limit
            {
                return Err(GrantError::Malformed);
            }
            let mut counters = std::collections::BTreeSet::new();
            for counter in &node.counters {
                if !counters.insert((counter.meter, counter.window))
                    || counter.window_id != counter.window.id(value.now)
                    || counter
                        .limit
                        .zip(counter.remaining)
                        .is_some_and(|(limit, remaining)| {
                            remaining
                                > limit
                                    .saturating_sub(counter.used)
                                    .saturating_sub(counter.reserved)
                        })
                {
                    return Err(GrantError::Malformed);
                }
            }
        }
        if !nodes.contains(&own) || nodes.len() != if owner { 2 } else { 1 } {
            return Err(GrantError::Malformed);
        }
        Ok(value)
    }
}
