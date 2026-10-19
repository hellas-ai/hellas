//! Private, connection-bound standing queries. The stable locator admits stale
//! generations for discovery only; it grants no execution or result authority.
use super::{budget::*, records::*, *};
use hellas_rpc::protocol::value::{BoundedCborError, decode_canonical_bounded, encode_bounded};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandingLocator {
    pub provider: ContentId,
    pub grant: GrantId,
    pub client: PrincipalId,
    pub generation: u64,
}
impl StandingLocator {
    /// Provider, grant, tagged client principal and generation.
    pub const SIZE: usize = 32 + 16 + 1 + 33 + 8;
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
        let client = self.client.public_key();
        let mut bytes = [0; Self::SIZE];
        bytes[..32].copy_from_slice(self.provider.as_bytes());
        bytes[32..48].copy_from_slice(&self.grant.0);
        bytes[48] = client.kind().to_byte();
        bytes[49..82].copy_from_slice(client.bytes());
        bytes[82..].copy_from_slice(&self.generation.to_be_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        let bytes: &[u8; Self::SIZE] = bytes.try_into().map_err(|_| GrantError::Malformed)?;
        if bytes[48] != hellas_auth::SignatureKind::P256.to_byte() {
            return Err(GrantError::UnsupportedKey);
        }
        Ok(Self {
            provider: ContentId::from_bytes(
                bytes[..32].try_into().map_err(|_| GrantError::Malformed)?,
            ),
            grant: GrantId(
                bytes[32..48]
                    .try_into()
                    .map_err(|_| GrantError::Malformed)?,
            ),
            client: PrincipalId::from_public_key(hellas_auth::PublicKey::P256(
                bytes[49..82]
                    .try_into()
                    .map_err(|_| GrantError::Malformed)?,
            ))
            .map_err(|_| GrantError::UnsupportedKey)?,
            generation: u64::from_be_bytes(
                bytes[82..].try_into().map_err(|_| GrantError::Malformed)?,
            ),
        })
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
        encode_bounded(self, Self::MAX_BYTES).map_err(|error| match error {
            BoundedCborError::OutputLimit => GrantError::StateCapacity,
            _ => GrantError::Malformed,
        })
    }
    pub fn decode(bytes: &[u8], now: UnixMillis) -> Result<Self, GrantError> {
        let value: Self =
            decode_canonical_bounded(bytes, Self::MAX_BYTES).map_err(|error| match error {
                BoundedCborError::InputLimit => GrantError::StateCapacity,
                _ => GrantError::Malformed,
            })?;
        SignedOffer::decode(&value.offer.encode()?, now)?;
        let own = value.offer.offer().grant.budget;
        let mut nodes = std::collections::BTreeSet::new();
        for node in &value.nodes {
            if !nodes.insert(node.node)
                || node.node != own
                || node.counters.len() != Meter::ALL.len() * Window::ALL.len()
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
        if !nodes.contains(&own) || nodes.len() != 1 {
            return Err(GrantError::Malformed);
        }
        Ok(value)
    }
}
