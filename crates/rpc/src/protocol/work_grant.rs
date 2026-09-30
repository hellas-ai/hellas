//! Grant identities and authorization bytes. Admission and accounting belong to Work.
use super::work::{
    BodyReader, EncodedNetwork, PaidWorkError, PrivateRecord, tag, versioned_record_digest, xh,
};
use crate::{ContentId, Digest, RequestCommitment};
use hellas_kernel::{Encode, NetworkId};
use hellas_xet::MIN_CHUNK_SIZE;
use serde::{Deserialize, Serialize};
pub mod admin;
pub mod budget;
pub mod records;
pub mod resource;
pub mod standing;

/// Standalone Work namespace shared by CLI providers and managed workers.
/// It names no financial chain and does not require a chain client.
pub fn grant_network() -> NetworkId {
    NetworkId::new("hellas-grants-v1").expect("fixed grant namespace")
}

/// Stable provider-local grant identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GrantId(pub [u8; 16]);
/// Stable project-local track identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrackId(pub [u8; 16]);
/// Canonical enrollment identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrincipalId(pub ContentId);
/// Funding-separated channel identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelId(pub Digest);
/// Monotone grant or catalogue revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Revision(pub u64);
/// Absolute Unix wall-clock milliseconds, never a finalized block height.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub struct UnixMillis(pub u64);

/// A grant job has signed resource authority and deadlines, with no payment edges or price.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantJobAuthorizationV1 {
    /// Stable channel and generation selected by the caller.
    pub channel_id: ChannelId,
    /// Grant, or its explicitly enabled track child.
    pub grant_id: GrantId,
    /// Exact grant revision required at acceptance.
    pub grant_revision: Revision,
    /// Exact signed catalogue revision; zero for a principal grant.
    pub catalogue_revision: Revision,
    /// Commitment to the application resource policy.
    pub work_policy_digest: Digest,
    /// Commitment to the prepared input bundle.
    pub prepared_input_digest: Digest,
    /// Monotone proposal nonce allocated by the channel's single writer.
    pub proposal_nonce: u64,
    /// Latest time this proposal may be accepted.
    pub acceptance_deadline_ms: UnixMillis,
    /// Signed application request.
    pub request_commitment: RequestCommitment,
    /// Exact application environment.
    pub environment_commitment: ContentId,
    /// Latest terminal time, also bounding dispatch.
    pub terminal_deadline_ms: UnixMillis,
    /// Latest delivery time; no execution may be restarted for delivery.
    pub delivery_deadline_ms: UnixMillis,
}
impl PrivateRecord for GrantJobAuthorizationV1 {
    const TAG: u8 = tag::GRANT_JOB_AUTHORIZATION_V1;
    const BODY_SIZE: usize = 5 * 32 + 16 + 6 * 8;
    fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.channel_id.0.as_bytes());
        out.extend_from_slice(&self.grant_id.0);
        out.extend_from_slice(&self.grant_revision.0.to_be_bytes());
        out.extend_from_slice(&self.catalogue_revision.0.to_be_bytes());
        out.extend_from_slice(self.work_policy_digest.as_bytes());
        out.extend_from_slice(self.prepared_input_digest.as_bytes());
        out.extend_from_slice(&self.proposal_nonce.to_be_bytes());
        out.extend_from_slice(&self.acceptance_deadline_ms.0.to_be_bytes());
        out.extend_from_slice(self.request_commitment.as_bytes());
        out.extend_from_slice(self.environment_commitment.as_bytes());
        out.extend_from_slice(&self.terminal_deadline_ms.0.to_be_bytes());
        out.extend_from_slice(&self.delivery_deadline_ms.0.to_be_bytes());
    }
    fn decode_body(reader: &mut BodyReader<'_>) -> Result<Self, PaidWorkError> {
        Ok(Self {
            channel_id: ChannelId(Digest::from_bytes(reader.bytes32()?)),
            grant_id: GrantId(reader.take::<16>()?),
            grant_revision: Revision(reader.u64()?),
            catalogue_revision: Revision(reader.u64()?),
            work_policy_digest: Digest::from_bytes(reader.bytes32()?),
            prepared_input_digest: Digest::from_bytes(reader.bytes32()?),
            proposal_nonce: reader.u64()?,
            acceptance_deadline_ms: UnixMillis(reader.u64()?),
            request_commitment: RequestCommitment::from_digest(Digest::from_bytes(
                reader.bytes32()?,
            )),
            environment_commitment: ContentId::from_bytes(reader.bytes32()?),
            terminal_deadline_ms: UnixMillis(reader.u64()?),
            delivery_deadline_ms: UnixMillis(reader.u64()?),
        })
    }
}
const GRANT_CHANNEL: &[u8] = b"hellas.work.grant-channel.v1";
pub(crate) const GRANT_JOB_AUTHORIZE: &[u8] = b"hellas.work.grant-job-authorize.v1";
/// Derives a channel without consuming funds or creating a grant.
pub fn grant_channel_id(
    network: NetworkId,
    provider: ContentId,
    grant: GrantId,
    client: PrincipalId,
    generation: u64,
) -> ChannelId {
    ChannelId(xh(
        GRANT_CHANNEL,
        &[
            EncodedNetwork::new(network).as_slice(),
            provider.as_bytes(),
            &grant.0,
            client.0.as_bytes(),
            &generation.to_be_bytes(),
        ],
    ))
}
/// The grant work id; payment authorizations cannot sign this domain.
pub fn grant_work_id(network: NetworkId, authorization: &GrantJobAuthorizationV1) -> Digest {
    versioned_record_digest(
        GRANT_JOB_AUTHORIZE,
        network,
        authorization.channel_id.0,
        &authorization.encode(),
    )
}
const _: () = assert!(
    GRANT_JOB_AUTHORIZE.len()
        + <NetworkId as Encode>::MAX_ENCODED_SIZE
        + 32
        + GrantJobAuthorizationV1::ENCODED_SIZE
        < MIN_CHUNK_SIZE
);
const _: () = assert!(
    GRANT_CHANNEL.len() + <NetworkId as Encode>::MAX_ENCODED_SIZE + 32 + 16 + 32 + 8
        < MIN_CHUNK_SIZE
);

/// Stable identity: recreating owner configuration never recreates allowance.
pub fn owner_grant_id(network: NetworkId, provider: ContentId, owner: PrincipalId) -> GrantId {
    let digest = xh(
        b"hellas.work.owner-grant.v1",
        &[
            EncodedNetwork::new(network).as_slice(),
            provider.as_bytes(),
            owner.0.as_bytes(),
        ],
    );
    let mut id = [0; 16];
    id.copy_from_slice(&digest.as_bytes()[..16]);
    GrantId(id)
}
