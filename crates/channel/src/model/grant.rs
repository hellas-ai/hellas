//! Grant identities and authorization bytes. Admission and accounting belong to Work.
use crate::model::work::{
    BodyReader, EncodedNetwork, PaidWorkError, PrivateRecord, tag, versioned_record_digest, xh,
};
use hellas_auth::Digest;
use hellas_auth::authority::{
    AuthenticatedCaller, CallerRecord, CredentialHolder, GrantId, NodeKey, PrincipalId, ResourceId,
    Revision, UnixMillis,
};
use hellas_kernel::{Encode, NetworkId};
use hellas_rpc::{ContentId, RequestCommitment};
use hellas_xet::MIN_CHUNK_SIZE;
use serde::{Deserialize, Serialize};

pub mod records;

/// Standalone Work namespace shared by CLI providers and managed workers.
/// It names no financial chain and does not require a chain client.
pub const fn grant_network() -> NetworkId {
    const {
        match NetworkId::new("hellas-grants-v1") {
            Some(network) => network,
            None => panic!("invalid fixed grant namespace"),
        }
    }
}

/// Funding-separated channel identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelId(pub Digest);

/// A grant job signs resource and price revisions, with no payment edges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantJobAuthorizationV1 {
    /// Stable channel and generation selected by the caller.
    pub channel_id: ChannelId,
    /// Explicit generation permits stale discovery without preallocating channels.
    pub generation: u64,
    /// Exact configured allowance.
    pub grant_id: GrantId,
    /// Exact grant revision required at acceptance.
    pub grant_revision: Revision,
    /// Configured resource and exact policy revision selected from the offer.
    pub resource_id: ResourceId,
    pub resource_revision: Revision,
    /// Exact operator price schedule, frozen with the selected resource policy.
    pub pricing_revision: Revision,
    /// Commitment to the application resource policy.
    pub work_policy_digest: Digest,
    /// Commitment to the prepared input bundle.
    pub input_content: hellas_rpc::ContentRef,
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
    const BODY_SIZE: usize = 6 * 32 + 16 + 8 * 8 + 40;
    fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.channel_id.0.as_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.grant_id.0);
        out.extend_from_slice(&self.grant_revision.0.to_be_bytes());
        out.extend_from_slice(self.resource_id.0.as_bytes());
        out.extend_from_slice(&self.resource_revision.0.to_be_bytes());
        out.extend_from_slice(&self.pricing_revision.0.to_be_bytes());
        out.extend_from_slice(self.work_policy_digest.as_bytes());
        out.extend_from_slice(&hellas_rpc::protocol::content_upload::encode_reference(
            self.input_content,
        ));
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
            generation: reader.u64()?,
            grant_id: GrantId(reader.take::<16>()?),
            grant_revision: Revision(reader.u64()?),
            resource_id: ResourceId(Digest::from_bytes(reader.bytes32()?)),
            resource_revision: Revision(reader.u64()?),
            pricing_revision: Revision(reader.u64()?),
            work_policy_digest: Digest::from_bytes(reader.bytes32()?),
            input_content: hellas_rpc::ContentRef::new(
                ContentId::from_bytes(reader.bytes32()?),
                reader.u64()?,
            ),
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
const GRANT_CHANNEL: &[u8] = b"hellas.work.grant-channel.v4";
pub(crate) const GRANT_JOB_AUTHORIZE: &[u8] = b"hellas.work.grant-job-authorize.v1";

/// The party a grant channel serves: a principal acting through one device.
/// Each device has its own channel, so two nodes of one principal never share
/// a channel or its nonce sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelClient {
    pub principal: PrincipalId,
    /// The node key the principal's credential is bound to; it signs every job.
    pub node: NodeKey,
}
impl ChannelClient {
    /// The channel client an authenticated caller acts as. A bearer credential
    /// holds no node key and so has no channel.
    pub fn of(caller: &AuthenticatedCaller) -> Result<Self, records::GrantError> {
        match caller.holder() {
            CredentialHolder::Node(node) => Ok(Self {
                principal: caller.subject(),
                node,
            }),
            CredentialHolder::Bearer => Err(records::GrantError::Unauthorized),
        }
    }
    /// The channel client a journaled caller acted as.
    pub fn recorded(caller: &CallerRecord) -> Result<Self, records::GrantError> {
        match caller.holder() {
            CredentialHolder::Node(node) => Ok(Self {
                principal: caller.actor(),
                node,
            }),
            CredentialHolder::Bearer => Err(records::GrantError::Unauthorized),
        }
    }
    /// The node key as the kernel key the job signature verifies against.
    pub fn signer(self) -> hellas_kernel::Key {
        hellas_kernel::Key::from_bytes(*self.node.as_bytes())
    }
}

/// Derives a channel without consuming funds or creating a grant. Both keys
/// enter the preimage with their curve tags.
pub fn grant_channel_id(
    network: NetworkId,
    provider: ContentId,
    grant: GrantId,
    client: ChannelClient,
    generation: u64,
) -> ChannelId {
    let principal = client.principal.public_key();
    let node = client.node.public_key();
    ChannelId(xh(
        GRANT_CHANNEL,
        &[
            EncodedNetwork::new(network).as_slice(),
            provider.as_bytes(),
            &grant.0,
            &[principal.kind().to_byte()],
            principal.bytes(),
            &[node.kind().to_byte()],
            node.bytes(),
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
    GRANT_CHANNEL.len() + <NetworkId as Encode>::MAX_ENCODED_SIZE + 32 + 16 + 34 + 34 + 8
        < MIN_CHUNK_SIZE
);

/// Stable identity: recreating owner configuration never recreates allowance.
pub fn owner_grant_id(network: NetworkId, provider: ContentId, owner: PrincipalId) -> GrantId {
    let digest = xh(
        b"hellas.work.owner-grant.v3",
        &[
            EncodedNetwork::new(network).as_slice(),
            provider.as_bytes(),
            owner.as_bytes(),
        ],
    );
    let mut id = [0; 16];
    id.copy_from_slice(&digest.as_bytes()[..16]);
    GrantId(id)
}
