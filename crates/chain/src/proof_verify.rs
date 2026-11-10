//! Runtime-independent proof verification for untrusted read responses.
//!
//! Any client that reads from an indexer it does not trust needs this: it
//! turns a response plus its embedded evidence into something checked against
//! consensus. Named for the capability, not for the explorer that happens to
//! be its first consumer -- a browser, a relay and a CLI all verify the same
//! way.
//!
//! A trust document must be authenticated independently of the indexer. An embedded bundle
//! proves consensus finality, not that its observation timestamp or latest-block claim is fresh.
use crate::domain::{Digest, Object, ObjectId};
use crate::{
    ConsensusInfo, ConsensusVerifier, FinalizedBlock, FinalizedBlockQuery, FinalizedBlockView,
    LatestBlock, genesis_digest,
};
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _};
use commonware_consensus::CertifiableBlock as _;
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_storage::{
    mmr,
    qmdb::{
        any::{
            ordered::{Operation, Update},
            value::FixedEncoding,
        },
        current::ordered::{ExclusionProof, fixed::KeyValueProof},
    },
};
use hellas_genesis::TrustDocument;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CURRENT_KEYS: usize = crate::owner_proof::OWNER_PAGE_LIMIT as usize;

pub use hellas_rpc::edge_index::{PROOF_SCHEMA_VERSION, ProofBundle};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofQuery {
    Block(FinalizedBlockQuery),
    /// SHA-256 of the transaction's canonical chain encoding.
    Transaction(Digest),
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error(transparent)]
    Trust(#[from] hellas_genesis::TrustError),
    #[error(transparent)]
    Consensus(#[from] crate::ConsensusVerificationError),
    #[error(transparent)]
    Block(#[from] crate::BlockViewError),
    #[error("trust document does not match the independently provisioned genesis")]
    Genesis,
    #[error("proof schema, network, or trust document does not match")]
    Identity,
    #[error("proof exceeds the maximum supported size")]
    Size,
    #[error("invalid canonical hexadecimal digest")]
    Digest,
    #[error("certificate epoch does not match the trusted height schedule")]
    Epoch,
    #[error("certificate round does not match the block context")]
    Round,
    #[error("proof does not answer the requested route")]
    Query,
    #[error("invalid current-state proof")]
    InvalidProof,
}

type CurrentInclusion = KeyValueProof<mmr::Family, ObjectId, Digest, 32>;
type CurrentExclusion = ExclusionProof<mmr::Family, ObjectId, FixedEncoding<Object>, Digest, 32>;
type CurrentOperation = Operation<mmr::Family, ObjectId, FixedEncoding<Object>>;

pub struct ProofVerifier {
    trust: TrustDocument,
    trust_sha256: String,
    verifiers: Vec<ConsensusVerifier>,
}

impl ProofVerifier {
    /// Both inputs must be authenticated deployment inputs, never accepted from a query peer.
    /// The digest covers the exact JSON bytes, including whitespace and trailing newlines.
    pub fn with_genesis(
        trust: TrustDocument,
        genesis_json: &[u8],
    ) -> Result<Self, VerificationError> {
        trust.validate()?;
        let genesis: hellas_genesis::Genesis =
            serde_json::from_slice(genesis_json).map_err(|_| VerificationError::Genesis)?;
        if genesis.validate().is_err()
            || genesis.network_id != trust.network_id
            || trust.genesis_sha256 != hex::encode(Sha256::hash(genesis_json))
        {
            return Err(VerificationError::Genesis);
        }
        Self::with_digest(trust, genesis_digest(&genesis).into())
    }

    /// The profile's trust document and consensus digest, both authenticated
    /// when the profile was loaded.
    pub fn for_profile(profile: &hellas_genesis::ChainProfile) -> Result<Self, VerificationError> {
        Self::with_digest(profile.trust().clone(), profile.consensus_digest())
    }

    /// Authenticated canonical digest permits light verification without allocations.
    pub fn with_digest(
        trust: TrustDocument,
        canonical_digest: [u8; 32],
    ) -> Result<Self, VerificationError> {
        trust.validate()?;
        let trust_sha256 = hex::encode(Sha256::hash(
            &serde_json::to_vec(&trust).expect("trust serializes"),
        ));
        let verifiers = trust
            .epochs
            .iter()
            .map(|epoch| {
                ConsensusVerifier::new(
                    &ConsensusInfo {
                        validators: Vec::new(),
                        network_id: trust.network_id.clone(),
                        threshold_identity: hex::decode(&epoch.threshold_identity)
                            .expect("validated hex"),
                    },
                    canonical_digest.into(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            trust,
            trust_sha256,
            verifiers,
        })
    }

    /// Packages locally stored finalized evidence under this trust identity.
    /// The returned bytes still require `verify` before use as a checkpoint.
    #[cfg(feature = "indexer-api")]
    pub(crate) fn bundle(&self, finalized: FinalizedBlock) -> ProofBundle {
        let epoch = crate::finality_proof::FinalityProof::decode(&finalized.snapshot.finalization)
            .map_or(u64::MAX, |proof| proof.certificate_epoch());
        ProofBundle {
            schema_version: PROOF_SCHEMA_VERSION,
            network_id: self.trust.network_id.clone(),
            trust_sha256: self.trust_sha256.clone(),
            height: finalized.snapshot.height,
            payload: hex::encode(finalized.snapshot.payload),
            state_root: hex::encode(finalized.snapshot.state_root),
            finalization: finalized.snapshot.finalization,
            canonical_block: finalized.block,
            observed_at_ms: 0,
            epoch,
        }
    }

    pub fn trust_sha256(&self) -> &str {
        &self.trust_sha256
    }

    pub fn network(&self) -> hellas_kernel::NetworkId {
        hellas_kernel::NetworkId::new(&self.trust.network_id).expect("validated trust network")
    }

    pub fn verify(
        &self,
        bundle: ProofBundle,
        query: ProofQuery,
    ) -> Result<VerifiedBlock, VerificationError> {
        if bundle.schema_version != PROOF_SCHEMA_VERSION
            || bundle.network_id != self.trust.network_id
            || bundle.trust_sha256 != self.trust_sha256
        {
            return Err(VerificationError::Identity);
        }
        let finalized = FinalizedBlock {
            snapshot: LatestBlock {
                height: bundle.height,
                payload: parse_digest(&bundle.payload)?,
                state_root: parse_digest(&bundle.state_root)?,
                finalization: bundle.finalization.clone(),
            },
            block: bundle.canonical_block.clone(),
        };
        self.verify_finalized_inner(finalized, query, Some(bundle))
    }

    /// Verify locally fetched canonical block evidence without a self-built hex envelope.
    pub fn verify_finalized(
        &self,
        finalized: FinalizedBlock,
        query: ProofQuery,
    ) -> Result<VerifiedBlock, VerificationError> {
        self.verify_finalized_inner(finalized, query, None)
    }

    fn verify_finalized_inner(
        &self,
        finalized: FinalizedBlock,
        query: ProofQuery,
        bundle: Option<ProofBundle>,
    ) -> Result<VerifiedBlock, VerificationError> {
        if finalized.block.len() > MAX_PROOF_BYTES {
            return Err(VerificationError::Size);
        }
        let proof = crate::finality_proof::FinalityProof::decode(&finalized.snapshot.finalization)?;
        let epoch = self
            .trust
            .epoch_at(proof.certified_height(finalized.snapshot.height)?)?;
        if bundle
            .as_ref()
            .is_some_and(|bundle| bundle.epoch != epoch.epoch)
            || proof.certificate_epoch() != epoch.epoch
        {
            return Err(VerificationError::Epoch);
        }
        let position = self
            .trust
            .epochs
            .iter()
            .position(|candidate| candidate.epoch == epoch.epoch)
            .expect("selected epoch");
        proof.verify(&self.verifiers[position], &finalized.snapshot)?;
        let view = FinalizedBlockView::decode(&finalized)?;
        let block = view.block();
        for candidate in std::iter::once(block).chain(proof.descendants.iter()) {
            use commonware_consensus::Heightable as _;
            if self.trust.epoch_at(candidate.height().get())?.epoch
                != candidate.context().round.epoch().get()
            {
                return Err(VerificationError::Epoch);
            }
        }
        proof
            .verify_terminal_context(proof.descendants.last().unwrap_or(block))
            .map_err(|_| VerificationError::Round)?;
        let transaction_index = match query {
            ProofQuery::Block(FinalizedBlockQuery::Latest) => None,
            ProofQuery::Block(FinalizedBlockQuery::Height(height)) if height == view.height() => {
                None
            }
            ProofQuery::Block(FinalizedBlockQuery::Payload(payload))
                if payload == view.payload() =>
            {
                None
            }
            ProofQuery::Transaction(wanted) => Some(
                view.txs()
                    .iter()
                    .position(|tx| transaction_digest(tx) == wanted)
                    .ok_or(VerificationError::Query)?,
            ),
            _ => return Err(VerificationError::Query),
        };
        let bundle = bundle.unwrap_or_else(|| ProofBundle {
            schema_version: PROOF_SCHEMA_VERSION,
            network_id: self.trust.network_id.clone(),
            trust_sha256: self.trust_sha256.clone(),
            height: finalized.snapshot.height,
            payload: hex::encode(finalized.snapshot.payload),
            state_root: hex::encode(finalized.snapshot.state_root),
            finalization: finalized.snapshot.finalization,
            canonical_block: finalized.block,
            observed_at_ms: 0,
            epoch: epoch.epoch,
        });
        Ok(VerifiedBlock {
            bundle,
            view,
            transaction_index,
        })
    }

    /// Verify an exact key set at one certified Current-QMDB root, plus the
    /// owner page of at most `OWNER_PAGE_LIMIT` holdings after the
    /// `(owner, after)` key cursor.
    pub fn verify_objects(
        &self,
        response: hellas_rpc::pb::chain::GetObjectProofsResponse,
        requested: &BTreeSet<ObjectId>,
        query: FinalizedBlockQuery,
        owner: Option<(crate::domain::SettlementKey, Option<[u8; 32]>)>,
    ) -> Result<crate::light_client::Verified<crate::light_client::ObjectSnapshot>, VerificationError>
    {
        let block = response.block.ok_or(VerificationError::Query)?;
        let finalized = crate::client::finalized_block_from_proto(block)
            .map_err(|_| VerificationError::Query)?;
        let verified = self.verify_finalized(finalized, ProofQuery::Block(query))?;
        let owner_page = match (owner, response.owner_page) {
            (Some((owner, after)), Some(page)) => {
                let page = crate::owner_proof::OwnerPageProof::from_proto(page)
                    .map_err(|_| VerificationError::Query)?;
                let summary = crate::owner_proof::verify_owner_page_after(
                    verified.view().owner_root(),
                    owner,
                    after,
                    crate::owner_proof::OWNER_PAGE_LIMIT,
                    &page,
                )
                .map_err(|_| VerificationError::Query)?;
                Some((page, summary))
            }
            (None, None) => None,
            _ => return Err(VerificationError::Query),
        };
        let mut expected = requested.clone();
        if let Some((page, _)) = &owner_page {
            expected.extend(
                page.holdings
                    .iter()
                    .map(|holding| ObjectId::from(holding.object_id)),
            );
        }
        if response.proofs.len() != expected.len() {
            return Err(VerificationError::Query);
        }
        let root = verified.view().state_root();
        let mut seen = BTreeSet::new();
        let mut objects = BTreeMap::new();
        for entry in response.proofs {
            let key = ObjectId::from(
                <[u8; 32]>::try_from(entry.object_id.as_slice())
                    .map_err(|_| VerificationError::Query)?,
            );
            if !expected.contains(&key) || !seen.insert(key) {
                return Err(VerificationError::Query);
            }
            match entry.object {
                Some(value) => {
                    let object = Object::decode(value.as_slice())
                        .map_err(|_| VerificationError::InvalidProof)?;
                    let proof = CurrentInclusion::decode_cfg(entry.proof.as_slice(), &(128, ()))
                        .map_err(|_| VerificationError::InvalidProof)?;
                    let operation = CurrentOperation::Update(Update {
                        key,
                        value: object,
                        next_key: proof.next_key,
                    });
                    if !proof.proof.verify::<Sha256, _>(operation, &root) {
                        return Err(VerificationError::InvalidProof);
                    }
                    objects.insert(key, object);
                }
                None => {
                    let proof =
                        CurrentExclusion::decode_cfg(entry.proof.as_slice(), &(128, (), ()))
                            .map_err(|_| VerificationError::InvalidProof)?;
                    let (op_proof, operation) = match proof {
                        ExclusionProof::KeyValue(op_proof, data) => {
                            if data.key == key
                                || !current_span_contains(&data.key, &data.next_key, &key)
                            {
                                return Err(VerificationError::InvalidProof);
                            }
                            (op_proof, CurrentOperation::Update(data))
                        }
                        ExclusionProof::Commit(op_proof, value) => {
                            let loc = op_proof.loc;
                            (op_proof, CurrentOperation::CommitFloor(value, loc))
                        }
                    };
                    if !op_proof.verify::<Sha256, _>(operation, &root) {
                        return Err(VerificationError::InvalidProof);
                    }
                }
            }
        }
        let holdings = match owner_page {
            Some((page, summary)) => {
                let owner = owner.ok_or(VerificationError::Query)?.0;
                for holding in &page.holdings {
                    let object = objects
                        .get(&ObjectId::from(holding.object_id))
                        .ok_or(VerificationError::InvalidProof)?;
                    crate::owner_proof::validate_holding(owner, holding, object)
                        .map_err(|_| VerificationError::InvalidProof)?;
                }
                let keys = page
                    .holdings
                    .iter()
                    .map(|holding| ObjectId::from(holding.object_id))
                    .collect();
                Some((keys, page.offset, summary.count))
            }
            None => None,
        };
        let snapshot = crate::light_client::ObjectSnapshot::new(
            self.network(),
            verified.view.snapshot().clone(),
            verified.view.timestamp(),
            objects,
        );
        let snapshot = match holdings {
            Some((keys, offset, count)) => snapshot
                .with_holdings(keys, offset, count)
                .map_err(|_| VerificationError::InvalidProof)?,
            None => snapshot,
        };
        Ok(crate::light_client::Verified::new(snapshot))
    }
}

// Matches Commonware's ordered circular span rule; the proof below still
// authenticates both adjacent active keys and their activity bit.
fn current_span_contains(start: &ObjectId, end: &ObjectId, key: &ObjectId) -> bool {
    if start >= end {
        key >= start || key < end
    } else {
        key >= start && key < end
    }
}

pub fn transaction_digest(tx: &crate::domain::Transaction) -> Digest {
    Sha256::hash(&tx.encode())
}

fn parse_digest(value: &str) -> Result<Digest, VerificationError> {
    hellas_auth::hex::parse_lower(value)
        .map(Digest::from)
        .map_err(|_| VerificationError::Digest)
}

/// Cannot be constructed without certificate, canonical-block, epoch, and route verification.
#[derive(Clone)]
pub struct VerifiedBlock {
    bundle: ProofBundle,
    view: FinalizedBlockView,
    transaction_index: Option<usize>,
}
impl VerifiedBlock {
    pub fn bundle(&self) -> &ProofBundle {
        &self.bundle
    }
    pub fn view(&self) -> &FinalizedBlockView {
        &self.view
    }
    pub fn transaction_index(&self) -> Option<usize> {
        self.transaction_index
    }
    pub fn cursor(&self) -> VerifiedCursor {
        VerifiedCursor {
            height: self.view.height(),
            payload: self.view.payload(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedCursor {
    pub height: u64,
    pub payload: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CursorError {
    #[error("conflicting finalized payload at the same height")]
    Conflict,
}

/// Historical fills never regress the head. A backend must perform this check and its write in
/// one transaction, and reject any conflicting immutable height/payload already in its cache.
pub fn advance_cursor(
    current: Option<VerifiedCursor>,
    incoming: VerifiedCursor,
) -> Result<VerifiedCursor, CursorError> {
    match current {
        Some(cursor) if cursor.height == incoming.height && cursor.payload != incoming.payload => {
            Err(CursorError::Conflict)
        }
        Some(cursor) if cursor.height >= incoming.height => Ok(cursor),
        _ => Ok(incoming),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressStoreQuery {
    pub owner: crate::domain::SettlementKey,
    pub offset: u64,
    pub limit: u32,
    pub payload: Option<Digest>,
}

/// Backends retain canonical evidence. Re-verify returned bundles against the current pinned
/// trust document before rendering. Futures intentionally need not be Send on a WASM isolate.
/// `commit` atomically stores evidence and advances the cursor, rejects immutable-key conflicts,
/// and may evict old bundles without evicting the durable cursor. Observation time is advisory.
#[allow(async_fn_in_trait)]
pub trait VerifiedStore {
    type Error;
    async fn cursor(&self) -> Result<Option<VerifiedCursor>, Self::Error>;
    async fn get(&self, query: FinalizedBlockQuery) -> Result<Option<ProofBundle>, Self::Error>;
    async fn commit(&self, block: &VerifiedBlock) -> Result<(), Self::Error>;
    async fn get_address(
        &self,
        query: AddressStoreQuery,
    ) -> Result<Option<AddressProofBundle>, Self::Error>;
    /// Store snapshot-bound address evidence atomically with its certified block/cursor.
    async fn commit_address(&self, address: &VerifiedAddress) -> Result<(), Self::Error>;
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::domain::{Scheme, ThresholdVariant};
    use crate::owner_proof::OWNER_PAGE_LIMIT;
    use commonware_consensus::{
        Heightable as _,
        simplex::types::{Context, Finalization as NativeFinalization, Finalize, Proposal},
        types::{Epoch, Height, Round, View},
    };
    use commonware_cryptography::{
        Digest as _, Digestible as _, Signer as _, bls12381::dkg::feldman_desmedt::deal, ed25519,
    };
    use commonware_parallel::Sequential;
    use commonware_storage::{merkle::Location, mmr};
    use commonware_utils::{N3f1, non_empty_range, ordered::Set};
    use hellas_genesis::{HELLAS_DEVNET_3_ID, HELLAS_DEVNET_3_JSON, TrustEpoch};
    use rand::{SeedableRng, rngs::StdRng};

    fn immediate<F: std::future::Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
        {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => panic!("memory fixture must not wait for IO"),
        }
    }
    fn owner_fixture() -> (
        crate::domain::SettlementKey,
        crate::owner_proof::MemoryOwnerTree,
    ) {
        let owner = crate::domain::SettlementKey::from_bytes([1; 33]);
        let mut tree = crate::owner_proof::MemoryOwnerTree::default();
        immediate(crate::owner_proof::update_holding(
            &mut tree,
            owner,
            Digest::from([1; 32]),
            Some((0, 123)),
        ))
        .unwrap();
        (owner, tree)
    }

    #[test]
    fn provisioned_genesis_is_pinned_by_exact_bytes_and_network() {
        let (verifier, _) = fixture();
        let mut trust = verifier.trust.clone();
        let mut genesis: hellas_genesis::Genesis =
            serde_json::from_str(HELLAS_DEVNET_3_JSON).unwrap();
        genesis.validators[0].label = "disposable-demo".into();
        let document = serde_json::to_vec(&genesis).unwrap();
        trust.genesis_sha256 = hex::encode(Sha256::hash(&document));
        assert!(ProofVerifier::with_genesis(trust.clone(), &document).is_ok());
        assert!(matches!(
            ProofVerifier::with_genesis(trust.clone(), HELLAS_DEVNET_3_JSON.as_bytes()),
            Err(VerificationError::Genesis)
        ));
        let mut changed = document.clone();
        changed.push(b'\n');
        assert!(matches!(
            ProofVerifier::with_genesis(trust.clone(), &changed),
            Err(VerificationError::Genesis)
        ));
        genesis.network_id = "untrusted-network".into();
        let document = serde_json::to_vec(&genesis).unwrap();
        trust.genesis_sha256 = hex::encode(Sha256::hash(&document));
        assert!(matches!(
            ProofVerifier::with_genesis(trust, &document),
            Err(VerificationError::Genesis)
        ));
    }

    #[test]
    fn shared_threshold_proof_cannot_cross_genesis() {
        let (source, mut bundle) = fixture();
        let mut genesis: hellas_genesis::Genesis =
            serde_json::from_str(HELLAS_DEVNET_3_JSON).unwrap();
        genesis.validators[0].label = "different-generation".into();
        let document = serde_json::to_vec(&genesis).unwrap();
        let mut trust = source.trust.clone();
        trust.genesis_sha256 = hex::encode(Sha256::hash(&document));
        let target = ProofVerifier::with_genesis(trust, &document).unwrap();
        bundle.trust_sha256 = target.trust_sha256().into();
        assert!(
            target
                .verify(bundle, ProofQuery::Block(FinalizedBlockQuery::Latest))
                .is_err()
        );
    }

    #[test]
    fn digest_only_light_pin_verifies_the_same_certificate_and_rejects_another_digest() {
        let (full, bundle) = fixture();
        let genesis: hellas_genesis::Genesis = serde_json::from_str(HELLAS_DEVNET_3_JSON).unwrap();
        let digest_only =
            ProofVerifier::with_digest(full.trust.clone(), genesis_digest(&genesis).0).unwrap();
        assert!(
            digest_only
                .verify(
                    bundle.clone(),
                    ProofQuery::Block(FinalizedBlockQuery::Latest)
                )
                .is_ok()
        );
        let other = ProofVerifier::with_digest(full.trust.clone(), [0x42; 32]).unwrap();
        assert!(
            other
                .verify(bundle, ProofQuery::Block(FinalizedBlockQuery::Latest))
                .is_err()
        );
    }

    fn fixture() -> (ProofVerifier, ProofBundle) {
        fixture_at_height(1)
    }

    fn fixture_at_height(height: u64) -> (ProofVerifier, ProofBundle) {
        let keys = (0..4)
            .map(ed25519::PrivateKey::from_seed)
            .collect::<Vec<_>>();
        let participants =
            Set::try_from(keys.iter().map(|key| key.public_key()).collect::<Vec<_>>()).unwrap();
        let (output, shares) = deal::<ThresholdVariant, _, N3f1>(
            &mut StdRng::seed_from_u64(42),
            Default::default(),
            participants.clone(),
        )
        .unwrap();
        let polynomial = output.public().clone();
        let schemes = keys
            .iter()
            .map(|key| {
                Scheme::signer(
                    &crate::consensus_namespace(
                        hellas_kernel::NetworkId::new(HELLAS_DEVNET_3_ID).unwrap(),
                        crate::genesis_digest(&serde_json::from_str(HELLAS_DEVNET_3_JSON).unwrap()),
                    ),
                    participants.clone(),
                    polynomial.clone(),
                    shares.get_value(&key.public_key()).unwrap().clone(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let assembler = Scheme::verifier(
            &crate::consensus_namespace(
                hellas_kernel::NetworkId::new(HELLAS_DEVNET_3_ID).unwrap(),
                crate::genesis_digest(&serde_json::from_str(HELLAS_DEVNET_3_JSON).unwrap()),
            ),
            participants,
            polynomial,
        );
        let trust = TrustDocument {
            schema_version: 1,
            network_id: HELLAS_DEVNET_3_ID.into(),
            genesis_sha256: hex::encode(Sha256::hash(HELLAS_DEVNET_3_JSON.as_bytes())),
            epochs: vec![TrustEpoch {
                epoch: 0,
                start_height: 0,
                end_height: None,
                threshold_identity: hex::encode(assembler.identity().encode()),
            }],
        };
        let verifier = ProofVerifier::with_genesis(trust, HELLAS_DEVNET_3_JSON.as_bytes()).unwrap();
        let block = crate::HellasBlock::new(
            Context {
                round: Round::new(Epoch::zero(), View::new(height)),
                leader: keys[0].public_key(),
                parent: (View::zero(), Digest::EMPTY),
            },
            Digest::EMPTY,
            Height::new(height),
            1000,
            Digest::from([5; 32]),
            crate::UtxoSyncTarget::new(
                Digest::from([5; 32]),
                non_empty_range!(
                    Location::<mmr::Family>::new(0),
                    Location::<mmr::Family>::new(1)
                ),
            ),
            vec![crate::domain::Transaction::Kernel(
                hellas_kernel::test_support::valid_open_tx().unwrap(),
            )],
        );
        let (_, tree) = owner_fixture();
        let block =
            block.with_owner_root(immediate(crate::owner_proof::owner_root(&tree)).unwrap());
        let proposal = Proposal::new(block.context().round, View::zero(), block.digest());
        let votes = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect::<Vec<_>>();
        let certificate =
            NativeFinalization::from_finalizes(&assembler, &votes, &Sequential).unwrap();
        let bundle = ProofBundle {
            schema_version: 1,
            network_id: HELLAS_DEVNET_3_ID.into(),
            trust_sha256: verifier.trust_sha256().into(),
            height: block.height().get(),
            payload: hex::encode(block.digest()),
            state_root: hex::encode(block.state_root()),
            finalization: crate::finality_proof::encode(&certificate.encode(), &[]).unwrap(),
            canonical_block: block.encode().to_vec(),
            observed_at_ms: 1000,
            epoch: 0,
        };
        (verifier, bundle)
    }

    #[test]
    #[ignore = "writes deterministic local integration fixtures only when explicitly requested"]
    fn export_integration_fixture() {
        let directory =
            std::env::var("HELLAS_EXPLORER_FIXTURE_DIR").expect("set fixture output directory");
        let directory = std::path::Path::new(&directory);
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(directory.join("genesis.json"), HELLAS_DEVNET_3_JSON).unwrap();
        let (verifier, bundle) = fixture();
        let (owner, tree) = owner_fixture();
        let page = immediate(crate::owner_proof::prove_owner_page(
            &tree,
            owner,
            0,
            OWNER_PAGE_LIMIT,
        ))
        .unwrap();
        let address = AddressProofBundle {
            schema_version: 1,
            block: Some(bundle.clone()),
            page: Some(page.clone().into_proto()),
        };
        std::fs::write(
            directory.join("address.json"),
            serde_json::to_vec(&address).unwrap(),
        )
        .unwrap();
        std::fs::write(
            directory.join("address.pb"),
            prost::Message::encode_to_vec(&address),
        )
        .unwrap();
        std::fs::write(directory.join("owner.txt"), owner.to_string()).unwrap();

        std::fs::write(
            directory.join("trust.json"),
            serde_json::to_vec_pretty(&verifier.trust).unwrap(),
        )
        .unwrap();
        std::fs::write(
            directory.join("proof.json"),
            serde_json::to_vec(&bundle).unwrap(),
        )
        .unwrap();
        std::fs::write(
            directory.join("proof.pb"),
            prost::Message::encode_to_vec(&bundle),
        )
        .unwrap();

        // A separately certified higher block with the same owner tree lets
        // workerd exercise asynchronously rebuilt snapshot freshness.
        let (next_verifier, next_bundle) = fixture_at_height(2);
        assert_eq!(next_verifier.trust_sha256(), verifier.trust_sha256());
        let next_address = AddressProofBundle {
            block: Some(next_bundle.clone()),
            ..address
        };
        next_verifier
            .verify_address(next_address.clone(), owner, 0, OWNER_PAGE_LIMIT)
            .unwrap();
        std::fs::write(
            directory.join("proof-next.pb"),
            prost::Message::encode_to_vec(&next_bundle),
        )
        .unwrap();
        std::fs::write(
            directory.join("address-next.pb"),
            prost::Message::encode_to_vec(&next_address),
        )
        .unwrap();
        let page = immediate(crate::owner_proof::prove_owner_page(&tree, owner, 0, 1)).unwrap();
        let next_small_page = AddressProofBundle {
            page: Some(page.clone().into_proto()),
            ..next_address
        };
        next_verifier
            .verify_address(next_small_page.clone(), owner, 0, 1)
            .unwrap();
        std::fs::write(
            directory.join("address-next-limit1.pb"),
            prost::Message::encode_to_vec(&next_small_page),
        )
        .unwrap();
    }

    #[test]
    fn address_bundle_binds_owner_summary_and_page_to_certified_block() {
        let (verifier, bundle) = fixture();
        let (owner, tree) = owner_fixture();
        let page = immediate(crate::owner_proof::prove_owner_page(
            &tree,
            owner,
            0,
            OWNER_PAGE_LIMIT,
        ))
        .unwrap();
        let bundle = AddressProofBundle {
            schema_version: 1,
            block: Some(bundle),
            page: Some(page.clone().into_proto()),
        };
        let verified = verifier
            .verify_address(bundle.clone(), owner, 0, OWNER_PAGE_LIMIT)
            .unwrap();
        assert_eq!(verified.summary().balance, 123);
        assert_eq!(verified.summary().count, 1);
        let mut bad = bundle.clone();
        let mut page = page;
        page.holdings[0].path.leaf = Some(crate::owner_proof::OwnerLeaf::Holding {
            kind: 0,
            balance: 999,
        });
        bad.page = Some(page.into_proto());
        assert!(
            verifier
                .verify_address(bad, owner, 0, OWNER_PAGE_LIMIT)
                .is_err()
        );
        let mut missing = bundle.clone();
        missing.page = None;
        assert!(
            verifier
                .verify_address(missing, owner, 0, OWNER_PAGE_LIMIT)
                .is_err()
        );
        assert!(
            verifier
                .verify_address(bundle, owner, 1, OWNER_PAGE_LIMIT)
                .is_err()
        );
    }

    #[test]
    fn verifies_block_transaction_and_both_wire_encodings() {
        let (verifier, bundle) = fixture();
        let json: ProofBundle =
            serde_json::from_slice(&serde_json::to_vec(&bundle).unwrap()).unwrap();
        let proto = <ProofBundle as prost::Message>::decode(
            prost::Message::encode_to_vec(&bundle).as_slice(),
        )
        .unwrap();
        assert_eq!(json, proto);
        let block = verifier
            .verify(json, ProofQuery::Block(FinalizedBlockQuery::Height(1)))
            .unwrap();
        let tx = transaction_digest(&block.view().txs()[0]);
        assert_eq!(
            verifier
                .verify(proto, ProofQuery::Transaction(tx))
                .unwrap()
                .transaction_index(),
            Some(0)
        );
        assert!(matches!(
            verifier.verify(
                bundle.clone(),
                ProofQuery::Block(FinalizedBlockQuery::Height(2))
            ),
            Err(VerificationError::Query)
        ));
        assert!(matches!(
            verifier.verify(bundle, ProofQuery::Transaction(Digest::from([9; 32]))),
            Err(VerificationError::Query)
        ));
    }

    #[test]
    fn rejects_tampered_certificate_block_snapshot_and_identity() {
        let (verifier, bundle) = fixture();
        let query = ProofQuery::Block(FinalizedBlockQuery::Latest);
        let mut bad = bundle.clone();
        bad.finalization[10] ^= 1;
        assert!(verifier.verify(bad, query).is_err());
        let mut bad = bundle.clone();
        bad.canonical_block[10] ^= 1;
        assert!(matches!(
            verifier.verify(bad, query),
            Err(VerificationError::Block(_))
        ));
        let mut bad = bundle.clone();
        bad.height += 1;
        assert!(matches!(
            verifier.verify(bad, query),
            Err(VerificationError::Block(_))
        ));
        let mut bad = bundle.clone();
        bad.state_root = "11".repeat(32);
        assert!(matches!(
            verifier.verify(bad, query),
            Err(VerificationError::Block(_))
        ));
        let mut bad = bundle.clone();
        bad.epoch = 1;
        assert!(matches!(
            verifier.verify(bad, query),
            Err(VerificationError::Epoch)
        ));
        let mut bad = bundle.clone();
        bad.network_id = "another-network".into();
        assert!(matches!(
            verifier.verify(bad, query),
            Err(VerificationError::Identity)
        ));
        let mut bad = bundle.clone();
        bad.trust_sha256 = "ff".repeat(32);
        assert!(matches!(
            verifier.verify(bad, query),
            Err(VerificationError::Identity)
        ));
        // Observation time deliberately makes no cryptographic freshness claim.
        let mut changed = bundle;
        changed.observed_at_ms = u64::MAX;
        assert!(verifier.verify(changed, query).is_ok());
    }

    #[test]
    fn historical_fills_preserve_cursor_and_conflicts_are_rejected() {
        let old = VerifiedCursor {
            height: 1,
            payload: Digest::from([1; 32]),
        };
        let new = VerifiedCursor {
            height: 2,
            payload: Digest::from([2; 32]),
        };
        assert_eq!(advance_cursor(None, old), Ok(old));
        assert_eq!(advance_cursor(Some(old), new), Ok(new));
        assert_eq!(advance_cursor(Some(new), old), Ok(new));
        assert_eq!(advance_cursor(Some(new), new), Ok(new));
        assert_eq!(
            advance_cursor(Some(new), VerifiedCursor { height: 2, ..old }),
            Err(CursorError::Conflict)
        );
    }
}

/// Address evidence uses the identical canonical block bundle and typed owner proof.
/// Claims are checked against the owner root in the certified block.
#[derive(Clone, PartialEq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct AddressProofBundle {
    #[prost(uint32, tag = "1")]
    pub schema_version: u32,
    #[prost(message, optional, tag = "2")]
    pub block: Option<ProofBundle>,
    #[prost(message, optional, tag = "3")]
    #[serde(with = "address_page_serde")]
    pub page: Option<hellas_rpc::pb::chain::OwnerPageProof>,
}

// The JSON HTTP representation keeps the native page shape; protobuf carries the same
// typed message directly. Conversion is structural and never round-trips through JSON.
mod address_page_serde {
    use super::*;

    pub fn serialize<S: serde::Serializer>(
        value: &Option<hellas_rpc::pb::chain::OwnerPageProof>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .as_ref()
            .map(|page| crate::owner_proof::OwnerPageProof::from_proto(page.clone()))
            .transpose()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<hellas_rpc::pb::chain::OwnerPageProof>, D::Error> {
        Option::<crate::owner_proof::OwnerPageProof>::deserialize(deserializer)
            .map(|page| page.map(crate::owner_proof::OwnerPageProof::into_proto))
    }
}

pub struct VerifiedAddress {
    block: VerifiedBlock,
    page: crate::owner_proof::OwnerPageProof,
    summary: crate::owner_proof::OwnerCommitment,
    bundle: AddressProofBundle,
}
impl VerifiedAddress {
    pub fn block(&self) -> &VerifiedBlock {
        &self.block
    }
    pub fn page(&self) -> &crate::owner_proof::OwnerPageProof {
        &self.page
    }
    pub fn summary(&self) -> crate::owner_proof::OwnerCommitment {
        self.summary
    }
    pub fn bundle(&self) -> &AddressProofBundle {
        &self.bundle
    }
}
impl ProofVerifier {
    pub fn verify_address(
        &self,
        bundle: AddressProofBundle,
        owner: crate::domain::SettlementKey,
        offset: u64,
        limit: u32,
    ) -> Result<VerifiedAddress, VerificationError> {
        if bundle.schema_version != PROOF_SCHEMA_VERSION {
            return Err(VerificationError::Identity);
        }
        let page = bundle.page.as_ref().ok_or(VerificationError::Query)?;
        if prost::Message::encoded_len(page) > MAX_PROOF_BYTES {
            return Err(VerificationError::Size);
        }
        let page = crate::owner_proof::OwnerPageProof::from_proto(page.clone())
            .map_err(|_| VerificationError::Query)?;
        let block = self.verify(
            bundle.block.clone().ok_or(VerificationError::Query)?,
            ProofQuery::Block(FinalizedBlockQuery::Latest),
        )?;
        block.verify_owner_page(&page, owner, offset, limit)
    }
}

impl VerifiedBlock {
    /// Assemble and verify a local owner page against an already certified block.
    /// The typed block keeps certificate admission separate from page generation.
    pub(crate) fn verify_owner_page(
        self,
        page: &crate::owner_proof::OwnerPageProof,
        owner: crate::domain::SettlementKey,
        offset: u64,
        limit: u32,
    ) -> Result<VerifiedAddress, VerificationError> {
        let bundle = AddressProofBundle {
            schema_version: PROOF_SCHEMA_VERSION,
            block: Some(self.bundle.clone()),
            page: Some(page.clone().into_proto()),
        };
        let summary = crate::owner_proof::verify_owner_page(
            self.view().owner_root(),
            owner,
            offset,
            limit,
            page,
        )
        .map_err(|_| VerificationError::Query)?;
        Ok(VerifiedAddress {
            block: self,
            page: page.clone(),
            summary,
            bundle,
        })
    }
}
