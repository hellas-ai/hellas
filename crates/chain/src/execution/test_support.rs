use crate::ConsensusInfo;
use crate::HellasBlock;
use crate::consensus::{ConsensusVerifier, Finalization};
use crate::domain::{
    ObjectId, PrivateKey, PublicKey, Scheme, SettlementKey, ThresholdVariant, Transaction,
    genesis_object_id,
};
use crate::execution::store::UtxoSyncTarget;
use commonware_codec::Encode;
use commonware_consensus::{
    CertifiableBlock, Heightable,
    simplex::types::{Context, Finalize, Proposal},
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{
    Digest as _, Digestible, Signer as _, bls12381::dkg::feldman_desmedt::deal, ed25519,
};
use commonware_parallel::Sequential;
#[cfg(any(feature = "validator", feature = "full-node"))]
use commonware_runtime::{Runner as _, tokio};
use commonware_storage::{merkle::Location, mmr};
use commonware_utils::{N3f1, non_empty_range, ordered::Set};
#[cfg(any(feature = "validator", feature = "full-node"))]
use core::future::Future;
use hellas_kernel::{
    Auth, BlockHeight, CloseKind, CoinId, EdgeId, Funding, List, MAX_EDGE_OUTPUTS,
    MAX_PARTY_INPUTS, Parties, PartyAuth, PartyKeys, Payout, Proof, ProtocolCode, SoftPasskey,
    SoftPasskeyError, Terms, Tx,
};
use rand::{SeedableRng, rngs::StdRng};

pub(crate) struct ConsensusFixture {
    pub(crate) schemes: Vec<Scheme>,
    pub(crate) assembler: Scheme,
    pub(crate) verifier: ConsensusVerifier,
    pub(crate) leaders: Vec<PublicKey>,
}

pub(crate) fn consensus_fixture(seed: u64) -> ConsensusFixture {
    consensus_fixture_of(seed, 4)
}

/// The same committee, at a caller-chosen size.
///
/// The count is a parameter because the shipped devnet document names
/// six validators and the suites written before it named four; a
/// fixture that could only be four would make "the shipped validator
/// count" untestable.
pub(crate) fn consensus_fixture_of(seed: u64, validators: u64) -> ConsensusFixture {
    consensus_fixture_in(
        seed,
        validators,
        crate::domain::TEST_NETWORK,
        [0; 32].into(),
    )
}

pub(crate) fn consensus_fixture_in(
    seed: u64,
    validators: u64,
    network: hellas_kernel::NetworkId,
    genesis: commonware_cryptography::sha256::Digest,
) -> ConsensusFixture {
    let namespace = crate::consensus_namespace(network, genesis);
    let private_keys = (0..validators)
        .map(|offset| ed25519::PrivateKey::from_seed(seed + offset))
        .collect::<Vec<_>>();
    let leaders = private_keys
        .iter()
        .map(|key| key.public_key())
        .collect::<Vec<_>>();
    let participants = Set::try_from(leaders.clone()).expect("unique participants");
    let mut rng = StdRng::seed_from_u64(seed);
    let (output, shares) =
        deal::<ThresholdVariant, _, N3f1>(&mut rng, Default::default(), participants.clone())
            .expect("threshold deal");
    let polynomial = output.public().clone();
    let schemes = private_keys
        .iter()
        .map(|key| {
            let share = shares.get_value(&key.public_key()).expect("share").clone();
            Scheme::signer(&namespace, participants.clone(), polynomial.clone(), share)
                .expect("scheme")
        })
        .collect::<Vec<_>>();
    let assembler = Scheme::verifier(&namespace, participants, polynomial);
    let info = ConsensusInfo {
        network_id: network.as_str().to_string(),
        validators: leaders
            .iter()
            .map(|public_key| hex::encode(public_key.encode()))
            .collect(),
        threshold_identity: assembler.identity().encode().to_vec(),
    };
    let verifier = ConsensusVerifier::new(&info, genesis).expect("verifier");
    ConsensusFixture {
        schemes,
        assembler,
        verifier,
        leaders,
    }
}

pub(crate) fn finalization(fixture: &ConsensusFixture, block: &HellasBlock) -> Finalization {
    let context = block.context();
    let proposal = Proposal::new(context.round, context.parent.0, block.digest());
    let votes = fixture
        .schemes
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("finalize vote"))
        .collect::<Vec<_>>();
    Finalization::from_finalizes(&fixture.assembler, &votes, &Sequential).expect("finalization")
}

// Drives a QMDB runtime for the app and replay tests; the `indexer`-only
// build compiles neither.
#[cfg(any(feature = "validator", feature = "full-node"))]
pub(crate) fn run_qmdb<F, Fut, T>(test: F) -> T
where
    F: FnOnce(tokio::Context) -> Fut,
    Fut: Future<Output = T>,
{
    let directory = tempfile::tempdir().expect("QMDB tempdir");
    let config = tokio::Config::new().with_storage_directory(directory.path());
    // Own the composed fixture on the heap before the runtime wraps/polls it.
    // Real-chain scenarios otherwise exhaust libtest's default debug stack.
    tokio::Runner::new(config).start(|context| Box::pin(test(context)))
}

pub(crate) fn validator_key(seed: u64) -> PrivateKey {
    ed25519::PrivateKey::from_seed(seed)
}

/// A native owner for index and reshape fixtures, from a non-zero seed.
pub(crate) fn owner_signer(seed: u8) -> hellas_kernel::Secp256k1Signer {
    hellas_kernel::Secp256k1Signer::from_secret_scalar([seed; 32])
        .expect("a repeated non-zero byte is a valid secp256k1 scalar")
}

/// The settlement key [`owner_signer`] owns coins under.
pub(crate) fn owner_key(seed: u8) -> SettlementKey {
    SettlementKey::from(owner_signer(seed).party_key())
}

pub(crate) fn index_genesis() -> HellasBlock {
    let sync_target = UtxoSyncTarget::new(
        commonware_cryptography::sha256::Digest::EMPTY,
        non_empty_range!(
            Location::<mmr::Family>::new(0),
            Location::<mmr::Family>::new(1)
        ),
    );
    HellasBlock::genesis(
        validator_key(0).public_key(),
        commonware_cryptography::sha256::Digest::EMPTY,
        sync_target,
        commonware_cryptography::sha256::Digest::from([0; 32]),
    )
}

pub(crate) fn index_block(
    parent: &HellasBlock,
    state_root: commonware_cryptography::sha256::Digest,
    txs: Vec<Transaction>,
) -> HellasBlock {
    let height = parent.height().get() + 1;
    let sync_target = UtxoSyncTarget::new(
        state_root,
        non_empty_range!(
            Location::<mmr::Family>::new(0),
            Location::<mmr::Family>::new(1)
        ),
    );
    HellasBlock::new(
        Context {
            round: Round::new(Epoch::zero(), View::new(height)),
            leader: validator_key(0).public_key(),
            parent: (parent.context().round.view(), parent.digest()),
        },
        parent.digest(),
        Height::new(height),
        height,
        state_root,
        sync_target,
        txs,
    )
}

// `timeout_close`, `maker_passkey` and `taker_passkey` are read only by the
// kernel tests. `kernel_fixture` still builds them for every caller, so they
// cannot be `cfg`-ed out without splitting the constructor; scope the
// allowance to exactly the build where nothing reads them.
#[cfg_attr(
    not(any(feature = "validator", feature = "full-node")),
    allow(dead_code)
)]
pub(crate) struct KernelFixture {
    pub(crate) allocations: Vec<(SettlementKey, u64)>,
    pub(crate) maker: SettlementKey,
    pub(crate) funding: Funding,
    pub(crate) terms: Terms,
    pub(crate) outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    pub(crate) edge: EdgeId,
    pub(crate) open: Tx,
    pub(crate) mutual_close: Tx,
    pub(crate) timeout_close: Tx,
    maker_passkey: SoftPasskey,
    taker_passkey: SoftPasskey,
}

impl KernelFixture {
    pub(crate) fn payout_ids(&self) -> List<CoinId, MAX_EDGE_OUTPUTS> {
        Tx::close_output_ids(self.edge, &self.outputs)
    }

    // Read only by the kernel tests, and `kernel` is gated.
    #[cfg(any(feature = "validator", feature = "full-node"))]
    pub(crate) fn bad_auth_open(&self) -> Result<Tx, SoftPasskeyError> {
        let hash = Tx::open_hash(crate::domain::TEST_NETWORK, &self.funding, &self.terms);
        let wrong_hash = Tx::payload_hash(
            crate::domain::TEST_NETWORK,
            self.edge,
            CloseKind::Mutual,
            self.terms.hash(),
            &self.outputs,
        );
        Ok(Tx::open(
            self.funding.clone(),
            self.terms.clone(),
            PartyAuth::owner(Auth::webauthn(self.maker_passkey.sign(wrong_hash)?)),
            PartyAuth::owner(Auth::webauthn(self.taker_passkey.sign(hash)?)),
        ))
    }
}

fn coin_id(id: ObjectId) -> CoinId {
    CoinId::from_bytes(id.0)
}

pub(crate) fn kernel_fixture(timeout: u64) -> Result<KernelFixture, SoftPasskeyError> {
    kernel_fixture_at(timeout, 0, 7, 8)
}

pub(crate) fn kernel_fixture_at(
    timeout: u64,
    first_allocation: u16,
    maker_secret: u8,
    taker_secret: u8,
) -> Result<KernelFixture, SoftPasskeyError> {
    let maker_passkey = SoftPasskey::from_secret_scalar([maker_secret; 32])?;
    let taker_passkey = SoftPasskey::from_secret_scalar([taker_secret; 32])?;
    let maker = SettlementKey::from(maker_passkey.party_key());
    let taker = SettlementKey::from(taker_passkey.party_key());
    let taker_allocation = first_allocation
        .checked_add(1)
        .expect("test fixture allocation index overflow");
    let maker_inputs = List::take(
        [coin_id(genesis_object_id(first_allocation)); MAX_PARTY_INPUTS],
        1,
    );
    let taker_inputs = List::take(
        [coin_id(genesis_object_id(taker_allocation)); MAX_PARTY_INPUTS],
        1,
    );
    let funding = Funding::new(maker_inputs, taker_inputs);
    let mut payout_values = [Payout::default(); MAX_EDGE_OUTPUTS];
    if let Some(payout) = payout_values.first_mut() {
        *payout = Payout::new(maker_passkey.party_key(), 40);
    }
    if let Some(payout) = payout_values.get_mut(1) {
        *payout = Payout::new(taker_passkey.party_key(), 60);
    }
    let outputs = List::take(payout_values, 2);
    let terms = Terms::basic(
        ProtocolCode::new(1),
        Parties::new(
            PartyKeys::sole(maker_passkey.party_key()),
            PartyKeys::sole(taker_passkey.party_key()),
        ),
        BlockHeight::new(timeout),
        outputs.clone(),
    );
    let edge = Tx::edge_id_of(&funding, &terms);
    let open_hash = Tx::open_hash(crate::domain::TEST_NETWORK, &funding, &terms);
    let open = Tx::open(
        funding.clone(),
        terms.clone(),
        PartyAuth::owner(Auth::webauthn(maker_passkey.sign(open_hash)?)),
        PartyAuth::owner(Auth::webauthn(taker_passkey.sign(open_hash)?)),
    );
    let close_hash = Tx::payload_hash(
        crate::domain::TEST_NETWORK,
        edge,
        CloseKind::Mutual,
        terms.hash(),
        &outputs,
    );
    let mutual_close = Tx::close(
        edge,
        Proof::mutual(
            PartyAuth::owner(Auth::webauthn(maker_passkey.sign(close_hash)?)),
            PartyAuth::owner(Auth::webauthn(taker_passkey.sign(close_hash)?)),
        ),
        outputs.clone(),
    );
    let timeout_close =
        Tx::timeout_close(edge, &terms).expect("basic terms commit a timeout payout");

    Ok(KernelFixture {
        allocations: vec![(maker, 40), (taker, 60)],
        maker,
        funding,
        terms,
        outputs,
        edge,
        open,
        mutual_close,
        timeout_close,
        maker_passkey,
        taker_passkey,
    })
}

/// An owner's reshape of `inputs` into `outputs`, signed by
/// [`owner_signer`]`(owner)`, and the ids of the coins it issues.
pub(crate) fn reshape(
    owner: u8,
    inputs: &[ObjectId],
    outputs: &[(SettlementKey, Option<SettlementKey>, u64)],
) -> (Transaction, Vec<ObjectId>) {
    reshape_authorized(inputs, outputs, |hash| {
        Auth::native(owner_signer(owner).sign(hash))
    })
}

/// The same consuming reshape for either supported owner authorization curve.
pub(crate) fn reshape_authorized(
    inputs: &[ObjectId],
    outputs: &[(SettlementKey, Option<SettlementKey>, u64)],
    authorize: impl FnOnce(hellas_kernel::PayloadHash) -> Auth,
) -> (Transaction, Vec<ObjectId>) {
    let mut input_ids = [CoinId::from_bytes([0; 32]); hellas_kernel::MAX_EDGE_INPUTS];
    for (slot, id) in input_ids.iter_mut().zip(inputs) {
        *slot = CoinId::from_bytes(id.0);
    }
    let inputs = List::take(input_ids, inputs.len());
    let mut payouts = [Payout::default(); MAX_EDGE_OUTPUTS];
    for (slot, (owner, delegate, value)) in payouts.iter_mut().zip(outputs) {
        *slot = Payout::delegated(
            owner.into_kernel(),
            delegate.map(SettlementKey::into_kernel),
            *value,
        );
    }
    let outputs = List::take(payouts, outputs.len());
    let hash = hellas_kernel::Reshape::payload_hash(crate::domain::TEST_NETWORK, &inputs, &outputs);
    let ids = hellas_kernel::Reshape::output_ids(crate::domain::TEST_NETWORK, &inputs, &outputs)
        .iter()
        .copied()
        .map(crate::domain::coin_object_id)
        .collect();
    let auth = authorize(hash);
    (
        Transaction::Kernel(Tx::Owner(hellas_kernel::Reshape::new(
            inputs, outputs, auth,
        ))),
        ids,
    )
}
