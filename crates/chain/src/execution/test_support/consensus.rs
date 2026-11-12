use crate::{
    ConsensusInfo, HellasBlock,
    consensus::{ConsensusVerifier, Finalization},
    domain::{PublicKey, Scheme, ThresholdVariant},
};
use commonware_codec::Encode as _;
use commonware_consensus::{
    CertifiableBlock as _,
    simplex::types::{Finalize, Proposal},
};
use commonware_cryptography::{
    Digestible as _, Signer as _, bls12381::dkg::feldman_desmedt::deal, ed25519,
};
use commonware_parallel::Sequential;
use commonware_utils::{N3f1, ordered::Set};
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

/// The single wire envelope (`finality_proof`) around [`finalization`].
pub(crate) fn finality_envelope(fixture: &ConsensusFixture, block: &HellasBlock) -> Vec<u8> {
    crate::finality_proof::FinalityProof::encode(&finalization(fixture, block).encode(), &[])
        .expect("finality envelope")
}
