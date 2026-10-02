//! A funded, metadata-only Fetch channel for SDK boundary tests.
// Client and provider feature suites use different parts of this fixture.
#![allow(dead_code)]
use crate::work_config::{ChainCrossCheck, WorkConfig};
use hellas_kernel::{
    BlockHeight, Decode as _, Edge, EdgeId, EdgeValues, Fees, Key, LeaseSlots, List,
    MAX_EDGE_OUTPUTS, NetworkId, Parties, Payout, PendingSlot, RegistryChunk, RegistryNamespace,
    RegistryRecordTag, Secp256k1Signer, Secp256k1Verifier, Terms, TermsHash, WorkPaymentTerms,
    WorkStakeBondTerms, work_payment_settlement,
};
use hellas_rpc::protocol::work::{JobDeadlines, PaidChannelPolicyV1, private_policy_commitment};
use hellas_rpc::protocol::work_fetch::{
    FetchPolicyV2, FetchRoutePolicy, PreparedPaidFetchInputV1, fetch_route_commitment,
};
use hellas_rpc::protocol::work_profile::WorkPolicy;
use hellas_rpc::protocol::work_setup::{
    ObservedChannel, ReadyChannel, WorkChannelConfig, WorkChannelDescriptor, payment_terms_hash,
};
use hellas_rpc::{Assurance, FetchEnvironment, ProducerSigningKey, Retention};
use hellas_work::work::{ClientEndpoint, JobProposal, ProviderEndpoint, WorkService};
use hellas_work::work_store::{ChannelStore, Role, SetupOrigin};

#[cfg(feature = "paid-client")]
pub(crate) use crate::test_identity::enrollment;
#[cfg(feature = "paid-client")]
use iroh::EndpointId;

pub(crate) const PRICE: u64 = 10;
pub(crate) const BODY: &[u8] = br#"{"input":"sdk-private-request"}"#;
const HORIZON: u64 = 500;
const OMISSION_BOND: u64 = 601;

pub(crate) struct PaidFixture {
    pub root: tempfile::TempDir,
    pub ready: ReadyChannel,
    pub descriptor: WorkChannelDescriptor,
    pub config: WorkConfig,
    pub proposal: hellas_rpc::protocol::work_bundle::WorkChannelSetupBundleV1,
}

pub(crate) fn signer(byte: u8) -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([byte; 32]).unwrap()
}

impl PaidFixture {
    pub fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let network = NetworkId::new("sdk-paid-test").unwrap();
        let payment_id = EdgeId::from_bytes([12; 32]);
        let values = EdgeValues::new(1000, 200, Fees::ZERO);
        let channel_policy = PaidChannelPolicyV1 {
            compute_credit_limit: 40,
            delivery_credit_limit: 40,
        };
        let route = FetchRoutePolicy::sealed_route("openai", "responses").unwrap();
        let work_policy = WorkPolicy::Fetch {
            policy: FetchPolicyV2 {
                allowed_environment: FetchEnvironment::OpenAiResponses.manifest_id(),
                route_commitment: fetch_route_commitment(&route.canonical_body_bytes()).unwrap(),
                max_request_body_bytes: 4096,
                max_output_events: 64,
                max_output_bytes: 16384,
                max_spool_bytes: 65536,
                max_encoded_result_frame: 65536,
                max_encoded_prepared_input: 65536,
            },
            route,
        };
        let bond_terms = WorkStakeBondTerms {
            parties: Parties::new(signer(2).party_key(), signer(1).party_key()),
            timeout: BlockHeight::new(HORIZON),
            timeout_outputs: List::take(
                [Payout::new(signer(2).party_key(), 64); MAX_EDGE_OUTPUTS],
                1,
            ),
            max_job_price: 40,
        };
        let funding = hellas_kernel::Funding::new(
            List::take(
                [hellas_kernel::CoinId::from_bytes([11; 32]); hellas_kernel::MAX_PARTY_INPUTS],
                1,
            ),
            List::empty(hellas_kernel::CoinId::from_bytes([0; 32])),
        );
        let hash = hellas_kernel::Tx::open_hash(
            network,
            &funding,
            &Terms::work_stake_bond(bond_terms.clone()),
        );
        let proposal = hellas_rpc::protocol::work_bundle::WorkChannelSetupBundleV1::propose_bond(
            network,
            funding,
            bond_terms.clone(),
            hellas_kernel::Auth::native(signer(2).sign(hash)),
        )
        .unwrap();
        let bond_id = proposal.bond_edge();
        let terms = WorkPaymentTerms {
            bond_edge: bond_id,
            bond_terms: bond_terms.clone(),
            private_policy_commitment: private_policy_commitment(
                network,
                &[9; 32],
                &channel_policy,
            ),
            omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
            start_validity_blocks: 8,
            omission_bond: OMISSION_BOND,
        };
        let descriptor = WorkChannelDescriptor::open(WorkChannelConfig {
            payment_policy: payment_policy(),
            network,
            payment_edge: payment_id,
            payment_terms: terms.clone(),
            policy_salt: [9; 32],
            channel_policy,
            work_policy: work_policy.clone(),
            expected_payment_values: values,
        })
        .unwrap();
        let bond = edge(
            64,
            0,
            signer(2).party_key(),
            signer(1).party_key(),
            Terms::work_stake_bond(bond_terms).hash(),
            0b10,
        );
        let payment = edge(
            1000,
            200,
            signer(1).party_key(),
            signer(2).party_key(),
            payment_terms_hash(terms.clone()),
            0b11000,
        );
        let mut lease = vec![1, 31, 2];
        lease.extend_from_slice(&bond_id.to_bytes());
        lease.extend_from_slice(&payment_id.to_bytes());
        lease.extend_from_slice(payment_terms_hash(terms.clone()).as_bytes());
        lease.extend_from_slice(&terms.private_policy_commitment);
        lease.extend_from_slice(&HORIZON.to_be_bytes());
        let lease = hellas_kernel::parse_bond_lease(
            [0, 1].map(|index| {
                RegistryChunk::split(
                    RegistryNamespace::BondLease,
                    RegistryRecordTag::BondLease,
                    &lease,
                    index,
                )
            }),
            bond_id,
        );
        assert!(matches!(lease, LeaseSlots::Present(_)));
        let ready = descriptor
            .check_ready(&ObservedChannel {
                height: 1,
                bond: Some(&bond),
                payment: Some(&payment),
                lease,
                pending: PendingSlot::Absent,
            })
            .unwrap();
        let config = WorkConfig {
        payment_policy: payment_policy(),
            chain: ChainCrossCheck { network, genesis_payload_digest: [0; 32].into(), threshold_identity: hex::decode("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb").unwrap() },
            validators: vec!["ws://unused.invalid".to_owned()], journal_root: root.path().join("provider"), routes: Default::default(),
            policy_salt: [9; 32], channel_policy, work_policy,
            poll: std::time::Duration::from_millis(10), max_observation_age: std::time::Duration::from_secs(60),
            expected_payment_values: values, min_omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        };
        Self {
            root,
            ready,
            descriptor,
            config,
            proposal,
        }
    }

    pub fn store(&self, role: Role) -> ChannelStore {
        let name = if role == Role::Client {
            "client"
        } else {
            "provider"
        };
        ChannelStore::open_metadata_only(
            &self.root.path().join(name),
            self.ready.channel().clone(),
            work_payment_settlement(self.config.expected_payment_values, OMISSION_BOND).unwrap(),
            role,
            SetupOrigin {
                payment_edge: self.ready.channel().payment_edge(),
                height: 1,
                payload: [1; 32],
                parent: [0; 32],
            },
            &Secp256k1Verifier::new(),
        )
        .unwrap()
    }

    pub fn client(&self) -> ClientEndpoint {
        ClientEndpoint::new(self.ready.clone(), self.store(Role::Client), signer(1)).unwrap()
    }

    pub fn provider(&self) -> WorkService {
        WorkService::new(
            ProviderEndpoint::new(self.ready.clone(), self.store(Role::Provider), signer(2))
                .unwrap(),
        )
    }

    pub fn proposal(&self) -> JobProposal {
        let events = hellas_rpc::fetch::build_input_events_with_retention(
            "openai",
            "responses",
            BODY,
            FetchEnvironment::OpenAiResponses.manifest_id(),
            Assurance::ProducerSigned,
            &ProducerSigningKey::from_secret_bytes([1; 32]).unwrap(),
            Retention::Ephemeral,
        )
        .unwrap();
        JobProposal {
            prepared_input: PreparedPaidFetchInputV1::new(
                &events,
                &FetchEnvironment::OpenAiResponses.manifest(),
            )
            .unwrap()
            .into(),
            deadlines: JobDeadlines {
                acceptance: 50,
                terminal: 100,
                payment: 200,
            },
        }
    }
}

fn edge(value: u64, reserve: u64, maker: Key, taker: Key, terms: TermsHash, allowed: u8) -> Edge {
    // Canonical kernel edges, including their close permissions.
    let mut bytes = vec![1, 5];
    bytes.extend_from_slice(&value.to_be_bytes());
    bytes.extend_from_slice(&reserve.to_be_bytes());
    bytes.extend_from_slice(&[1, 2]);
    bytes.extend_from_slice(&[0; 32]);
    bytes.extend_from_slice(&[1, 1]);
    bytes.extend_from_slice(&HORIZON.to_be_bytes());
    bytes.extend_from_slice(&[1, 3]);
    bytes.extend_from_slice(&maker.to_bytes());
    bytes.extend_from_slice(&taker.to_bytes());
    bytes.extend_from_slice(terms.as_bytes());
    bytes.push(allowed);
    Edge::decode_exact(&bytes).unwrap()
}

fn payment_policy() -> hellas_rpc::protocol::work::JobPaymentPolicyV2 {
    hellas_rpc::protocol::work::JobPaymentPolicyV2 {
        fixed_price: PRICE,
        dispatch_margin_blocks: 4,
        delivery_margin_blocks: 2,
        oracle_grace_blocks: 6,
    }
}

#[cfg(feature = "paid-client")]
pub(crate) fn provider_trust(peer: EndpointId) -> hellas_client::ProviderTrustAnchor {
    hellas_client::ProviderTrustAnchor {
        expected_genesis: enrollment(peer).0.content_id(),
        required_assurance: Assurance::ProducerSigned,
        apple_app_attest: None,
    }
}
