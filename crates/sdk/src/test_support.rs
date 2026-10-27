//! A funded, metadata-only Fetch channel for SDK boundary tests.
// Client and provider feature suites use different parts of this fixture.
pub(crate) use crate::provider::tests::host::{Host, RemoteHost, provider_enrollment};
use crate::work_config::{ChainCrossCheck, WorkConfig};
use hellas_auth::ProducerSigningKey;
use hellas_channel::model::setup::{
    ObservedChannel, ReadyChannel, WorkChannelConfig, WorkChannelDescriptor, payment_terms_hash,
};
use hellas_channel::model::work::{JobDeadlines, PaidChannelPolicyV1, private_policy_commitment};
use hellas_channel::work::{ClientEndpoint, JobProposal, ProviderEndpoint, WorkService};
use hellas_channel::work_store::{ChannelStore, Role, SetupOrigin};
use hellas_kernel::{
    BlockHeight, Decode as _, Edge, EdgeId, EdgeValues, Fees, Key, LeaseSlots, List,
    MAX_EDGE_OUTPUTS, NetworkId, Parties, PartyKeys, Payout, PendingSlot, RegistryChunk,
    RegistryNamespace, RegistryRecordTag, Secp256k1Signer, Secp256k1Verifier, Terms, TermsHash,
    WorkPaymentTerms, WorkStakeBondTerms, work_payment_settlement,
};
use hellas_rpc::protocol::invocation::fetch::{FetchAdmission, FetchLimits, FetchRoutePolicy};
use hellas_rpc::protocol::invocation::{Admission, InvocationPolicy, Limits};
use hellas_rpc::{Assurance, Retention};

pub(crate) use crate::test_identity::enrollment;

pub(crate) async fn authority(
    root: &std::path::Path,
    enrollment: hellas_rpc::ProviderEnrollmentBundle,
) -> hellas_authority::node::NodeCoordinator {
    let now = hellas_auth::authority::UnixMillis(1);
    let store = crate::test_node::bootstrap_node(
        root,
        hellas_authority::model::grant::grant_network(),
        Some(enrollment),
        now,
    )
    .await
    .unwrap();
    hellas_authority::node::NodeCoordinator::new(store, std::sync::Arc::new(move || now))
}

pub(crate) const PRICE: u64 = 10;

pub(crate) async fn application_profile(
    node: &hellas_authority::node::NodeCoordinator,
    administrator: &hellas_auth::authority::CredentialSecret,
    subject: hellas_auth::authority::PrincipalId,
    allowance: hellas_auth::authority::GrantId,
) -> std::sync::Arc<crate::node_control::profile::ClientProfile> {
    let credential =
        crate::test_node::execution_credential(node, administrator, subject, allowance).await;
    let caller = hellas_authority::test_support::session(node, administrator).await;
    std::sync::Arc::new(crate::node_control::profile::ClientProfile {
        authority: caller.authority(),
        authorization: crate::test_node::EXECUTION_AUTHORIZATION,
        credential,
        local: None,
    })
}
pub(crate) const BODY: &[u8] =
    br#"{"model":"fixture","input":"sdk-private-request","max_output_tokens":8}"#;
const HORIZON: u64 = 500;
const OMISSION_BOND: u64 = 601;

pub(crate) struct PaidFixture {
    pub root: tempfile::TempDir,
    pub ready: ReadyChannel,
    pub descriptor: WorkChannelDescriptor,
    pub config: WorkConfig,
    pub policy: hellas_channel::model::setup::ProviderChannelPolicy,
    pub proposal: hellas_channel::model::bundle::WorkChannelSetupBundleV2,
}

pub(crate) fn signer(byte: u8) -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([byte; 32]).unwrap()
}

impl PaidFixture {
    /// A real idle node for SDK startup/admission tests. The fixture supplies
    /// genesis itself; no network endpoint is trusted to choose its execution inputs.
    pub async fn node(&mut self) -> crate::FullNode {
        use commonware_codec::DecodeExt as _;
        use commonware_cryptography::Digestible as _;
        use commonware_runtime::Runner as _;
        let mut genesis: hellas_chain::genesis::Genesis =
            serde_json::from_str(hellas_chain::genesis::HELLAS_DEVNET_1_JSON).unwrap();
        genesis.network_id = self.config.chain.network.as_str().into();
        genesis.allocations.clear();
        let leader = genesis
            .validators
            .iter()
            .map(|validator| {
                hellas_chain::domain::PublicKey::decode(
                    hex::decode(&validator.public_key).unwrap().as_slice(),
                )
                .unwrap()
            })
            .min()
            .unwrap();
        let directory = self.root.path().join("genesis-probe");
        let network = self.config.chain.network;
        let genesis_document = hellas_chain::genesis_digest(&genesis);
        let digest = tokio::task::spawn_blocking(move || {
            let runtime = commonware_runtime::tokio::Runner::new(
                commonware_runtime::tokio::Config::new().with_storage_directory(directory),
            );
            runtime.start(move |context| async move {
                let application = hellas_chain::Application::new(
                    context,
                    network,
                    genesis_document,
                    leader,
                    vec![],
                    "fixture",
                    Default::default(),
                )
                .await;
                application.genesis_block().digest()
            })
        })
        .await
        .unwrap();
        self.config.chain.genesis = Some(genesis);
        self.config.chain.genesis_payload_digest = digest.0.into();
        let mut config = self
            .config
            .node_config(self.root.path().join("chain"), None)
            .unwrap();
        config.validators.clear();
        crate::FullNode::start(config).await.unwrap()
    }

    pub fn new() -> Self {
        Self::on_network(NetworkId::new("sdk-paid-test").unwrap())
    }

    pub fn on_network(network: NetworkId) -> Self {
        let root = tempfile::tempdir().unwrap();
        let payment_id = EdgeId::from_bytes([12; 32]);
        let values = EdgeValues::new(1000, 200, Fees::ZERO);
        let channel_policy = PaidChannelPolicyV1 {
            compute_credit_limit: 40,
            delivery_credit_limit: 40,
        };
        let work_policy = work_policy();
        let bond_terms = WorkStakeBondTerms {
            parties: Parties::new(
                PartyKeys::sole(signer(2).party_key()),
                PartyKeys::sole(signer(1).party_key()),
            ),
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
        let proposal = hellas_channel::model::bundle::WorkChannelSetupBundleV2::propose_bond(
            network,
            funding,
            bond_terms.clone(),
            hellas_kernel::PartyAuth::signer(hellas_kernel::Auth::native(signer(2).sign(hash))),
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
            invocation_policy: work_policy.clone(),
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
        let policy = hellas_channel::model::setup::ProviderChannelPolicy {
            payment_policy: payment_policy(),
            network,
            policy_salt: [9; 32],
            channel_policy,
            invocation_policy: work_policy,
            expected_payment_values: values,
            min_omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        };
        let config = WorkConfig {
            chain: ChainCrossCheck { network, genesis: None, genesis_payload_digest: [0; 32].into(), threshold_identity: hex::decode("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb").unwrap() },
            validators: vec!["ws://unused.invalid".to_owned()], journal_root: root.path().join("provider"),
            poll: std::time::Duration::from_millis(10), max_observation_age: std::time::Duration::from_secs(60),
        };
        Self {
            root,
            ready,
            descriptor,
            config,
            policy,
            proposal,
        }
    }

    pub async fn store(&self, role: Role) -> ChannelStore {
        let name = if role == Role::Client {
            "client"
        } else {
            "provider"
        };
        ChannelStore::open(
            &self.root.path().join(name),
            self.ready.channel().clone(),
            work_payment_settlement(self.policy.expected_payment_values, OMISSION_BOND).unwrap(),
            role,
            SetupOrigin {
                payment_edge: self.ready.channel().payment_edge(),
                height: 1,
                payload: [1; 32],
                parent: [0; 32],
            },
            hellas_store::ContentStore::new(),
            &Secp256k1Verifier::new(),
        )
        .await
        .unwrap()
    }

    pub async fn client(&self) -> ClientEndpoint {
        ClientEndpoint::new(
            self.ready.clone(),
            self.store(Role::Client).await,
            signer(1),
        )
        .unwrap()
    }

    pub async fn provider(&self) -> WorkService {
        WorkService::new(
            ProviderEndpoint::new(
                self.ready.clone(),
                self.store(Role::Provider).await,
                signer(2),
            )
            .unwrap(),
        )
    }

    pub fn proposal(&self) -> JobProposal {
        let events = hellas_rpc::fetch::build_input_events_with_retention(
            "openai",
            "responses",
            BODY,
            test_responses_contract().manifest_id(),
            Assurance::ProducerSigned,
            &ProducerSigningKey::from_secret_bytes([1; 32]).unwrap(),
            Retention::Ephemeral,
        )
        .unwrap();
        JobProposal {
            prepared_input: hellas_rpc::protocol::invocation::fetch::prepare(
                &events,
                &test_responses_contract(),
                ProducerSigningKey::from_secret_bytes([2; 32])
                    .unwrap()
                    .public_key(),
                work_policy().canonical_bytes().unwrap(),
                [1; 32],
            )
            .unwrap(),
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
    // Each party: owner, signer, and an absent payout delegate.
    for party in [maker, taker] {
        bytes.extend_from_slice(&party.to_bytes());
        bytes.extend_from_slice(&party.to_bytes());
        bytes.push(0);
    }
    bytes.extend_from_slice(terms.as_bytes());
    bytes.push(allowed);
    Edge::decode_exact(&bytes).unwrap()
}

/// The metadata-only Fetch policy this fixture's channel admits.
pub(crate) fn work_policy() -> InvocationPolicy {
    InvocationPolicy {
        admissions: vec![Admission::Fetch {
            admission: FetchAdmission {
                contract: test_responses_contract(),
                route: FetchRoutePolicy::sealed_route("openai", "responses").unwrap(),
                limits: FetchLimits {
                    max_request_body_bytes: 4096,
                    max_output_events: 64,
                    max_spool_bytes: 65536,
                    max_encoded_result_frame: 65536,
                    max_encoded_prepared_input: 65536,
                },
            },
        }],
        limits: Limits {
            max_upload_bytes: 65536,
            max_output_bytes: 16384,
            max_steps: 1,
            execution_timeout_ms: 60_000,
        },
    }
}

fn payment_policy() -> hellas_channel::model::work::JobPaymentPolicyV2 {
    hellas_channel::model::work::JobPaymentPolicyV2 {
        fixed_price: PRICE,
        dispatch_margin_blocks: 4,
        delivery_margin_blocks: 2,
        oracle_grace_blocks: 6,
    }
}

use hellas_channel::test_support::test_responses_contract;
