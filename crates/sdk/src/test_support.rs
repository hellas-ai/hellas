//! A funded, metadata-only Fetch channel for SDK boundary tests.
use hellas_private::Durability::Crash;
use hellas_private::StoreLocation;
// Client and provider feature suites use different parts of this fixture.
pub(crate) use crate::provider::tests::host::{Host, RemoteHost, provider_enrollment};
use crate::work_config::WorkConfig;
use hellas_auth::ProducerSigningKey;
use hellas_chain::genesis::{ChainProfile, CustomChainFile};

pub(crate) fn chain_dir(
    home: &std::path::Path,
    network: NetworkId,
) -> hellas_chain::chain_dir::ChainDir {
    let known = ChainProfile::known(hellas_chain::genesis::Chain::Devnet);
    if network.as_str() == known.network_id() {
        return hellas_chain::chain_dir::ChainDir::open(
            &StoreLocation::from_home(home, Crash),
            &known,
        )
        .unwrap();
    }
    let mut genesis = known.genesis().clone();
    genesis.network_id = network.as_str().into();
    chain_dir_with_genesis(home, &genesis)
}

pub(crate) fn chain_dir_with_genesis(
    home: &std::path::Path,
    genesis: &hellas_chain::genesis::Genesis,
) -> hellas_chain::chain_dir::ChainDir {
    use commonware_cryptography::{Hasher as _, Sha256};
    let known = ChainProfile::known(hellas_chain::genesis::Chain::Devnet);
    let genesis_json = serde_json::to_string(genesis).unwrap();
    let mut trust = known.trust().clone();
    trust.network_id = genesis.network_id.clone();
    trust.genesis_sha256 = hex::encode(Sha256::hash(genesis_json.as_bytes()));
    let profile = ChainProfile::custom(CustomChainFile {
        trust,
        validators: vec!["ws://unused.invalid".into()],
        genesis_json,
    })
    .unwrap();
    hellas_chain::chain_dir::ChainDir::open(&StoreLocation::from_home(home, Crash), &profile)
        .unwrap()
}

#[cfg(all(test, feature = "integration-tests"))]
pub(crate) fn chain_dir_with_variant(
    home: &std::path::Path,
    network: NetworkId,
    variant: u64,
) -> hellas_chain::chain_dir::ChainDir {
    let known = ChainProfile::known(hellas_chain::genesis::Chain::Devnet);
    let mut genesis = known.genesis().clone();
    genesis.network_id = network.as_str().into();
    genesis.allocations[0].balance += variant;
    chain_dir_with_genesis(home, &genesis)
}
use hellas_channel::model::setup::{
    ObservedChannel, ReadyChannel, WorkChannelConfig, WorkChannelDescriptor, payment_terms_hash,
};
use hellas_channel::model::work::{JobDeadlines, PaidChannelPolicyV1, private_policy_commitment};
use hellas_channel::work::{
    ClientEndpoint, ClientService, JobProposal, ProviderEndpoint, WorkService,
};
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

pub(crate) use crate::test_identity::{address, enrollment};

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
    /// The fixture's live bond, payment edge and lease, as a certified
    /// read shows them.
    pub bond: Edge,
    pub payment: Edge,
    pub lease: LeaseSlots,
    pub descriptor: WorkChannelDescriptor,
    pub config: WorkConfig,
    pub policy: hellas_channel::model::setup::ProviderChannelPolicy,
    pub proposal: hellas_channel::model::bundle::WorkChannelSetupBundleV2,
}

pub(crate) fn signer(byte: u8) -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([byte; 32]).unwrap()
}

impl PaidFixture {
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
            .check_ready(&observed(1, &bond, &payment, lease, PendingSlot::Absent))
            .unwrap();
        let policy = hellas_channel::model::setup::ProviderChannelPolicy {
            payment_policy: payment_policy(),
            network,
            policy_salt: [9; 32],
            channel_policy,
            invocation_policy: work_policy,
            expected_payment_values: values,
        };
        let config = WorkConfig {
            chain: chain_dir(root.path(), network),
        };
        Self {
            root,
            ready,
            bond,
            payment,
            lease,
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
        let root = self.root.path().join(name);
        let location = StoreLocation::for_test(&root);
        let content = hellas_channel::test_support::channel::content_store(&root).await;
        let store = ChannelStore::open(
            &location,
            self.ready.channel().clone(),
            work_payment_settlement(self.policy.expected_payment_values, OMISSION_BOND).unwrap(),
            role,
            SetupOrigin {
                payment_edge: self.ready.channel().payment_edge(),
                height: 1,
                payload: hellas_channel::test_support::channel::payload_at(1),
            },
            content.clone(),
            &Secp256k1Verifier::new(),
        )
        .await
        .unwrap();
        let mut store = store;
        if store.state().certified_at_ms() == 0 {
            hellas_channel::work_close::observe(
                &mut store,
                &self.observed(1, PendingSlot::Absent),
                &Secp256k1Verifier::new(),
            )
            .await
            .unwrap();
        }
        content.finish_recovery().await.unwrap();
        store
    }

    /// One fresh certified read of the fixture channel at `height`.
    pub fn observed(&self, height: u64, pending: PendingSlot) -> ObservedChannel<'_> {
        observed(height, &self.bond, &self.payment, self.lease, pending)
    }

    pub async fn client(&self) -> ClientService {
        hellas_channel::test_support::channel::client_service(
            ClientEndpoint::new(
                self.ready.clone(),
                self.store(Role::Client).await,
                signer(1),
            )
            .unwrap(),
            self.ready.clone(),
        )
        .await
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

fn observed<'a>(
    height: u64,
    bond: &'a Edge,
    payment: &'a Edge,
    lease: LeaseSlots,
    pending: PendingSlot,
) -> ObservedChannel<'a> {
    ObservedChannel {
        height,
        payload: hellas_channel::test_support::channel::payload_at(height),
        certified_at_ms: hellas_channel::test_support::channel::now_ms(),
        bond: Some(bond),
        payment: Some(payment),
        lease,
        pending,
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

/// Exercise the actual generic upload path before reference-only acceptance.
pub async fn accept_uploaded(
    fixture: &PaidFixture,
    service: &hellas_channel::work::WorkService,
    client: &hellas_channel::work::ClientService,
    request: &hellas_rpc::pb::work::AcceptWorkRequest,
) -> hellas_rpc::pb::work::AcceptWorkResponse {
    let (wire, upload) = upload_paid_input(fixture, service, client, request).await;
    let response = service.accept(&wire, None).await;
    drop(upload);
    tokio::time::timeout(hellas_channel::test_support::HANG_GUARD, async {
        while service.content_upload_count().await.unwrap() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    response
}

pub async fn upload_paid_input(
    fixture: &PaidFixture,
    service: &hellas_channel::work::WorkService,
    client: &hellas_channel::work::ClientService,
    request: &hellas_rpc::pb::work::AcceptWorkRequest,
) -> (
    hellas_rpc::pb::work::AcceptWorkRequest,
    hellas_channel::work::admission::CancelOnFailure,
) {
    use hellas_channel::model::work::{
        PaidJobAuthorizationV2, PrivateRecord as _, signing_hash, work_id,
    };
    let authorization = PaidJobAuthorizationV2::decode(&request.authorization).unwrap();
    let id = work_id(fixture.ready.channel(), &authorization);
    let bytes = client
        .with_state(|state| state.job_by_id(id).unwrap().prepared_input().to_vec())
        .await
        .unwrap();
    let (wire, mut frames) = hellas_channel::test_support::channel::input_uploads(
        fixture.ready.channel(),
        request,
        &bytes,
    );
    if let Some(hellas_rpc::pb::content::upload_request::Part::Open(open)) = &mut frames[0].part {
        let opening = open.work.as_mut().unwrap();
        opening.binding_signature = signer(1)
            .sign(signing_hash(hellas_channel::job::opening_digest(
                opening, &[7; 32],
            )))
            .as_bytes()
            .to_vec();
    }
    let connection = hellas_channel::work::admission::Cancellation::new();
    let _stop = hellas_channel::work::admission::CancelOnFailure(vec![connection.clone()]);
    upload_frames(frames, async |requests| {
        service
            .upload_stream(
                requests,
                hellas_wire::TransportContext {
                    open_exporter: Some([7; 32]),
                    ..Default::default()
                },
                connection.clone(),
            )
            .await
    })
    .await
    .expect("fresh positive acceptance completes its content upload");
    (wire, _stop)
}

/// Drive one real generic stream, respecting complete-on-Open for cached objects.
pub async fn upload_frames(
    frames: Vec<hellas_rpc::pb::content::UploadRequest>,
    open: impl AsyncFnOnce(
        std::pin::Pin<
            Box<
                dyn futures::Stream<
                        Item = Result<
                            hellas_rpc::pb::content::UploadRequest,
                            hellas_wire::WireStatus,
                        >,
                    > + Send,
            >,
        >,
    ) -> Result<
        hellas_rpc::call::ResponseStream<hellas_rpc::pb::content::UploadResponse>,
        hellas_wire::WireStatus,
    >,
) -> Result<(), hellas_wire::WireStatus> {
    use futures::StreamExt as _;
    use hellas_rpc::pb::content::upload_request::Part;
    let mut frames = frames.into_iter();
    let (send, receive) = futures::channel::mpsc::unbounded();
    send.unbounded_send(Ok(frames.next().unwrap())).unwrap();
    let mut replies = open(Box::pin(receive)).await?;
    loop {
        let reply = replies.next().await.expect("one answer per sent frame")?;
        match frames.find(|frame| !reply.complete || matches!(frame.part, Some(Part::Open(_)))) {
            Some(frame) => send.unbounded_send(Ok(frame)).unwrap(),
            None => {
                drop(send);
                return hellas_channel::test_support::drive_upload(Ok(replies)).await;
            }
        }
    }
}

/// A one-backend daemon fixture; production callers supply the document's map.
pub fn gateway(
    backend: crate::Backend,
    evaluator: Option<String>,
    signer: std::sync::Arc<hellas_auth::ProducerSigningKey>,
) -> std::sync::Arc<crate::ExecutorGateway> {
    crate::ExecutorGateway::new(
        [(
            "test".into(),
            crate::BackendEntry {
                backend,
                evaluator,
                max_in_flight: std::num::NonZeroUsize::new(32).unwrap(),
            },
        )]
        .into(),
        signer,
    )
}

pub fn job() -> std::sync::Arc<hellas_gateway::jobs::Job> {
    request_job(&std::sync::Arc::new(hellas_gateway::jobs::Jobs::default()))
}
pub fn request_job(
    jobs: &std::sync::Arc<hellas_gateway::jobs::Jobs>,
) -> std::sync::Arc<hellas_gateway::jobs::Job> {
    jobs.admit(&hellas_gateway::jobs::Request {
        origin: hellas_gateway::jobs::Origin::Local,
        method: "POST".into(),
        path: "/test".into(),
    })
    .unwrap()
}

pub(crate) use hellas_gateway::test_server as server;
