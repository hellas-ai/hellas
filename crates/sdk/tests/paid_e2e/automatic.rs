use super::*;
use hellas_auth::test_support::{
    Actor,
    actors::{AGENT, OPERATOR, STRANGER},
};
use hellas_channel::model::offer::{SignedPaidOffer, request_digest};
use hellas_channel::work::{
    BackendFault, WorkBackend,
    admission::{CapacityDomain, WorkPermit},
};
use hellas_channel::work_store::{Role, SetupAbort, SetupEnd, SetupStore};
use hellas_private::StoreLocation;
use hellas_rpc::pb::work::{
    ExchangeSetupRequest, OfferRefusalCode, RequestOfferRequest, RequestOfferResponse,
    exchange_setup_response, request_offer_response::Outcome,
};
use hellas_rpc::protocol::invocation::compute::{
    Arg, Bind, Call, Declared, OutputKind, Plan, Step, StepArg, Stop, ValueKind,
};
use hellas_rpc::services::work_setup::{WorkSetup, WorkSetupServer};
use hellas_sdk::paid_client::{SessionFundingOptions, SessionOpenMode};
use hellas_sdk::paid_provider::{
    MountedSetup, MountedWork, WorkRunner, WorkRunnerConfig, WorkWatcher,
};
use hellas_sdk::work_router::WorkRouter;
use hellas_wire::{
    Dispatcher, Metadata, ServiceMarker, StreamTransport, WireStatus, iroh::IrohTransport,
};
use iroh::{Endpoint, EndpointAddr, TransportAddr, endpoint::presets};

const JOB_PRICE: u64 = 20;
const FUNDING: u64 = 401;

/// The executor's own compile child, validation and signed driver over the
/// Hex-generated scalar C ABI, built for the host instead of a GPU. Only the
/// device is a double; it counts loads, and the source it compiles is read
/// from A's content store.
#[derive(Clone, Default)]
struct HostCompute(Arc<HostComputeState>);
#[derive(Default)]
struct HostComputeState {
    permits: std::sync::OnceLock<Arc<tokio::sync::Semaphore>>,
    calls: std::sync::atomic::AtomicUsize,
    loads: std::sync::atomic::AtomicUsize,
    store: std::sync::Mutex<Option<LocalStore>>,
    pause: std::sync::atomic::AtomicBool,
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
impl HostCompute {
    fn calls(&self) -> usize {
        self.0.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn loads(&self) -> usize {
        self.0.loads.load(std::sync::atomic::Ordering::SeqCst)
    }
    async fn have(&self, object: hellas_rpc::ContentRef) -> bool {
        let store = self.0.store.lock().unwrap().clone();
        match store {
            Some(store) => store
                .open_verified(&Scope::Owner, object, None)
                .await
                .unwrap()
                .is_some(),
            None => false,
        }
    }
}
impl WorkBackend for HostCompute {
    fn try_admit(&self, domain: CapacityDomain) -> Result<WorkPermit, BackendFault> {
        if domain != CapacityDomain::Gpu {
            return Err(
                hellas_channel::work::admission::AdmissionError::Unsupported(domain).into(),
            );
        }
        let permits = self
            .0
            .permits
            .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1)));
        Ok(WorkPermit::new(
            domain,
            permits.clone().try_acquire_owned().map_err(|_| {
                BackendFault::from(hellas_channel::work::admission::AdmissionError::Capacity)
            })?,
        ))
    }
    async fn execute(
        &self,
        input: hellas_channel::work::Admitted<PreparedInvocation>,
    ) -> Result<Vec<hellas_rpc::OutputEventEnvelope>, BackendFault> {
        use hellas_executor::catena::{assets::Assets, driver, program::BoundProgram};
        let (prepared, limits, content, admission) = input.into_parts_and_admission();
        let _running = admission
            .reserve(CapacityDomain::Gpu, async {
                self.try_admit(CapacityDomain::Gpu)
            })
            .await?
            .dispatch()
            .await?;
        self.0
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        *self.0.store.lock().unwrap() = match &content.0 {
            LocalStore::Disk(store) => Some(LocalStore::Disk(store.clone())),
            _ => None,
        };
        if self.0.pause.load(std::sync::atomic::Ordering::SeqCst) {
            self.0.started.notify_one();
            self.0.release.notified().await;
        }
        let opened = BoundProgram::open(&content, &prepared, &limits)
            .await
            .map_err(|error| error.to_string());
        let state = self.0.clone();
        tokio::task::spawn_blocking(move || -> Result<_, String> {
            let dialect = hellas_executor::GpuDialect::Hip;
            let key = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
            // As the executor does: a preparation failure, an invalid plan
            // included, is a signed Failed terminal.
            let (program, mut readers) = match opened.and_then(|(environment, sources, readers)| {
                BoundProgram::compile_cancellable(
                    environment,
                    sources,
                    &prepared,
                    &limits,
                    &std::env::current_exe().unwrap(),
                    &hellas_executor::catena::Cancellation::default(),
                    dialect,
                )
                .map(|program| (program, readers))
                .map_err(|error| error.to_string())
            }) {
                Ok(program) => program,
                Err(_) => {
                    return invocation::output::OutputStream::new(
                        &prepared.request,
                        &key,
                        invocation::MAX_INVOCATION_BYTES,
                    )
                    .and_then(|stream| stream.fail(invocation::output::FailureReason::Compilation))
                    .map(|(_, events)| events)
                    .map_err(|e| e.to_string());
                }
            };
            driver::execute_signed(
                &mut HostScalarDevice::new(state),
                &program,
                &prepared,
                &limits,
                &Assets::new(0, dialect),
                &mut readers,
                &key,
                |_| Ok(()),
            )
            .map(|(_, events)| events)
            .map_err(|e| e.to_string())
        })
        .await
        .map_err(BackendFault::caused_by)?
        .map_err(|e| BackendFault::caused_by(hellas_executor::ExecutorError::Execution(e)))
    }
}

/// Compiles the generated C ABI with the host C++ compiler. The header
/// aborts on any GPU operation; there is no arithmetic model here.
struct HostScalarDevice {
    dir: tempfile::TempDir,
    library: Option<libloading::Library>,
    signatures: Vec<catena_lang::runtime::GeneratedFunction>,
    state: Arc<HostComputeState>,
}
impl HostScalarDevice {
    fn new(state: Arc<HostComputeState>) -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            library: None,
            signatures: vec![],
            state,
        }
    }
}
type DeviceResult<T> = Result<T, Box<dyn std::error::Error>>;
impl hellas_executor::catena::driver::Device for HostScalarDevice {
    fn load(
        &mut self,
        module: &catena_lang::runtime::RuntimeModule,
    ) -> DeviceResult<hellas_executor::catena::Cancellation> {
        self.state
            .loads
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = self.dir.path();
        std::fs::create_dir_all(dir.join("hip"))?;
        std::fs::write(
            dir.join("hip/hip_runtime.h"),
            "#pragma once\n#include <cstdlib>\n#define __host__\n#define __device__\nusing hipError_t = int;\nconstexpr int hipSuccess = 0;\ninline const char* hipGetErrorString(int) { std::abort(); }\ninline int hipMalloc(void**, size_t) { std::abort(); }\nstruct dim3 { unsigned x,y,z; dim3(unsigned a,unsigned b,unsigned c):x(a),y(b),z(c){} };\n",
        )?;
        std::fs::write(dir.join("module.cpp"), &module.source)?;
        let output = std::process::Command::new("c++")
            .args(["-std=c++17", "-shared", "-fPIC", "-O1", "-I"])
            .arg(dir)
            .arg(dir.join("module.cpp"))
            .arg("-o")
            .arg(dir.join("module.so"))
            .output()?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
        }
        self.library = Some(unsafe { libloading::Library::new(dir.join("module.so"))? });
        self.signatures = module.functions.clone();
        Ok(hellas_executor::catena::Cancellation::default())
    }
    fn call(
        &mut self,
        entry: &str,
        args: Vec<catena_lang::runtime::Value<'_>>,
    ) -> DeviceResult<Vec<catena_lang::runtime::Value<'static>>> {
        use catena_lang::runtime::{Value, ValueKind};
        let signature = self
            .signatures
            .iter()
            .find(|f| f.source_name == entry)
            .ok_or("unknown entry")?;
        assert_eq!(signature.outputs, vec![ValueKind::U64]);
        let args: Vec<u64> = args
            .into_iter()
            .map(|v| match v {
                Value::U64(n) => n,
                _ => panic!("the scalar double takes u64 arguments"),
            })
            .collect();
        let lib = self.library.as_ref().unwrap();
        let symbol = signature.symbol.as_bytes();
        let mut result = 0;
        unsafe {
            match args.as_slice() {
                [] => lib.get::<unsafe extern "C" fn(*mut u64)>(symbol)?(&mut result),
                [a] => lib.get::<unsafe extern "C" fn(u64, *mut u64)>(symbol)?(*a, &mut result),
                [a, b] => lib.get::<unsafe extern "C" fn(u64, u64, *mut u64)>(symbol)?(
                    *a,
                    *b,
                    &mut result,
                ),
                _ => return Err("unsupported scalar arity".into()),
            }
        }
        Ok(vec![Value::U64(result)])
    }
}

/// Only the device is a double. Setup, Work, journals, clocks and owner
/// signatures use the native services and the six-validator chain.
fn composition_policies() -> Vec<hellas_authority::model::grant::records::GrantPolicy> {
    let mut compute = hellas_authority::test_support::compute::Compute.policy();
    compute.resource = auth::ResourceId(Digest::hash(b"composition compute"));
    let mut http = hellas_authority::test_support::definition(
        auth::GrantId([71; 16]),
        hellas_channel::test_support::principal(1).0,
    )
    .policies
    .remove(0);
    http.name = "http".into();
    let mut template = hellas_authority::test_support::chat_resource("https://provider.fixture", 4);
    template.accounting = hellas_authority::model::grant::resource::AccountingProfile::None;
    hellas_authority::test_support::use_https(&mut http, template);
    vec![compute, http]
}

struct Provider {
    enrollment: hellas_rpc::ProviderEnrollmentBundle,
    funded_held: Arc<std::sync::atomic::AtomicBool>,
    offer_held: Arc<std::sync::atomic::AtomicBool>,
    unavailable: Arc<std::sync::atomic::AtomicUsize>,
    funding_refusal: Arc<std::sync::atomic::AtomicUsize>,
    funding_requests: Arc<std::sync::Mutex<Vec<RequestOfferRequest>>>,
    endpoint: Endpoint,
    clock: WorkWatcher,
    serving: tokio::task::JoinHandle<()>,
    admin: hellas_authority::grant_service::WorkAdministration,
    grants: hellas_authority::grant_service::GrantService,
    compute: HostCompute,
    content: hellas_store::content::DiskStore,
}

#[derive(Clone)]
struct RecoveringSetup {
    inner: MountedSetup,
    funded_held: Arc<std::sync::atomic::AtomicBool>,
    offer_held: Arc<std::sync::atomic::AtomicBool>,
    unavailable: Arc<std::sync::atomic::AtomicUsize>,
    funding_refusal: Arc<std::sync::atomic::AtomicUsize>,
    funding_requests: Arc<std::sync::Mutex<Vec<RequestOfferRequest>>>,
}

impl hellas_rpc::services::work_setup::WorkSetupHandler for RecoveringSetup {
    async fn request_offer(
        &self,
        request: RequestOfferRequest,
        context: hellas_wire::TransportContext,
    ) -> Result<impl Into<hellas_rpc::call::WithTrailer<RequestOfferResponse>> + Send, WireStatus>
    {
        if self.offer_held.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(WireStatus::new(
                hellas_wire::WireCode::Unavailable,
                "held offer response",
            ));
        }
        if !request.funding_coins.is_empty() {
            if self.funded_held.load(std::sync::atomic::Ordering::SeqCst) {
                self.unavailable
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                return Err(WireStatus::new(
                    hellas_wire::WireCode::Unavailable,
                    "held funded-offer read",
                ));
            }
            let step = self
                .funding_refusal
                .load(std::sync::atomic::Ordering::SeqCst);
            if step != 0 {
                self.funding_requests.lock().unwrap().push(request.clone());
                if step == 1 {
                    self.funding_refusal
                        .store(2, std::sync::atomic::Ordering::SeqCst);
                    return Ok(RequestOfferResponse {
                        outcome: Some(
                            hellas_rpc::pb::work::request_offer_response::Outcome::Refused(
                                hellas_rpc::pb::work::OfferRefused {
                                    code: OfferRefusalCode::NeedsFunding as i32,
                                    required: FUNDING,
                                },
                            ),
                        ),
                    }
                    .into());
                }
                self.funding_refusal
                    .store(0, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let result = self.inner.request_offer(request, context).await;
        if result
            .as_ref()
            .is_err_and(|status| status.code() == hellas_wire::WireCode::Unavailable)
        {
            self.unavailable
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        result.map(Into::<hellas_rpc::call::WithTrailer<RequestOfferResponse>>::into)
    }

    async fn exchange_setup(
        &self,
        request: ExchangeSetupRequest,
        context: hellas_wire::TransportContext,
    ) -> Result<
        impl Into<hellas_rpc::call::WithTrailer<hellas_rpc::pb::work::ExchangeSetupResponse>> + Send,
        WireStatus,
    > {
        self.inner.exchange_setup(request, context).await
    }
}
impl Provider {
    fn start<'a>(
        root: &'a std::path::Path,
        config: WorkConfig,
        compute: HostCompute,
        identity: NodeIdentity,
        port: u16,
    ) -> impl std::future::Future<Output = Self> + 'a {
        Box::pin(Self::start_inner(root, config, compute, identity, port))
    }

    async fn start_inner(
        root: &std::path::Path,
        config: WorkConfig,
        compute: HostCompute,
        identity: NodeIdentity,
        port: u16,
    ) -> Self {
        let enrollment = provider_enrollment(&identity);
        let location = StoreLocation::for_test(&root.join("authority"));
        let store = NodeStore::open(
            &location,
            hellas_authority::model::grant::grant_network(),
            Some(enrollment.clone()),
            UnixMillis(1),
        )
        .await
        .unwrap();
        let authority =
            NodeCoordinator::new(store, Arc::new(|| UnixMillis::now().unwrap_or_default()));
        let key = Arc::new(ProducerSigningKey::from_secret_bytes([2; 32]).unwrap());
        let content = hellas_channel::test_support::channel::content_store(root).await;
        let grants = hellas_authority::grant_service::GrantService::from_node(
            authority.clone(),
            &enrollment,
            key.clone(),
            hellas_channel::test_support::backend::Backend {
                signer: key.clone(),
                finish: hellas_channel::test_support::backend::Completion::Immediate,
                reply: hellas_channel::test_support::backend::Reply::events(
                    hellas_channel::test_support::backend::Reply::http(
                        200,
                        "application/json",
                        "{}",
                    ),
                ),
                ..Default::default()
            },
            vec![],
            content.clone(),
        )
        .await
        .unwrap();
        let admin = hellas_authority::grant_service::WorkAdministration::new(
            grants.clone(),
            hellas_authority::test_support::common_node::configuration(composition_policies()),
            std::num::NonZeroU64::new(5000).unwrap(),
        );
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(identity.transport_key())
            .alpns(vec![
                WorkSetup::ALPN.as_bytes().to_vec(),
                hellas_rpc::services::work::Work::ALPN.as_bytes().to_vec(),
            ])
            // One socket, kept across restarts: a client dialing this identity
            // again retains its earlier paths, and a path to a released port
            // can reach an unrelated endpoint that bound it since.
            .clear_ip_transports()
            .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
            .unwrap()
            .bind()
            .await
            .unwrap();
        let setup = MountedSetup::with_content_store(content.clone());
        let work = MountedWork::with_backend(compute.clone());
        let runner = WorkRunner::discover(
            WorkRunnerConfig {
                chain: config.chain.clone(),
                settlement_key: provider_settlement(),
            },
            work.clone(),
            setup.clone(),
        )
        .await
        .unwrap()
        .on_chain(
            config.clone(),
            authority,
            enrollment.clone(),
            endpoint
                .bound_sockets()
                .iter()
                .map(ToString::to_string)
                .collect(),
        );
        content.finish_recovery().await.unwrap();
        let clock = WorkWatcher::spawn(runner);
        let funded_held = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let offer_held = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let unavailable = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let funding_refusal = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let funding_requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let setup = RecoveringSetup {
            inner: setup,
            funded_held: funded_held.clone(),
            offer_held: offer_held.clone(),
            unavailable: unavailable.clone(),
            funding_refusal: funding_refusal.clone(),
            funding_requests: funding_requests.clone(),
        };
        let router = WorkRouter::both(work, grants.clone());
        let open = Arc::new(
            hellas_sdk::ProviderOpen::<ProducerSigningKey>::new(key, enrollment.clone(), None)
                .unwrap(),
        );
        let server = endpoint.clone();
        let serving = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Some(incoming) = server.accept().await {
                let setup = setup.clone();
                let router = router.clone();
                let open = open.clone();
                connections.spawn(async move {
                    let connection = incoming.await.unwrap();
                    let is_setup = connection.alpn() == WorkSetup::ALPN.as_bytes();
                    let transport = IrohTransport::new(connection);
                    if is_setup {
                        let dispatcher =
                            hellas_rpc::open::OpenDispatcher::<
                                _,
                                _,
                                hellas_rpc::services::work_setup::Open,
                            >::new(WorkSetupServer(setup), open);
                        while let Ok(Some(inbound)) = transport.accept().await {
                            if let Err(error) =
                                Dispatcher::<IrohTransport>::dispatch(&dispatcher, inbound).await
                            {
                                eprintln!("fixture WorkSetup dispatch failed: {error}");
                            }
                        }
                    } else {
                        let Ok(dispatcher) = router.accept_iroh(&transport, open).await else {
                            return;
                        };
                        while let Ok(Some(inbound)) = transport.accept().await {
                            if let Err(error) = dispatcher.dispatch(inbound).await {
                                eprintln!("fixture Work dispatch failed: {error}");
                            }
                        }
                    }
                });
            }
            while let Some(result) = connections.join_next().await {
                result.unwrap();
            }
        });
        Self {
            enrollment,
            funded_held,
            offer_held,
            unavailable,
            funding_refusal,
            funding_requests,
            endpoint,
            clock,
            serving,
            admin,
            grants,
            compute,
            content,
        }
    }
    async fn policy(
        &self,
        secret: &auth::CredentialSecret,
        revision: u64,
        policy: hellas_channel::model::paid_policy::PaidPolicy,
    ) {
        let node = self.admin.node();
        let caller = hellas_authority::test_support::session(&node, secret).await;
        self.admin
            .execute(
                &caller,
                auth::GrantId([0; 16]),
                hellas_authority::model::grant::admin::WorkControlCommand::SetPaidPolicy {
                    expected_revision: auth::Revision(revision),
                    policy: Box::new(policy),
                },
            )
            .await
            .unwrap();
    }
    fn port(&self) -> u16 {
        self.endpoint.bound_sockets()[0].port()
    }
    fn addr(&self) -> EndpointAddr {
        EndpointAddr::from_parts(
            self.endpoint.id(),
            self.endpoint
                .bound_sockets()
                .into_iter()
                .map(TransportAddr::Ip),
        )
    }
    async fn shutdown(mut self) {
        self.endpoint.close().await;
        tokio::time::timeout(Duration::from_secs(30), self.clock.shutdown())
            .await
            .unwrap()
            .unwrap();
        self.serving.await.unwrap();
        self.content.close().await;
    }
}

async fn connect_offer(client: &Endpoint, provider: &Provider) -> IrohTransport {
    let connection = client
        .connect(provider.addr(), WorkSetup::ALPN.as_bytes())
        .await
        .unwrap();
    let transport = IrohTransport::new(connection);
    let trust = hellas_client::ProviderAddress::of(&provider.enrollment)
        .unwrap()
        .trust(Assurance::ProducerSigned, None)
        .unwrap();
    hellas_client::confidential_open::<hellas_rpc::services::work_setup::Open>(&transport, &trust)
        .await
        .unwrap();
    transport
}

async fn request(
    client: &Endpoint,
    provider: &Provider,
    network: hellas_kernel::NetworkId,
    owner: Actor,
    key: &Secp256k1Signer,
    coins: &[CoinId],
    mutation: Option<&str>,
) -> Result<RequestOfferResponse, WireStatus> {
    let transport = connect_offer(client, provider).await;
    let mut request = RequestOfferRequest {
        client_principal: owner.principal().as_bytes().to_vec(),
        client_key: key.party_key().to_bytes().to_vec(),
        funding_coins: coins.iter().map(|c| c.to_bytes().to_vec()).collect(),
        signature: vec![],
    };
    let mut exporter = transport.context().open_exporter.unwrap();
    if mutation == Some("exporter") {
        exporter[0] ^= 1;
    }
    let signed_network = if mutation == Some("network") {
        hellas_kernel::NetworkId::new("wrong-network").unwrap()
    } else {
        network
    };
    let genesis = if mutation == Some("provider") {
        ContentId::from_bytes([7; 32])
    } else {
        provider.enrollment.content_id()
    };
    let hash = request_digest(signed_network, genesis, &request, &exporter);
    request.signature = key
        .sign(hellas_kernel::PayloadHash::from_bytes(*hash.as_bytes()))
        .as_bytes()
        .to_vec();
    match mutation {
        Some("principal") => request.client_principal = ROOT.principal().as_bytes().to_vec(),
        Some("key") => request.client_key = provider_settlement().party_key().to_bytes().to_vec(),
        Some("coin") => request.funding_coins[0][0] ^= 1,
        Some("signature") => request.signature[0] ^= 1,
        _ => {}
    }
    hellas_rpc::call::unary::<_, hellas_rpc::services::work_setup::RequestOffer>(
        &transport,
        request,
        Metadata::new(),
    )
    .await
}
fn granted(response: RequestOfferResponse) -> Box<SignedPaidOffer> {
    let Some(Outcome::Granted(granted)) = response.outcome else {
        panic!("expected offer, got {response:?}")
    };
    Box::new(SignedPaidOffer::decode(&granted.offer).unwrap())
}
fn refused(response: RequestOfferResponse, code: OfferRefusalCode) {
    let Some(Outcome::Refused(refused)) = response.outcome else {
        panic!("expected refusal, got {response:?}")
    };
    assert_eq!(refused.code, code as i32);
}
fn files(root: &std::path::Path) -> usize {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    entries
        .map(|entry| {
            let path = entry.unwrap().path();
            if path.is_dir() { files(&path) } else { 1 }
        })
        .sum()
}
fn revision_two(
    offer: &SignedPaidOffer,
    key: &Secp256k1Signer,
    funding: Funding,
    omission: u64,
) -> hellas_channel::model::bundle::WorkChannelSetupBundleV2 {
    let one = &offer.offer().proposal;
    let policy = &offer.offer().policy;
    let terms = hellas_kernel::WorkPaymentTerms {
        bond_edge: one.bond_edge(),
        bond_terms: one.bond_terms().clone(),
        omission_bond: omission,
        private_policy_commitment: hellas_channel::model::work::private_policy_commitment(
            policy.network,
            &policy.policy_salt,
            &policy.channel_policy,
        ),
        start_validity_blocks: hellas_kernel::MAX_START_VALIDITY_BLOCKS,
    };
    let payment = hellas_kernel::Tx::open_hash(
        policy.network,
        &funding,
        &hellas_kernel::Terms::work_payment(terms.clone()),
    );
    one.clone()
        .countersign_bond_and_propose_payment(
            hellas_kernel::PartyAuth::signer(key.sign(one.bond_open_hash())),
            funding,
            terms,
            hellas_kernel::PartyAuth::signer(key.sign(payment)),
        )
        .unwrap()
}

// Construct the large scenario future outside its parent's poll frame. Boxing
// it at the await site still leaves debug construction temporaries on that
// parent's stack while setup polls and decodes finalized transactions.
fn compute_and_settle<'a>(
    devnet: &'a mut Devnet,
    options: PaidWorkOptions,
    endpoint: &'a Endpoint,
    key: &'a Secp256k1Signer,
    root: &'a std::path::Path,
    provider: &'a Provider,
    original: &'a SignedPaidOffer,
) -> impl std::future::Future<Output = ()> + 'a {
    Box::pin(compute_and_settle_inner(
        devnet, options, endpoint, key, root, provider, original,
    ))
}

async fn compute_and_settle_inner(
    devnet: &mut Devnet,
    options: PaidWorkOptions,
    endpoint: &Endpoint,
    key: &Secp256k1Signer,
    _root: &std::path::Path,
    provider: &Provider,
    original: &SignedPaidOffer,
) {
    let compute = &provider.compute;
    let owner = Arc::new(
        hellas_sdk::client_owner::ClientOwner::new(
            Arc::new(FRIEND.passkey()),
            key.party_key(),
            &options.config.chain,
        )
        .unwrap(),
    );
    let store = SetupStore::open(
        &options.journal_root(),
        devnet.network(),
        original.offer().proposal.bond_edge(),
        Role::Client,
        &hellas_kernel::Secp256k1Verifier::new(),
    )
    .await
    .unwrap();
    let mut setup = hellas_channel::work_handshake::SetupEndpoint::new(
        store,
        key.clone(),
        hellas_channel::work_handshake::PaymentAdmission::Proposes(Box::new(
            original.offer().policy.clone(),
        )),
    );
    setup
        .import_offer(*options.provider.node.as_bytes(), original.clone())
        .await
        .unwrap();
    drop(setup);
    let coin = original
        .offer()
        .payment_funding
        .maker()
        .iter()
        .next()
        .copied()
        .unwrap();
    provider
        .offer_held
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let mut unavailable_args = options.clone();
    unavailable_args.timeout = Some(Duration::from_millis(100));
    let started = tokio::time::Instant::now();
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        hellas_sdk::paid_client::request_paid_quote(
            &unavailable_args,
            endpoint,
            key,
            FRIEND.principal(),
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(
        matches!(
            error,
            hellas_sdk::paid_client::PaidClientError::OfferUnavailable { ref source }
                if source.code() == hellas_wire::WireCode::Unavailable
                    && source.message() == "held offer response"
        ),
        "bounded quote expiry: {error}"
    );
    assert!(started.elapsed() >= unavailable_args.timeout.unwrap());
    provider
        .offer_held
        .store(false, std::sync::atomic::Ordering::SeqCst);
    devnet.seal().await;

    provider
        .funded_held
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let attempts = provider
        .unavailable
        .load(std::sync::atomic::Ordering::SeqCst);
    let error = request(
        endpoint,
        provider,
        devnet.network(),
        FRIEND,
        key,
        &[coin],
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), hellas_wire::WireCode::Unavailable);
    assert!(
        provider
            .unavailable
            .load(std::sync::atomic::Ordering::SeqCst)
            > attempts
    );
    provider
        .funded_held
        .store(false, std::sync::atomic::Ordering::SeqCst);
    devnet.seal().await;
    let open = PaidWorkSession::open(
        options.clone(),
        endpoint.clone(),
        key.clone(),
        owner.clone(),
        SessionOpenMode::Any,
        SessionFundingOptions::default(),
    );
    tokio::pin!(open);
    let mut session = sealing_while(devnet, Duration::from_millis(100), &mut open)
        .await
        .unwrap();
    assert_eq!(
        session.descriptor().bond_edge(),
        original.offer().proposal.bond_edge()
    );
    // Idempotence survives consumption of the originally proven payment coins.
    assert_eq!(
        granted(
            request(
                endpoint,
                provider,
                devnet.network(),
                FRIEND,
                key,
                &[coin],
                None
            )
            .await
            .unwrap()
        )
        .encode()
        .unwrap(),
        original.encode().unwrap()
    );
    // The sealing driver finishes its last block even when setup wins the
    // race. Reopen from journals on that stable tip before testing payment.
    session.shutdown().await;
    drop(session);
    let mut session = PaidWorkSession::open(
        options.clone(),
        endpoint.clone(),
        key.clone(),
        owner.clone(),
        SessionOpenMode::Any,
        SessionFundingOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        session.descriptor().bond_edge(),
        original.offer().proposal.bond_edge()
    );
    // Job 1: A has never seen this program. B uploads it, A compiles and runs
    // it, and B pays exactly the price for the signed result.
    let client_key = ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap();
    let (k, nonce) = (u64::from(rand::random::<u32>()), rand::random::<u32>());
    let (job, source) = compute_job(&increment(k), increment_plan(Arg::U64(41))).await;
    let first_job = job.clone();
    let terms = hellas_sdk::execution::ExecutionTerms::Paid { price: job.price() };
    let attempt_path = hellas_sdk::transact::PaidAttemptPath::new(
        &options.config.chain,
        options.provider,
        owner.principal(),
        job.digest(),
    );
    let mut attempt =
        hellas_sdk::execution::ExecutionAttempt::open_paid(&attempt_path, job.input(), job.price())
            .unwrap();
    attempt
        .bind_target(hellas_sdk::execution::ExecutionTarget {
            network: options.config.network(),
            provider: options.provider,
        })
        .unwrap();
    let result = execute(
        hellas_sdk::execution::ExecutionSession::Paid(&mut session),
        job.input().clone(),
        terms,
        &client_key,
        Default::default(),
        Some(&mut attempt),
    )
    .await
    .unwrap();
    let Some(hellas_sdk::execution::ExecutionResult::Paid(result)) = result.live else {
        panic!("paid result")
    };
    let first_work = result.work_id;
    assert!(hellas_kernel::SigVerifier::verify_sig(
        &hellas_kernel::Secp256k1Verifier::new(),
        result.acceptance_signature,
        session.descriptor().channel().provider_key(),
        hellas_channel::model::work::signing_hash(result.work_id),
    ));
    assert!(attempt.inspect().unwrap().result_available);
    attempt.reported().unwrap();
    assert!(attempt.inspect().unwrap().reported);
    assert!(
        execute(
            hellas_sdk::execution::ExecutionSession::Paid(&mut session),
            job.input().clone(),
            terms,
            &client_key,
            Default::default(),
            Some(&mut attempt)
        )
        .await
        .is_err()
    );
    assert_eq!(compute.calls(), 1);
    // A paid marker whose receipt was never written remains paid, with no
    // locally deliverable output, and cannot authorize another execution.
    let paid_without_receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(attempt_path.as_path()).unwrap()).unwrap();
    let paid_without_receipt_path = attempt_path.with_nonce([1; 16]);
    hellas_private::write_atomically(
        paid_without_receipt_path.as_path(),
        ".writing",
        &serde_json::to_vec(&paid_without_receipt).unwrap(),
    )
    .unwrap();
    let mut paid_without_receipt = hellas_sdk::execution::ExecutionAttempt::open_existing_paid(
        &paid_without_receipt_path,
        job.input(),
        job.price(),
    )
    .unwrap();
    let facts = paid_without_receipt.inspect().unwrap();
    assert_eq!(facts.payment, hellas_sdk::execution::Payment::Paid);
    assert!(!facts.result_available);
    assert!(!facts.reported);
    assert!(matches!(
        execute(
            hellas_sdk::execution::ExecutionSession::Paid(&mut session),
            job.input().clone(),
            terms,
            &client_key,
            Default::default(),
            Some(&mut paid_without_receipt)
        )
        .await,
        Err(hellas_sdk::execution::ExecutionError::RecoveryRequired)
    ));
    assert_eq!(compute.calls(), 1);
    // A persisted proposal nonce survives an interrupted caller. Even if the
    // attempt has no recorded acceptance, it may only be recovered.
    let mut interrupted_record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(attempt_path.as_path()).unwrap()).unwrap();
    interrupted_record["proposal"]
        .as_object_mut()
        .unwrap()
        .remove("outcome");
    let interrupted_path = attempt_path.with_nonce([2; 16]);
    hellas_private::write_atomically(
        interrupted_path.as_path(),
        ".writing",
        &serde_json::to_vec(&interrupted_record).unwrap(),
    )
    .unwrap();
    let mut interrupted_attempt = hellas_sdk::execution::ExecutionAttempt::open_existing_paid(
        &interrupted_path,
        job.input(),
        job.price(),
    )
    .unwrap();
    assert!(matches!(
        execute(
            hellas_sdk::execution::ExecutionSession::Paid(&mut session),
            job.input().clone(),
            terms,
            &client_key,
            Default::default(),
            Some(&mut interrupted_attempt)
        )
        .await,
        Err(hellas_sdk::execution::ExecutionError::RecoveryRequired)
    ));
    assert_eq!(compute.calls(), 1);
    assert_eq!(
        (result.job_price, result.credited_cumulative),
        (JOB_PRICE, JOB_PRICE)
    );
    assert_eq!(
        result.provider_key,
        ProducerSigningKey::from_secret_bytes([2; 32])
            .unwrap()
            .public_key()
    );
    assert_eq!(result.output.artifacts.len(), 1);
    assert_eq!(
        result.output.artifacts[0].bytes.as_bytes(),
        (41 + k).to_le_bytes()
    );
    assert!(compute.have(source).await, "A retained B's uploaded source");
    assert_eq!(provider.content.stats().unwrap().outstanding, 0);
    assert_eq!((compute.calls(), compute.loads()), (1, 1));
    assert!(
        !session
            .with_state(|state| state.is_closing())
            .await
            .unwrap()
    );

    // 8a: a step bound over A's policy is refused; nothing is uploaded,
    // compiled or credited.
    let mut over = counter_plan();
    over.step.as_mut().unwrap().stop.max_steps = 65;
    let (job, source) = compute_job(&increment(k ^ 1), over).await;
    assert!(
        session
            .run(
                Some(unchecked(&job, &session, nonce)),
                &job.content(),
                false,
                None
            )
            .await
            .is_err()
    );
    assert!(!compute.have(source).await);
    assert_eq!(provider.content.stats().unwrap().outstanding, 0);
    assert_eq!(compute.calls(), 1);
    assert_eq!(credited(&session).await, JOB_PRICE);

    // 8b: a mistyped argument fails validation after acceptance. A signs the
    // Failed terminal, nothing is loaded, and B retires the job unpaid.
    let (job, _) = compute_job(&increment(k ^ 3), increment_plan(Arg::U32(41))).await;
    let Err(error) = transact(&mut session, &job, &client_key, None).await else {
        panic!("a mistyped argument produced a payable result");
    };
    assert!(
        matches!(
            error,
            hellas_sdk::transact::TransactError::Client(
                hellas_sdk::paid_client::PaidClientError::InvocationFailed { .. }
            )
        ),
        "{error}"
    );
    assert_eq!((compute.calls(), compute.loads()), (2, 1));
    assert_eq!(credited(&session).await, JOB_PRICE);

    // 8d: a counter streams one signed event per step and stops on its match.
    let streamed = Arc::new(std::sync::Mutex::new(0usize));
    let progress = streamed.clone();
    let (job, _) = compute_job(COUNTER, counter_plan()).await;
    let result = transact(
        &mut session,
        &job,
        &client_key,
        Some(Arc::new(move |_| {
            *progress.lock().unwrap() += 1;
            Ok(())
        })),
    )
    .await
    .unwrap();
    let metadata: invocation::compute::RunMetadata =
        hellas_rpc::value::decode_canonical_dag_cbor(result.output.metadata.as_bytes()).unwrap();
    assert_eq!(
        metadata,
        invocation::compute::RunMetadata {
            steps: 5,
            stop: Some(invocation::compute::StopReason::Matched(5)),
        }
    );
    assert_eq!(
        *streamed.lock().unwrap(),
        5 + 1,
        "one signed event per step, then the terminal"
    );
    assert_eq!(result.credited_cumulative, 2 * JOB_PRICE);

    // 9: interrupted after A accepted, the same work resumes and pays once.
    let (job, _) = compute_job(&increment(k ^ 2), increment_plan(Arg::U64(41))).await;
    let calls = compute.calls();
    compute
        .0
        .pause
        .store(true, std::sync::atomic::Ordering::SeqCst);
    {
        let first = transact(&mut session, &job, &client_key, None);
        tokio::pin!(first);
        tokio::select! {
            result = &mut first => panic!("job completed before interruption: {:?}", result.err()),
            () = compute.0.started.notified() => {},
        }
    }
    let interrupted = session
        .with_state(|state| state.jobs().last().unwrap().work_id())
        .await
        .unwrap();
    session.shutdown().await;
    drop(session);
    let mut session = PaidWorkSession::open(
        options.clone(),
        endpoint.clone(),
        key.clone(),
        owner.clone(),
        SessionOpenMode::Any,
        SessionFundingOptions::default(),
    )
    .await
    .unwrap();
    compute
        .0
        .pause
        .store(false, std::sync::atomic::Ordering::SeqCst);
    compute.0.release.notify_one();
    let result = transact(&mut session, &job, &client_key, None)
        .await
        .unwrap();
    assert_eq!(result.work_id, interrupted);
    assert_eq!(compute.calls(), calls + 1);
    assert_eq!(result.credited_cumulative, CREDITED - JOB_PRICE);

    // A different explicit attempt is a new purchase, even for identical input.
    let mut second = hellas_sdk::execution::ExecutionAttempt::open_paid(
        &attempt_path.with_nonce([3; 16]),
        first_job.input(),
        first_job.price(),
    )
    .unwrap();
    second
        .bind_target(hellas_sdk::execution::ExecutionTarget {
            network: options.config.network(),
            provider: options.provider,
        })
        .unwrap();
    let calls = compute.calls();
    let Some(hellas_sdk::execution::ExecutionResult::Paid(second_result)) = execute(
        hellas_sdk::execution::ExecutionSession::Paid(&mut session),
        first_job.input().clone(),
        terms,
        &client_key,
        Default::default(),
        Some(&mut second),
    )
    .await
    .unwrap()
    .live
    else {
        panic!("paid result")
    };
    assert_ne!(second_result.work_id, first_work);
    assert_eq!(compute.calls(), calls + 1);
    assert_eq!(second_result.credited_cumulative, CREDITED);

    // 10: the settled close pays A exactly the credited total.
    session.shutdown().await;
    drop(session);
    let closed = sealing_while(
        devnet,
        Duration::from_millis(100),
        hellas_sdk::paid_client::settle_channel(
            &options,
            original.offer().proposal.bond_edge(),
            owner.principal(),
            key,
        ),
    )
    .await
    .unwrap();
    assert_eq!(closed.provider_payout, CREDITED);
    let receipt = hellas_sdk::paid_client::finalized_channel_settlement(
        &options,
        original.offer().proposal.bond_edge(),
        owner.principal(),
        owner.delegate(),
    )
    .await
    .unwrap()
    .expect("settled channel has finalized evidence");
    assert_eq!(closed, receipt);
    assert_eq!(receipt.provider_payout, CREDITED);
    assert_eq!(
        receipt.client_returned + receipt.provider_payout,
        receipt.funding_value
    );
}

const CREDITED: u64 = 4 * JOB_PRICE;
const COUNTER: &str = r#"(def program initialize : [] -> (u64 val) = const.u64.0x0000000000000000)
(def program advance : {(u64 val) (u64 val)} -> (u64 val)
= ({smolcat.value.named smolcat.value.named stdlib.numeric.numeric.u64} stdlib.numeric.+ :.forget))
"#;
fn increment(k: u64) -> String {
    format!(
        "(def program increment : (u64 val) -> (u64 val) = ({{_ const.u64.0x{k:016X}}} {{smolcat.value.named smolcat.value.named stdlib.numeric.numeric.u64}} stdlib.numeric.+ :.forget))\n"
    )
}
fn increment_plan(arg: Arg) -> Plan {
    Plan {
        calls: vec![Call {
            entry: "increment".into(),
            args: vec![arg],
            bind: vec![Bind::Name("answer".into())],
        }],
        step: None,
        outputs: vec![Declared {
            slot: "answer".into(),
            kind: OutputKind::Scalar(ValueKind::U64),
        }],
    }
}
fn counter_plan() -> Plan {
    let value = || Bind::Name("value".into());
    Plan {
        calls: vec![Call {
            entry: "initialize".into(),
            args: vec![],
            bind: vec![value()],
        }],
        step: Some(Step {
            entry: "advance".into(),
            args: vec![
                StepArg::Arg(Arg::Slot {
                    name: "value".into(),
                }),
                StepArg::Arg(Arg::U64(1)),
            ],
            bind: vec![value()],
            emit: "value".into(),
            stop: Stop {
                any_of: vec![5],
                max_steps: 64,
            },
        }),
        outputs: vec![Declared {
            slot: "value".into(),
            kind: OutputKind::Scalar(ValueKind::U64),
        }],
    }
}
async fn compute_job(source: &str, plan: Plan) -> (hellas_sdk::job::Job, hellas_rpc::ContentRef) {
    let mut bytes: Vec<_> = catena_lang::stdlib::core_sources()
        .map(|text| text.as_bytes().to_vec())
        .collect();
    let mut sources: Vec<_> = bytes
        .iter()
        .map(|text| hellas_rpc::ContentRef::for_bytes(text))
        .collect();
    let source_ref = hellas_rpc::ContentRef::for_bytes(source.as_bytes());
    sources.push(source_ref);
    bytes.push(source.as_bytes().to_vec());
    let environment = invocation::compute::Environment {
        sources,
        assets: vec![],
    };
    bytes.push(environment.canonical_bytes().unwrap());
    let content = source_content(bytes).await;
    let job = hellas_sdk::job::Job::compute(JOB_PRICE, environment, plan, vec![], content)
        .await
        .unwrap();
    (job, source_ref)
}
/// `Job::prepare` without B's policy pre-check, as a client that skips it.
fn unchecked(
    job: &hellas_sdk::job::Job,
    session: &PaidWorkSession,
    nonce: u32,
) -> PreparedInvocation {
    let hellas_sdk::job::JobInput::Compute { plan, .. } = job.input() else {
        unreachable!()
    };
    let input = invocation::InvocationInput {
        parameters: hellas_rpc::JsonBytes(plan.canonical_bytes().unwrap()),
        artifacts: vec![],
    };
    let request = invocation::InvocationRequest {
        execution_environment: job.manifest().content_id(),
        input: input.content_id().unwrap(),
        runner_public_key: ProducerSigningKey::from_secret_bytes([2; 32])
            .unwrap()
            .public_key(),
        nonce: [
            nonce.to_le_bytes(),
            [0; 4],
            [0; 4],
            [0; 4],
            [0; 4],
            [0; 4],
            [0; 4],
            [0; 4],
        ]
        .concat()
        .try_into()
        .unwrap(),
        assurance: Assurance::ProducerSigned,
        retain: true,
    };
    PreparedInvocation::new(
        request,
        &job.manifest(),
        input,
        session
            .descriptor()
            .invocation_policy()
            .canonical_bytes()
            .unwrap(),
    )
    .unwrap()
}
async fn transact(
    session: &mut PaidWorkSession,
    job: &hellas_sdk::job::Job,
    key: &ProducerSigningKey,
    progress: Option<hellas_channel::work::PaidProgress>,
) -> Result<hellas_sdk::paid_client::PaidWorkResult, hellas_sdk::transact::TransactError> {
    hellas_sdk::transact::transact(
        session,
        job,
        key,
        hellas_sdk::transact::TransactionOptions {
            progress,
            ..Default::default()
        },
    )
    .await
}
async fn credited(session: &PaidWorkSession) -> u64 {
    session
        .with_state(|state| state.ledger().credited_cumulative())
        .await
        .unwrap()
}

pub(super) fn exercise(
    runtime: commonware_runtime::tokio::Context,
) -> impl std::future::Future<Output = ()> {
    Box::pin(exercise_inner(runtime))
}

struct Case {
    identity: NodeIdentity,
    root: tempfile::TempDir,
    devnet: Devnet,
    chain: RemoteLightClient,
    owners: [GenesisOwner; 5],
    keys: Vec<Secp256k1Signer>,
    payment_coins: Vec<CoinId>,
    config: WorkConfig,
    compute: HostCompute,
    provider: Provider,
    endpoint: Endpoint,
    policy: hellas_channel::model::paid_policy::PaidPolicy,
    secret: auth::CredentialSecret,
    first: Box<SignedPaidOffer>,
    second: Box<SignedPaidOffer>,
    third: Box<SignedPaidOffer>,
}

async fn exercise_inner(runtime: commonware_runtime::tokio::Context) {
    let case = Box::pin(allocate(runtime)).await;
    Box::pin(finish(case)).await;
}

async fn allocate(runtime: commonware_runtime::tokio::Context) -> Box<Case> {
    let identity = provider_identity();
    let root = tempfile::tempdir().unwrap();
    let owners = [
        GenesisOwner {
            kind: OwnerKind::Passkey,
            secret_scalar: [0x11; 32],
            balance: 39,
        },
        GenesisOwner {
            kind: OwnerKind::Passkey,
            secret_scalar: [0x13; 32],
            balance: 3 * FUNDING,
        },
        GenesisOwner {
            kind: OwnerKind::Passkey,
            secret_scalar: [0x12; 32],
            balance: 2 * FUNDING,
        },
        GenesisOwner {
            kind: OwnerKind::Passkey,
            secret_scalar: [0x14; 32],
            balance: FUNDING,
        },
        GenesisOwner {
            kind: OwnerKind::Passkey,
            secret_scalar: [0x16; 32],
            balance: FUNDING,
        },
    ];
    let actors = [ROOT, FRIEND, OPERATOR, AGENT, STRANGER];
    let keys: Vec<_> = [2, 0x21, 0x23, 0x24, 0x25]
        .into_iter()
        .map(|n| Secp256k1Signer::from_secret_scalar([n; 32]).unwrap())
        .collect();
    let mut devnet = Devnet::start(
        runtime,
        DevnetConfig {
            name: "sdk_automatic_offers",
            owners: owners.to_vec(),
            full_nodes: 1,
        },
    )
    .await;
    // Paid parties refuse certified state that falls behind the local
    // clock, so the chain certifies while a test seals nothing.
    devnet.keep_certifying();
    devnet.seal().await;
    let trust_config = work_config(&devnet, root.path().join("paid"));
    let profile = &trust_config.chain;
    let verifier = std::sync::Arc::new(
        hellas_chain::proof_verify::ProofVerifier::for_profile(profile).unwrap(),
    );
    let chain = RemoteLightClient::connect(devnet.light_client_url(0), verifier)
        .await
        .unwrap();
    let mut payment_coins = Vec::new();
    let mut alternate_funding = Vec::new();
    let mut short_funding = None;
    for index in 0..owners.len() {
        assert_eq!(
            owners[index].key().into_kernel().to_bytes(),
            *actors[index].principal().as_bytes()
        );
        let (tx, coin) = delegate_allocation(
            devnet.allocations(),
            &owners[index],
            keys[index].party_key().into(),
        );
        if index == 0 {
            let hellas_chain::domain::Transaction::Kernel(hellas_kernel::Tx::Owner(reshape)) = tx
            else {
                panic!("owner delegation")
            };
            let selected: Vec<_> = reshape.inputs().iter().copied().collect();
            let plan = hellas_sdk::coin_owner::OwnerReshape::prepare(
                &chain,
                devnet.network(),
                owners[0].key().into_kernel(),
                &selected,
                Some(keys[0].party_key()),
                Some(12),
            )
            .await
            .unwrap();
            assert_eq!(plan.outputs().len(), 4);
            let outputs: Vec<_> = plan.outputs().iter().cloned().collect();
            assert_eq!(
                outputs.iter().map(|p| p.value()).collect::<Vec<_>>(),
                vec![12, 12, 12, 3]
            );
            assert_eq!(
                outputs[3],
                hellas_kernel::Payout::new(owners[0].key().into_kernel(), 3)
            );
            assert!(
                plan.clone()
                    .authorize(hellas_kernel::Auth::native(
                        keys[0].sign(plan.payload_hash())
                    ))
                    .is_err(),
                "node delegation never grants reshape authority"
            );
            let tx = plan
                .clone()
                .authorize(owners[0].authorize(plan.payload_hash()))
                .unwrap();
            chain
                .submit_tx(hellas_chain::domain::Transaction::Kernel(tx))
                .await
                .unwrap();
        } else if index <= 2 {
            let hellas_chain::domain::Transaction::Kernel(hellas_kernel::Tx::Owner(reshape)) = tx
            else {
                panic!("owner delegation")
            };
            let selected: Vec<_> = reshape.inputs().iter().copied().collect();
            let plan = hellas_sdk::coin_owner::OwnerReshape::prepare(
                &chain,
                devnet.network(),
                owners[index].key().into_kernel(),
                &selected,
                Some(keys[index].party_key()),
                Some(FUNDING),
            )
            .await
            .unwrap();
            let ids: Vec<_> = plan.output_ids().iter().copied().collect();
            assert_eq!(ids.len(), if index == 1 { 3 } else { 2 });
            if index == 1 {
                short_funding = Some(ids[2]);
            }
            payment_coins.push(ids[0]);
            alternate_funding.push((index, ids[1]));
            let tx = plan
                .clone()
                .authorize(owners[index].authorize(plan.payload_hash()))
                .unwrap();
            chain
                .submit_tx(hellas_chain::domain::Transaction::Kernel(tx))
                .await
                .unwrap();
            continue;
        } else {
            chain.submit_tx(tx).await.unwrap();
        }
        payment_coins.push(coin);
    }
    devnet.seal().await;
    let mut alternate_coins = std::collections::BTreeMap::new();
    for (index, coin) in alternate_funding {
        let other_key = if index == 1 { &keys[2] } else { &keys[1] };
        let plan = hellas_sdk::coin_owner::OwnerReshape::prepare(
            &chain,
            devnet.network(),
            owners[index].key().into_kernel(),
            &[coin],
            Some(other_key.party_key()),
            None,
        )
        .await
        .unwrap();
        alternate_coins.insert(index, *plan.output_ids().iter().next().unwrap());
        let tx = plan
            .clone()
            .authorize(owners[index].authorize(plan.payload_hash()))
            .unwrap();
        chain
            .submit_tx(hellas_chain::domain::Transaction::Kernel(tx))
            .await
            .unwrap();
    }
    let short_plan = hellas_sdk::coin_owner::OwnerReshape::prepare(
        &chain,
        devnet.network(),
        owners[1].key().into_kernel(),
        &[short_funding.unwrap()],
        Some(keys[1].party_key()),
        Some(FUNDING - 1),
    )
    .await
    .unwrap();
    let short_coin = *short_plan.output_ids().iter().next().unwrap();
    let short_tx = short_plan
        .clone()
        .authorize(owners[1].authorize(short_plan.payload_hash()))
        .unwrap();
    chain
        .submit_tx(hellas_chain::domain::Transaction::Kernel(short_tx))
        .await
        .unwrap();
    devnet.seal().await;
    let coin_at = async |id: CoinId| {
        chain
            .get_objects(vec![hellas_chain::domain::ObjectKey::Coin(id)])
            .await
            .unwrap()
            .unwrap()
            .coin(id)
            .unwrap()
            .expect("a live coin")
    };
    for (index, id) in &alternate_coins {
        let coin = coin_at(*id).await;
        let delegate = if *index == 1 {
            keys[2].party_key()
        } else {
            keys[1].party_key()
        };
        assert_eq!(coin.owner.into_kernel(), owners[*index].key().into_kernel());
        assert_eq!(coin.delegate.map(|key| key.into_kernel()), Some(delegate));
        assert_eq!(coin.value, FUNDING);
    }
    let short = coin_at(short_coin).await;
    assert_eq!(short.owner.into_kernel(), owners[1].key().into_kernel());
    assert_eq!(
        short.delegate.map(|key| key.into_kernel()),
        Some(keys[1].party_key())
    );
    assert_eq!(short.value, FUNDING - 1);
    let (store, secret) =
        hellas_authority::test_support::common_node::bootstrap_node_with_credential(
            &root.path().join("authority"),
            hellas_authority::model::grant::grant_network(),
            Some(provider_enrollment(&identity)),
            UnixMillis(1),
        )
        .await
        .unwrap();
    drop(store);
    let config = trust_config;
    let compute = HostCompute::default();
    let mut provider = Provider::start(
        root.path(),
        config.clone(),
        compute.clone(),
        identity.clone(),
        0,
    )
    .await;
    let endpoint = bind_paid_endpoint(iroh::SecretKey::generate())
        .await
        .unwrap();
    refused(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            FRIEND,
            &keys[1],
            &[],
            None,
        )
        .await
        .unwrap(),
        OfferRefusalCode::NoPolicy,
    );
    assert_eq!(files(&config.chain.provider().join("channels")), 0);
    let mut policy = paid_policy();
    policy.invocation_policy = InvocationPolicy {
        admissions: vec![Admission::Compute {
            evaluator: invocation::compute::EVALUATOR.into(),
            programs: hellas_rpc::protocol::invocation::ComputePrograms::Any {},
        }],
        limits: Limits {
            max_upload_bytes: 1 << 20,
            max_output_bytes: 4096,
            max_steps: 64,
            execution_timeout_ms: 10_000,
        },
    };
    policy.payment_policy.fixed_price = JOB_PRICE;
    policy.expected_payment_values = EdgeValues::new(FUNDING, 0, Fees::ZERO);
    policy.offers.omission_bond = 201;
    policy.offers.max_open_offers = 2;
    provider.policy(&secret, 0, policy.clone()).await;
    for field in [
        "principal",
        "key",
        "coin",
        "signature",
        "network",
        "provider",
        "exporter",
    ] {
        assert!(
            request(
                &endpoint,
                &provider,
                devnet.network(),
                FRIEND,
                &keys[1],
                &[payment_coins[1]],
                Some(field)
            )
            .await
            .is_err(),
            "signed {field}"
        );
    }
    assert_eq!(files(&config.chain.provider().join("channels")), 0);
    refused(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            ROOT,
            &keys[1],
            &[payment_coins[1]],
            None,
        )
        .await
        .unwrap(),
        OfferRefusalCode::NeedsFunding,
    );
    refused(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            FRIEND,
            &keys[2],
            &[payment_coins[1]],
            None,
        )
        .await
        .unwrap(),
        OfferRefusalCode::NeedsFunding,
    );
    let delegate = keys[0].party_key().into();
    let stake = devnet
        .light_client(0)
        .get_holdings(delegate, None)
        .await
        .unwrap()
        .unwrap()
        .delegated_coins(delegate)[0]
        .0;
    refused(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            ROOT,
            &keys[0],
            &[CoinId::from_bytes(stake.0)],
            None,
        )
        .await
        .unwrap(),
        OfferRefusalCode::NeedsFunding,
    );
    for coins in [vec![short_coin], vec![payment_coins[1], short_coin]] {
        refused(
            request(
                &endpoint,
                &provider,
                devnet.network(),
                FRIEND,
                &keys[1],
                &coins,
                None,
            )
            .await
            .unwrap(),
            OfferRefusalCode::NeedsFunding,
        );
    }
    assert_eq!(files(&config.chain.provider().join("channels")), 0);
    let quote = request(
        &endpoint,
        &provider,
        devnet.network(),
        FRIEND,
        &keys[1],
        &[],
        None,
    )
    .await
    .unwrap();
    let Some(Outcome::Quote(quote)) = quote.outcome else {
        panic!("quote")
    };
    assert_eq!(quote.funding_value, FUNDING);
    assert_eq!(files(&config.chain.provider().join("channels")), 0);
    std::fs::create_dir_all(config.chain.provider()).unwrap();
    std::fs::write(
        config.chain.provider().join("channels"),
        b"blocked journal root",
    )
    .unwrap();
    assert!(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            FRIEND,
            &keys[1],
            &[payment_coins[1]],
            None
        )
        .await
        .is_err()
    );
    std::fs::remove_file(config.chain.provider().join("channels")).unwrap();
    assert!(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            FRIEND,
            &keys[1],
            &[payment_coins[1]],
            None
        )
        .await
        .is_err(),
        "an ambiguous durable failure cannot be followed by another allocation"
    );
    let port = provider.port();
    provider.shutdown().await;
    provider = Provider::start(
        root.path(),
        config.clone(),
        compute.clone(),
        identity.clone(),
        port,
    )
    .await;
    let first = granted(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            FRIEND,
            &keys[1],
            &[payment_coins[1]],
            None,
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        quote.provider_channel_policy,
        hellas_rpc::protocol::value::encode_bounded(
            &first.offer().policy,
            hellas_authority::model::grant::records::MAX_OFFER_BYTES
        )
        .unwrap()
    );
    let before = files(&config.chain.provider().join("channels"));
    assert!(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            FRIEND,
            &keys[2],
            &[alternate_coins[&1]],
            None
        )
        .await
        .is_err(),
        "one live offer per principal"
    );
    assert!(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            OPERATOR,
            &keys[1],
            &[alternate_coins[&2]],
            None
        )
        .await
        .is_err(),
        "one live offer per key"
    );
    assert_eq!(
        granted(
            request(
                &endpoint,
                &provider,
                devnet.network(),
                FRIEND,
                &keys[1],
                &[payment_coins[1]],
                None
            )
            .await
            .unwrap()
        )
        .encode()
        .unwrap(),
        first.encode().unwrap()
    );
    assert_eq!(files(&config.chain.provider().join("channels")), before);
    let other_peer = bind_paid_endpoint(iroh::SecretKey::generate())
        .await
        .unwrap();
    assert_eq!(
        granted(
            request(
                &other_peer,
                &provider,
                devnet.network(),
                FRIEND,
                &keys[1],
                &[payment_coins[1]],
                None
            )
            .await
            .unwrap()
        )
        .encode()
        .unwrap(),
        first.encode().unwrap()
    );
    let transport = connect_offer(&other_peer, &provider).await;
    let denied = hellas_rpc::call::unary::<_, hellas_rpc::services::work_setup::ExchangeSetup>(
        &transport,
        ExchangeSetupRequest {
            bond_edge: first.offer().proposal.bond_edge().to_bytes().to_vec(),
            bundle: vec![],
        },
        Metadata::new(),
    )
    .await
    .unwrap();
    assert!(matches!(
        denied.outcome,
        Some(exchange_setup_response::Outcome::Refused(_))
    ));
    other_peer.close().await;
    for change in ["omission", "funding"] {
        let mut funding = first.offer().payment_funding.clone();
        if change == "funding" {
            funding = Funding::new(
                List::take([CoinId::from_bytes([0xee; 32]); 4], 1),
                List::empty(CoinId::from_bytes([0; 32])),
            );
        }
        let proposal = revision_two(
            &first,
            &keys[1],
            funding,
            if change == "omission" { 300 } else { 201 },
        );
        let transport = connect_offer(&endpoint, &provider).await;
        let refused =
            hellas_rpc::call::unary::<_, hellas_rpc::services::work_setup::ExchangeSetup>(
                &transport,
                ExchangeSetupRequest {
                    bond_edge: first.offer().proposal.bond_edge().to_bytes().to_vec(),
                    bundle: proposal.encode(),
                },
                Metadata::new(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                refused.outcome,
                Some(exchange_setup_response::Outcome::Refused(_))
            ),
            "changed {change} cannot get a provider payment signature"
        );
    }
    let second = granted(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            OPERATOR,
            &keys[2],
            &[payment_coins[2]],
            None,
        )
        .await
        .unwrap(),
    );
    refused(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            AGENT,
            &keys[3],
            &[payment_coins[3]],
            None,
        )
        .await
        .unwrap(),
        OfferRefusalCode::OfferLimit,
    );
    policy.offers.max_open_offers = 3;
    provider.policy(&secret, 1, policy.clone()).await;
    let third = granted(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            AGENT,
            &keys[3],
            &[payment_coins[3]],
            None,
        )
        .await
        .unwrap(),
    );
    // Simulate a client interrupted after accepting revision one. Its funding
    // stays live; recovery after the horizon must ask for a fresh offer.
    let interrupted_chain = devnet.chain_dir(&root.path().join("interrupted-home"), 0);
    let interrupted_root = interrupted_chain.client_journals(
        &hellas_client::ProviderAddress::of(&provider.enrollment)
            .unwrap()
            .to_string(),
    );
    let location = StoreLocation::for_test(&interrupted_root);
    let mut interrupted = SetupStore::open(
        &location,
        devnet.network(),
        third.offer().proposal.bond_edge(),
        Role::Client,
        &hellas_kernel::Secp256k1Verifier::new(),
    )
    .await
    .unwrap();
    interrupted
        .commit(
            hellas_channel::work_store::SetupRecord::Offer {
                peer: *provider.endpoint.id().as_bytes(),
                offer: third.clone(),
            },
            &hellas_kernel::Secp256k1Verifier::new(),
        )
        .await
        .unwrap();
    drop(interrupted);
    policy.offers.max_open_offers = 4;
    provider.policy(&secret, 2, policy.clone()).await;
    refused(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            STRANGER,
            &keys[4],
            &[payment_coins[4]],
            None,
        )
        .await
        .unwrap(),
        OfferRefusalCode::NoStakeAvailable,
    );
    let reserved: std::collections::BTreeSet<_> = [&first, &second, &third]
        .into_iter()
        .flat_map(|o| o.offer().proposal.bond_funding().maker().iter().copied())
        .collect();
    assert_eq!(
        reserved.len(),
        3,
        "automatic offers use disjoint owner-delegated stake"
    );
    for offer in [&first, &second, &third] {
        assert_eq!(offer.offer().proposal.bond_funding().maker().len(), 1);
        assert_eq!(
            offer
                .offer()
                .proposal
                .bond_terms()
                .timeout_outputs
                .iter()
                .map(|p| p.value())
                .sum::<u64>(),
            12
        );
    }
    // A restart reads both standing terms and original offers from their journals.
    let port = provider.port();
    provider.shutdown().await;
    provider = Provider::start(
        root.path(),
        config.clone(),
        compute.clone(),
        identity.clone(),
        port,
    )
    .await;
    assert_eq!(
        provider
            .admin
            .node()
            .paid_policy()
            .await
            .unwrap()
            .unwrap()
            .revision,
        auth::Revision(3)
    );
    assert_eq!(
        granted(
            request(
                &endpoint,
                &provider,
                devnet.network(),
                FRIEND,
                &keys[1],
                &[payment_coins[1]],
                None
            )
            .await
            .unwrap()
        )
        .encode()
        .unwrap(),
        first.encode().unwrap()
    );
    Box::new(Case {
        identity,
        root,
        devnet,
        chain,
        owners,
        keys,
        payment_coins,
        config,
        compute,
        provider,
        endpoint,
        policy,
        secret,
        first,
        second,
        third,
    })
}

/// Exercise granted Compute on the endpoint that also serves paid work.
fn grant_composition<'a>(
    provider: &'a Provider,
    secret: &'a auth::CredentialSecret,
    root: &'a std::path::Path,
) -> futures::future::BoxFuture<'a, ()> {
    Box::pin(async move {
        use hellas_authority::model::grant::{
            budget::{Limit, Meter, Window},
            records::{Offer, SignedOffer},
        };
        use hellas_authority::test_support::{common_node, definition};
        use hellas_channel::test_support::principal;
        use hellas_sdk::grant_client::{GrantSessionOptions, GrantTransport, UnpinnedOffer};
        use hellas_sdk::node_control::profile::ClientProfile;

        let subject = principal(1).0;
        let data_root = root.join("composition-grants");
        let policies = composition_policies();
        let mut definition = definition(auth::GrantId([71; 16]), subject);
        definition.policies = policies.clone();
        let mut admin =
            common_node::WorkAdmin::new(provider.grants.clone(), secret, policies).await;
        admin.capacity(4, vec![]).await;
        admin
            .budgets(
                common_node::POOL,
                subject,
                vec![Limit::new(
                    Meter::Requests,
                    Window::Total,
                    2,
                )],
                2,
            )
            .await;
        admin.create(definition.clone()).await;
        let node = provider.grants.node();
        let credential =
            common_node::execution_credential(&node, secret, subject, definition.id).await;
        let caller = hellas_authority::test_support::session(&node, secret).await;
        let now = UnixMillis::now().unwrap();
        let signed = SignedOffer::sign(
            Offer {
                network: hellas_authority::model::grant::grant_network(),
                provider: provider.enrollment.clone(),
                grant: definition.clone(),
                generation: 0,
                sequence: 1,
                valid_until: UnixMillis(now.0 + 600_000),
                addresses: provider
                    .endpoint
                    .bound_sockets()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            },
            &ProducerSigningKey::from_secret_bytes([2; 32]).unwrap(),
        )
        .unwrap();
        let target = UnpinnedOffer::decode(&signed.encode().unwrap(), now)
            .unwrap()
            .pin(&hellas_client::ProviderTrustAnchor {
                expected_genesis: provider.enrollment.content_id(),
                required_assurance: Assurance::ProducerSigned,
                apple_app_attest: None,
            })
            .unwrap();
        let location = StoreLocation::for_test(&data_root.join("channels"));
        let options = GrantSessionOptions {
            target,
            principal: subject,
            signer: Arc::new(principal(1).1),
            application: Arc::new(ClientProfile {
                authority: caller.authority(),
                authorization: common_node::EXECUTION_AUTHORIZATION,
                credential,
                local: None,
            }),
            journal_root: location.clone(),
            control_timeout: Duration::from_secs(10),
        };
        let transport = bind_paid_endpoint(iroh::SecretKey::generate())
            .await
            .unwrap();
        let environment = hellas_channel::test_support::channel::environment();
        let content = source_content([environment.canonical_bytes().unwrap()]).await;
        let input = hellas_sdk::job::JobInput::Compute {
            environment,
            plan: hellas_channel::test_support::channel::plan(),
            inputs: vec![],
            content: content.into(),
        };
        let terms = hellas_sdk::execution::ExecutionTerms::Grant {
            resource: definition.policies[0].resource,
        };
        let mut attempt = hellas_sdk::execution::ExecutionAttempt::open(
            &root.join("composition-attempt"),
            &input,
            terms,
        )
        .unwrap();
        let mut session = attempt
            .open_grant_session(options.clone(), GrantTransport::Remote(transport.clone()))
            .await
            .unwrap();
        let result = execute(
            hellas_sdk::execution::ExecutionSession::Grant(&mut session),
            input,
            terms,
            &principal(1).1,
            Default::default(),
            Some(&mut attempt),
        )
        .await
        .unwrap();
        assert!(matches!(
            result.live,
            Some(hellas_sdk::execution::ExecutionResult::Grant(_))
        ));
        session.shutdown().await.unwrap();
        drop(session);

    })
}

async fn finish(case: Box<Case>) {
    let Case {
        identity,
        root,
        mut devnet,
        chain,
        owners,
        keys,
        payment_coins,
        config,
        compute,
        mut provider,
        endpoint,
        mut policy,
        secret,
        first,
        second,
        third,
    } = *case;
    let options = PaidWorkOptions {
        content: fresh_client_content(&root.path().join("client-store")).await,
        config: config.clone(),
        journal_kind: hellas_sdk::paid_client::PaidJournalKind::Client,
        provider: hellas_client::ProviderAddress::of(&provider.enrollment).unwrap(),
        provider_addrs: provider.endpoint.bound_sockets(),
        assurance: Assurance::ProducerSigned,
        apple_trust: None,
        expected_price: JOB_PRICE,
        acceptance_blocks: 16,
        terminal_blocks: 64,
        payment_blocks: 32,
        timeout: Some(Duration::from_secs(120)),
    };
    compute_and_settle(
        &mut devnet,
        options.clone(),
        &endpoint,
        &keys[1],
        root.path(),
        &provider,
        &first,
    )
    .await;
    assert_eq!(compute.calls(), 5);
    assert_eq!(
        holdings(&devnet, owners[1].key())
            .await
            .iter()
            .map(|(_, v)| *v)
            .sum::<u64>(),
        owners[1].balance - CREDITED
    );
    // A malicious no-show can post its countersigned bond alone. The same
    // production clock reclaims it without waiting for a payment proposal.
    let partial = revision_two(
        &second,
        &keys[2],
        second.offer().payment_funding.clone(),
        201,
    );
    chain
        .submit_tx(hellas_chain::domain::Transaction::Kernel(
            partial.bond_open().unwrap(),
        ))
        .await
        .unwrap();
    devnet.seal().await;
    let unposted: std::collections::BTreeSet<_> = [&second, &third]
        .into_iter()
        .flat_map(|o| o.offer().proposal.bond_funding().maker().iter().copied())
        .collect();
    wait_for_holdings(&mut devnet, owners[0].key(), |held| {
        held.iter()
            .any(|(id, value)| *value == 12 && !unposted.contains(id))
    })
    .await;
    assert!(
        holdings(&devnet, owners[0].key())
            .await
            .iter()
            .any(|(id, v)| *v == 12 && !unposted.contains(id)),
        "partial bond reclaimed by runner"
    );
    assert!(
        chain.get_latest_block().await.unwrap().unwrap().height
            < second.offer().proposal.bond_terms().timeout.get()
    );
    let expiry = [&first, &second, &third]
        .into_iter()
        .map(|o| o.offer().proposal.bond_terms().timeout.get())
        .max()
        .unwrap();
    devnet.seal_through(expiry).await;
    wait_for_holdings(&mut devnet, owners[0].key(), |held| {
        held.iter().map(|(_, value)| *value).sum::<u64>() == 39 + CREDITED
    })
    .await;
    let held = holdings(&devnet, owners[0].key()).await;
    assert_eq!(held.iter().map(|(_, v)| *v).sum::<u64>(), 39 + CREDITED);
    assert_eq!(held.iter().filter(|(_, v)| *v == 12).count(), 3);
    assert_eq!(held.iter().filter(|(_, v)| *v == CREDITED).count(), 1);
    let transport = connect_offer(&endpoint, &provider).await;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let response = hellas_rpc::call::unary::<_,hellas_rpc::services::work_setup::ExchangeSetup>(
                &transport, ExchangeSetupRequest { bond_edge: third.offer().proposal.bond_edge().to_bytes().to_vec(), bundle: vec![] }, Metadata::new(),
            ).await.unwrap();
            if matches!(response.outcome, Some(exchange_setup_response::Outcome::Refused(ref r)) if r.code == hellas_channel::work::WorkRefusal::Expired.code() as i32) { break; }
            tokio::time::sleep(hellas_channel::work::SETUP_POLL).await;
        }
    }).await.expect("the unanswered offer durably expires at its horizon");
    drop(transport);
    let port = provider.port();
    provider.shutdown().await;
    let location = StoreLocation::for_test(&config.chain.provider().join("channels"));
    let store = SetupStore::open(
        &location,
        devnet.network(),
        third.offer().proposal.bond_edge(),
        Role::Provider,
        &hellas_kernel::Secp256k1Verifier::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        store.state().end(),
        Some(SetupEnd::Aborted(SetupAbort::BondOpenExpired))
    );
    drop(store);
    provider = Provider::start(
        root.path(),
        config.clone(),
        compute.clone(),
        identity.clone(),
        port,
    )
    .await;
    policy.offers.max_stake_per_client = 11;
    provider.policy(&secret, 3, policy.clone()).await;
    refused(
        request(
            &endpoint,
            &provider,
            devnet.network(),
            STRANGER,
            &keys[4],
            &[payment_coins[4]],
            None,
        )
        .await
        .unwrap(),
        OfferRefusalCode::NoStakeAvailable,
    );
    policy.offers.max_stake_per_client = 12;
    provider.policy(&secret, 4, policy).await;
    let mut fresh_args = options;
    fresh_args.config.chain = devnet.chain_dir(&root.path().join("interrupted-home"), 0);
    fresh_args.provider_addrs = provider.endpoint.bound_sockets();
    let agent_owner = Arc::new(
        hellas_sdk::client_owner::ClientOwner::new(
            Arc::new(AGENT.passkey()),
            keys[3].party_key(),
            &fresh_args.config.chain,
        )
        .unwrap(),
    );
    provider
        .funded_held
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let attempts = provider
        .unavailable
        .load(std::sync::atomic::Ordering::SeqCst);
    let open = PaidWorkSession::open(
        fresh_args.clone(),
        endpoint.clone(),
        keys[3].clone(),
        agent_owner.clone(),
        SessionOpenMode::Any,
        SessionFundingOptions::default(),
    );
    let mut fresh = sealing_while(&mut devnet, Duration::from_millis(100), async {
        tokio::pin!(open);
        tokio::time::timeout(hellas_chain::node::RECOVERY_TIMEOUT, async {
            tokio::select! {
                result = &mut open => panic!("session ended before funded offer recovery: {}", result.err().map_or_else(|| "unexpected success".into(), |error| error.to_string())),
                () = async { while provider.unavailable.load(std::sync::atomic::Ordering::SeqCst) < attempts + 2 { tokio::task::yield_now().await; } } => {},
            }
        }).await.expect("one session retries its funded offer while the provider source is unavailable");
        provider.funding_refusal.store(1, std::sync::atomic::Ordering::SeqCst);
        provider.funded_held.store(false, std::sync::atomic::Ordering::SeqCst);
        open.await
    }).await.unwrap();
    {
        let requests = provider.funding_requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "one refusal and one retry");
        assert_eq!(
            requests[0], requests[1],
            "retry uses the identical signed request"
        );
    }
    assert_ne!(
        fresh.descriptor().bond_edge(),
        third.offer().proposal.bond_edge(),
        "expired client revision one cannot pin recovery to a dead offer"
    );
    let bond = fresh.descriptor().bond_edge();
    fresh.shutdown().await;
    drop(fresh);
    assert_eq!(
        sealing_while(
            &mut devnet,
            Duration::from_millis(100),
            hellas_sdk::paid_client::settle_channel(
                &fresh_args,
                bond,
                agent_owner.principal(),
                &keys[3],
            )
        )
        .await
        .unwrap()
        .provider_payout,
        0
    );
    grant_composition(&provider, &secret, root.path()).await;
    provider.grants.drain().await.unwrap();
    provider.shutdown().await;
    endpoint.close().await;
    devnet.shutdown().await;
}
