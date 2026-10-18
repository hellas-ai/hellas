use super::*;
use crate::node_control::host::{HostHandle, HostOptions};
use hellas_work::test_support::{assert_err, within};
use std::sync::atomic::AtomicUsize;

type Client = Arc<HostControlClientImpl<hellas_wire::mux::MuxTransport>>;
struct Harness {
    fixture: Fixture,
    host: HostHandle,
    socket: std::path::PathBuf,
    tls: Arc<rustls::ClientConfig>,
    starting: Arc<tokio::sync::Notify>,
    release: Arc<Semaphore>,
    starts: Arc<AtomicUsize>,
    forbidden_journal: std::path::PathBuf,
}
impl Harness {
    async fn new() -> Self {
        Self::with(fixture().await).await
    }
    async fn with(f: Fixture) -> Self {
        let (tls, client_tls) = tls_configs();
        let socket = f.directory.path().join("host.sock");
        let forbidden_journal = f.directory.path().join("unused-provider-directory");
        let enrollment = crate::test_support::provider_enrollment();
        let starting = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(Semaphore::new(0));
        let starts = Arc::new(AtomicUsize::new(0));
        let factory: host::ProviderFactory = {
            let (starting, release, starts, enrollment, forbidden_journal) = (
                starting.clone(),
                release.clone(),
                starts.clone(),
                enrollment.clone(),
                forbidden_journal.clone(),
            );
            Arc::new(move |control: Option<NodeControl>| {
                let (starting, release, starts, enrollment, forbidden_journal) = (
                    starting.clone(),
                    release.clone(),
                    starts.clone(),
                    enrollment.clone(),
                    forbidden_journal.clone(),
                );
                Box::pin(async move {
                    if starts.fetch_add(1, Ordering::SeqCst) == 0 {
                        starting.notify_one();
                        release.acquire().await.unwrap().forget();
                    }
                    Ok(crate::start_fetch_provider(
                        crate::FetchProviderOptions {
                            port: Some(0),
                            identity: crate::ClientIdentity::from_secret_bytes([5; 32], [5; 32])?,
                            enrollment,
                            root: Arc::new(hellas_work::test_support::actors::PROVIDER.key()),
                            state_directory: forbidden_journal,
                            grants: Some(crate::GrantProviderOptions {
                                policies: vec![],
                                max_job_millis: std::num::NonZeroU64::MIN,
                            }),
                            routes: crate::FetchRouteRegistry::new(),
                            fetch_max_in_flight: 1,
                            fetch_queue_capacity: 1,
                            paid_work: None,
                        }
                        .prepare()
                        .await?
                        .on_host(control.ok_or(crate::ProviderError::FundingRequired)?)?,
                    )
                    .await?)
                })
                    as futures::future::BoxFuture<
                        'static,
                        Result<crate::ProviderHandle, Box<dyn std::error::Error + Send + Sync>>,
                    >
            })
        };
        let host = HostHandle::start(HostOptions {
            control: Some((
                f.node.clone(),
                crate::ProviderControl {
                    socket: socket.clone(),
                    tls,
                    remote: RemoteControlAdmission::default(),
                },
            )),
            provider: Some(factory),
            gateway: None,
        })
        .await
        .unwrap();
        Self {
            fixture: f,
            host,
            socket,
            tls: client_tls,
            starting,
            release,
            starts,
            forbidden_journal,
        }
    }
    async fn connect(&self, credential: &CredentialSecret) -> Client {
        Arc::new(
            connect_local(
                &self.socket,
                self.tls.clone(),
                "localhost".try_into().unwrap(),
                authority(),
                credential,
                &ROOT.key(),
            )
            .await
            .unwrap(),
        )
    }
    async fn owner(&self) -> Client {
        self.connect(&self.fixture.secret).await
    }
    async fn credential(&self, operation: &str) -> CredentialSecret {
        let admin = self
            .fixture
            .node
            .authenticate(&self.fixture.secret)
            .await
            .unwrap();
        let mut scope = scope(ROOT);
        scope
            .permissions
            .retain(|p| p.operation.as_str() == operation);
        scope.issuance = None;
        scope.delegation_depth = 0;
        self.fixture
            .node
            .issue_credential(&admin, ROOT_GRANT, scope)
            .await
            .unwrap()
            .1
    }
    async fn status(&self) -> HostStatus {
        self.owner()
            .await
            .get_host_status(read_request(ROOT_GRANT))
            .await
            .unwrap()
    }
    fn enable(client: Client) -> tokio::task::JoinHandle<Result<HostStatus, WireStatus>> {
        tokio::spawn(async move { client.set_provider_state(provider_state(true)).await })
    }
}
fn provider_state(enabled: bool) -> SetProviderStateRequest {
    SetProviderStateRequest {
        enabled,
        authorization: ROOT_GRANT.0.to_vec(),
    }
}
fn gateway_state(enabled: bool) -> SetGatewayStateRequest {
    SetGatewayStateRequest {
        enabled,
        authorization: ROOT_GRANT.0.to_vec(),
    }
}
fn access_request() -> GetGatewayAccessRequest {
    GetGatewayAccessRequest {
        authorization: ROOT_GRANT.0.to_vec(),
    }
}

async fn unbound_fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let (store, secret) = NodeStore::bootstrap(
        directory.path(),
        hellas_work::test_support::network(),
        ROOT_GRANT,
        scope(ROOT),
        scope(ROOT),
        None,
        UnixMillis(1000),
    )
    .await
    .unwrap();
    let node = NodeCoordinator::new(store, Arc::new(|| UnixMillis(1000)));
    Fixture {
        service: NodeControl::new(node.clone()),
        directory,
        node,
        secret,
    }
}
fn bind_request(enrollment: Vec<u8>) -> BindProviderRequest {
    BindProviderRequest {
        authorization: ROOT_GRANT.0.to_vec(),
        enrollment,
    }
}

#[tokio::test]
async fn an_unbound_host_serves_control_and_starts_its_provider_once_bound() {
    let h = Harness::with(unbound_fixture().await).await;
    let owner = h.owner().await;
    let status = h.status().await;
    assert!(!status.provider_configured && status.identity.is_none());
    let provider = status.provider.unwrap();
    assert_eq!(provider.state, RuntimeState::Stopped as i32);
    assert_eq!(provider.detail, "provider is not bound");
    let refused = owner
        .set_provider_state(provider_state(true))
        .await
        .unwrap_err();
    assert_eq!(
        (refused.code(), refused.message()),
        (WireCode::FailedPrecondition, "provider is not bound")
    );
    let enrollment = crate::test_support::provider_enrollment();
    let gateway = h
        .connect(&h.credential(hellas_work::node::GATEWAY_INVOKE).await)
        .await;
    assert_eq!(
        gateway
            .bind_provider(bind_request(enrollment.canonical_bytes()))
            .await
            .unwrap_err()
            .code(),
        WireCode::PermissionDenied
    );
    let mut forged = enrollment.clone();
    forged.genesis.statement.installation_nonce = [9; 32];
    assert_eq!(
        owner
            .bind_provider(bind_request(forged.canonical_bytes()))
            .await
            .unwrap_err()
            .code(),
        WireCode::InvalidArgument
    );
    let bound = owner
        .bind_provider(bind_request(enrollment.canonical_bytes()))
        .await
        .unwrap();
    assert_eq!(bound.provider_genesis, enrollment.content_id().as_bytes());
    let other = hellas_work::test_support::software_enrollment(3, [3; 32]);
    let refused = owner
        .bind_provider(bind_request(other.canonical_bytes()))
        .await
        .unwrap_err();
    assert_eq!(
        (refused.code(), refused.message()),
        (WireCode::FailedPrecondition, "provider already bound")
    );
    let status = h.status().await;
    assert!(status.provider_configured);
    assert_eq!(
        status.identity.unwrap().attestation,
        AttestationState::Software as i32
    );
    h.release.add_permits(1);
    let status = within(owner.set_provider_state(provider_state(true)))
        .await
        .unwrap();
    assert_eq!(status.provider.unwrap().state, RuntimeState::Running as i32);
    drop(owner);
    h.host.shutdown().await.unwrap();
}

#[tokio::test]
async fn status_only_credentials_cannot_control_services_or_read_gateway_secrets() {
    let h = Harness::new().await;
    let reader = h
        .connect(&h.credential(hellas_work::node::HOST_STATUS).await)
        .await;
    reader
        .get_host_status(read_request(ROOT_GRANT))
        .await
        .unwrap();
    assert_eq!(
        reader
            .set_provider_state(provider_state(true))
            .await
            .unwrap_err()
            .code(),
        WireCode::PermissionDenied
    );
    assert_eq!(
        reader
            .set_gateway_state(gateway_state(true))
            .await
            .unwrap_err()
            .code(),
        WireCode::PermissionDenied
    );
    assert_eq!(
        reader
            .get_gateway_access(access_request())
            .await
            .unwrap_err()
            .code(),
        WireCode::PermissionDenied
    );
    assert_eq!(h.starts.load(Ordering::SeqCst), 0);
    h.host.shutdown().await.unwrap();
}

#[tokio::test]
async fn an_unmounted_gateway_refuses_state_changes() {
    let h = Harness::new().await;
    let owner = h.owner().await;
    assert!(h.status().await.gateway.is_none());
    for enabled in [false, true] {
        assert_eq!(
            owner
                .set_gateway_state(gateway_state(enabled))
                .await
                .unwrap_err()
                .code(),
            WireCode::Unimplemented
        );
    }
    h.host.shutdown().await.unwrap();
}

#[tokio::test]
async fn standalone_node_control_reports_unmounted_lifecycle() {
    let f = fixture().await;
    let (tls, client_tls) = tls_configs();
    let socket = f.directory.path().join("standalone.sock");
    let listener = f.service.bind_local(&socket, tls).unwrap();
    let client = connect_local(
        &socket,
        client_tls,
        "localhost".try_into().unwrap(),
        authority(),
        &f.secret,
        &ROOT.key(),
    )
    .await
    .unwrap();
    let status = client
        .get_host_status(read_request(ROOT_GRANT))
        .await
        .unwrap();
    assert!(status.provider.is_none());
    assert!(status.gateway.is_none());
    assert_eq!(
        client
            .set_provider_state(provider_state(true))
            .await
            .unwrap_err()
            .code(),
        WireCode::Unimplemented
    );
    assert_eq!(
        client
            .set_gateway_state(gateway_state(true))
            .await
            .unwrap_err()
            .code(),
        WireCode::Unimplemented
    );
    assert_eq!(
        client
            .get_gateway_access(access_request())
            .await
            .unwrap_err()
            .code(),
        WireCode::Unimplemented
    );
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn eight_lifecycle_commands_can_queue_over_rpc() {
    let h = Harness::new().await;
    let first = Harness::enable(h.owner().await);
    within(h.starting.notified()).await;
    assert_eq!(
        h.status().await.provider.unwrap().state,
        RuntimeState::Starting as i32
    );
    let mut pending = tokio::task::JoinSet::new();
    for _ in 0..9 {
        let client = h.owner().await;
        pending.spawn(async move { client.set_provider_state(provider_state(true)).await });
    }
    // The first completed RPC must be the ninth queued command's refusal.
    assert_eq!(
        within(pending.join_next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .code(),
        WireCode::ResourceExhausted
    );
    assert_eq!(pending.len(), 8);
    h.release.add_permits(1);
    assert_eq!(
        within(first)
            .await
            .unwrap()
            .unwrap()
            .provider
            .unwrap()
            .state,
        RuntimeState::Running as i32
    );
    while let Some(result) = within(pending.join_next()).await {
        assert_eq!(
            result.unwrap().unwrap().provider.unwrap().state,
            RuntimeState::Running as i32
        );
    }
    assert_eq!(h.starts.load(Ordering::SeqCst), 1);
    h.host.shutdown().await.unwrap();
}

#[tokio::test]
async fn accepted_start_survives_requester_cancellation() {
    let h = Harness::new().await;
    let credential = h
        .credential(hellas_work::node::HOST_PROVIDER_CONFIGURE)
        .await;
    let request = Harness::enable(h.connect(&credential).await);
    within(h.starting.notified()).await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    let admin = h
        .fixture
        .node
        .authenticate(&h.fixture.secret)
        .await
        .unwrap();
    h.fixture
        .node
        .revoke_credential(&admin, ROOT_GRANT, credential.id(), Revision(1))
        .await
        .unwrap();
    h.release.add_permits(1);
    let status = within(Harness::enable(h.owner().await))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status.provider.unwrap().state, RuntimeState::Running as i32);
    assert_eq!(h.starts.load(Ordering::SeqCst), 1);
    h.host.shutdown().await.unwrap();
}

#[tokio::test]
async fn provider_restart_retains_the_host_control_writer() {
    let h = Harness::new().await;
    h.release.add_permits(1);
    let owner = h.owner().await;
    for enabled in [true, false, true, false] {
        let status = within(owner.set_provider_state(provider_state(enabled)))
            .await
            .unwrap();
        assert_eq!(
            status.provider.unwrap().state,
            if enabled {
                RuntimeState::Running
            } else {
                RuntimeState::Stopped
            } as i32
        );
        if enabled {
            assert_eq!(
                status.endpoint,
                SecretKey::from_bytes(&[5; 32]).public().to_string()
            );
            assert_eq!(
                status.identity.unwrap().attestation,
                AttestationState::Software as i32
            );
        }
        assert_eq!(h.status().await.machine.unwrap().max_in_flight, 4);
        assert_err!(
            NodeStore::open(
                h.fixture.directory.path(),
                hellas_work::test_support::network(),
                Some(crate::test_support::provider_enrollment()),
                UnixMillis(1000)
            )
            .await,
            hellas_work::work_store::grant::NodeStoreError::Journal(
                hellas_work::work_store::journal::JournalError::Locked { .. }
            )
        );
    }
    assert_eq!(h.starts.load(Ordering::SeqCst), 2);
    assert!(
        !h.forbidden_journal.exists(),
        "host startup must reuse its writer"
    );
    drop(owner);
    h.host.shutdown().await.unwrap();
    drop(h.fixture.service);
    drop(h.fixture.node);
    NodeStore::open(
        h.fixture.directory.path(),
        hellas_work::test_support::network(),
        Some(crate::test_support::provider_enrollment()),
        UnixMillis(1000),
    )
    .await
    .unwrap();
}

async fn gateway_host(
    world: &crate::test_support::Host,
) -> (HostHandle, Client, Client, crate::test_support::RemoteHost) {
    let remote = world.remote().await;
    let options = world.responses_options(remote.addresses()).await;
    let (host, client, observer) = controlled_host(
        world.world.service.node(),
        world.world.secret(ROOT),
        world.root.path(),
        None,
        Some((
            options.access.clone(),
            options.into_factory(SecretKey::from_bytes(&[3; 32])),
        )),
    )
    .await;
    (host, client, observer, remote)
}

async fn controlled_host(
    node: NodeCoordinator,
    secret: &CredentialSecret,
    directory: &std::path::Path,
    provider: Option<host::ProviderFactory>,
    gateway: Option<(hellas_gateway::GatewayAccess, host::GatewayFactory)>,
) -> (HostHandle, Client, Client) {
    let (tls, client_tls) = tls_configs();
    let socket = directory.join("control.sock");
    let host = HostHandle::start(HostOptions {
        control: Some((
            node,
            crate::ProviderControl {
                socket: socket.clone(),
                tls,
                remote: RemoteControlAdmission::default(),
            },
        )),
        provider,
        gateway,
    })
    .await
    .unwrap();
    let observer = Arc::new(
        connect_local(
            &socket,
            client_tls.clone(),
            "localhost".try_into().unwrap(),
            authority(),
            secret,
            &ROOT.key(),
        )
        .await
        .unwrap(),
    );
    let client = Arc::new(
        connect_local(
            socket,
            client_tls,
            "localhost".try_into().unwrap(),
            authority(),
            secret,
            &ROOT.key(),
        )
        .await
        .unwrap(),
    );
    (host, client, observer)
}

#[tokio::test]
async fn set_gateway_state_starts_the_gateway_chosen_at_run_time() {
    let world = crate::test_support::Host::builder().build().await;
    let remote = world.remote().await;
    let options = world.responses_options(remote.addresses()).await;
    let access = options.access.clone();
    let chosen = options.into_factory(SecretKey::from_bytes(&[3; 32]));
    let starts = Arc::new(AtomicUsize::new(0));
    let factory: host::GatewayFactory = {
        let (node, starts) = (world.world.service.node(), starts.clone());
        Arc::new(move |access: hellas_gateway::GatewayAccess| {
            assert!(access.shares_writer(&node));
            starts.fetch_add(1, Ordering::SeqCst);
            chosen(access)
        })
    };
    let (host, client, _observer) = controlled_host(
        world.world.service.node(),
        world.world.secret(ROOT),
        world.root.path(),
        None,
        Some((access, factory)),
    )
    .await;
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    let status = client.set_gateway_state(gateway_state(true)).await.unwrap();
    assert_eq!(status.gateway.unwrap().state, RuntimeState::Running as i32);
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    client.get_gateway_access(access_request()).await.unwrap();
    host.shutdown().await.unwrap();
    remote.shutdown().await;
}

#[tokio::test]
async fn failed_provider_start_reports_its_error() {
    let f = fixture().await;
    let factory: host::ProviderFactory = Arc::new(|_| {
        Box::pin(async {
            let panicked = tokio::spawn(async { panic!("model weights are missing") })
                .await
                .unwrap_err();
            Err(crate::ProviderError::from(panicked).into())
        })
    });
    let (host, client, _observer) = controlled_host(
        f.node.clone(),
        &f.secret,
        f.directory.path(),
        Some(factory),
        None,
    )
    .await;
    assert_eq!(
        client
            .set_provider_state(provider_state(true))
            .await
            .unwrap_err()
            .code(),
        WireCode::Unavailable
    );
    let provider = client
        .get_host_status(read_request(ROOT_GRANT))
        .await
        .unwrap()
        .provider
        .unwrap();
    assert_eq!(provider.state, RuntimeState::Failed as i32);
    assert!(
        provider.detail.starts_with("provider task failed: task ")
            && provider
                .detail
                .ends_with("panicked with message \"model weights are missing\""),
        "{}",
        provider.detail
    );
    host.shutdown().await.unwrap();
}

#[tokio::test]
async fn stopped_gateway_does_not_disclose_access() {
    let world = crate::test_support::Host::builder().build().await;
    let (host, client, _observer, remote) = gateway_host(&world).await;
    assert_eq!(
        client
            .get_gateway_access(access_request())
            .await
            .unwrap_err()
            .code(),
        WireCode::FailedPrecondition
    );
    client.set_gateway_state(gateway_state(true)).await.unwrap();
    client.get_gateway_access(access_request()).await.unwrap();
    client
        .set_gateway_state(gateway_state(false))
        .await
        .unwrap();
    assert_eq!(
        client
            .get_gateway_access(access_request())
            .await
            .unwrap_err()
            .code(),
        WireCode::FailedPrecondition
    );
    host.shutdown().await.unwrap();
    remote.shutdown().await;
}

#[tokio::test]
async fn stopping_gateway_drains_in_flight_work() {
    use hellas_work::test_support::backend::{Backend, Completion};
    let backend = Backend {
        finish: Completion::Permits(Arc::new(Semaphore::new(0))),
        ..Default::default()
    };
    let world = crate::test_support::Host::builder()
        .with_backend(backend)
        .build()
        .await;
    let (host, client, observer, remote) = gateway_host(&world).await;
    client.set_gateway_state(gateway_state(true)).await.unwrap();
    let access = client.get_gateway_access(access_request()).await.unwrap();
    let request = tokio::spawn(async move {
        let response = reqwest::Client::new()
            .post(format!("{}/v1/responses", access.address))
            .bearer_auth(access.bearer)
            .json(&serde_json::json!({"model":"fixture","input":"hello","max_output_tokens":8}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        response.bytes().await.unwrap();
    });
    within(world.backend.started.notified()).await;
    let stopping =
        tokio::spawn(async move { client.set_gateway_state(gateway_state(false)).await });
    // Status uses a separate connection while the stop RPC waits for physical completion.
    within(async {
        loop {
            let status = observer
                .get_host_status(read_request(ROOT_GRANT))
                .await
                .unwrap();
            if status.gateway.unwrap().state == RuntimeState::Stopping as i32 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(!stopping.is_finished());
    world.backend.finish.release();
    assert_eq!(
        within(stopping)
            .await
            .unwrap()
            .unwrap()
            .gateway
            .unwrap()
            .state,
        RuntimeState::Stopped as i32
    );
    within(request).await.unwrap();
    assert_eq!(world.backend.calls.load(Ordering::SeqCst), 1);
    host.shutdown().await.unwrap();
    remote.shutdown().await;
}
