//! The bilateral acceptance exchange: what each side has on its disk
//! before it releases a signature, and what it answers when it will not.
//!
//! Replay reopens the actual journals after releasing their writers;
//! abrupt process-loss coverage is in the SDK lifecycle target. The happy
//! path runs over a real multiplexed
//! transport, so the request is framed, routed by method id, decoded,
//! and answered rather than handed to a function.

use hellas_channel::test_support::HANG_GUARD;
use hellas_private::StoreLocation;
use std::sync::Arc;
use support::temp;

use hellas_auth::Digest;
use hellas_auth::PublicKey;
use hellas_channel::job::{prepared_input_digest, propose as propose_authorization};
use hellas_channel::model::setup::{ReadyChannel, WorkChannelDescriptor};
use hellas_channel::model::work::{
    JobDeadlines, PaidChannel, PaidJobAuthorizationV2, PrivateRecord as _, signing_hash, work_id,
};
use hellas_channel::test_support::channel::accept_uploaded_service;
use hellas_channel::test_support::channel::{
    CURSOR, OMISSION_BOND, PAYMENT_RESERVE, PAYMENT_VALUE, PRICE, SALT, advance, bundle,
    bundle_bytes, channel_policy, client, deadlines, descriptor,
    descriptor_with as descriptor_with_policy, invocation_request, manifest, network, origin,
    payload_at, payment_policy, payment_terms, provider, settlement, signer, work_policy,
};
use hellas_channel::work::{
    ClientChannel as _, ClientEndpoint, ClientService, CloseEndpoint, EndpointError, JobProposal,
    ProposeError, ProviderEndpoint, WorkRefusal, WorkService, propose_work,
};
use hellas_channel::work_close::CloseChannel as _;
use hellas_channel::work_store::{
    Channel, ChannelRecord, ChannelStore, JobPhase, JobState, Role, SetupOrigin, TerminalOutcome,
};
use hellas_kernel::{
    EdgeId, EdgeValues, Fees, PayloadHash, Secp256k1Signer, Secp256k1Verifier, Sig,
    SigVerifier as _, WorkPaymentSettlement, work_payment_settlement,
};
use hellas_rpc::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, WorkAccepted, WorkRefusalCode, WorkRefused,
    accept_work_response::Outcome,
};
use hellas_rpc::protocol::invocation::{PreparedInvocation, compute};

use hellas_rpc::ContentId;
use hellas_rpc::services::work::Work;
use hellas_wire::mux::MuxTransport;
use hellas_wire::{ServiceMarker, StreamTransport};

mod support;

// ── Fixture ───────────────────────────────────────────────────────────

/// A third party with no role on this channel.
fn stranger() -> Secp256k1Signer {
    signer(0x23)
}

fn ready() -> ReadyChannel {
    ready_with_descriptor(descriptor())
}

fn ready_with_descriptor(descriptor: WorkChannelDescriptor) -> ReadyChannel {
    hellas_channel::test_support::channel::ready_of(&descriptor, CURSOR)
}

async fn store(root: &std::path::Path, role: Role) -> ChannelStore {
    store_with(root, role, settlement()).await
}

async fn store_with(
    root: &std::path::Path,
    role: Role,
    settlement: WorkPaymentSettlement,
) -> ChannelStore {
    let content = hellas_channel::test_support::channel::content_store(root).await;
    let location = StoreLocation::for_test(root);
    let store = match ChannelStore::open(
        &location,
        ready().channel().clone(),
        settlement,
        role,
        origin(),
        content.clone(),
        &Secp256k1Verifier::new(),
    )
    .await
    {
        Ok(store) => store,
        Err(error) => panic!("the fixture store opens: {error}"),
    };
    content.finish_recovery().await.unwrap();
    store
}

/// A store that has processed one finalized block, which is what lets
/// either endpoint measure a deadline.
async fn store_at_cursor(root: &std::path::Path, role: Role) -> ChannelStore {
    at_height(store(root, role).await, CURSOR).await
}

async fn at_height(mut store: ChannelStore, height: u64) -> ChannelStore {
    advance(&mut store, height).await;
    store
}

async fn raw_client_endpoint(root: &std::path::Path) -> ClientEndpoint {
    match ClientEndpoint::new(ready(), store_at_cursor(root, Role::Client).await, client()) {
        Ok(endpoint) => endpoint,
        Err(error) => panic!("the fixture client endpoint binds: {error}"),
    }
}

async fn client_endpoint(root: &std::path::Path) -> ClientService {
    hellas_channel::test_support::channel::client_service(raw_client_endpoint(root).await, ready())
        .await
}

async fn provider_service(root: &std::path::Path) -> WorkService {
    match ProviderEndpoint::new(
        ready(),
        store_at_cursor(root, Role::Provider).await,
        provider(),
    ) {
        Ok(endpoint) => WorkService::new(endpoint),
        Err(error) => panic!("the fixture provider endpoint binds: {error}"),
    }
}

// In-process replay must finish SQLite pool shutdown before opening another
// writer. This changes no journal records; process-loss tests use SIGKILL.
async fn close_client(endpoint: &mut impl hellas_channel::work::ClientChannel) {
    endpoint
        .client()
        .await
        .unwrap()
        .store()
        .await
        .unwrap()
        .content_store()
        .close()
        .await;
}
async fn close_provider(service: WorkService) {
    service
        .drive()
        .unwrap()
        .store()
        .await
        .unwrap()
        .content_store()
        .close()
        .await;
}

// ── The prepared inputs a job executes from ───────────────────────────

fn proposal(nonce: u8) -> JobProposal {
    JobProposal {
        prepared_input: bundle(nonce),
        deadlines: deadlines(),
    }
}

/// The authorization the client would build for one proposal at one
/// nonce, computed here rather than taken from the endpoint.
fn authorization(nonce: u8, proposal_nonce: u64) -> PaidJobAuthorizationV2 {
    match propose_authorization(
        ready().channel(),
        &work_policy(),
        &payment_policy(),
        &bundle(nonce),
        proposal_nonce,
        deadlines(),
    ) {
        Ok(authorization) => authorization,
        Err(error) => panic!("the fixture authorization builds: {error}"),
    }
}

/// A request built by hand rather than by the client endpoint, so a
/// provider test can vary exactly one field of it.
fn request(authorization: &PaidJobAuthorizationV2, signature: Sig, nonce: u8) -> AcceptWorkRequest {
    AcceptWorkRequest {
        route: Some(hellas_rpc::pb::work::WorkRoute::payment(
            authorization.channel_id,
        )),
        authorization: authorization.encode(),
        client_signature: signature.as_bytes().to_vec(),
        prepared_input: hellas_rpc::protocol::content::encode_reference(
            hellas_rpc::ContentRef::new(
                ContentId::hash(&bundle_bytes(nonce)),
                bundle_bytes(nonce).len() as u64,
            ),
        ),
    }
}

fn signed_request(nonce: u8, proposal_nonce: u64) -> AcceptWorkRequest {
    signed_request_with(nonce, proposal_nonce, deadlines())
}

fn signed_request_with(
    nonce: u8,
    proposal_nonce: u64,
    deadlines: JobDeadlines,
) -> AcceptWorkRequest {
    let authorization = match propose_authorization(
        ready().channel(),
        &work_policy(),
        &payment_policy(),
        &bundle(nonce),
        proposal_nonce,
        deadlines,
    ) {
        Ok(authorization) => authorization,
        Err(error) => panic!("the fixture authorization builds: {error}"),
    };
    let signature = client().sign(signing_hash(work_id(ready().channel(), &authorization)));
    request(&authorization, signature, nonce)
}

// ── Canonical chain objects, spelled out ──────────────────────────────

// ── Reading answers ───────────────────────────────────────────────────

fn accepted_signature(response: &AcceptWorkResponse) -> Sig {
    match response.outcome.as_ref() {
        Some(Outcome::Accepted(accepted)) => {
            let Ok(bytes) = <[u8; Sig::LENGTH]>::try_from(&accepted.provider_signature[..]) else {
                panic!("an accepted signature is 64 bytes");
            };
            Sig::from_bytes(bytes)
        }
        other => panic!("expected an acceptance, got {other:?}"),
    }
}

fn refusal_code(response: &AcceptWorkResponse) -> WorkRefusalCode {
    match response.outcome.as_ref() {
        Some(Outcome::Refused(refused)) => match WorkRefusalCode::try_from(refused.code) {
            Ok(code) => code,
            Err(_) => panic!("a refusal names a defined code, got {}", refused.code),
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn refusal_text(response: &AcceptWorkResponse) -> String {
    match response.outcome.as_ref() {
        Some(Outcome::Refused(refused)) => refused.reason.clone(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ── An in-memory pipe pair, so the wire is a real wire ────────────────

use hellas_channel::test_support::transport;
use transport::transport_pair;

/// Serves one provider endpoint over one transport until the caller
/// drops the returned handle.
fn serve(transport: MuxTransport, service: WorkService) -> tokio::task::JoinHandle<()> {
    hellas_channel::test_support::channel::serve_work(transport, service)
}

// ── The exchange, over a real transport ───────────────────────────────

#[tokio::test]
async fn an_accepted_exchange_leaves_both_signatures_on_both_disks() {
    let client_root = temp();
    let provider_root = temp();
    let service = provider_service(provider_root.path()).await;
    let (client_transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());

    let mut endpoint = client_endpoint(client_root.path()).await;
    let accepted = propose_work(
        client_transport,
        &mut endpoint,
        &proposal(1),
        &hellas_channel::test_support::channel::program_content().await,
        None,
    )
    .await;
    let Ok(work_id) = accepted else {
        panic!("the fixture exchange completes: {accepted:?}");
    };

    // Both endpoints let go of their journals before anything reopens
    // them: the exclusive lock is the store's, and a live server still
    // holds one.
    close_client(&mut endpoint).await;
    drop(endpoint);
    serving.abort();
    let _ = serving.await;
    service
        .drive()
        .unwrap()
        .store()
        .await
        .unwrap()
        .content_store()
        .close()
        .await;
    drop(service);

    // Reopened from the files, not read from the objects that wrote
    // them: what is on the disk is the only thing a restart has.
    let client_store = store(client_root.path(), Role::Client).await;
    let provider_store = store(provider_root.path(), Role::Provider).await;
    for (side, state) in [
        ("client", client_store.state()),
        ("provider", provider_store.state()),
    ] {
        let Some(job) = state.jobs().next() else {
            panic!("the {side} journal holds the accepted job");
        };
        assert_eq!(job.work_id(), work_id, "{side} names the same job");
        assert_eq!(job.phase(), JobPhase::Accepted, "{side} is accepted");
        assert!(
            job.provider_signature().is_some(),
            "{side} holds the co-signature",
        );
    }
}

/// A retained Compute proposal keeps the closure its upload needs, so a
/// restart can send the same signed proposal again; one that never
/// retained it is unresolved, not an empty program.
#[tokio::test]
async fn a_retained_compute_proposal_resumes_after_an_interrupted_preacceptance_rpc() {
    let client_root = temp();
    let provider_root = temp();
    let service = provider_service(provider_root.path()).await;
    let (client_transport, server_transport) = transport_pair();
    let entered = Arc::new(tokio::sync::Notify::new());
    let seen = entered.clone();
    let serving = tokio::spawn(async move {
        let _inbound = server_transport.accept().await.unwrap().unwrap();
        seen.notify_one();
        std::future::pending::<()>().await;
    });
    let mut endpoint = client_endpoint(client_root.path()).await;
    let content = hellas_channel::test_support::channel::program_content().await;
    let pending_proposal = proposal(1);
    {
        let sending = propose_work(
            client_transport,
            &mut endpoint,
            &pending_proposal,
            &content,
            None,
        );
        tokio::pin!(sending);
        tokio::time::timeout(hellas_channel::test_support::HANG_GUARD, async {
            tokio::select! {
                result = &mut sending => panic!("request completed before interruption: {result:?}"),
                _ = entered.notified() => {},
            }
        }).await.unwrap();
    }
    serving.abort();
    let _ = serving.await;
    let id = endpoint
        .client()
        .await
        .unwrap()
        .state()
        .jobs()
        .next()
        .unwrap()
        .work_id();
    assert_eq!(
        endpoint
            .client()
            .await
            .unwrap()
            .state()
            .job_by_id(id)
            .unwrap()
            .phase(),
        JobPhase::HalfSigned,
    );
    close_client(&mut endpoint).await;
    drop(endpoint);

    // The reopened journal can rebuild the exact upload closure from its
    // own store, so the same signed proposal is retryable.
    let store = store_at_cursor(client_root.path(), Role::Client).await;
    let content = store
        .recoverable_content(id)
        .expect("the retained closure reads")
        .expect("the upload retained its closure");
    assert!(matches!(
        content,
        (hellas_store::content::LocalStore::Disk(_), _)
    ));

    let (client_transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service);
    let mut endpoint = ClientEndpoint::new(ready(), store, client()).unwrap();
    let resumed =
        hellas_channel::work::resume_work_proposal(client_transport, &mut endpoint, id, &content)
            .await;
    serving.abort();
    let _ = serving.await;
    assert_eq!(
        resumed.expect("the retained proposal is accepted"),
        id,
        "the provider holds the same signed job",
    );
    assert_eq!(
        endpoint
            .client()
            .await
            .unwrap()
            .state()
            .job_by_id(id)
            .unwrap()
            .phase(),
        JobPhase::Accepted,
    );
    assert_eq!(
        endpoint
            .client()
            .await
            .unwrap()
            .state()
            .job_book()
            .pending_proposal(),
        None
    );
}

#[tokio::test]
async fn a_missing_retained_proposal_root_blocks_recovery_and_collection() {
    use hellas_store::content::{ContentStore, Error, Scope};
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let request = endpoint
        .propose(
            &proposal(2),
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await
        .unwrap();
    let authorization = PaidJobAuthorizationV2::decode(&request.authorization).unwrap();
    let id = work_id(ready().channel(), &authorization);
    let missing = endpoint.client().await.unwrap().state().retained_roots()[&id];
    close_client(&mut endpoint).await;
    drop(endpoint);
    std::fs::remove_file(
        root.path()
            .join("content/objects")
            .join(missing.id().to_string()),
    )
    .unwrap();
    let content = hellas_channel::test_support::channel::content_store(root.path()).await;
    let recovered = ChannelStore::open(
        &hellas_private::StoreLocation::for_test(root.path()),
        ready().channel().clone(),
        settlement(),
        Role::Client,
        origin(),
        content.clone(),
        &Secp256k1Verifier::new(),
    )
    .await;
    assert!(matches!(
        recovered,
        Err(hellas_channel::work_store::WorkStoreError::Content(
            Error::Missing
        ))
    ));
    assert!(matches!(
        content.collect(&Scope::Owner).await,
        Err(Error::Denied)
    ));
}

/// A journaled proposal whose body did not survive replay must not occupy
/// the channel's one proposal slot forever.
///
/// Ephemeral input is never written to the journal, so metadata-only
/// recovery cannot rebuild the request. The job stays half-signed — a late
/// acceptance is still evidence — but the durable exchange marker is
/// released, and the next proposal takes a strictly higher nonce rather
/// than reusing the burned one.
#[tokio::test]
async fn an_unreconstructable_proposal_releases_the_channel_for_a_fresh_nonce() {
    let root = temp();
    let ready = ready_with_descriptor(descriptor_with_policy(
        hellas_channel::test_support::channel::fetch_policy(),
    ));
    let mut endpoint = hellas_channel::test_support::channel::client_service(
        ClientEndpoint::new(
            ready.clone(),
            hellas_channel::test_support::channel::store_at(
                root.path(),
                &ready,
                Role::Client,
                CURSOR,
            )
            .await,
            client(),
        )
        .unwrap(),
        ready.clone(),
    )
    .await;
    let request = endpoint
        .propose(
            &JobProposal {
                prepared_input: hellas_channel::test_support::channel::fetch_bundle(1),
                deadlines: deadlines(),
            },
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await
        .unwrap();
    let authorization = PaidJobAuthorizationV2::decode(&request.authorization).unwrap();
    let id = work_id(ready.channel(), &authorization);
    assert_eq!(
        endpoint
            .client()
            .await
            .unwrap()
            .state()
            .job_book()
            .pending_proposal(),
        Some(id)
    );
    close_client(&mut endpoint).await;
    drop(endpoint);

    // Metadata-only replay: the authorization survives, the body does not.
    let store =
        hellas_channel::test_support::channel::store_at(root.path(), &ready, Role::Client, CURSOR)
            .await;
    assert_eq!(
        store.state().job_book().pending_proposal(),
        None,
        "the unreconstructable proposal no longer holds the slot",
    );
    assert_eq!(store.state().proposal_nonce_high_water(), 1);
    assert_eq!(
        store.state().job_by_id(id).map(JobState::phase),
        Some(JobPhase::HalfSigned),
        "the signed job is kept for a late acceptance",
    );

    let mut endpoint = hellas_channel::test_support::channel::client_service(
        ClientEndpoint::new(ready.clone(), store, client()).unwrap(),
        ready.clone(),
    )
    .await;
    let request = endpoint
        .propose(
            &JobProposal {
                prepared_input: hellas_channel::test_support::channel::fetch_bundle(2),
                deadlines: deadlines(),
            },
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await
        .expect("a fresh proposal is admitted after the release");
    let next = PaidJobAuthorizationV2::decode(&request.authorization).unwrap();
    assert_eq!(next.proposal_nonce, 2, "the burned nonce is not reused");
    assert_eq!(
        endpoint
            .client()
            .await
            .unwrap()
            .state()
            .job_book()
            .pending_proposal(),
        Some(work_id(ready.channel(), &next)),
    );
}

#[tokio::test]
async fn the_service_answers_a_refusal_over_the_same_wire() {
    let provider_root = temp();
    // A provider that has processed no block cannot measure a deadline.
    let endpoint = match ProviderEndpoint::new(
        ready(),
        store(provider_root.path(), Role::Provider).await,
        provider(),
    ) {
        Ok(endpoint) => endpoint,
        Err(error) => panic!("the endpoint binds: {error}"),
    };
    let service = WorkService::new(endpoint);
    let (client_transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service);

    let client = hellas_rpc::services::work::WorkClientImpl::new(client_transport);
    let response = match client.accept_work(signed_request(1, 1)).await {
        Ok(response) => response,
        Err(status) => panic!("the call completes: {status}"),
    };
    serving.abort();
    assert_eq!(refusal_code(&response), WorkRefusalCode::NotReady);
}

/// One channel has one cursor driver, and naming a different job does
/// not buy a second one.
///
/// The authority is the channel's, not a digest's. A guard keyed on
/// what a caller says would hand the second call its own drive of the
/// same cursor, and the two would fetch every block twice and each treat
/// the other's apply as a redundant re-read of its own.
#[tokio::test]
async fn one_channel_has_one_cursor_driver_whatever_a_second_caller_names() {
    let root = temp();
    let service = provider_service(root.path()).await;
    let held = service.drive().expect("the first driver enters");
    assert!(
        matches!(service.drive(), Err(EndpointError::CatchingUp)),
        "a second driver of this channel is refused",
    );
    assert!(
        service.with_state(|state| state.cursor().0).await.is_ok(),
        "and the one driver does not strand brief journal work",
    );
    drop(held);
    assert!(
        service.drive().is_ok(),
        "the authority comes back when the driver goes",
    );
}

#[test]
fn the_service_catalogue_names_the_work_service() {
    let names: Vec<&str> = hellas_rpc::services::KNOWN_SERVICES
        .iter()
        .map(|service| service.name)
        .collect();
    assert!(
        names.contains(&"hellas.work.v1.Work"),
        "the work service is catalogued, got {names:?}",
    );
    assert_eq!(<Work as ServiceMarker>::ALPN, "/hellas.work.v1.Work/2.0");
}

// ── What the client puts on its disk, and when ────────────────────────

#[tokio::test]
async fn a_client_journals_its_signature_before_the_request_leaves() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let Ok(request) = endpoint
        .propose(
            &proposal(1),
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await
    else {
        panic!("the fixture proposal is accepted by its own rules");
    };
    close_client(&mut endpoint).await;
    drop(endpoint);

    let reopened = store(root.path(), Role::Client).await;
    let Some(job) = reopened.state().jobs().next() else {
        panic!("the journal holds the proposal the caller was handed");
    };
    assert_eq!(job.phase(), JobPhase::HalfSigned);
    assert_eq!(
        job.client_signature().as_bytes().to_vec(),
        request.client_signature,
        "the signature on the disk is the signature on the wire",
    );
    assert_eq!(job.authorization().encode(), request.authorization);
    assert!(
        job.prepared_input().is_empty(),
        "replay keeps only retained references until the body is used"
    );
    assert_eq!(
        hellas_rpc::protocol::content::encode_reference(job.authorization().input_content),
        request.prepared_input
    );
}

#[tokio::test]
async fn a_proposal_refused_before_signing_leaves_no_job() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    // Terminal deadline inside the measured dispatch and delivery
    // margins: legal, ordered, and unreachable.
    let unreachable = JobProposal {
        prepared_input: bundle(1),
        deadlines: JobDeadlines {
            acceptance: 11,
            terminal: 12,
            payment: 30,
        },
    };
    let refused = endpoint
        .propose(
            &unreachable,
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await;
    assert!(
        matches!(refused, Err(ProposeError::Setup(_))),
        "an unreachable terminal deadline is refused, got {refused:?}",
    );
    assert!(
        endpoint
            .client()
            .await
            .unwrap()
            .state()
            .jobs()
            .next()
            .is_none()
    );
    close_client(&mut endpoint).await;
    drop(endpoint);
    assert!(
        store(root.path(), Role::Client)
            .await
            .state()
            .jobs()
            .next()
            .is_none()
    );
}

#[tokio::test]
async fn a_repeat_proposal_returns_the_retained_request() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let Ok(first) = endpoint
        .propose(
            &proposal(1),
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await
    else {
        panic!("the first proposal is built");
    };
    let Ok(second) = endpoint
        .propose(
            &proposal(1),
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await
    else {
        panic!("the same proposal is retained, not rebuilt");
    };
    assert_eq!(first, second, "the retained bytes come back unchanged");
}

#[tokio::test]
async fn a_retained_proposal_survives_restart_expiry_and_policy_change() {
    let root = temp();
    let provider_root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let first = endpoint
        .propose(
            &proposal(1),
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await
        .unwrap();
    let work_id = endpoint
        .client()
        .await
        .unwrap()
        .state()
        .jobs()
        .next()
        .unwrap()
        .work_id();
    let provider_service = provider_service(provider_root.path()).await;
    let response = accept_uploaded_service(&provider_service, &first).await;
    {
        let mut client = endpoint.client().await.unwrap();
        let mut journal = client.store().await.unwrap();
        let content = journal.content_store();
        let before = content.stats().unwrap();
        journal.close().await.unwrap();
        assert_eq!(
            content.stats().unwrap().outstanding,
            before.outstanding,
            "closing a client writer must retain its half-signed output obligation"
        );
    }
    close_client(&mut endpoint).await;
    drop(endpoint); // The provider response was lost before journaling.

    let mut policy = work_policy();
    policy.admissions[0] = hellas_rpc::protocol::invocation::Admission::Compute {
        evaluator: "other/evaluator".into(),
        programs: hellas_rpc::protocol::invocation::ComputePrograms::Any {},
    };
    let changed = ready_with_descriptor(descriptor_with_policy(policy));
    let reopened = at_height(
        store(root.path(), Role::Client).await,
        proposal(1).deadlines.acceptance + 1,
    )
    .await;
    let mut endpoint = ClientEndpoint::new(changed, reopened, client()).unwrap();
    let resumed = endpoint
        .client()
        .await
        .unwrap()
        .resume_proposal(work_id)
        .await
        .unwrap();
    assert_eq!(resumed, first);
    assert_eq!(
        endpoint
            .client()
            .await
            .unwrap()
            .state()
            .proposal_nonce_high_water(),
        1
    );
    assert_eq!(
        accept_uploaded_service(&provider_service, &resumed).await,
        response
    );
    assert_eq!(
        endpoint
            .client()
            .await
            .unwrap()
            .accepted(&response)
            .await
            .unwrap(),
        work_id
    );
}

#[tokio::test]
async fn a_different_proposal_waits_for_the_outstanding_reply() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let first = endpoint
        .propose(
            &proposal(1),
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await
        .unwrap();
    assert!(matches!(
        endpoint
            .propose(
                &proposal(2),
                &hellas_channel::test_support::channel::program_content().await,
                None
            )
            .await,
        Err(ProposeError::Conflict)
    ));
    assert_eq!(endpoint.client().await.unwrap().state().jobs().len(), 1);
    assert_eq!(
        endpoint
            .client()
            .await
            .unwrap()
            .state()
            .proposal_nonce_high_water(),
        1
    );
    assert_eq!(
        endpoint
            .propose(
                &proposal(1),
                &hellas_channel::test_support::channel::program_content().await,
                None
            )
            .await
            .unwrap(),
        first
    );
    let provider_root = temp();
    let provider_service = provider_service(provider_root.path()).await;
    let response = accept_uploaded_service(&provider_service, &first).await;
    endpoint
        .client()
        .await
        .unwrap()
        .accepted(&response)
        .await
        .unwrap();
    assert!(
        endpoint
            .propose(
                &proposal(2),
                &hellas_channel::test_support::channel::program_content().await,
                None
            )
            .await
            .is_ok()
    );
    assert_eq!(
        endpoint.client().await.unwrap().state().jobs().len(),
        2,
        "accepted executions still overlap"
    );
    assert_eq!(
        endpoint
            .client()
            .await
            .unwrap()
            .state()
            .proposal_nonce_high_water(),
        2
    );
    let pending = endpoint
        .client()
        .await
        .unwrap()
        .state()
        .job_book()
        .pending_proposal();
    assert!(matches!(
        endpoint.client().await.unwrap().accepted(&response).await,
        Err(ProposeError::Conflict)
    ));
    assert_eq!(
        endpoint
            .client()
            .await
            .unwrap()
            .state()
            .job_book()
            .pending_proposal(),
        pending,
        "a signed reply for another job cannot answer this exchange"
    );
}

#[tokio::test]
async fn a_known_refusal_releases_only_the_proposal_slot_durably() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let first = endpoint
        .propose(
            &proposal(1),
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await
        .unwrap();
    let id = endpoint
        .client()
        .await
        .unwrap()
        .state()
        .job_book()
        .pending_proposal()
        .unwrap();
    let refused = AcceptWorkResponse {
        outcome: Some(Outcome::Refused(WorkRefused {
            grant: None,
            code: WorkRefusalCode::NotReady as i32,
            reason: String::new(),
        })),
    };
    assert!(matches!(
        endpoint.client().await.unwrap().accepted(&refused).await,
        Err(ProposeError::Refused { .. })
    ));
    assert_eq!(
        endpoint
            .client()
            .await
            .unwrap()
            .state()
            .job_book()
            .pending_proposal(),
        None
    );
    assert_eq!(
        endpoint
            .client()
            .await
            .unwrap()
            .state()
            .job_by_id(id)
            .unwrap()
            .phase(),
        JobPhase::HalfSigned
    );
    close_client(&mut endpoint).await;
    drop(endpoint);
    let mut reopened = client_endpoint(root.path()).await;
    assert_eq!(
        reopened
            .client()
            .await
            .unwrap()
            .state()
            .job_book()
            .pending_proposal(),
        None
    );
    assert_eq!(
        reopened
            .client()
            .await
            .unwrap()
            .resume_proposal(id)
            .await
            .unwrap(),
        first
    );
    assert_eq!(
        reopened
            .client()
            .await
            .unwrap()
            .state()
            .job_book()
            .pending_proposal(),
        Some(id)
    );
    assert!(matches!(
        reopened
            .propose(
                &proposal(2),
                &hellas_channel::test_support::channel::program_content().await,
                None
            )
            .await,
        Err(ProposeError::Conflict)
    ));
    reopened
        .client()
        .await
        .unwrap()
        .accepted(&refused)
        .await
        .unwrap_err();
    assert!(
        reopened
            .propose(
                &proposal(2),
                &hellas_channel::test_support::channel::program_content().await,
                None
            )
            .await
            .is_ok()
    );
    assert_eq!(reopened.client().await.unwrap().state().jobs().len(), 2);
}

#[tokio::test]
async fn a_lost_reply_blocks_new_nonces_across_restart_and_malformed_replies() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let request = endpoint
        .propose(
            &proposal(1),
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await
        .unwrap();
    let id = endpoint
        .client()
        .await
        .unwrap()
        .state()
        .job_book()
        .pending_proposal()
        .unwrap();
    close_client(&mut endpoint).await;
    drop(endpoint);
    let mut reopened = client_endpoint(root.path()).await;
    // The retained share is journaled before the request can leave; replay
    // preserves the uncertain exchange until retry or a conclusive response.
    assert_eq!(
        reopened
            .client()
            .await
            .unwrap()
            .state()
            .job_book()
            .pending_proposal(),
        Some(id)
    );
    assert_eq!(
        reopened
            .client()
            .await
            .unwrap()
            .state()
            .proposal_nonce_high_water(),
        1
    );
    assert_eq!(
        reopened
            .client()
            .await
            .unwrap()
            .resume_proposal(id)
            .await
            .unwrap(),
        request
    );
    assert_eq!(
        reopened
            .client()
            .await
            .unwrap()
            .state()
            .job_book()
            .pending_proposal(),
        Some(id)
    );
    assert!(matches!(
        reopened
            .propose(
                &proposal(2),
                &hellas_channel::test_support::channel::program_content().await,
                None
            )
            .await,
        Err(ProposeError::Conflict)
    ));
    assert!(
        reopened
            .client()
            .await
            .unwrap()
            .accepted(&AcceptWorkResponse::default())
            .await
            .is_err()
    );
    assert_eq!(
        reopened
            .client()
            .await
            .unwrap()
            .state()
            .job_book()
            .pending_proposal(),
        Some(id)
    );
}

#[tokio::test]
async fn an_acceptance_with_no_proposal_has_nothing_to_answer() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let authorization = authorization(1, 1);
    let signature = provider().sign(signing_hash(work_id(ready().channel(), &authorization)));
    let response = accepted_response(signature);
    let refused = endpoint.client().await.unwrap().accepted(&response).await;
    assert!(
        matches!(refused, Err(ProposeError::NoOpenJob)),
        "an acceptance answers a proposal or nothing, got {refused:?}",
    );
}

#[tokio::test]
async fn a_co_signature_from_another_key_is_not_an_acceptance() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let Ok(_) = endpoint
        .propose(
            &proposal(1),
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await
    else {
        panic!("the proposal is built");
    };
    let authorization = authorization(1, 1);
    let forged = stranger().sign(signing_hash(work_id(ready().channel(), &authorization)));
    let refused = endpoint
        .client()
        .await
        .unwrap()
        .accepted(&accepted_response(forged))
        .await;
    assert!(
        matches!(refused, Err(ProposeError::Store(_))),
        "only the provider's key accepts, got {refused:?}",
    );
    assert_eq!(
        phase_of(endpoint.client().await.unwrap().state()),
        Some(JobPhase::HalfSigned),
        "a forged co-signature moves nothing",
    );
}

#[tokio::test]
async fn a_refusal_is_read_back_as_the_refusal_it_names() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let Ok(_) = endpoint
        .propose(
            &proposal(1),
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await
    else {
        panic!("the proposal is built");
    };
    let response = AcceptWorkResponse {
        outcome: Some(Outcome::Refused(WorkRefused {
            grant: None,
            code: WorkRefusalCode::Declined as i32,
            reason: "no".into(),
        })),
    };
    let refused = endpoint.client().await.unwrap().accepted(&response).await;
    assert!(
        matches!(
            refused,
            Err(ProposeError::Refused {
                refusal: WorkRefusal::Declined,
                ..
            })
        ),
        "the client reads the code the provider sent, got {refused:?}",
    );
}

#[tokio::test]
async fn every_wire_code_reads_back_as_the_refusal_it_names() {
    // A known refusal releases the proposal slot, so each code is read
    // against its own fresh proposal.
    for (code, refusal) in [
        (WorkRefusalCode::NotReady, WorkRefusal::NotReady),
        (WorkRefusalCode::Expired, WorkRefusal::Expired),
        (WorkRefusalCode::Invalid, WorkRefusal::Invalid),
        (WorkRefusalCode::Conflict, WorkRefusal::Conflict),
        (WorkRefusalCode::Declined, WorkRefusal::Declined),
        (WorkRefusalCode::Unavailable, WorkRefusal::Unavailable),
    ] {
        let root = temp();
        let mut endpoint = client_endpoint(root.path()).await;
        let Ok(_) = endpoint
            .propose(
                &proposal(1),
                &hellas_channel::test_support::channel::program_content().await,
                None,
            )
            .await
        else {
            panic!("the proposal is built");
        };
        let response = AcceptWorkResponse {
            outcome: Some(Outcome::Refused(WorkRefused {
                grant: None,
                code: code as i32,
                reason: "no".into(),
            })),
        };
        let refused = endpoint.client().await.unwrap().accepted(&response).await;
        assert!(
            matches!(refused, Err(ProposeError::Refused { refusal: got, .. }) if got == refusal),
            "{code:?} reads back as {refusal:?}, got {refused:?}",
        );
    }
}

#[tokio::test]
async fn a_response_this_service_does_not_define_is_malformed() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let Ok(_) = endpoint
        .propose(
            &proposal(1),
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await
    else {
        panic!("the proposal is built");
    };
    for (what, response) in [
        ("no outcome", AcceptWorkResponse { outcome: None }),
        (
            "unspecified refusal",
            AcceptWorkResponse {
                outcome: Some(Outcome::Refused(WorkRefused {
                    grant: None,
                    code: WorkRefusalCode::Unspecified as i32,
                    reason: String::new(),
                })),
            },
        ),
        (
            "unassigned refusal",
            AcceptWorkResponse {
                outcome: Some(Outcome::Refused(WorkRefused {
                    grant: None,
                    code: 99,
                    reason: String::new(),
                })),
            },
        ),
        (
            "short signature",
            AcceptWorkResponse {
                outcome: Some(Outcome::Accepted(WorkAccepted {
                    provider_signature: vec![0; Sig::LENGTH - 1],
                    work_id: vec![0; Digest::LEN],
                })),
            },
        ),
    ] {
        let refused = endpoint.client().await.unwrap().accepted(&response).await;
        assert!(
            matches!(refused, Err(ProposeError::Malformed(_))),
            "{what} is malformed, got {refused:?}",
        );
    }
}

fn accepted_response(signature: Sig) -> AcceptWorkResponse {
    let authorization = authorization(1, 1);
    AcceptWorkResponse {
        outcome: Some(Outcome::Accepted(WorkAccepted {
            provider_signature: signature.as_bytes().to_vec(),
            work_id: work_id(ready().channel(), &authorization)
                .as_bytes()
                .to_vec(),
        })),
    }
}

fn phase_of(state: &Channel) -> Option<JobPhase> {
    state.jobs().next().map(JobState::phase)
}

// ── What the provider puts on its disk, and when ──────────────────────

#[tokio::test]
async fn the_co_signature_is_on_the_disk_before_it_is_answered() {
    let root = temp();
    let endpoint = provider_service(root.path()).await;
    let response = accept_uploaded_service(&endpoint, &signed_request(1, 1)).await;
    let signature = accepted_signature(&response);
    close_provider(endpoint).await;

    let reopened = store(root.path(), Role::Provider).await;
    let Some(job) = reopened.state().jobs().next() else {
        panic!("the journal holds the job it answered for");
    };
    assert_eq!(job.phase(), JobPhase::Accepted);
    assert_eq!(job.provider_signature(), Some(signature));
}

#[tokio::test]
async fn nothing_is_journaled_for_a_proposal_that_is_refused() {
    let root = temp();
    let endpoint = provider_service(root.path()).await;
    let before = endpoint
        .with_state(|state| state.jobs().next().is_none())
        .await
        .unwrap();
    // Another channel's authorization: the channel id is the first
    // thing `check_authorization` compares.
    let mut foreign = authorization(1, 1);
    foreign.channel_id = Digest::from_bytes([0x00; 32]);
    let signature = client().sign(signing_hash(work_id(ready().channel(), &foreign)));
    let response = accept_uploaded_service(&endpoint, &request(&foreign, signature, 1)).await;

    assert_eq!(refusal_code(&response), WorkRefusalCode::Invalid);
    assert!(
        before
            && endpoint
                .with_state(|state| state.jobs().next().is_none())
                .await
                .unwrap()
    );
    close_provider(endpoint).await;
    assert!(
        store(root.path(), Role::Provider)
            .await
            .state()
            .jobs()
            .next()
            .is_none()
    );
}

/// A proposal the journal's own rules would take, refused by the rules
/// that run before it.
///
/// `apply_proposed` checks the channel, the bundle digest, the client
/// signature, and the nonce. It does not check the price, the policy
/// digest, or the deadline order, because nothing in a journal knows
/// what a policy fixed. So this is the case that separates the two: with
/// the acceptance checks removed, these bytes are journaled, credited,
/// and co-signed.
#[tokio::test]
async fn a_price_the_policy_does_not_fix_is_refused_before_anything_is_journaled() {
    let root = temp();
    let endpoint = provider_service(root.path()).await;
    let mut overpriced = authorization(1, 1);
    overpriced.price = PRICE + 1;
    let signature = client().sign(signing_hash(work_id(ready().channel(), &overpriced)));
    let response = accept_uploaded_service(&endpoint, &request(&overpriced, signature, 1)).await;

    assert_eq!(
        refusal_code(&response),
        WorkRefusalCode::Invalid,
        "{}",
        refusal_text(&response),
    );
    assert!(
        endpoint
            .with_state(|state| state.jobs().next().is_none())
            .await
            .unwrap()
    );
    close_provider(endpoint).await;
    assert!(
        store(root.path(), Role::Provider)
            .await
            .state()
            .jobs()
            .next()
            .is_none()
    );
}

#[tokio::test]
async fn a_retry_returns_the_retained_co_signature() {
    let root = temp();
    let endpoint = provider_service(root.path()).await;
    let first =
        accepted_signature(&accept_uploaded_service(&endpoint, &signed_request(1, 1)).await);
    let second =
        accepted_signature(&accept_uploaded_service(&endpoint, &signed_request(1, 1)).await);
    assert_eq!(first, second);
}

#[tokio::test]
async fn a_retry_after_the_deadline_still_returns_the_retained_signature() {
    let root = temp();
    let client_root = temp();
    let mut caller = client_endpoint(client_root.path()).await;
    let request = caller
        .propose(
            &proposal(1),
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await
        .expect("the client journals its proposal");
    let endpoint = provider_service(root.path()).await;
    let first = accepted_signature(&accept_uploaded_service(&endpoint, &request).await);
    close_provider(endpoint).await;
    close_client(&mut caller).await;
    drop(caller); // The acceptance acknowledgement never reached the client.

    // Both sides restart. The provider is past acceptance and close-only,
    // while the client still has only its own signature.
    let late = at_height(
        store(root.path(), Role::Provider).await,
        deadlines().acceptance + 1,
    )
    .await;
    let service = WorkService::close_only(CloseEndpoint::new(late, provider()).unwrap());
    let checkpoint = service.with_state(Channel::checkpoint).await.unwrap();
    let mut caller = client_endpoint(client_root.path()).await;
    assert_eq!(
        phase_of(caller.client().await.unwrap().state()),
        Some(JobPhase::HalfSigned)
    );
    let id = work_id(ready().channel(), &authorization(1, 1));
    let resumed = caller
        .client()
        .await
        .unwrap()
        .resume_proposal(id)
        .await
        .unwrap();
    let mut forged = resumed.clone();
    forged.client_signature = stranger().sign(signing_hash(id)).as_bytes().to_vec();
    assert_eq!(
        refusal_code(&service.accept(&forged, None).await),
        WorkRefusalCode::Invalid,
        "a retained signature is returned only to an authenticated proposal",
    );
    let again = service.accept(&resumed, None).await;
    assert_eq!(
        accepted_signature(&again),
        first,
        "an answer already given is not unsaid by a passing height",
    );
    assert_eq!(accept_uploaded_service(&service, &resumed).await, again);
    assert_eq!(
        service.with_state(Channel::checkpoint).await.unwrap(),
        checkpoint
    );
    assert_eq!(
        caller
            .client()
            .await
            .unwrap()
            .accepted(&again)
            .await
            .unwrap(),
        id
    );
    assert_eq!(
        phase_of(caller.client().await.unwrap().state()),
        Some(JobPhase::Accepted)
    );

    // A terminal is also an authenticated, permanent answer without readiness.
    service
        .drive()
        .unwrap()
        .store()
        .await
        .unwrap()
        .content_store()
        .close()
        .await;
    drop(service);
    let mut ended = store(root.path(), Role::Provider).await;
    ended
        .commit(
            ChannelRecord::JobTerminated {
                work_id: id,
                outcome: TerminalOutcome::Failed { code: 1 },
            },
            &Secp256k1Verifier::new(),
        )
        .await
        .unwrap();
    let service = WorkService::close_only(CloseEndpoint::new(ended, provider()).unwrap());
    let checkpoint = service.with_state(Channel::checkpoint).await.unwrap();
    assert_eq!(
        refusal_code(&service.accept(&forged, None).await),
        WorkRefusalCode::Invalid
    );
    assert_eq!(
        refusal_code(&service.accept(&resumed, None).await),
        WorkRefusalCode::Conflict
    );
    assert_eq!(
        service.with_state(Channel::checkpoint).await.unwrap(),
        checkpoint
    );
}

#[tokio::test]
async fn a_crash_between_the_two_commits_co_signs_on_retry() {
    let root = temp();
    // A provider that journaled the proposal and died before signing.
    let mut store = store_at_cursor(root.path(), Role::Provider).await;
    let authorization = authorization(1, 1);
    let signature = client().sign(signing_hash(work_id(ready().channel(), &authorization)));
    hellas_channel::test_support::channel::commit(
        &mut store,
        ChannelRecord::JobProposed {
            authorization,
            client_signature: signature,
            prepared_input: bundle_bytes(1).into(),

            retained_tree: None,
        },
    )
    .await;
    store.content_store().close().await;
    drop(store);

    let endpoint = provider_service(root.path()).await;
    assert_eq!(
        endpoint.with_state(phase_of).await.unwrap(),
        Some(JobPhase::HalfSigned),
        "the reopened provider is half-signed",
    );
    let response = accept_uploaded_service(&endpoint, &request(&authorization, signature, 1)).await;
    assert_eq!(
        endpoint.with_state(phase_of).await.unwrap(),
        Some(JobPhase::Accepted),
    );
    accepted_signature(&response);
}

// ── The six refusals, one at a time ───────────────────────────────────

#[tokio::test]
async fn a_provider_with_no_finalized_block_is_not_ready() {
    let root = temp();
    let Ok(endpoint) = ProviderEndpoint::new(
        ready(),
        store(root.path(), Role::Provider).await,
        provider(),
    ) else {
        panic!("the endpoint binds");
    };
    let endpoint = WorkService::new(endpoint);
    let response = accept_uploaded_service(&endpoint, &signed_request(1, 1)).await;
    assert_eq!(refusal_code(&response), WorkRefusalCode::NotReady);
    assert!(WorkRefusal::NotReady.is_retryable());
}

#[tokio::test]
async fn expired_upload_returns_the_typed_refusal_and_preserves_the_signed_proposal() {
    use hellas_channel::work_close::CloseChannel as _;
    use hellas_store::content::{ContentStore as _, Cursor, Scope};
    let client_root = temp();
    let provider_root = temp();
    let late = at_height(
        store(provider_root.path(), Role::Provider).await,
        deadlines().acceptance + 1,
    )
    .await;
    let service = WorkService::new(ProviderEndpoint::new(ready(), late, provider()).unwrap());
    let (client_transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());
    let mut endpoint = client_endpoint(client_root.path()).await;
    let content = endpoint
        .client()
        .await
        .unwrap()
        .store()
        .await
        .unwrap()
        .content_store();
    let result = propose_work(
        client_transport,
        &mut endpoint,
        &proposal(1),
        &hellas_channel::test_support::channel::program_content().await,
        None,
    )
    .await;
    assert!(matches!(
        result,
        Err(ProposeError::Refused {
            refusal: WorkRefusal::Expired,
            ..
        })
    ));
    assert_eq!(
        endpoint
            .client()
            .await
            .unwrap()
            .state()
            .job_book()
            .pending_proposal(),
        None
    );
    let job = endpoint
        .client()
        .await
        .unwrap()
        .state()
        .jobs()
        .next()
        .unwrap()
        .clone();
    let id = job.work_id();
    assert_eq!(job.phase(), JobPhase::HalfSigned);
    assert_eq!(job.authorization().retention, hellas_rpc::Retention::Retain);
    let signed = endpoint
        .client()
        .await
        .unwrap()
        .resume_proposal(id)
        .await
        .unwrap();
    let pins = content
        .pins(&Scope::Owner, "channel/", Cursor::default())
        .await
        .unwrap();
    assert_eq!(
        pins.pins.len(),
        1,
        "the signed proposal still protects its exact share"
    );
    assert!(
        pins.pins[0]
            .0
            .as_str()
            .ends_with(&format!("/proposal/{id}"))
    );
    // Clear the resumed exchange through the same real expired provider, then
    // reopen the journal to prove the refusal was durable without abandonment.
    let response = service.accept(&signed, None).await;
    assert!(matches!(
        endpoint.client().await.unwrap().accepted(&response).await,
        Err(ProposeError::Refused {
            refusal: WorkRefusal::Expired,
            ..
        })
    ));
    content.close().await;
    drop(endpoint);
    let mut reopened = client_endpoint(client_root.path()).await;
    assert_eq!(
        reopened
            .client()
            .await
            .unwrap()
            .state()
            .job_book()
            .pending_proposal(),
        None
    );
    assert_eq!(
        reopened
            .client()
            .await
            .unwrap()
            .state()
            .job_by_id(id)
            .unwrap()
            .phase(),
        JobPhase::HalfSigned
    );
    assert_eq!(
        reopened
            .client()
            .await
            .unwrap()
            .resume_proposal(id)
            .await
            .unwrap(),
        signed
    );
    serving.abort();
    let _ = serving.await;
}

#[tokio::test]
async fn an_authorization_past_its_acceptance_deadline_expires() {
    let root = temp();
    let late = at_height(
        store(root.path(), Role::Provider).await,
        deadlines().acceptance + 1,
    )
    .await;
    let Ok(endpoint) = ProviderEndpoint::new(ready(), late, provider()) else {
        panic!("the endpoint binds");
    };
    let endpoint = WorkService::new(endpoint);
    let response = accept_uploaded_service(&endpoint, &signed_request(1, 1)).await;
    assert_eq!(refusal_code(&response), WorkRefusalCode::Expired);
    assert!(!WorkRefusal::Expired.is_retryable());
    close_provider(endpoint).await;

    let service = WorkService::close_only(
        CloseEndpoint::new(store(root.path(), Role::Provider).await, provider()).unwrap(),
    );
    let checkpoint = service.with_state(Channel::checkpoint).await.unwrap();
    let expired = signed_request(1, 1);
    assert_eq!(
        refusal_code(&service.accept(&expired, None).await),
        WorkRefusalCode::Expired,
        "the persisted cursor proves expiry without any new readiness",
    );
    assert_eq!(
        refusal_code(&accept_uploaded_service(&service, &expired).await),
        WorkRefusalCode::Expired
    );
    let mut forged = expired;
    forged.client_signature = stranger()
        .sign(signing_hash(work_id(
            ready().channel(),
            &authorization(1, 1),
        )))
        .as_bytes()
        .to_vec();
    assert_eq!(
        refusal_code(&service.accept(&forged, None).await),
        WorkRefusalCode::Invalid
    );
    let fresh = signed_request_with(
        1,
        1,
        JobDeadlines {
            acceptance: deadlines().acceptance + 1,
            ..deadlines()
        },
    );
    assert_eq!(
        refusal_code(&accept_uploaded_service(&service, &fresh).await),
        WorkRefusalCode::NotReady
    );
    assert_eq!(
        service.with_state(Channel::checkpoint).await.unwrap(),
        checkpoint
    );
}

#[tokio::test]
async fn a_bundle_that_is_not_the_committed_one_is_invalid() {
    let root = temp();
    let endpoint = provider_service(root.path()).await;
    // The authorization commits to bundle 1; the request carries 2.
    let authorization = authorization(1, 1);
    let signature = client().sign(signing_hash(work_id(ready().channel(), &authorization)));
    let response = accept_uploaded_service(&endpoint, &request(&authorization, signature, 2)).await;
    assert_eq!(refusal_code(&response), WorkRefusalCode::Invalid);
    assert!(
        endpoint
            .with_state(|state| state.jobs().next().is_none())
            .await
            .unwrap()
    );
}

/// A bundle that hashes to its own authorization and still breaks the
/// policy the channel signed.
///
/// The digest binding is not the same rule as the envelope: a client is
/// free to commit to whatever it likes, and what makes a proposal
/// runnable is that the committed graph fits inside the bounds both
/// parties fixed. Nothing in a journal can see that.
fn overlong_bundle() -> PreparedInvocation {
    let mut input = bundle(1);
    let mut plan = hellas_channel::test_support::channel::plan();
    plan.outputs[0].kind = compute::OutputKind::Buffer {
        max_bytes: work_policy().limits.max_output_bytes + 1,
    };
    input.input.parameters = hellas_rpc::JsonBytes(plan.canonical_bytes().unwrap());
    input.request.input = input.input.content_id().unwrap();
    input
}
fn foreign_runner_bundle() -> PreparedInvocation {
    let mut input = bundle(1);
    input.request.runner_public_key = PublicKey::Secp256k1(stranger().party_key().to_bytes());
    input
}

#[tokio::test]
async fn a_bundle_the_policy_does_not_allow_is_refused_though_its_digest_matches() {
    let root = temp();
    let endpoint = provider_service(root.path()).await;
    for (what, bundle) in [
        ("a generation policy over the envelope", overlong_bundle()),
        ("a runner that is not the client", foreign_runner_bundle()),
    ] {
        let authorization = match propose_authorization(
            ready().channel(),
            &work_policy(),
            &payment_policy(),
            &bundle,
            1,
            deadlines(),
        ) {
            Ok(authorization) => authorization,
            Err(error) => panic!("{what} still builds an authorization: {error}"),
        };
        let signature = client().sign(signing_hash(work_id(ready().channel(), &authorization)));
        let Ok(bytes) = bundle.canonical_bytes() else {
            panic!("{what} encodes");
        };
        let response = accept_uploaded_service(
            &endpoint,
            &AcceptWorkRequest {
                route: Some(hellas_rpc::pb::work::WorkRoute::payment(
                    authorization.channel_id,
                )),
                authorization: authorization.encode(),
                client_signature: signature.as_bytes().to_vec(),
                prepared_input: bytes,
            },
        )
        .await;

        assert_eq!(
            refusal_code(&response),
            WorkRefusalCode::Invalid,
            "{what}: {}",
            refusal_text(&response),
        );
        assert!(
            endpoint
                .with_state(|state| state.jobs().next().is_none())
                .await
                .unwrap(),
            "{what} reserved nothing"
        );
    }
}

#[tokio::test]
async fn a_forged_client_signature_is_invalid() {
    let root = temp();
    let endpoint = provider_service(root.path()).await;
    let authorization = authorization(1, 1);
    let forged = stranger().sign(signing_hash(work_id(ready().channel(), &authorization)));
    let response = accept_uploaded_service(&endpoint, &request(&authorization, forged, 1)).await;
    assert_eq!(refusal_code(&response), WorkRefusalCode::Invalid);
    assert!(
        endpoint
            .with_state(|state| state.jobs().next().is_none())
            .await
            .unwrap(),
        "a proposal nobody signed reserves nothing",
    );
}

/// A signature is exactly 64 bytes, and a longer field is not one.
///
/// The load-bearing case is the last: the real signature with a byte
/// after it. A field of the wrong length full of *garbage* is refused by
/// the verifier however the length is read, so on its own it proves
/// nothing about the length rule — it is here as the neighbour that a
/// reader who truncates would also refuse.
#[tokio::test]
async fn a_signature_of_any_other_length_is_not_a_signature() {
    let root = temp();
    let endpoint = provider_service(root.path()).await;
    let valid = signed_request(1, 1).client_signature;

    let mut cases: Vec<(String, Vec<u8>)> = [Sig::LENGTH - 1, Sig::LENGTH + 1, 0]
        .into_iter()
        .map(|length| (format!("{length} garbage bytes"), vec![0x11; length]))
        .collect();
    cases.push((
        "the signature with a byte after it".to_owned(),
        valid.iter().copied().chain([0x00]).collect(),
    ));
    cases.push((
        "the signature one byte short".to_owned(),
        valid[..Sig::LENGTH - 1].to_vec(),
    ));

    for (what, client_signature) in cases {
        let mut request = signed_request(1, 1);
        request.client_signature = client_signature;
        let response = accept_uploaded_service(&endpoint, &request).await;
        assert_eq!(
            refusal_code(&response),
            WorkRefusalCode::Invalid,
            "{what} is refused",
        );
        assert!(
            endpoint
                .with_state(|state| state.jobs().next().is_none())
                .await
                .unwrap(),
            "{what} reserved nothing"
        );
    }
}

/// The two refusals the measured margins produce, and the reason they
/// are not the same answer.
///
/// A terminal deadline this height can no longer reach is a fact about
/// the height, and no later one recovers it. A payment deadline too
/// close to its terminal is a fact about two carried numbers and no
/// height at all, so it is wrong rather than late.
#[tokio::test]
async fn the_measured_margins_separate_a_late_job_from_a_malformed_one() {
    let root = temp();
    let endpoint = provider_service(root.path()).await;
    for (what, deadlines, expected) in [
        (
            "a terminal deadline inside the dispatch and delivery margins",
            JobDeadlines {
                acceptance: 12,
                terminal: 13,
                payment: 100,
            },
            WorkRefusalCode::Expired,
        ),
        (
            "a payment deadline under the measured oracle grace",
            JobDeadlines {
                acceptance: 50,
                terminal: 100,
                payment: 103,
            },
            WorkRefusalCode::Invalid,
        ),
    ] {
        let response =
            accept_uploaded_service(&endpoint, &signed_request_with(1, 1, deadlines)).await;
        assert_eq!(
            refusal_code(&response),
            expected,
            "{what}: {}",
            refusal_text(&response),
        );
        assert!(
            endpoint
                .with_state(|state| state.jobs().next().is_none())
                .await
                .unwrap(),
            "{what} reserved nothing",
        );
    }
}

#[tokio::test]
async fn bytes_that_are_not_an_authorization_are_invalid() {
    let root = temp();
    let endpoint = provider_service(root.path()).await;
    let mut truncated = signed_request(1, 1);
    truncated.authorization.pop();
    assert_eq!(
        refusal_code(&accept_uploaded_service(&endpoint, &truncated).await),
        WorkRefusalCode::Invalid,
    );

    let mut retagged = signed_request(1, 1);
    retagged.authorization[1] = 0xfe;
    assert_eq!(
        refusal_code(&accept_uploaded_service(&endpoint, &retagged).await),
        WorkRefusalCode::Invalid,
    );
}

#[tokio::test]
async fn a_job_already_in_flight_does_not_block_the_next_one() {
    let root = temp();
    let endpoint = provider_service(root.path()).await;
    accepted_signature(&accept_uploaded_service(&endpoint, &signed_request(1, 1)).await);
    let response = accept_uploaded_service(&endpoint, &signed_request(2, 2)).await;
    accepted_signature(&response);
    assert_eq!(
        endpoint
            .with_state(|state| state.jobs().len())
            .await
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn a_poisoned_endpoint_is_unavailable() {
    let root = temp();
    let service = provider_service(root.path()).await;
    // The panic happens inside a service operation, which is the only
    // place the endpoint is borrowed from at all now.
    use futures::FutureExt as _;
    let panicked =
        std::panic::AssertUnwindSafe(service.with_state(|_| panic!("poison the endpoint")))
            .catch_unwind()
            .await;
    assert!(
        panicked.is_err(),
        "the service operation panicked on purpose"
    );
    assert!(matches!(
        service.with_state(|state| state.cursor()).await,
        Err(EndpointError::Poisoned)
    ));
    // And the refusal that answer becomes on the wire is unavailability,
    // not an accusation about the proposal.
    assert_eq!(
        refusal_code(&accept_uploaded_service(&service, &signed_request(1, 1)).await),
        WorkRefusalCode::Unavailable,
    );
}

// ── Binding an endpoint to its own half of its own channel ────────────

#[tokio::test]
async fn an_endpoint_needs_its_own_store_settlement_role_and_key() {
    let root = temp();
    let wrong_role =
        ProviderEndpoint::new(ready(), store(root.path(), Role::Client).await, provider());
    assert!(
        matches!(wrong_role, Err(EndpointError::WrongRole { .. })),
        "a client journal is not a provider endpoint, got {wrong_role:?}",
    );

    let other = temp();
    let wrong_key =
        ProviderEndpoint::new(ready(), store(other.path(), Role::Provider).await, client());
    assert!(
        matches!(wrong_key, Err(EndpointError::WrongKey { .. })),
        "the client's key does not co-sign as the provider, got {wrong_key:?}",
    );

    let third = temp();
    let Some(thin) = work_payment_settlement(
        EdgeValues::new(PAYMENT_VALUE - 1, PAYMENT_RESERVE, Fees::new(0, 0, 0, 0)),
        OMISSION_BOND,
    ) else {
        panic!("a funded edge prices both exits");
    };
    let wrong_settlement = ProviderEndpoint::new(
        ready(),
        store_with(third.path(), Role::Provider, thin).await,
        provider(),
    );
    assert!(
        matches!(wrong_settlement, Err(EndpointError::WrongSettlement)),
        "a store bounded by other funding is not this channel's, got {wrong_settlement:?}",
    );

    let fourth = temp();
    let Ok(elsewhere) = PaidChannel::new(
        network(),
        EdgeId::from_bytes([0x99; EdgeId::LENGTH]),
        payment_terms(),
        &SALT,
        channel_policy(),
    ) else {
        panic!("a second payment edge is a second channel");
    };
    let other_origin = SetupOrigin {
        payment_edge: elsewhere.payment_edge(),
        ..origin()
    };
    let location = StoreLocation::for_test(fourth.path());
    let Ok(other_store) = ChannelStore::open(
        &location,
        elsewhere,
        settlement(),
        Role::Provider,
        other_origin,
        hellas_channel::test_support::channel::content_store(fourth.path()).await,
        &Secp256k1Verifier::new(),
    )
    .await
    else {
        panic!("the other channel's store opens");
    };
    let wrong_channel = ProviderEndpoint::new(ready(), other_store, provider());
    assert!(
        matches!(wrong_channel, Err(EndpointError::WrongChannel)),
        "another channel's journal is not this channel's, got {wrong_channel:?}",
    );

    let fifth = temp();
    let ok = ClientEndpoint::new(ready(), store(fifth.path(), Role::Client).await, client());
    assert!(ok.is_ok(), "the matching triple binds: {ok:?}");
}

// ── What the authorization derives ────────────────────────────────────

#[test]
fn the_authorization_derives_every_field_it_does_not_choose() {
    let channel = ready().channel().clone();
    let policy = work_policy();
    let built = authorization(7, 3);
    let request = invocation_request(7);

    // Each field against an independently computed value, not against
    // a second call to the same constructor: a swap of two fields of
    // the same width survives a round trip and does not survive this.
    assert_eq!(built.channel_id, channel.id());
    assert_eq!(built.retention, hellas_rpc::Retention::Retain);
    assert_eq!(
        built.work_policy_digest,
        hellas_channel::job::policy_digest(channel.network(), channel.id(), &policy).unwrap(),
    );
    assert_eq!(
        built.prepared_input_digest,
        match prepared_input_digest(&channel, &bundle(7)) {
            Ok(digest) => digest,
            Err(error) => panic!("the bundle hashes: {error}"),
        },
    );
    assert_eq!(built.proposal_nonce, 3);
    assert_eq!(built.acceptance_deadline, deadlines().acceptance);
    assert_eq!(built.request_commitment, request.commitment().unwrap());
    assert_eq!(built.environment_commitment, manifest().content_id());
    assert_eq!(built.price, payment_policy().fixed_price);
    assert_eq!(built.terminal_deadline, deadlines().terminal);
    assert_eq!(built.payment_deadline, deadlines().payment);

    // The three deadlines are distinct, so the three assertions above
    // are three assertions and not one repeated.
    assert!(
        deadlines().acceptance != deadlines().terminal
            && deadlines().terminal != deadlines().payment,
    );
}

#[tokio::test]
async fn the_wire_carries_the_authorization_the_signature_covers() {
    let root = temp();
    let mut endpoint = client_endpoint(root.path()).await;
    let Ok(request) = endpoint
        .propose(
            &proposal(1),
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await
    else {
        panic!("the proposal is built");
    };
    let authorization = authorization(1, 1);
    assert_eq!(
        request.authorization,
        authorization.encode(),
        "the wire field is the canonical record, not a re-spelling",
    );
    assert_eq!(
        request.authorization.get(..2),
        Some(&[1_u8, 9_u8][..]),
        "format version 1, private record tag 9",
    );
    assert_eq!(
        request.prepared_input,
        hellas_rpc::protocol::content::encode_reference(hellas_rpc::ContentRef::new(
            ContentId::hash(&bundle_bytes(1)),
            bundle_bytes(1).len() as u64
        ))
    );

    let expected = client().sign(signing_hash(work_id(ready().channel(), &authorization)));
    assert_eq!(request.client_signature, expected.as_bytes().to_vec());
    assert!(
        Secp256k1Verifier::new().verify_sig(
            expected,
            client().party_key(),
            PayloadHash::from_bytes(work_id(ready().channel(), &authorization).into_bytes(),),
        ),
        "the signature on the wire verifies over the work id",
    );
}

#[tokio::test]
async fn shared_client_can_follow_blocks_while_waiting_for_provider_acceptance() {
    use hellas_channel::work::ClientService;
    let client_root = temp();
    let provider_root = temp();
    let mut client = ClientService::new(raw_client_endpoint(client_root.path()).await);
    client.observer().observe_ready(ready()).await.unwrap();
    let observer = client.observer();
    let (client_transport, server_transport) = transport_pair();
    let request = tokio::spawn(async move {
        propose_work(
            client_transport,
            &mut client,
            &proposal(1),
            &hellas_channel::test_support::channel::program_content().await,
            None,
        )
        .await
    });
    // No server is running yet, so the request must wait for its response.
    tokio::time::timeout(HANG_GUARD, async {
        while observer
            .with_state(|state| state.proposal_nonce_high_water())
            .await
            .unwrap()
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (bond, payment) = (
        hellas_channel::test_support::channel::bond_object(),
        hellas_channel::test_support::channel::payment_object(),
    );
    observer
        .drive()
        .unwrap()
        .observe(&hellas_channel::test_support::channel::observed_at(
            CURSOR + 1,
            &bond,
            &payment,
            hellas_kernel::PendingSlot::Absent,
        ))
        .await
        .unwrap();
    let serving = serve(
        server_transport,
        provider_service(provider_root.path()).await,
    );
    request.await.unwrap().unwrap();
    assert_eq!(
        observer.with_state(|state| state.cursor().0).await.unwrap(),
        CURSOR + 1
    );
    serving.abort();
}

#[tokio::test]
async fn managed_observers_start_closed_and_stale_certified_reads_cannot_admit() {
    let client_root = temp();
    let provider_root = temp();
    // Journals that have read nothing yet.
    let mut client = ClientService::new(
        ClientEndpoint::new(
            ready(),
            store(client_root.path(), Role::Client).await,
            client(),
        )
        .unwrap(),
    );
    let provider = WorkService::new(
        ProviderEndpoint::new(
            ready(),
            store(provider_root.path(), Role::Provider).await,
            provider(),
        )
        .unwrap(),
    );
    provider.require_observer().await.unwrap();
    assert!(matches!(
        client.readiness().await,
        Err(EndpointError::ObservationStale)
    ));
    let request = signed_request(1, 1);
    let mut acceptance = Box::pin(provider.accept(&request, None));
    assert!(futures::poll!(&mut acceptance).is_pending());
    // A read older than the certified-age bound is applied, but cannot
    // admit work on either side.
    let stale = hellas_channel::test_support::channel::now_ms()
        - u64::try_from(hellas_channel::work::MAX_CERTIFIED_AGE.as_millis()).unwrap()
        - 1;
    let (bond, payment) = (
        hellas_channel::test_support::channel::bond_object(),
        hellas_channel::test_support::channel::payment_object(),
    );
    let mut observed = hellas_channel::test_support::channel::observed_at(
        CURSOR,
        &bond,
        &payment,
        hellas_kernel::PendingSlot::Absent,
    );
    observed.certified_at_ms = stale;
    client
        .observer()
        .drive()
        .unwrap()
        .observe(&observed)
        .await
        .unwrap();
    provider
        .advance_close(&observed, &hellas_channel::test_support::channel::NullSink)
        .await
        .unwrap();
    assert_eq!(
        client.observer().observe_ready(ready()).await,
        Err(EndpointError::ObservationStale)
    );
    assert_eq!(
        provider.observe_ready(ready()).await,
        Err(EndpointError::ObservationStale)
    );
    assert!(matches!(
        client
            .propose(
                &proposal(1),
                &hellas_channel::test_support::channel::program_content().await,
                None
            )
            .await,
        Err(ProposeError::Endpoint(EndpointError::ObservationStale))
    ));
    assert!(futures::poll!(&mut acceptance).is_pending());
    // A fresh read restores admission.
    observed.height = CURSOR + 1;
    observed.payload = payload_at(CURSOR + 1);
    observed.certified_at_ms = hellas_channel::test_support::channel::now_ms();
    client
        .observer()
        .drive()
        .unwrap()
        .observe(&observed)
        .await
        .unwrap();
    client.observer().observe_ready(ready()).await.unwrap();
    assert!(client.readiness().await.is_ok());
    assert_eq!(
        client
            .with_state(|state| state.proposal_nonce_high_water())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        provider
            .with_state(|state| state.jobs().len())
            .await
            .unwrap(),
        0
    );
}
