//! Abrupt process loss through actual paid journals and SDK mounted delivery.
use hellas_channel::{
    model::work::{PrivateRecord as _, signing_hash, work_id},
    test_support::channel as fixture,
    work::{ClientEndpoint, CloseEndpoint, ProviderEndpoint, WorkService, fetch_result_stream},
    work_store::{ChannelRecord, ChannelStore, Role},
};
use hellas_kernel::Secp256k1Verifier;
use hellas_rpc::{
    ContentRef,
    services::work::{WorkHandler as _, WorkServer},
};
use hellas_sdk::paid_provider::MountedWork;
use hellas_store::content::{ContentStore as _, DiskStore, IndexMode, Reservations, Scope};
use hellas_wire::{
    AuthLevel, PeerIdentity, StreamTransport as _, TransportContext, mux::MuxTransport,
    peers::PeerId,
};
use std::{path::Path, process::Stdio, time::Duration};

#[derive(serde::Serialize, serde::Deserialize)]
struct Expected {
    provider_roots: Vec<ContentRef>,
    client_roots: Vec<ContentRef>,
    provider_allowance: u64,
    client_allowance: u64,
}

async fn child(root: &Path, phase: &str) -> ! {
    let ready = fixture::ready();
    let mut provider = fixture::store_at(
        &root.join("provider"),
        &ready,
        Role::Provider,
        fixture::CURSOR,
    )
    .await;
    let mut client =
        fixture::store_at(&root.join("client"), &ready, Role::Client, fixture::CURSOR).await;
    let authorization = fixture::authorization();
    let work = work_id(ready.channel(), &authorization);
    for store in [&mut provider, &mut client] {
        fixture::commit(
            store,
            ChannelRecord::JobProposed {
                authorization,
                client_signature: fixture::client().sign(signing_hash(work)),
                prepared_input: fixture::bundle_bytes(fixture::NONCE).into(),
                retained_tree: None,
            },
        )
        .await;
    }
    if phase != "proposal" {
        for store in [&mut provider, &mut client] {
            fixture::commit(
                store,
                ChannelRecord::JobAccepted {
                    work_id: work,
                    provider_signature: fixture::provider().sign(signing_hash(work)),
                    retained_tree: None,
                },
            )
            .await;
        }
    }
    if phase == "terminal-checkpoint" {
        fixture::advance(&mut provider, fixture::deadlines().terminal + 1).await;
        provider.rotate().await.unwrap();
        assert!(provider.state().job_by_id(work).is_none());
        assert!(!provider.state().retained_roots().is_empty());
    }
    let node = provider.content_store();
    let client_node = client.content_store();
    let roots = |store: &ChannelStore| store.state().retained_roots().values().copied().collect();
    let provider_roots = if phase == "result" {
        let service = WorkService::new(
            ProviderEndpoint::new(ready.clone(), provider, fixture::provider()).unwrap(),
        );
        fixture::run_to_result(&service, &ready, work).await;
        let roots = service
            .with_state(|state| state.retained_roots().values().copied().collect())
            .await
            .unwrap();
        // Keep the live service and all its SQLite workers until SIGKILL.
        std::mem::forget(service);
        roots
    } else {
        let roots = roots(&provider);
        std::mem::forget(provider);
        roots
    };
    let expected = Expected {
        provider_roots,
        client_roots: roots(&client),
        provider_allowance: node.stats().unwrap().outstanding,
        client_allowance: client_node.stats().unwrap().outstanding,
    };
    std::fs::write(
        root.join("ready.pending"),
        serde_json::to_vec(&expected).unwrap(),
    )
    .unwrap();
    std::fs::rename(root.join("ready.pending"), root.join("ready")).unwrap();
    // No Drop, SQLite close, checkpoint or graceful shutdown runs in this child.
    std::future::pending().await
}

async fn recover(root: &Path, role: Role) -> (ChannelStore, DiskStore) {
    let ready = fixture::ready();
    let content = DiskStore::open(
        root.join("content"),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
    )
    .await
    .unwrap();
    assert!(content.collect(&Scope::Owner).await.is_err());
    let store = ChannelStore::recover(
        root,
        ready.channel().clone(),
        role,
        content.clone(),
        &Secp256k1Verifier::new(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(content.collect(&Scope::Owner).await.is_err());
    (store, content)
}

async fn assert_roots(node: &DiskStore, expected: &[ContentRef]) {
    use hellas_store::content::{Cursor, LocalStore, Target, Tree};
    let pins = node
        .pins(&Scope::Owner, "channel/", Cursor::default())
        .await
        .unwrap();
    let mut actual = pins
        .pins
        .iter()
        .map(|(_, pin)| pin.target.object())
        .collect::<Vec<_>>();
    actual.sort();
    let mut expected = expected.to_vec();
    expected.sort();
    assert_eq!(actual, expected);
    let mut pending = expected.into_iter().map(Target::Tree).collect::<Vec<_>>();
    while let Some(target) = pending.pop() {
        let object = target.object();
        let bytes = hellas_channel::content::read(
            &LocalStore::Disk(node.clone()),
            &Scope::Owner,
            object,
            hellas_channel::content::MAX_CONTENT_BYTES as u64,
        )
        .await
        .unwrap();
        assert_eq!(ContentRef::for_bytes(&bytes), object);
        if matches!(target, Target::Tree(_)) {
            pending.extend(
                Tree::decode(&bytes)
                    .unwrap()
                    .entries()
                    .iter()
                    .map(|(_, target)| *target),
            );
        }
    }
}

#[tokio::test]
async fn retained_process_loss_restores_authority_before_collect_and_sdk_delivery() {
    if let Some(root) = std::env::var_os("HELLAS_CONTENT_LIFECYCLE_ROOT") {
        child(
            Path::new(&root),
            &std::env::var("HELLAS_CONTENT_LIFECYCLE_PHASE").unwrap(),
        )
        .await;
    }
    for phase in ["proposal", "accepted", "result", "terminal-checkpoint"] {
        tokio::time::timeout(Duration::from_secs(30), async {
            let root = tempfile::tempdir().unwrap();
            let log = std::fs::File::create(root.path().join("child.log")).unwrap();
            let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "retained_process_loss_restores_authority_before_collect_and_sdk_delivery", "--nocapture"])
                .env("HELLAS_CONTENT_LIFECYCLE_ROOT", root.path())
                .env("HELLAS_CONTENT_LIFECYCLE_PHASE", phase)
                .stdout(Stdio::from(log.try_clone().unwrap())).stderr(Stdio::from(log))
                .kill_on_drop(true).spawn().unwrap();
            while !root.path().join("ready").exists() {
                assert!(child.try_wait().unwrap().is_none(), "child failed: {}",
                    std::fs::read_to_string(root.path().join("child.log")).unwrap());
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let expected: Expected = serde_json::from_slice(&std::fs::read(root.path().join("ready")).unwrap()).unwrap();
            child.kill().await.unwrap();
            assert!(!child.wait().await.unwrap().success());
            let (provider, node) = recover(&root.path().join("provider"), Role::Provider).await;
            let (client, client_node) = recover(&root.path().join("client"), Role::Client).await;
            assert_eq!(provider.state().retained_roots().values().copied().collect::<Vec<_>>(), expected.provider_roots);
            assert_eq!(client.state().retained_roots().values().copied().collect::<Vec<_>>(), expected.client_roots);
            assert_eq!(node.stats().unwrap().outstanding,
                if phase == "proposal" { 0 } else { expected.provider_allowance });
            assert_eq!(client_node.stats().unwrap().outstanding, expected.client_allowance);
            // Every journal in these two independent node roots is restored first.
            node.finish_recovery().await.unwrap();
            client_node.finish_recovery().await.unwrap();
            node.collect(&Scope::Owner).await.unwrap();
            client_node.collect(&Scope::Owner).await.unwrap();
            assert_roots(&node, &expected.provider_roots).await;
            assert_roots(&client_node, &expected.client_roots).await;
            assert_eq!(node.stats().unwrap().outstanding,
                if phase == "proposal" { 0 } else { expected.provider_allowance });
            let ready = fixture::ready();
            let work = work_id(ready.channel(), &fixture::authorization());
            let mut client = ClientEndpoint::new(ready.clone(), client, fixture::client()).unwrap();
            if phase == "proposal" {
                assert_eq!(node.stats().unwrap().used, 0);
                let resumed = client.resume_proposal(work).await.unwrap();
                assert_eq!(resumed.authorization, fixture::authorization().encode());
                assert_eq!(resumed.client_signature, fixture::client().sign(signing_hash(work)).as_bytes());
                assert!(!expected.client_roots.is_empty());
                return;
            }
            if phase == "terminal-checkpoint" {
                assert!(provider.state().job_by_id(work).is_none());
                assert!(!provider.state().retained_roots().is_empty());
                return;
            }
            let service = WorkService::close_only(CloseEndpoint::new(provider, fixture::provider()).unwrap());
            let mounts = MountedWork::default();
            let peer = PeerId::from_bytes([1; 32]);
            mounts.mount(peer, &service).await.unwrap();
            let context = TransportContext {
                peer: Some(PeerIdentity(peer.into_bytes())), auth_level: AuthLevel::Vouched,
                open_exporter: Some([7; 32]), ..Default::default()
            };
            assert!(mounts.service(&TransportContext::default(), ready.channel().id()).unwrap().is_none());
            let handler = mounts.handler(&context, Some(&hellas_rpc::pb::work::WorkRoute::payment(ready.channel().id()))).unwrap().unwrap();
            // Recovery restores close authority; a fresh readiness decision is separate.
            let mut next = fixture::authorization();
            next.proposal_nonce += 1;
            let next_id = work_id(ready.channel(), &next);
            let refused: hellas_rpc::call::WithTrailer<_> = handler.accept_work(
                hellas_rpc::pb::work::AcceptWorkRequest {
                    route: Some(hellas_rpc::pb::work::WorkRoute::payment(ready.channel().id())),
                    authorization: next.encode(),
                    client_signature: fixture::client().sign(signing_hash(next_id)).as_bytes().to_vec(),
                    prepared_input: hellas_rpc::protocol::content::encode_reference(ContentRef::for_bytes(&fixture::bundle_bytes(fixture::NONCE))),
                }, context.clone()).await.unwrap().into();
            assert!(matches!(refused.response.outcome, Some(hellas_rpc::pb::work::accept_work_response::Outcome::Refused(refusal))
                if refusal.code == hellas_rpc::pb::work::WorkRefusalCode::NotReady as i32));
            if phase != "result" { return; }
            service.admit_new_work(ready.clone()).await.unwrap();
            let (transport, server) = hellas_channel::test_support::transport::transport_pair_with_context(context.clone(), context);
            let server_handler = WorkServer(handler.clone());
            let serving = tokio::spawn(async move {
                while let Ok(Some(inbound)) = server.accept().await {
                    let _ = hellas_wire::Dispatcher::<MuxTransport>::dispatch(&server_handler, inbound).await;
                }
            });
            let delivery = fetch_result_stream(transport, &mut client, &ready, work, |_| Ok(())).await.unwrap();
            assert_eq!(ContentRef::for_bytes(&delivery.transcript), delivery.result.transcript_content);
            client.verified(work, &fixture::bundle(fixture::NONCE)).await.unwrap();
            let paid = client.pay(work).await.unwrap();
            let credited: hellas_rpc::call::WithTrailer<_> = handler.admit_certificate(paid.clone(), TransportContext::default()).await.unwrap().into();
            assert_eq!(client.acknowledged(work, &credited.response).unwrap(), fixture::PRICE);
            serving.abort();
        }).await.unwrap();
    }
}
