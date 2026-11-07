//! Paid and SDK Grant payloads across abrupt process loss and canonical replay.
use hellas_authority::{grant_service::GrantService, test_support as common};
use hellas_channel::{
    model::work::encode_transcript,
    test_support::{
        backend::{Backend, Completion, Reply},
        channel as fixture, principal,
    },
    work::{
        Admitted, BackendFault, ClientChannel as _, ClientEndpoint, JobProposal, ProviderEndpoint,
        RunOutcome, WorkBackend, WorkService, fetch_result_stream, propose_work,
    },
    work_close::CloseChannel as _,
    work_store::{ChannelStore, Role},
};
use hellas_kernel::Secp256k1Verifier;
use hellas_rpc::{
    Assurance, Retention,
    protocol::invocation::{Admission, PreparedInvocation},
};
use hellas_sdk::grant_client::{GrantSession, GrantTransport};
use hellas_store::content::{
    ContentStore as _, Cursor, DiskStore, IndexMode, LocalStore, MemoryStore, Reservations, Scope,
};
use sqlx::{Connection as _, Row as _, TypeInfo as _, ValueRef as _};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
#[path = "support/grant_content.rs"]
mod grant_content;

fn files(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            paths.extend(files(&entry.path()));
        } else if kind.is_file() {
            paths.push(entry.path());
        }
    }
    paths
}
fn check(bytes: &[u8], canaries: &[Vec<u8>], path: &Path) -> Result<(), PathBuf> {
    for canary in canaries {
        if bytes.windows(canary.len()).any(|part| part == canary) {
            return Err(path.to_owned());
        }
    }
    Ok(())
}
async fn scan(root: &Path, canaries: &[Vec<u8>]) -> Result<(), PathBuf> {
    for path in files(root) {
        let bytes = std::fs::read(&path).unwrap();
        check(&bytes, canaries, &path)?;
        if !bytes.starts_with(b"SQLite format 3\0") {
            continue;
        }
        // Journals deliberately hold SQLite EXCLUSIVE locks. At the controlled
        // child barrier, read the exact DB/WAL/SHM snapshot with SQLite itself.
        let snapshot = tempfile::tempdir().unwrap();
        let copied = snapshot.path().join("scan.sqlite");
        std::fs::write(&copied, &bytes).unwrap();
        for suffix in ["-wal", "-shm"] {
            let mut original = path.as_os_str().to_owned();
            original.push(suffix);
            if Path::new(&original).exists() {
                let mut destination = copied.as_os_str().to_owned();
                destination.push(suffix);
                std::fs::copy(&original, &destination).unwrap();
            }
        }
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&copied)
            .read_only(true)
            .busy_timeout(Duration::ZERO);
        let mut db = sqlx::SqliteConnection::connect_with(&options)
            .await
            .unwrap();
        let tables: Vec<String> =
            sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table'")
                .fetch_all(&mut db)
                .await
                .unwrap();
        for table in tables {
            let quoted = table.replace('"', "\"\"");
            // The fixture DB supplies an identifier; double quotes were escaped above.
            let rows = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT * FROM \"{quoted}\"")))
                .fetch_all(&mut db)
                .await
                .unwrap();
            for row in rows {
                for column in 0..row.len() {
                    let raw = row.try_get_raw(column).unwrap();
                    if raw.is_null() {
                        continue;
                    }
                    match raw.type_info().name() {
                        "BLOB" => {
                            check(&row.try_get::<Vec<u8>, _>(column).unwrap(), canaries, &path)?
                        }
                        "TEXT" => check(
                            row.try_get::<String, _>(column).unwrap().as_bytes(),
                            canaries,
                            &path,
                        )?,
                        _ => {}
                    }
                }
            }
        }
        db.close().await.unwrap();
    }
    Ok(())
}
async fn checkpoint(root: &Path) {
    let databases = files(root)
        .into_iter()
        .filter(|path| {
            std::fs::read(path)
                .unwrap()
                .starts_with(b"SQLite format 3\0")
        })
        .collect::<Vec<_>>();
    for path in databases {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .busy_timeout(Duration::ZERO);
        let mut db = sqlx::SqliteConnection::connect_with(&options)
            .await
            .unwrap();
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_all(&mut db)
            .await
            .unwrap();
        db.close().await.unwrap();
    }
}
fn ready(root: &Path, grant: Option<&Path>) {
    let marker = grant.map(|path| path.to_owned());
    std::fs::write(
        root.join("ready.pending"),
        serde_json::to_vec(&marker).unwrap(),
    )
    .unwrap();
    std::fs::rename(root.join("ready.pending"), root.join("ready")).unwrap();
}
fn content() -> (LocalStore, Scope) {
    (
        LocalStore::Memory(MemoryStore::new(Reservations::ram(
            hellas_channel::content::DEFAULT_MAX_STAGING_BYTES,
        ))),
        Scope::Owner,
    )
}
fn request(
    body: &[u8],
    policy: &[u8],
    caller: &hellas_auth::ProducerSigningKey,
    provider: hellas_auth::PublicKey,
) -> PreparedInvocation {
    let contract = hellas_channel::test_support::test_responses_contract();
    let events = hellas_rpc::fetch::build_input_events_with_retention(
        "openai",
        "responses",
        body,
        contract.manifest_id(),
        Assurance::ProducerSigned,
        caller,
        Retention::Ephemeral,
    )
    .unwrap();
    hellas_rpc::protocol::invocation::fetch::prepare(
        &events,
        &contract,
        provider,
        policy.to_vec(),
        [1; 32],
    )
    .unwrap()
}
// Envelope payloads are Vec<u8>: DAG-CBOR encodes their bytes as integers.
// Keep header-free subspans so a leaked partial object/chunk is also detected.
fn encoded_canary(bytes: &[u8]) -> Vec<u8> {
    let encoded = hellas_rpc::canonical_dag_cbor(&bytes.to_vec()).unwrap();
    let mut header = hellas_rpc::protocol::value::DagCborEncoder::new();
    header.array(bytes.len() as u64);
    encoded[header.into_bytes().len()..].to_vec()
}
fn canaries(seed: &str) -> Vec<Vec<u8>> {
    [
        format!("private-prompt-{seed}"),
        format!("private-response-{seed}"),
        "private-prompt-".into(),
        "private-response-".into(),
    ]
    .into_iter()
    .flat_map(|text| {
        let raw = text.into_bytes();
        [encoded_canary(&raw), raw]
    })
    .collect()
}
fn output_events(
    input: &PreparedInvocation,
    output: String,
) -> Vec<hellas_rpc::OutputEventEnvelope> {
    let payload = hellas_rpc::fetch::encode_fetch_event_payload(
        &hellas_rpc::output::OutputEvent::TextDelta {
            index: 0,
            delta: output,
            channel: hellas_rpc::output::TextChannel::Output,
        },
    )
    .unwrap();
    let terminal = hellas_rpc::fetch::encode_fetch_terminal_payload(
        &hellas_rpc::output::OutputEvent::Finished {
            stop_reason: hellas_rpc::output::StopReason::EndOfText,
            usage: None,
        },
    )
    .unwrap();
    hellas_rpc::protocol::invocation::fetch::output(&[payload], &terminal)
        .unwrap()
        .sign(&input.request, &fixture::provider_producer(), 16 << 10)
        .unwrap()
}

#[tokio::test]
async fn scanner_detects_canonical_payloads_and_partial_content_chunks() {
    let seed = hex::encode(rand::random::<[u8; 32]>());
    let canaries = canaries(&seed);
    let input_secret = format!("private-prompt-{seed}");
    let output_secret = format!("private-response-{seed}");
    let body = serde_json::to_vec(&serde_json::json!({"model":"fixture", "input":input_secret.repeat(4096), "max_output_tokens":8})).unwrap();
    let policy = common::policy().invocation_policy;
    let input = request(
        &body,
        &policy.canonical_bytes().unwrap(),
        &hellas_auth::ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap(),
        fixture::provider_producer().public_key(),
    );
    let transcript = encode_transcript(&output_events(&input, output_secret.repeat(4096))).unwrap();
    // This separate control root never contains a node's journal or content store.
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("deliberate-leak");
    for (bytes, secret) in [
        (input.canonical_bytes().unwrap(), input_secret),
        (transcript, output_secret),
    ] {
        let encoded = encoded_canary(secret.as_bytes());
        assert!(bytes.windows(encoded.len()).any(|part| part == encoded));
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(scan(root.path(), &canaries).await.unwrap_err(), path);
        std::fs::remove_file(&path).unwrap();
        let mut offset = 0;
        let chunk = hellas_xet::chunk(&bytes)
            .into_iter()
            .find_map(|chunk| {
                let start = offset;
                offset += usize::try_from(chunk.data_len).unwrap();
                let chunk = &bytes[start..offset];
                chunk
                    .windows(encoded.len())
                    .any(|part| part == encoded)
                    .then_some(chunk)
            })
            .unwrap();
        assert!(chunk.len() < bytes.len());
        std::fs::write(&path, chunk).unwrap();
        assert_eq!(scan(root.path(), &canaries).await.unwrap_err(), path);
        std::fs::remove_file(&path).unwrap();
    }
    scan(root.path(), &canaries).await.unwrap();
}

struct PaidBackend {
    events: Vec<hellas_rpc::OutputEventEnvelope>,
    calls: Arc<AtomicUsize>,
}
impl WorkBackend for PaidBackend {
    fn try_admit(
        &self,
        domain: hellas_channel::work::admission::CapacityDomain,
    ) -> Result<hellas_channel::work::admission::WorkPermit, BackendFault> {
        Err(hellas_channel::work::admission::AdmissionError::Unsupported(domain).into())
    }
    async fn execute(
        &self,
        _: Admitted,
    ) -> Result<Vec<hellas_rpc::OutputEventEnvelope>, BackendFault> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.events.clone())
    }
}
async fn child(root: &Path, funding: &str, phase: &str, seed: &str) -> ! {
    let input_secret = format!("private-prompt-{seed}");
    let output_secret = format!("private-response-{seed}");
    let canaries = canaries(seed);
    let body = serde_json::to_vec(&serde_json::json!({"model":"fixture", "input":input_secret.repeat(4096), "max_output_tokens":8})).unwrap();
    let output = output_secret.repeat(4096);
    assert!(body.len() > hellas_xet::MAX_CHUNK_SIZE && output.len() > hellas_xet::MAX_CHUNK_SIZE);
    if funding == "grant" {
        let prefixes = output
            .as_bytes()
            .chunks(16 << 10)
            .map(|chunk| hellas_rpc::output::OutputEvent::TextDelta {
                index: 0,
                delta: std::str::from_utf8(chunk).unwrap().into(),
                channel: hellas_rpc::output::TextChannel::Output,
            })
            .collect();
        let fixture =
            grant_content::Fixture::with_reply(false, Some(Reply::events(prefixes))).await;
        let mut session = GrantSession::open(
            fixture.options(vec![]),
            GrantTransport::Local(fixture.service.clone()),
        )
        .await
        .unwrap();
        let accepted = (phase == "accepted").then(|| {
            let root = root.to_owned();
            let grant = fixture.root.path().to_owned();
            Arc::new(move |_| -> () {
                ready(&root, Some(&grant));
                loop {
                    std::thread::park();
                }
            }) as hellas_sdk::transact::Accepted
        });
        let result = session
            .run(
                "responses",
                fixture.input_from(&body),
                &content(),
                None,
                accepted,
                None,
            )
            .await
            .unwrap();
        assert!(result.output.is_success());
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.node_content.ram_pool().held(), 0);
        scan(root, &canaries).await.unwrap();
        if phase == "checkpoint" {
            let channel = session.store().channel().clone();
            session.shutdown().await.unwrap();
            drop(session);
            let directory = fixture
                .options(vec![])
                .journal_root
                .join(hex::encode(channel.id.0.as_bytes()));
            let mut client = hellas_authority::work_store::grant::GrantClientStore::open(
                &directory,
                common::network(),
                fixture.enrollment.clone(),
                channel,
                fixture.now,
                Default::default(),
            )
            .await
            .unwrap();
            client.rotate().await.unwrap();
            scan(root, &canaries).await.unwrap();
        }
        ready(root, Some(fixture.root.path()));
        std::future::pending().await
    } else {
        let mut policy = common::policy().invocation_policy;
        let Admission::Fetch { admission } = &mut policy.admissions[0] else {
            unreachable!()
        };
        admission.limits.max_request_body_bytes = 1 << 20;
        admission.limits.max_spool_bytes = 1 << 20;
        let channel = fixture::ready_of(&fixture::descriptor_with(policy.clone()), fixture::CURSOR);
        let input = request(
            &body,
            &policy.canonical_bytes().unwrap(),
            &hellas_auth::ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap(),
            fixture::provider_producer().public_key(),
        );
        let provider = ProviderEndpoint::new(
            channel.clone(),
            fixture::store_at(
                &root.join("provider"),
                &channel,
                Role::Provider,
                fixture::CURSOR,
            )
            .await,
            fixture::provider(),
        )
        .unwrap();
        let service = WorkService::new(provider);
        let client_store = fixture::store_at(
            &root.join("client"),
            &channel,
            Role::Client,
            fixture::CURSOR,
        )
        .await;
        let mut client = fixture::client_service(
            ClientEndpoint::new(channel.clone(), client_store, fixture::client()).unwrap(),
            channel.clone(),
        )
        .await;
        let (transport, server) = hellas_channel::test_support::transport::transport_pair();
        let _serving = fixture::serve_work(server, service.clone());
        let work = propose_work(
            transport.clone(),
            &mut client,
            &JobProposal {
                prepared_input: input.clone(),
                deadlines: fixture::deadlines(),
            },
            &content(),
        )
        .await
        .unwrap();
        if phase == "accepted" {
            ready(root, None);
            std::future::pending::<()>().await;
        }
        let events = output_events(&input, output);
        assert!(encode_transcript(&events).unwrap().len() > hellas_xet::MAX_CHUNK_SIZE);
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = PaidBackend {
            events,
            calls: calls.clone(),
        };
        assert!(matches!(
            hellas_channel::work::run_accepted_work(&service, &channel, &backend, work)
                .await
                .unwrap(),
            RunOutcome::Completed { .. }
        ));
        fetch_result_stream(transport, &mut client, &channel, work, |_| Ok(()))
            .await
            .unwrap();
        client
            .client()
            .await
            .unwrap()
            .verified(work, &input)
            .await
            .unwrap();
        let payment = client.client().await.unwrap().pay(work).await.unwrap();
        use hellas_rpc::services::work::WorkHandler as _;
        service
            .admit_certificate(payment, Default::default())
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        scan(root, &canaries).await.unwrap();
        if phase == "checkpoint" {
            client
                .client()
                .await
                .unwrap()
                .store()
                .await
                .unwrap()
                .rotate()
                .await
                .unwrap();
            service
                .drive()
                .unwrap()
                .store()
                .await
                .unwrap()
                .rotate()
                .await
                .unwrap();
            scan(root, &canaries).await.unwrap();
        }
        ready(root, None);
        std::future::pending().await
    }
}

#[tokio::test]
async fn ephemeral_process_loss_keeps_large_paid_and_grant_payloads_out_of_every_durable_file() {
    if let Some(root) = std::env::var_os("HELLAS_CONTENT_ZDR_ROOT") {
        child(
            Path::new(&root),
            &std::env::var("HELLAS_CONTENT_ZDR_FUNDING").unwrap(),
            &std::env::var("HELLAS_CONTENT_ZDR_PHASE").unwrap(),
            &std::env::var("HELLAS_CONTENT_ZDR_SEED").unwrap(),
        )
        .await;
    }
    for funding in ["paid", "grant"] {
        for phase in ["accepted", "success", "checkpoint"] {
            tokio::time::timeout(Duration::from_secs(30), async {
                let root = tempfile::tempdir().unwrap();
                let data = root.path().join("data"); std::fs::create_dir(&data).unwrap();
                let seed = hex::encode(rand::random::<[u8;32]>());
                let canaries = canaries(&seed);
                let log = std::fs::File::create(root.path().join("child.log")).unwrap();
                let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "ephemeral_process_loss_keeps_large_paid_and_grant_payloads_out_of_every_durable_file", "--nocapture"])
                    .env("HELLAS_CONTENT_ZDR_ROOT",root.path()).env("TMPDIR", &data)
                    .env("HELLAS_CONTENT_ZDR_FUNDING", funding).env("HELLAS_CONTENT_ZDR_PHASE",phase).env("HELLAS_CONTENT_ZDR_SEED", &seed)
                    .stdout(Stdio::from(log.try_clone().unwrap())).stderr(Stdio::from(log)).kill_on_drop(true).spawn().unwrap();
                while !root.path().join("ready").exists() {
                    assert!(child.try_wait().unwrap().is_none(), "{funding}/{phase}: {}", std::fs::read_to_string(root.path().join("child.log")).unwrap());
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                scan(root.path(), &canaries).await.unwrap();
                let grant: Option<PathBuf> = serde_json::from_slice(&std::fs::read(root.path().join("ready")).unwrap()).unwrap();
                child.kill().await.unwrap(); assert!(!child.wait().await.unwrap().success());
                scan(root.path(), &canaries).await.unwrap();
                checkpoint(root.path()).await;
                scan(root.path(), &canaries).await.unwrap();
                if let Some(grant) = grant {
                    assert!(grant.starts_with(&data));
                    let enrollment = hellas_channel::test_support::software_enrollment(2, *iroh::SecretKey::from_bytes(&[2;32]).public().as_bytes());
                    let store = hellas_authority::work_store::grant::NodeStore::open(&grant.join("provider"), common::network(), Some(enrollment), hellas_auth::authority::UnixMillis::now().unwrap(), Default::default(),).await.unwrap();
                    let backend = Backend { finish:Completion::Immediate, ..Default::default() };
                    let calls = backend.calls.clone();
                    let content = common::content_store(&grant.join("provider")).await;
                    let service = GrantService::new(store, Arc::new(principal(2).1), backend, vec![], Arc::new(||hellas_auth::authority::UnixMillis::now().unwrap()), content.clone()).unwrap();
                    service.drain().await.unwrap(); assert_eq!(calls.load(Ordering::SeqCst),0);
                    assert_eq!(content.ram_pool().held(),0);
                    assert!(content.pins(&Scope::Owner,"",Cursor::default()).await.unwrap().pins.is_empty());
                    scan(root.path(), &canaries).await.unwrap();
                } else {
                    let mut policy = common::policy().invocation_policy;
                    let Admission::Fetch {admission} = &mut policy.admissions[0] else {unreachable!()};
                    admission.limits.max_request_body_bytes=1<<20; admission.limits.max_spool_bytes=1<<20;
                    let channel = fixture::ready_of(&fixture::descriptor_with(policy), fixture::CURSOR);
                    for (name, role) in [("provider",Role::Provider),("client",Role::Client)] {
                        let node_root = root.path().join(name);
                        let content = DiskStore::open(node_root.join("content"),vec![],IndexMode::Resume,None,Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES), false, Default::default(),).await.unwrap();
                        assert!(content.collect(&Scope::Owner).await.is_err());
                        let journal = ChannelStore::recover(&node_root,channel.channel().clone(),role,content.clone(),&Secp256k1Verifier::new()).await.unwrap().unwrap();
                        for job in journal.state().jobs() {assert!(job.prepared_input().is_empty() && job.transcript().is_empty());}
                        assert!(journal.state().retained_roots().is_empty());
                        content.finish_recovery().await.unwrap(); content.collect(&Scope::Owner).await.unwrap();
                        assert_eq!(content.ram_pool().held(),0); assert_eq!(content.stats().unwrap().used,0); assert_eq!(content.stats().unwrap().outstanding,0);
                        scan(root.path(),&canaries).await.unwrap();
                    }
                }
            }).await.unwrap();
        }
    }
}
