mod hub_responses;

use super::*;
use sha2::{Digest as _, Sha256};
use std::{io::Read, sync::Arc};
use std::{
    io::{BufRead, Write},
    net::TcpListener,
    sync::mpsc,
};

fn pin(name: &str) -> PinTarget {
    PinTarget {
        name: PinName::new(name.into()).unwrap(),
        policy: PinPolicy::Public,
    }
}
fn path(name: &str) -> Path {
    Path::new(PinName::new(name.into()).unwrap(), String::new()).unwrap()
}
pub(crate) fn https(body: &'static [u8]) -> (url::Url, ureq::Agent, std::thread::JoinHandle<()>) {
    https_with(body, || {})
}
pub(crate) fn https_with(
    body: &'static [u8],
    on_request: impl FnOnce() + Send + 'static,
) -> (url::Url, ureq::Agent, std::thread::JoinHandle<()>) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = certified.cert.der().clone();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let http = ureq::Agent::config_builder()
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .root_certs(ureq::tls::RootCerts::new_with_certs(&[
                    ureq::tls::Certificate::from_der(cert.as_ref()).to_owned(),
                ]))
                .build(),
        )
        .build()
        .new_agent();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "https://localhost:{}/file",
        listener.local_addr().unwrap().port()
    )
    .parse()
    .unwrap();
    let serving = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let mut tls = rustls::StreamOwned::new(
            rustls::ServerConnection::new(Arc::new(tls)).unwrap(),
            socket,
        );
        {
            let mut input = std::io::BufReader::new(&mut tls);
            let mut line = String::new();
            loop {
                line.clear();
                input.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
        }
        on_request();
        write!(
            tls,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        tls.write_all(body).unwrap();
        tls.flush().unwrap();
        tls.conn.send_close_notify();
        let _ = tls.flush();
    });
    (url, http, serving)
}

#[tokio::test]
async fn cold_https_acquisition_pins_only_verified_bytes_and_sha_is_not_the_id() {
    let (url, http, serving) = https(b"canonical HTTPS bytes");
    let pool = Reservations::ram(10_000);
    let mut store = MemoryStore::new(pool.clone());
    store.core.http = http;
    let sha: [u8; 32] = Sha256::digest(b"canonical HTTPS bytes").into();
    let got = store
        .acquire(
            &Scope::Owner,
            Source::Https {
                url,
                sha256: Some(sha),
                bytes: 21,
            },
            None,
            pin("https"),
        )
        .await
        .unwrap();
    serving.join().unwrap();
    assert_eq!(got.object, ContentRef::for_bytes(b"canonical HTTPS bytes"));
    assert_ne!(got.object.id().as_bytes(), &sha);
    let mut read = store
        .read(&Scope::Public, &path("https"), 0..21)
        .await
        .unwrap();
    assert_eq!(
        read.bytes.next().await.unwrap().unwrap().as_ref(),
        b"canonical HTTPS bytes"
    );
    drop(read);
    assert_eq!(pool.held(), 21);
}

#[tokio::test]
async fn mismatched_https_expectation_or_transport_digest_leaves_no_pin_or_ram() {
    for wrong_sha in [false, true] {
        let (url, http, serving) = https(b"never publish me");
        let pool = Reservations::ram(10_000);
        let mut store = MemoryStore::new(pool.clone());
        store.core.http = http;
        let expect = (!wrong_sha).then(|| ContentRef::for_bytes(b"wrong content id"));
        let result = store
            .acquire(
                &Scope::Owner,
                Source::Https {
                    url,
                    sha256: wrong_sha.then_some([0; 32]),
                    bytes: 16,
                },
                expect,
                pin("failed"),
            )
            .await;
        serving.join().unwrap();
        assert!(result.is_err());
        assert_eq!(pool.held(), 0);
        assert!(
            store
                .stat(&Scope::Owner, &path("failed"))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(store.collect(&Scope::Owner).await.unwrap().objects, 0);
    }
}

#[tokio::test]
async fn cancellation_keeps_the_worker_charge_until_the_blocking_reader_stops() {
    // The reader blocks inside the actual streaming copy; dropping its JoinHandle
    // cannot give its still-owned reservation back to another operation.
    struct Reader {
        entered: Option<mpsc::Sender<()>>,
        release: mpsc::Receiver<()>,
        sent: bool,
    }
    impl Read for Reader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.sent {
                return Ok(0);
            }
            assert_eq!(
                output.len(),
                1,
                "tiny acquisition reads into its reserved allocation"
            );
            self.entered.take().unwrap().send(()).unwrap();
            self.release.recv().unwrap();
            output[0] = b'x';
            self.sent = true;
            Ok(1)
        }
    }
    let pool = Reservations::ram(1);
    let charge = pool.reserve(1).unwrap();
    let (entered, waiting) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    let core = Core::new(pool.clone());
    let worker = tokio::task::spawn_blocking(move || {
        let mut buffer = Buffer::new(&core, 1, charge).unwrap();
        buffer
            .fill(
                Reader {
                    entered: Some(entered),
                    release: blocked,
                    sent: false,
                },
                None,
                &core.pool,
            )
            .unwrap();
        finish(buffer, None)
    });
    waiting.recv().unwrap();
    drop(worker);
    assert_eq!(pool.held(), 1);
    assert!(pool.reserve(1).is_err());
    release.send(()).unwrap();
    // Dropping the JoinHandle leaves no owner for the worker's result. Its
    // reservation releases when the staged result is dropped after the read.
    while pool.held() != 0 {
        tokio::task::yield_now().await;
    }
    assert!(pool.reserve(1).is_ok());
}

pub(crate) fn framed(bytes: &[u8]) -> Vec<u8> {
    let mut frame = vec![0];
    frame.extend_from_slice(&bytes.len().to_le_bytes()[..3]);
    frame.push(0);
    frame.extend_from_slice(&bytes.len().to_le_bytes()[..3]);
    frame.extend_from_slice(bytes);
    frame
}
pub(crate) fn hub(
    responses: impl FnOnce(&str) -> Vec<(String, u16, Vec<u8>)>,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let responses = responses(&base);
    let serving = std::thread::spawn(move || {
        for (expected, status, body) in responses {
            let (mut socket, _) = listener.accept().unwrap();
            let mut input = std::io::BufReader::new(socket.try_clone().unwrap());
            let mut first = String::new();
            input.read_line(&mut first).unwrap();
            assert!(
                first.starts_with(&format!("GET {expected} ")),
                "unexpected Hub request path"
            );
            loop {
                let mut line = String::new();
                input.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                assert!(
                    !line.to_ascii_lowercase().starts_with("authorization:"),
                    "a non-HF origin received a credential"
                );
            }
            write!(
                socket,
                "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            socket.write_all(&body).unwrap();
        }
    });
    (base, serving)
}
fn repo(kind: crate::hf::RepoKind) -> crate::hf::Repo {
    crate::hf::Repo {
        kind,
        id: "org/repo".into(),
        revision: "a".repeat(40),
    }
}

#[test]
fn hf_git_paths_are_encoded_and_dataset_files_use_the_dataset_endpoint() {
    let pool = Reservations::ram(10_000);
    let (base, serving) = hub(|_| {
        vec![(
            format!(
                "/datasets/org/repo/resolve/{}/a%3Fb%23c%25d%20e.txt",
                "a".repeat(40)
            ),
            200,
            b"git file".to_vec(),
        )]
    });
    let cas = crate::hf::HfCas::new(repo(crate::hf::RepoKind::Dataset)).with_hub(base);
    let file = crate::hf::RepoFile {
        path: "a?b#c%d e.txt".into(),
        size: 8,
        xet_hash: None,
        lfs: None,
    };
    let stage = hf_file(&cas, &file, &Core::new(pool.clone()), None).unwrap();
    serving.join().unwrap();
    assert_eq!(stage.object, ContentRef::for_bytes(b"git file"));
    assert_eq!(pool.held(), 8);
    drop(stage);
    assert_eq!(pool.held(), 0);
}

#[test]
fn new_hf_reconstruction_streams_multiterm_and_nonzero_offset() {
    let mut first = vec![b'x'; hellas_xet::MIN_CHUNK_SIZE];
    first[..12].copy_from_slice(b"prefixhello ");
    let expected = [&first[6..], b"world"].concat();
    let id = hellas_xet::XetHash::hash(&expected);
    let b = framed(&first);
    let c = framed(b"world");
    let one = b;
    let two = c;
    let xorb = hellas_xet::XetHash::ZERO;
    let (base, serving) = hub(|base| {
        let plan=serde_json::json!({"offset_into_first_range":6,"terms":[{"hash":xorb.to_string(),"range":{"start":1,"end":2},"unpacked_length":first.len()},{"hash":xorb.to_string(),"range":{"start":2,"end":3},"unpacked_length":5}],"xorbs":{xorb.to_string():[{"url":format!("{base}/one"),"ranges":[{"chunks":{"start":1,"end":2},"bytes":{"start":0,"end":one.len()-1}}]},{"url":format!("{base}/two"),"ranges":[{"chunks":{"start":2,"end":3},"bytes":{"start":0,"end":two.len()-1}}]}]}}).to_string().into_bytes();
        vec![
            (
                format!("/api/models/org/repo/xet-read-token/{}", "a".repeat(40)),
                200,
                format!("{{\"accessToken\":\"t\",\"casUrl\":\"{base}\"}}").into_bytes(),
            ),
            (format!("/v2/reconstructions/{id}"), 200, plan),
            ("/one".into(), 206, one),
            ("/two".into(), 206, two),
        ]
    });
    let cas = crate::hf::HfCas::new(repo(crate::hf::RepoKind::Model)).with_hub(base);
    let pool = Reservations::ram(16 << 20);
    let mut bytes = Vec::new();
    cas.write_xet(id, expected.len() as u64, None, &mut bytes, &pool)
        .unwrap();
    serving.join().unwrap();
    assert_eq!(bytes, expected);
    assert_eq!(pool.held(), 0);
}

#[test]
fn legacy_hf_chunking_is_refused_before_writing_with_a_specific_store_error() {
    let short = vec![b'x'; hellas_xet::MIN_CHUNK_SIZE - 64];
    let last = vec![b'y'; hellas_xet::MIN_CHUNK_SIZE];
    let body = [framed(&short), framed(&last)].concat();
    let content = [short, last].concat();
    let id = hellas_xet::XetHash::hash(&content);
    let xorb = hellas_xet::XetHash::ZERO;
    let (base, serving) = hub(|base| {
        vec![
            (format!("/api/models/org/repo/xet-read-token/{}", "a".repeat(40)), 200,
                format!("{{\"accessToken\":\"t\",\"casUrl\":\"{base}\"}}").into_bytes()),
            (format!("/v2/reconstructions/{id}"), 200, serde_json::json!({
                "terms":[{"hash":xorb.to_string(),"range":{"start":0,"end":2},"unpacked_length":content.len()}],
                "xorbs":{xorb.to_string():[{"url":format!("{base}/xorb"),"ranges":[{"chunks":{"start":0,"end":2},"bytes":{"start":0,"end":body.len()-1}}]}]}
            }).to_string().into_bytes()),
            ("/xorb".into(), 206, body),
        ]
    });
    let cas = crate::hf::HfCas::new(repo(crate::hf::RepoKind::Model)).with_hub(base);
    let pool = Reservations::ram(16 << 20);
    let mut bytes = Vec::new();
    let error = cas
        .write_xet(id, content.len() as u64, None, &mut bytes, &pool)
        .unwrap_err();
    serving.join().unwrap();
    assert!(
        matches!(hf_error(error), Error::Invalid(reason) if reason == crate::hf::LEGACY_CHUNKING)
    );
    assert!(
        matches!(super::super::wire::error(hellas_wire::WireStatus::new(
        hellas_wire::WireCode::InvalidArgument, crate::hf::LEGACY_CHUNKING
    )), Error::Invalid(reason) if reason == crate::hf::LEGACY_CHUNKING)
    );
    assert!(bytes.is_empty());
    assert_eq!(pool.held(), 0);
}

#[test]
fn hf_expected_descriptors_never_downgrade_to_cold_when_the_list_is_short() {
    let cas =
        crate::hf::HfCas::new(repo(crate::hf::RepoKind::Model)).with_hub("http://127.0.0.1:1");
    let pool = Reservations::ram(16 << 20);
    let mut bytes = Vec::new();
    let result = cas.write_xet(
        hellas_xet::XetHash::hash(b"file"),
        4,
        Some(&[]),
        &mut bytes,
        &pool,
    );
    assert!(result.is_err());
    assert!(bytes.is_empty());
    assert_eq!(pool.held(), 0);
}

#[tokio::test]
async fn resolve_tree_fetches_git_files_but_not_weights_and_missing_weights_stay_missing() {
    let sha = "a".repeat(40);
    let weight = ContentRef::for_bytes(b"a model weight");
    let (base, serving) = hub(|_| {
        vec![(format!("/api/models/org/repo/tree/{sha}?recursive=true"),200,
        serde_json::json!([{"type":"file","path":"weights.bin","size":weight.bytes(),"xetHash":weight.id().to_string()},{"type":"file","path":"tokenizer.json","size":2}]).to_string().into_bytes()),
        (format!("/org/repo/resolve/{sha}/tokenizer.json"),200,b"{}".to_vec())]
    });
    let cas = crate::hf::HfCas::new(repo(crate::hf::RepoKind::Model)).with_hub(base);
    let pool = Reservations::ram(16 << 20);
    let (stages, root) = hf_stages(&cas, &Core::new(pool.clone()), None, None, false).unwrap();
    serving.join().unwrap();
    assert!(!stages.contains_key(&weight.id()));
    let store = MemoryStore::new(pool.clone());
    publish(
        &store.core,
        &Scope::Owner,
        stages,
        root,
        pin("resolved"),
        None,
    )
    .await
    .unwrap();
    assert_eq!(pool.held(), root.object().bytes() + 2);
    assert!(
        store
            .stat(&Scope::Public, &path("resolved"))
            .await
            .unwrap()
            .is_some()
    );
    let mut tokenizer = store
        .read(
            &Scope::Public,
            &Path::new(pin("resolved").name, "tokenizer.json".into()).unwrap(),
            0..2,
        )
        .await
        .unwrap();
    assert_eq!(
        tokenizer.bytes.next().await.unwrap().unwrap().as_ref(),
        b"{}"
    );
    assert!(matches!(
        store
            .stat(
                &Scope::Public,
                &Path::new(pin("resolved").name, "weights.bin".into()).unwrap()
            )
            .await,
        Err(Error::Missing)
    ));
}

#[test]
fn known_hf_reconstruction_checks_the_expected_chunk_hash_before_writing() {
    let good = b"hello";
    let wrong = framed(b"jello");
    let id = hellas_xet::XetHash::hash(good);
    let xorb = hellas_xet::XetHash::ZERO;
    let (base, serving) = hub(|base| {
        vec![(format!("/api/models/org/repo/xet-read-token/{}","a".repeat(40)),200,format!("{{\"accessToken\":\"t\",\"casUrl\":\"{base}\"}}").into_bytes()),
        (format!("/v2/reconstructions/{id}"),200,serde_json::json!({"terms":[{"hash":xorb.to_string(),"range":{"start":0,"end":1},"unpacked_length":5}],"xorbs":{xorb.to_string():[{"url":format!("{base}/xorb"),"ranges":[{"chunks":{"start":0,"end":1},"bytes":{"start":0,"end":wrong.len()-1}}]}]}}).to_string().into_bytes()),
        ("/xorb".into(),206,wrong)]
    });
    let cas = crate::hf::HfCas::new(repo(crate::hf::RepoKind::Model)).with_hub(base);
    let pool = Reservations::ram(16 << 20);
    let mut bytes = Vec::new();
    assert!(matches!(
        cas.write_xet(id, 5, Some(&hellas_xet::chunk(good)), &mut bytes, &pool),
        Err(crate::hf::FetchError::Xorb(
            crate::xorb::XorbError::HashMismatch { .. }
        ))
    ));
    serving.join().unwrap();
    assert!(bytes.is_empty());
    assert_eq!(pool.held(), 0);
}

#[tokio::test]
async fn disk_cold_https_streams_an_object_larger_than_any_tree_without_ram_materialization() {
    let data: &'static [u8] = Box::leak(vec![9; MAX_TREE_BYTES + 1].into_boxed_slice());
    let (url, http, serving) = https(data);
    let root = tempfile::tempdir().unwrap();
    let ram = Reservations::ram(2 << 20);
    let mut store = DiskStore::open(
        root.path().into(),
        vec![],
        IndexMode::Resume,
        Some(data.len() as u64),
        ram.clone(),
        Default::default(),
    )
    .await
    .unwrap();
    store.core.http = http;
    store.finish_recovery().await.unwrap();
    let acquired = store
        .acquire(
            &Scope::Owner,
            Source::Https {
                url,
                sha256: None,
                bytes: data.len() as u64,
            },
            None,
            pin("large"),
        )
        .await
        .unwrap();
    serving.join().unwrap();
    assert_eq!(acquired.object, ContentRef::for_bytes(data));
    assert_eq!(store.stats().unwrap().used, data.len() as u64);
    assert_eq!(store.stats().unwrap().outstanding, 0);
    assert_eq!(ram.held(), 0);
    let mut read = store
        .read(&Scope::Public, &path("large"), 120_000..140_000)
        .await
        .unwrap();
    let mut actual = Vec::new();
    while let Some(chunk) = read.bytes.next().await {
        actual.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(actual, data[120_000..140_000]);
}

#[tokio::test]
async fn disk_resolve_obeys_recovery_and_reclaims_before_retrying_the_same_commit() {
    let directory = tempfile::tempdir().unwrap();
    let tokenizer = ContentRef::for_bytes(b"{}");
    let tree = Tree::new(vec![("tokenizer.json".into(), Target::Object(tokenizer))]).unwrap();
    let capacity = tree.bytes().len() as u64 + tokenizer.bytes();
    let mut store = DiskStore::open(
        directory.path().into(),
        vec![],
        IndexMode::Resume,
        Some(capacity),
        Reservations::ram(32 << 20),
        Default::default(),
    )
    .await
    .unwrap();
    store.core.hf_hub = Some("http://127.0.0.1:1".into());
    let repo = crate::hf::Repo::from_uri("hf://org/repo").unwrap();
    assert!(matches!(
        store.resolve_hf(&Scope::Owner, repo.clone()).await,
        Err(Error::Denied)
    ));
    store.finish_recovery().await.unwrap();
    let cached = vec![17; capacity as usize];
    let mut upload = store
        .upload(
            &Scope::Owner,
            ContentRef::for_bytes(&cached),
            Some(pin("cached")),
        )
        .await
        .unwrap();
    upload
        .declare(&hellas_xet::chunk(&cached), true)
        .await
        .unwrap();
    upload.accept_chunk(&cached).await.unwrap();
    let value = store
        .pins(&Scope::Owner, "cached", Cursor::default())
        .await
        .unwrap()
        .pins
        .remove(0)
        .1;
    store
        .set_pin(&Scope::Owner, &pin("cached").name, Some(&value), None)
        .await
        .unwrap();
    let sha = "a".repeat(40);
    let (base, serving) = hub(|_| {
        let listing = serde_json::json!([{"type":"file","path":"tokenizer.json","size":2}])
            .to_string()
            .into_bytes();
        vec![
            (
                "/api/models/org/repo/revision/main".into(),
                200,
                serde_json::json!({"sha":sha}).to_string().into_bytes(),
            ),
            (
                format!("/api/models/org/repo/tree/{sha}?recursive=true"),
                200,
                listing.clone(),
            ),
            (
                format!("/api/models/org/repo/tree/{sha}?recursive=true"),
                200,
                listing,
            ),
            (
                format!("/org/repo/resolve/{sha}/tokenizer.json"),
                200,
                b"{}".to_vec(),
            ),
        ]
    });
    store.core.hf_hub = Some(base);
    let (resolved, object) = store.resolve_hf(&Scope::Owner, repo).await.unwrap();
    serving.join().unwrap();
    assert_eq!(resolved, sha);
    assert_eq!(object, ContentRef::for_bytes(&tree.bytes()));
    assert_eq!(store.stats().unwrap().used, capacity);
    assert_eq!(store.stats().unwrap().outstanding, 0);
    assert!(
        !directory
            .path()
            .join("objects")
            .join(ContentRef::for_bytes(&cached).id().to_string())
            .exists()
    );
    store.close().await;
}
