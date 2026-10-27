//! Real command handlers, provider and payments; only the HTTPS origin is a fixture.
use super::*;
use crate::commands::transact::{self as command, Context};
use hellas_sdk::job::Job;
use rcgen::PublicKeyData as _;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

async fn sealing<T>(devnet: &mut Devnet, work: impl std::future::Future<Output = T>) -> T {
    // Use the network's one-second block cadence: accelerated heights must not
    // expire a valid CLI authorization while its disk writes are still pending.
    super::sealing_with_period(devnet, work, Duration::from_secs(1)).await
}

struct Origin {
    url: String,
    certificate: PathBuf,
    pin: String,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Origin {
    async fn start(root: &Path) -> Self {
        let tls = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = root.join("origin.der");
        std::fs::write(&certificate, tls.cert.der()).unwrap();
        let pin = hex::encode(Sha256::digest(tls.signing_key.subject_public_key_info()));
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![tls.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(tls.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "https://localhost:{}/job",
            listener.local_addr().unwrap().port()
        );
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = calls.clone();
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (acceptor, count) = (acceptor.clone(), count.clone());
                tokio::spawn(async move {
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        assert!(head.len() < 16384);
                        head.push(socket.read_u8().await.unwrap());
                    }
                    assert!(head.starts_with(b"GET /job HTTP/1.1\r\n"));
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nanswer!").await.unwrap();
                    socket.shutdown().await.unwrap();
                });
            }
        });
        Self {
            url,
            certificate,
            pin,
            calls,
            task,
        }
    }
}

#[test]
fn transact_and_fetch_pay_the_provider_and_settlement_only_never_funds() {
    run(|runtime| {
        Box::pin(async move {
            let root = tempfile::tempdir().unwrap();
            let origin = Origin::start(root.path()).await;
            let owners = [GenesisOwner::faucet(0), GenesisOwner::faucet(1)];
            let mut devnet = Box::pin(Devnet::start(
                runtime,
                DevnetConfig {
                    name: "h6_transact_cli",
                    owners: owners.to_vec(),
                    full_nodes: 1,
                },
            ))
            .await;
            devnet.seal().await;
            let provider_identity_path = root.path().join("provider-identity");
            let provider_identity =
                crate::identity::load_or_create(Some(&provider_identity_path)).unwrap();
            let startup = Startup::new(
                root.path().join("provider"),
                SoftPasskey::from_secret_scalar(owners[0].secret_scalar).unwrap(),
                PolicyArgs::default(),
            )
            .unwrap();
            let fetch_config = root.path().join("fetch.json");
            std::fs::write(&fetch_config, r#"{"routes":[{"service":"http","method":"request","destination":{"type":"http","config":{"allow_private_addresses":true,"allowed_hosts":["localhost"]}}}]}"#).unwrap();
            let cfg = config(&devnet, &startup.root);
            let node = devnet.full_node(0).clone();
            let provider = sealing(
                &mut devnet,
                Box::pin(host_with_config(
                    &startup,
                    &provider_identity,
                    cfg,
                    node,
                    Some(fetch_config),
                )),
            )
            .await
            .unwrap();
            let endpoint = provider.provider_endpoint().borrow().clone().unwrap();
            let mut address = endpoint
                .bound_sockets()
                .into_iter()
                .find(|a| a.is_ipv4())
                .unwrap();
            address.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
            let target = format!("{}@{address}", endpoint.id());
            let genesis_path = root.path().join("genesis.json");
            let genesis = serde_json::to_vec(devnet.genesis()).unwrap();
            std::fs::write(&genesis_path, &genesis).unwrap();
            let trust_path = root.path().join("trust.json");
            let trust = hellas_chain::genesis::TrustDocument {
                schema_version: 1,
                network_id: devnet.network().as_str().into(),
                genesis_sha256: hex::encode(Sha256::digest(&genesis)),
                epochs: vec![hellas_chain::genesis::TrustEpoch {
                    epoch: 0,
                    start_height: 0,
                    end_height: None,
                    threshold_identity: hex::encode(&devnet.consensus_info().threshold_identity),
                }],
            };
            std::fs::write(&trust_path, serde_json::to_vec(&trust).unwrap()).unwrap();
            let client_identity_path = root.path().join("client-identity");
            let client_identity =
                crate::identity::load_or_create(Some(&client_identity_path)).unwrap();
            let urls = devnet.light_client_urls();
            let base = |name: &str| {
                let mut flags = vec![
                    "hellas".to_owned(),
                    name.into(),
                    "--provider".into(),
                    target.clone(),
                    "--trust".into(),
                    trust_path.display().to_string(),
                    "--genesis".into(),
                    genesis_path.display().to_string(),
                ];
                for url in &urls {
                    flags.extend(["--validator".into(), url.clone()]);
                }
                flags
            };
            let client_context = || {
                Context::new(
                    &client_identity,
                    Some(&SoftPasskey::from_secret_scalar(owners[1].secret_scalar).unwrap()),
                    Some(&client_identity_path),
                )
                .unwrap()
            };
            let request = hellas_rpc::http_fetch::HttpFetchRequest {
                url: origin.url.clone(),
                method: "GET".into(),
                headers: vec![],
                body_base64: String::new(),
                credential: None,
                max_response_bytes: 4096,
                tls: hellas_rpc::http_fetch::HttpTls {
                    roots: hellas_rpc::http_fetch::HttpTrustRoots::Certificates {
                        der_base64: vec![{
                            use base64::Engine as _;
                            base64::engine::general_purpose::STANDARD
                                .encode(std::fs::read(&origin.certificate).unwrap())
                        }],
                    },
                    spki_sha256: vec![origin.pin.clone()],
                },
            };
            let make_job = |price| {
                Job::fetch(
                    price,
                    hellas_rpc::FetchContract::http().unwrap(),
                    "http".into(),
                    "request".into(),
                    serde_json::to_vec(&request).unwrap(),
                    Assurance::ProducerSigned,
                )
                .unwrap()
            };
            let job_folder = root.path().join("job");
            make_job(20).save(&job_folder).unwrap();
            let bad_folder = root.path().join("wrong-price");
            make_job(21).save(&bad_folder).unwrap();
            let before = devnet.coins(0, owners[1].key(), []).await;
            let mut flags = base("transact");
            flags.extend(["--job".into(), bad_folder.display().to_string()]);
            let crate::Commands::Transact(args) =
                crate::Cli::try_parse_from(flags).unwrap().command
            else {
                panic!("transact");
            };
            let error = Box::pin(command::run(args, client_context()))
                .await
                .unwrap_err();
            assert!(
                format!("{error:#}").contains("Nothing was signed or paid"),
                "{error:#}"
            );
            assert_eq!(
                devnet.coins(0, owners[1].key(), []).await,
                before,
                "mismatched price performs no owner funding"
            );
            assert_eq!(origin.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            let mut receipts = Vec::new();
            for n in 0..2 {
                let out = root.path().join(format!("result-{n}"));
                let mut flags = base("transact");
                flags.extend([
                    "--job".into(),
                    job_folder.display().to_string(),
                    "-o".into(),
                    out.display().to_string(),
                ]);
                let crate::Commands::Transact(args) =
                    crate::Cli::try_parse_from(flags).unwrap().command
                else {
                    panic!("transact");
                };
                sealing(&mut devnet, Box::pin(command::run(args, client_context())))
                    .await
                    .unwrap();
                assert_eq!(std::fs::read(out.join("output-0000")).unwrap(), b"answer!");
                receipts.push(
                    serde_json::from_slice::<serde_json::Value>(
                        &std::fs::read(out.join("result.json")).unwrap(),
                    )
                    .unwrap(),
                );
            }
            assert_ne!(
                receipts[0]["work"], receipts[1]["work"],
                "a completed folder starts a new purchase"
            );
            assert_eq!(
                receipts[0]["channel"], receipts[1]["channel"],
                "jobs reuse the funded channel"
            );
            // The output destination fails only after the signed payment completes.
            let blocked = root.path().join("blocked");
            std::fs::write(&blocked, b"ordinary file").unwrap();
            let lost_output = blocked.join("result");
            let lost_flags = || {
                let mut flags = base("transact");
                flags.extend([
                    "--job".into(),
                    job_folder.display().to_string(),
                    "-o".into(),
                    lost_output.display().to_string(),
                ]);
                flags
            };
            let crate::Commands::Transact(args) =
                crate::Cli::try_parse_from(lost_flags()).unwrap().command
            else {
                panic!("transact");
            };
            let failure = sealing(&mut devnet, Box::pin(command::run(args, client_context())))
                .await
                .unwrap_err();
            assert!(
                failure.downcast_ref::<std::io::Error>().is_some(),
                "expected output publication failure after payment: {failure:#}"
            );
            assert_eq!(origin.calls.load(std::sync::atomic::Ordering::SeqCst), 3);
            let after_paid = devnet.coins(0, owners[1].key(), []).await;
            let crate::Commands::Transact(args) =
                crate::Cli::try_parse_from(lost_flags()).unwrap().command
            else {
                panic!("transact");
            };
            let lost = Box::pin(command::run(args, client_context()))
                .await
                .unwrap_err();
            assert!(format!("{lost:#}").contains("result lost"), "{lost:#}");
            assert_eq!(
                origin.calls.load(std::sync::atomic::Ordering::SeqCst),
                3,
                "retry cannot call the upstream or buy again"
            );
            assert_eq!(devnet.coins(0, owners[1].key(), []).await, after_paid);
            // Reproduce the on-disk crash window after certificate commit but
            // before the marker's Paid publication; the signed journal decides it.
            let state_root = crate::identity::funding_root(Some(&client_identity_path))
                .unwrap()
                .join("client/purchases");
            fn json_files(root: &Path) -> Vec<PathBuf> {
                let mut found = Vec::new();
                for entry in std::fs::read_dir(root).unwrap() {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        found.extend(json_files(&path));
                    } else if path
                        .extension()
                        .is_some_and(|extension| extension == "json")
                    {
                        found.push(path);
                    }
                }
                found
            }
            let files = json_files(&state_root);
            assert_eq!(files.len(), 1);
            let mut marker: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
            assert_eq!(marker["phase"], "Paid");
            marker["phase"] = "Paying".into();
            hellas_private::write_atomically(
                &files[0],
                ".crash",
                &serde_json::to_vec(&marker).unwrap(),
            )
            .unwrap();
            let crate::Commands::Transact(args) =
                crate::Cli::try_parse_from(lost_flags()).unwrap().command
            else {
                panic!("transact");
            };
            let lost = Box::pin(command::run(args, client_context()))
                .await
                .unwrap_err();
            assert!(format!("{lost:#}").contains("result lost"), "{lost:#}");
            assert_eq!(origin.calls.load(std::sync::atomic::Ordering::SeqCst), 3);
            assert_eq!(devnet.coins(0, owners[1].key(), []).await, after_paid);
            let mut flags = base("transact");
            flags.extend([
                "--job".into(),
                job_folder.display().to_string(),
                "--buy-again".into(),
                "-o".into(),
                root.path()
                    .join("deliberate-repurchase")
                    .display()
                    .to_string(),
            ]);
            let crate::Commands::Transact(args) =
                crate::Cli::try_parse_from(flags).unwrap().command
            else {
                panic!("transact");
            };
            sealing(&mut devnet, Box::pin(command::run(args, client_context())))
                .await
                .unwrap();
            assert_eq!(
                origin.calls.load(std::sync::atomic::Ordering::SeqCst),
                4,
                "explicit buy-again buys one more result"
            );
            let mut flags = base("transact");
            flags.push("--settle".into());
            let crate::Commands::Transact(args) =
                crate::Cli::try_parse_from(flags).unwrap().command
            else {
                panic!("transact");
            };
            sealing(&mut devnet, Box::pin(command::run(args, client_context())))
                .await
                .unwrap();
            assert_eq!(
                devnet
                    .coins(0, owners[1].key(), [])
                    .await
                    .iter()
                    .map(|(_, c)| c.value)
                    .sum::<u64>(),
                owners[1].balance - 80,
                "standalone settlement returns unused channel funding"
            );
            // Keep the closed price-20 journal, then create a live price-25
            // channel. Settlement must select its actual terms, not history.
            let changed = Startup::new(
                startup.root.clone(),
                startup.owner.clone(),
                PolicyArgs {
                    price: Some(25),
                    ..Default::default()
                },
            )
            .unwrap();
            let bootstrap: Bootstrap = serde_json::from_slice(
                &std::fs::read(startup.root.join("bootstrap.json")).unwrap(),
            )
            .unwrap();
            changed
                .configure(
                    &provider.administration().unwrap().unwrap(),
                    Some(&bootstrap.secret()),
                )
                .await
                .unwrap();
            let output = root.path().join("fetch.body");
            let saved = root.path().join("helper-job");
            let mut flags = base("fetch");
            flags.extend([
                origin.url.clone(),
                "--payment".into(),
                "25".into(),
                "--max-response-bytes".into(),
                "4096".into(),
                "--tls-root".into(),
                origin.certificate.display().to_string(),
                "--spki-sha256".into(),
                origin.pin.clone(),
                "--save-job".into(),
                saved.display().to_string(),
                "-o".into(),
                output.display().to_string(),
            ]);
            let before_reclaim = devnet.height();
            let provider_key = crate::identity::settlement_signer(&provider_identity)
                .unwrap()
                .party_key();
            tokio::time::timeout(hellas_chain::node::RECOVERY_TIMEOUT, async {
                loop {
                    let returned = devnet.coins(0, owners[0].key(), []).await;
                    if returned
                        .iter()
                        .filter(|(_, coin)| {
                            coin.value == 12 && coin.delegate == Some(provider_key.into())
                        })
                        .count()
                        == 3
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    devnet.seal().await;
                }
            })
            .await
            .expect("the provider reclaims stake after finalized payment closure");
            assert!(
                devnet.height() < before_reclaim + 32,
                "stake returns without waiting for the 256-block horizon"
            );
            let crate::Commands::Fetch(args) = crate::Cli::try_parse_from(flags).unwrap().command
            else {
                panic!("fetch");
            };
            sealing(
                &mut devnet,
                Box::pin(command::fetch(args, client_context())),
            )
            .await
            .unwrap();
            assert_eq!(std::fs::read(output).unwrap(), b"answer!");
            assert_eq!(Job::load(&saved).unwrap().digest(), make_job(25).digest());
            assert_eq!(origin.calls.load(std::sync::atomic::Ordering::SeqCst), 5);
            let mut flags = base("transact");
            flags.push("--settle".into());
            let crate::Commands::Transact(args) =
                crate::Cli::try_parse_from(flags).unwrap().command
            else {
                panic!("transact");
            };
            sealing(&mut devnet, Box::pin(command::run(args, client_context())))
                .await
                .unwrap();
            let coins = devnet.coins(0, owners[1].key(), []).await;
            assert_eq!(
                coins.iter().map(|(_, c)| c.value).sum::<u64>(),
                owners[1].balance - 105,
                "four purchases at 20 and one at 25 settle at their actual prices"
            );
            let mut flags = base("transact");
            flags.push("--settle".into());
            let crate::Commands::Transact(args) =
                crate::Cli::try_parse_from(flags).unwrap().command
            else {
                panic!("transact");
            };
            sealing(&mut devnet, Box::pin(command::run(args, client_context())))
                .await
                .unwrap();
            assert_eq!(
                devnet.coins(0, owners[1].key(), []).await,
                coins,
                "settle-only creates no new funding"
            );
            let client_root = crate::identity::funding_root(Some(&client_identity_path)).unwrap();
            assert!(!client_root.join("chain").exists());
            assert!(!client_root.join("provider").exists());
            assert!(!client_root.join("client/chain-reads").exists());
            provider.shutdown().await.unwrap();
            devnet.shutdown().await;
        })
    });
}
