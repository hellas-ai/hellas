use super::*;
use crate::daemon_config::{Backend, BackendKind, Upstream};
use hellas_authority::test_support::{Allowance, chat_resource, ids, use_https};
use hellas_channel::test_support::actors::{FRIEND, PROVIDER};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Both listeners run real HTTPS Fetch; the consumer reaches the provider over iroh.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_listeners_keep_admitted_backends_when_fetch_configuration_changes() {
    let run = async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("https://localhost:{}", socket.local_addr().unwrap().port());
        let mut template = chat_resource(&origin, 6);
        use base64::Engine;
        template.tls.roots = hellas_rpc::http_fetch::HttpTrustRoots::Certificates {
            der_base64: vec![base64::engine::general_purpose::STANDARD.encode(cert.cert.der())],
        };
        let (started, mut reached) = tokio::sync::mpsc::unbounded_channel();
        let release = Arc::new(Semaphore::new(0));
        let held = release.clone();
        let upstream = tokio::spawn(async move {
            let mut calls = tokio::task::JoinSet::new();
            for index in 0..4 {
                let (stream, _) = socket.accept().await.unwrap();
                let (acceptor, started, held) = (acceptor.clone(), started.clone(), held.clone());
                calls.spawn(async move {
                    let mut stream = acceptor.accept(stream).await.unwrap();
                    let mut headers = vec![];
                    while !headers.ends_with(b"\r\n\r\n") { headers.push(stream.read_u8().await.unwrap()); assert!(headers.len() < 16384); }
                    let headers = String::from_utf8(headers).unwrap().to_lowercase();
                    let length: usize = headers.lines().find_map(|h| h.strip_prefix("content-length: ")).unwrap().parse().unwrap();
                    let mut body = vec![0; length];
                    stream.read_exact(&mut body).await.unwrap();
                    started.send(index).unwrap();
                    if index < 2 { held.acquire().await.unwrap().forget(); }
                    if index == 3 {
                        assert!(matches!(stream.read_u8().await.unwrap_err().kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset));
                        return;
                    }
                    let body = r#"{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#;
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
                    stream.shutdown().await.unwrap();
                });
            }
            while let Some(call) = calls.join_next().await {
                call.unwrap();
            }
        });
        let mut allowance = Allowance::responses(ids::ALLOWANCE, FRIEND);
        use_https(&mut allowance.definition.policies[0], template.clone());
        let host = crate::test_support::Host::builder()
            .with_allowance(allowance)
            .build()
            .await;
        let node = host.world.service.node();
        let secret = host.world.secret(ROOT);
        let f = Fixture {
            directory: tempfile::tempdir().unwrap(),
            content: host.content.clone(),
            node: node.clone(),
            service: NodeControl::new(node.clone()).with_remote_admission(
                RemoteControlAdmission::new(vec![SecretKey::from_bytes(&[62; 32]).public()])
                    .unwrap(),
            ),
            secret: CredentialSecret::from_parts(secret.id(), *secret.expose_secret()),
        };
        let provider_access = access(&f).await;
        let mut opts = options(&f);
        opts.signer = Arc::new(PROVIDER.node_key());
        opts.transport = SecretKey::from_bytes(&[5; 32]);
        let mut document = Document {
            revision: node.configuration().await.unwrap().unwrap().revision,
            authority: hellas_authority::test_support::common_node::configuration(
                host.allowance.policies.clone(),
            ),
            ..Default::default()
        };
        document.backends.insert(
            "upstream".into(),
            Backend {
                max_in_flight: std::num::NonZeroUsize::new(2).unwrap(),
                kind: BackendKind::Fetch {
                    service: "openai".into(),
                    method: "responses".into(),
                    upstream: Upstream::Http {
                        allowed_hosts: vec!["localhost".into()],
                        allow_private_addresses: true,
                        credentials: Default::default(),
                    },
                },
            },
        );
        document.listeners.insert(
            "work".into(),
            Listener::Iroh {
                chain: None,
                port: 0,
                backends: vec!["upstream".into()],
            },
        );
        document.listeners.insert(
            "api".into(),
            Listener::Http {
                bind: "127.0.0.1:0".parse().unwrap(),
                zdr: true,
            },
        );
        document.routes.push(hellas_gateway::Route {
            backends: vec!["upstream".into()],
            presentation: hellas_gateway::Presentation::Http {
                targets: ["upstream"]
                    .into_iter()
                    .map(|id| {
                        (
                            id.into(),
                            hellas_gateway::HttpTarget {
                                service: "openai".into(),
                                method: "responses".into(),
                                route: hellas_gateway::HttpRoute {
                                    path: template.paths[0].clone(),
                                    method: "POST".into(),
                                    url: format!("{}{}", template.origin, template.paths[0]),
                                    credential: None,
                                    tls: template.tls.clone(),
                                    headers: vec![],
                                    max_response_bytes: template.max_response_bytes,
                                    models: None,
                                },
                            },
                        )
                    })
                    .collect(),
            },
        });
        let provider = Core::open(opts, document).await.unwrap();
        let (_client, _server, connection, rpc, served) = connect(&f, provider.clone()).await;
        let consumer_fixture = fixture().await;
        let consumer_access = access(&consumer_fixture).await;
        let mut consumer_options = options(&consumer_fixture);
        consumer_options.signer = Arc::new(FRIEND.node_key());
        consumer_options.owner = Some(Arc::new(FRIEND.passkey()));
        let session = host.options(
            provider.iroh_addresses()["work"]
                .ip_addrs()
                .map(ToString::to_string)
                .collect(),
        );
        let offer = hellas_authority::model::grant::records::SignedOffer::sign(
            session.target.offer().clone(),
            &PROVIDER.node_key(),
        )
        .unwrap();
        let secret = &host.application.credential;
        let bundle = crate::access_bundle::AccessBundle {
            offers: vec![offer],
            authority: host.application.authority,
            authorization: host.application.authorization,
            subject: FRIEND.principal(),
            holder: NodeKey::from_public_key(FRIEND.node_key().public_key()).unwrap(),
            credential: CredentialSecret::from_parts(secret.id(), *secret.expose_secret()),
            expires: UnixMillis(u64::MAX),
            label: None,
        };
        let mut document = Document::default();
        document.backends.insert(
            "friend".into(),
            Backend {
                max_in_flight: std::num::NonZeroUsize::new(2).unwrap(),
                kind: BackendKind::Grant {
                    access: Some(base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        bundle.encode().unwrap(),
                    )),
                    resource: None,
                    evaluator: None,
                    trust: None,
                },
            },
        );
        document.listeners.insert(
            "api".into(),
            Listener::Http {
                bind: "127.0.0.1:0".parse().unwrap(),
                zdr: true,
            },
        );
        document.routes = provider.watch().0.document.routes;
        document.routes[0].backends = vec!["friend".into()];
        let hellas_gateway::Presentation::Http { targets } = &mut document.routes[0].presentation
        else {
            unreachable!()
        };
        let target = targets.remove("upstream").unwrap();
        targets.insert("friend".into(), target);
        let consumer = Core::open(consumer_options, document).await.unwrap();
        let send = |core: &Core, access: &hellas_gateway::GatewayAccess| {
            let url = format!(
                "http://{}{}",
                core.http_addresses()["api"],
                template.paths[0]
            );
            let bearer = access.bearer();
            async move {
                let response = reqwest::Client::new()
                    .post(url)
                    .bearer_auth(bearer)
                    .json(&serde_json::json!({"messages":[],"max_tokens":6,"stream":false}))
                    .send()
                    .await
                    .unwrap();
                let status = response.status();
                let body = response.text().await.unwrap();
                assert_eq!(status, reqwest::StatusCode::OK, "{body}");
            }
        };
        let direct = tokio::spawn(send(&provider, &provider_access));
        let remote = tokio::spawn(send(&consumer, &consumer_access));
        reached.recv().await.unwrap();
        reached.recv().await.unwrap();
        let jobs = provider.watch().0.jobs;
        assert_eq!(jobs.len(), 2);
        assert!(
            jobs.iter()
                .any(|job| matches!(job.origin, hellas_gateway::jobs::Origin::Http { .. }))
        );
        assert!(
            jobs.iter()
                .any(|job| matches!(job.origin, hellas_gateway::jobs::Origin::Iroh { .. }))
        );
        assert_eq!(consumer.watch().0.jobs.len(), 1);
        use hellas_channel::work::{WorkBackend, admission::BackendKey};
        let backend = crate::gateway_work::provider::IrohBackend {
            core: Arc::downgrade(&provider),
            listener: "work".into(),
            assurance: hellas_rpc::Assurance::ProducerSigned,
        };
        let first = BackendKey::Fetch {
            service: "openai".into(),
            method: "responses".into(),
        };
        assert!(
            backend
                .try_admit(&first, FRIEND.node_key().public_key())
                .is_err()
        );
        let address = provider.iroh_addresses()["work"].clone();
        let mut document = provider.watch().0.document;
        // Replacing the executor cannot move the two held requests to it.
        document.backends.get_mut("upstream").unwrap().max_in_flight =
            std::num::NonZeroUsize::new(3).unwrap();
        let mut added = document.backends["upstream"].clone();
        let BackendKind::Fetch { service, .. } = &mut added.kind else {
            unreachable!()
        };
        *service = "added".into();
        added.max_in_flight = std::num::NonZeroUsize::MIN;
        document.backends.insert("added".into(), added);
        let Listener::Iroh { backends, .. } = document.listeners.get_mut("work").unwrap() else {
            unreachable!()
        };
        backends.push("added".into());
        document.routes[0].backends = vec!["added".into()];
        let hellas_gateway::Presentation::Http { targets } = &mut document.routes[0].presentation
        else {
            unreachable!()
        };
        let mut target = targets.remove("upstream").unwrap();
        target.service = "added".into();
        targets.insert("added".into(), target);
        rpc.configure(request(&document)).await.unwrap();
        let current = provider.iroh_addresses()["work"].clone();
        assert_eq!(current.id, address.id);
        assert_eq!(
            current.ip_addrs().collect::<Vec<_>>(),
            address.ip_addrs().collect::<Vec<_>>()
        );
        send(&provider, &provider_access).await;
        let second = BackendKey::Fetch {
            service: "added".into(),
            method: "responses".into(),
        };
        let second_permit = backend
            .try_admit(&second, FRIEND.node_key().public_key())
            .unwrap();
        assert!(
            backend
                .try_admit(&second, FRIEND.node_key().public_key())
                .is_err()
        );
        assert!(
            backend
                .try_admit(&first, FRIEND.node_key().public_key())
                .is_ok()
        );
        drop(second_permit);
        assert!(!direct.is_finished());
        assert!(!remote.is_finished());
        release.add_permits(2);
        direct.await.unwrap();
        remote.await.unwrap();
        assert_eq!(reached.recv().await.unwrap(), 2);
        let cancelled = tokio::spawn({
            let url = format!(
                "http://{}{}",
                consumer.http_addresses()["api"],
                template.paths[0]
            );
            let bearer = consumer_access.bearer();
            async move {
                reqwest::Client::new()
                    .post(url)
                    .bearer_auth(bearer)
                    .json(&serde_json::json!({"messages":[], "max_tokens":6, "stream":false}))
                    .send()
                    .await
                    .unwrap()
            }
        });
        assert_eq!(reached.recv().await.unwrap(), 3);
        let job = provider
            .watch()
            .0
            .jobs
            .into_iter()
            .find(|job| matches!(job.origin, hellas_gateway::jobs::Origin::Iroh { .. }))
            .unwrap();
        assert!(
            rpc.cancel_job(CancelJobRequest {
                authorization: ROOT_GRANT.0.to_vec(),
                id: job.id
            })
            .await
            .unwrap()
            .cancelled
        );
        let response = cancelled.await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
        assert!(!response.text().await.unwrap().is_empty());
        upstream.await.unwrap();
        consumer.shutdown().await.unwrap();
        provider.shutdown().await.unwrap();
        connection.close(0u32.into(), b"test finished");
        let _ = served.await.unwrap();
        host.world.service.shutdown().await.unwrap();
        consumer_fixture.node.close().await;
    };
    hellas_authority::test_support::within(run).await;
}
