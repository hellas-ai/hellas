use super::*;
use crate::{
    daemon::{Core, Options},
    daemon_config::{Document, Listener},
};
use futures::StreamExt;
use hellas_private::StoreLocation;

async fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let now = UnixMillis(1000);
    let extra: Vec<_> = hellas_authority::operations::OPERATIONS
        .iter()
        .filter(|op| !matches!(op.scope, hellas_authority::operations::Scope::Allowance))
        .map(|op| (op.name, op.permission(authority(), None).unwrap().resource))
        .collect();
    let scope = hellas_authority::test_support::common_node::admin_spec(
        authority(),
        ROOT.principal(),
        &extra,
        (now, UnixMillis(u64::MAX)),
        (u64::MAX, MAX_DELEGATION_DEPTH),
        &[],
    );
    let (store, secret) = NodeStore::bootstrap(
        &StoreLocation::for_test(directory.path()),
        hellas_channel::test_support::network(),
        ROOT_GRANT,
        hellas_authority::test_support::common_node::approval(
            Ownership::Bootstrap {
                root: ROOT_GRANT,
                target: None,
            },
            scope,
        ),
        None,
        now,
    )
    .await
    .unwrap();
    let node = NodeCoordinator::new(store, Arc::new(move || now));
    let content = hellas_authority::test_support::content_store(directory.path()).await;
    let service = NodeControl::new(node.clone())
        .with_content_store(content.clone())
        .with_remote_admission(
            RemoteControlAdmission::new(vec![SecretKey::from_bytes(&[62; 32]).public()]).unwrap(),
        );
    Fixture {
        directory,
        content,
        node,
        service,
        secret,
    }
}

fn options(f: &Fixture) -> Options {
    let home = StoreLocation::for_test(&f.directory.path().join("runtime"));
    Options {
        discovery: false,
        endpoint: None,
        remote_control: Default::default(),
        prover: None,
        chain: crate::test_support::chain_dir(
            home.as_ref(),
            hellas_channel::test_support::network(),
        ),
        home,
        signer: Arc::new(ROOT.node_key()),
        transport: SecretKey::from_bytes(&[63; 32]),
        settlement: hellas_kernel::Secp256k1Signer::from_secret_scalar([64; 32]).unwrap(),
        owner: Some(Arc::new(ROOT.passkey())),
        node: f.node.clone(),
        content: f.content.clone(),
    }
}

async fn access(f: &Fixture) -> hellas_gateway::GatewayAccess {
    let caller = hellas_authority::test_support::session(&f.node, &f.secret).await;
    let scope = hellas_channel::test_support::Rights::new(authority(), ROOT)
        .allow(
            hellas_authority::node::GATEWAY_INVOKE,
            host_resource(authority()),
        )
        .valid_from(UnixMillis(1000))
        .valid_until(UnixMillis(u64::MAX))
        .build();
    let grant = GrantId([104; 16]);
    f.node
        .grant(
            &caller,
            GrantCommand::Issue {
                authorization: ROOT_GRANT,
                id: grant,
                spec: scope.clone(),
            },
        )
        .await
        .unwrap();
    let (_, secret) = hellas_authority::test_support::credentials::issue_one(
        &f.node,
        &caller,
        ROOT_GRANT,
        scope,
        CredentialHolder::Bearer,
    )
    .await
    .unwrap();
    hellas_gateway::GatewayAccess::new(f.node.clone(), grant, secret)
        .await
        .unwrap()
}

fn request(document: &Document, expected_revision: u64) -> ConfigureRequest {
    ConfigureRequest {
        authorization: ROOT_GRANT.0.to_vec(),
        expected_revision,
        document: serde_json::to_vec(document).unwrap(),
    }
}
async fn connect(
    f: &Fixture,
    core: Arc<Core>,
) -> (
    Endpoint,
    Endpoint,
    Connection,
    HostControlClientImpl<IrohTransport>,
    tokio::task::JoinHandle<Result<(), WireStatus>>,
) {
    let (client, server, cc, sc) = pair().await;
    let task = serve(&f.service.clone().with_core(core).unwrap(), sc);
    let (rpc, _) = connect_iroh(
        cc.clone(),
        authority(),
        &f.secret,
        SessionKey::Passkey(&ROOT.passkey()),
    )
    .await
    .unwrap();
    (client, server, cc, rpc, task)
}

#[tokio::test]
async fn configure_commits_and_publishes_after_the_control_connection_closes() {
    hellas_authority::test_support::within(async {
        let f = fixture().await;
        let opts = options(&f);
        let core = Core::open(opts, Document::default()).await.unwrap();
        let (_client, _server, connection, rpc, served) = connect(&f, core.clone()).await;
        let committed = Arc::new(Semaphore::new(0));
        let resume = Arc::new(Semaphore::new(0));
        *core.after_commit.lock().unwrap() = Some((committed.clone(), resume.clone()));
        let mut document = Document::default();
        document.listeners.insert(
            "api".into(),
            Listener::Http {
                bind: "127.0.0.1:0".parse().unwrap(),
                zdr: true,
            },
        );
        let mut events = core.watch().1;
        let mut pending = tokio::spawn(async move { rpc.configure(request(&document, 0)).await });
        tokio::select! {
            permit = committed.acquire() => permit.unwrap().forget(),
            result = &mut pending => panic!("Configure ended before commit: {result:?}"),
        }
        assert_eq!(
            f.node.configuration().await.unwrap().unwrap().revision,
            Revision(1)
        );
        assert_eq!(core.watch().0.revision, Revision(0));
        assert!(core.http_addresses().is_empty());
        connection.close(0u32.into(), b"caller disconnected after commit");
        let _ = served.await.unwrap();
        assert!(pending.await.unwrap().is_err());
        resume.add_permits(1);
        assert!(matches!(
            events.recv().await.unwrap(),
            hellas_gateway::jobs::Event::Revision {
                revision: Revision(1)
            }
        ));
        let view = core.watch().0;
        let stored = f.node.configuration().await.unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(&view.document).unwrap(),
            serde_json::from_str::<serde_json::Value>(&stored.document).unwrap()
        );
        let address = core.http_addresses()["api"];
        let response = reqwest::get(format!("http://{address}/anything"))
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        response.bytes().await.unwrap();
        core.shutdown().await.unwrap();
        let opts = options(&f);
        let restored = Core::restore(opts).await.unwrap();
        assert_eq!(
            serde_json::to_value(&restored.watch().0.document).unwrap(),
            serde_json::to_value(view.document).unwrap()
        );
        restored.shutdown().await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn watch_reports_configure_and_cancellation_without_echoing_keys() {
    hellas_authority::test_support::within(async {
        let f = fixture().await;
        let core = Core::open(options(&f), Document::default()).await.unwrap();
        let (_client, _server, connection, rpc, served) = connect(&f, core.clone()).await;
        let mut watch = rpc.watch(WatchRequest { authorization: ROOT_GRANT.0.to_vec() }).await.unwrap();
        assert!(matches!(watch.next().await.unwrap().unwrap().update, Some(watch_response::Update::Snapshot(_))));
        let mut document: Document = serde_json::from_value(serde_json::json!({
            "listeners": {}, "limits": { "requests_per_minute": 1 }, "backends": {
                "openai": { "kind": "fetch", "max_in_flight": 2, "service": "openai", "method": "responses", "upstream": {"kind": "openai_responses", "secret": "input-only-key"} }
            }
        })).unwrap();
        assert_eq!(rpc.configure(request(&document, core.watch().0.revision.0)).await.unwrap().revision, 1);
        let event = watch.next().await.unwrap().unwrap();
        let Some(watch_response::Update::Event(bytes)) = event.update else { panic!("expected event") };
        assert!(matches!(serde_json::from_slice(&bytes).unwrap(), hellas_gateway::jobs::Event::Revision { revision: Revision(1) }));
        let stored = f.node.configuration().await.unwrap().unwrap();
        assert!(!stored.document.contains("input-only-key"));
        assert_eq!(stored.secrets.0["openai"]["bearer"], "input-only-key");
        assert!(!serde_json::to_string(&core.watch().0).unwrap().contains("input-only-key"));
        let mut fresh = rpc.watch(WatchRequest { authorization: ROOT_GRANT.0.to_vec() }).await.unwrap();
        let Some(watch_response::Update::Snapshot(bytes)) = fresh.next().await.unwrap().unwrap().update else { panic!("initial snapshot") };
        assert!(!String::from_utf8(bytes).unwrap().contains("input-only-key"));
        drop(fresh);
        assert!(rpc.configure(request(&document, 0)).await.is_err());
        document = core.watch().0.document;
        let old = serde_json::to_value(&document).unwrap();
        document.listeners.insert("invalid".into(), Listener::Iroh { chain: None,
port: 0, backends: vec!["missing".into()] });
        assert!(rpc.configure(request(&document, core.watch().0.revision.0)).await.is_err());
        assert_eq!(serde_json::to_value(&core.watch().0.document).unwrap(), old);
        assert_eq!(f.node.configuration().await.unwrap().unwrap(), stored);
        let document = core.watch().0.document;
        assert_eq!(rpc.configure(request(&document, core.watch().0.revision.0)).await.unwrap().revision, 2);
        assert_eq!(f.node.configuration().await.unwrap().unwrap().secrets, stored.secrets);
        let _revision = watch.next().await.unwrap().unwrap();
        let job = core.jobs.admit(&hellas_gateway::jobs::Request { origin: hellas_gateway::jobs::Origin::Local, method: "POST".into(), path: "/held".into() }).unwrap();
        assert!(core.jobs.admit(&hellas_gateway::jobs::Request { origin: hellas_gateway::jobs::Origin::Local, method: "POST".into(), path: "/over-limit".into() }).is_err());
        let admitted = watch.next().await.unwrap().unwrap();
        let Some(watch_response::Update::Event(bytes)) = admitted.update else { panic!("expected job") };
        assert!(matches!(serde_json::from_slice(&bytes).unwrap(), hellas_gateway::jobs::Event::Job { job: hellas_gateway::jobs::Info { state: hellas_gateway::jobs::State::Admitted, .. } }));
        assert!(rpc.cancel_job(CancelJobRequest { authorization: ROOT_GRANT.0.to_vec(), id: job.id() }).await.unwrap().cancelled);
        job.cancelled().await;
        drop(job);
        drop(watch);
        connection.close(0u32.into(), b"test finished");
        let _ = served.await.unwrap();
        core.shutdown().await.unwrap();
        let restored = Core::restore(options(&f)).await.unwrap();
        assert_eq!(restored.watch().0.revision, Revision(2));
        restored.shutdown().await.unwrap();
    }).await;
}

#[tokio::test]
async fn removing_a_backend_preserves_its_accepted_request_and_routes_the_next_one() {
    use crate::daemon_config::{Backend, BackendKind};
    use hellas_authority::test_support::{Allowance, chat_resource, ids, use_https};
    use hellas_channel::test_support::{
        actors::{FRIEND, PROVIDER},
        backend::{Backend as Fake, Completion, Reply},
    };
    hellas_authority::test_support::within(async {
        let f = fixture().await;
        let access = access(&f).await;
        let mut opts = options(&f);
        opts.signer = Arc::new(FRIEND.node_key());
        opts.owner = Some(Arc::new(FRIEND.passkey()));
        let core = Core::open(opts, Document::default()).await.unwrap();
        let (_client, _server, connection, rpc, served) = connect(&f, core.clone()).await;
        let mut document = Document::default();
        document.listeners.insert(
            "api".into(),
            Listener::Http {
                bind: "127.0.0.1:0".parse().unwrap(),
                zdr: true,
            },
        );
        let template = chat_resource("https://private.fixture", 6);
        let mut providers = Vec::new();
        for (id, key, completion) in [
            ("first", 5, Completion::Permits(Arc::new(Semaphore::new(0)))),
            ("second", 6, Completion::Immediate),
        ] {
            let mut allowance = Allowance::responses(ids::ALLOWANCE, FRIEND);
            use_https(&mut allowance.definition.policies[0], template.clone());
            let host = crate::test_support::Host::builder()
                .with_transport_key(key)
                .with_allowance(allowance)
                .with_backend(Fake {
                    finish: completion,
                    reply: Reply::events(Reply::http(
                        200,
                        "application/json",
                        r#"{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
                    )),
                    ..Default::default()
                })
                .build()
                .await;
            let remote = host.remote().await;
            let session = host.options(remote.addresses());
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
            let trust_store = f.directory.path().join("trust").join(id);
            crate::trust_policy::TrustPolicyStore::new(&trust_store)
                .approve(
                    id,
                    0,
                    crate::trust_policy::TrustPolicy {
                        provider_genesis: hellas_client::ProviderAddress::of(
                            &bundle.offers[0].offer().provider,
                        )
                        .unwrap()
                        .enrollment,
                        assurance: hellas_rpc::Assurance::ProducerSigned,
                        apple: None,
                    },
                    "independent test approval".into(),
                )
                .unwrap();
            document.backends.insert(
                id.into(),
                Backend {
                    max_in_flight: std::num::NonZeroUsize::MIN,
                    kind: BackendKind::Grant {
                        access: Some(base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            bundle.encode().unwrap(),
                        )),
                        resource: None,
                        evaluator: None,
                        trust: Some(crate::daemon_config::Trust {
                            store: trust_store,
                            policy: id.into(),
                        }),
                    },
                },
            );
            providers.push((host, remote));
        }
        document.routes.push(hellas_gateway::Route {
            backends: vec!["first".into(), "second".into()],
            presentation: hellas_gateway::Presentation::Http {
                targets: ["first", "second"]
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
        rpc.configure(request(&document, core.watch().0.revision.0))
            .await
            .unwrap();
        let execution = core.execution();
        let outgoing = execution.backend("first").unwrap().endpoint().unwrap();
        assert_eq!(
            outgoing.id(),
            execution
                .backend("second")
                .unwrap()
                .endpoint()
                .unwrap()
                .id()
        );
        assert_ne!(outgoing.id(), options(&f).transport.public());
        let url = format!(
            "http://{}{}",
            core.http_addresses()["api"],
            template.paths[0]
        );
        let send = || {
            let url = url.clone();
            let bearer = access.bearer();
            async move {
                let response = reqwest::Client::new()
                    .post(url)
                    .bearer_auth(bearer)
                    .json(&serde_json::json!({"messages":[], "max_tokens":6, "stream":false}))
                    .send()
                    .await
                    .unwrap();
                let status = response.status();
                let body = response.text().await.unwrap();
                assert_eq!(status, reqwest::StatusCode::OK, "{body}");
            }
        };
        let held = tokio::spawn(send());
        providers[0].0.backend.started.notified().await;
        assert_eq!(core.watch().0.jobs.len(), 1);
        // Unchanged document entries still recheck an external trust approval.
        let trust =
            crate::trust_policy::TrustPolicyStore::new(f.directory.path().join("trust/second"));
        let approved = trust.load("second").unwrap();
        let mut changed = approved.policy.clone();
        changed.provider_genesis = hellas_rpc::ContentId::from_bytes([99; 32]);
        trust
            .approve(
                "second",
                approved.revision,
                changed,
                "replacement pin".into(),
            )
            .unwrap();
        let stored = f.node.configuration().await.unwrap();
        assert!(
            rpc.configure(request(&core.watch().0.document, core.watch().0.revision.0))
                .await
                .is_err()
        );
        assert_eq!(core.watch().0.revision, Revision(1));
        assert_eq!(f.node.configuration().await.unwrap(), stored);
        assert!(!held.is_finished());
        trust
            .approve(
                "second",
                approved.revision + 1,
                approved.policy,
                "restored pin".into(),
            )
            .unwrap();
        let mut document = core.watch().0.document;
        document.remove_backend("first").unwrap();
        rpc.configure(request(&document, core.watch().0.revision.0))
            .await
            .unwrap();
        assert!(!held.is_finished());
        assert_eq!(core.watch().0.jobs[0].backend.as_deref(), Some("first"));
        send().await;
        assert!(!held.is_finished());
        assert_eq!(providers[1].0.backend.calls.load(Ordering::SeqCst), 1);
        providers[0].0.backend.finish.release();
        held.await.unwrap();
        core.shutdown().await.unwrap();
        let mut opts = options(&f);
        opts.signer = Arc::new(FRIEND.node_key());
        opts.owner = Some(Arc::new(FRIEND.passkey()));
        let restored = Core::restore(opts).await.unwrap();
        let view = restored.watch().0;
        assert_eq!(view.revision, Revision(2));
        assert_eq!(view.backends.len(), 1);
        assert!(matches!(
            &view.document.backends["second"].kind,
            BackendKind::Grant { access: None, .. }
        ));
        restored.shutdown().await.unwrap();
        connection.close(0u32.into(), b"test finished");
        let _ = served.await.unwrap();
        for (_, remote) in providers {
            remote.shutdown().await;
        }
    })
    .await;
}

mod iroh;

#[tokio::test]
async fn an_unbound_daemon_can_install_its_iroh_listener_after_owner_binding() {
    hellas_authority::test_support::within(async {
        let f = fixture().await;
        let opts = options(&f);
        let enrollment = hellas_channel::test_support::enrollment(
            &hellas_auth::ProducerSigningKey::from_secret_bytes([55; 32]).unwrap(),
            &opts.signer,
            *opts.transport.public().as_bytes(),
            [56; 32],
        );
        let core = Core::open(opts, Document::default()).await.unwrap();
        let (client, server, connection, rpc, served) = connect(&f, core.clone()).await;
        let mut document = Document::default();
        document.listeners.insert(
            "work".into(),
            Listener::Iroh {
                chain: Some(
                    hellas_chain::genesis::ChainProfile::known(
                        hellas_chain::genesis::Chain::Devnet,
                    )
                    .to_file(),
                ),
                port: 0,
                backends: vec![],
            },
        );
        assert!(
            rpc.configure(request(&document, core.watch().0.revision.0))
                .await
                .is_err()
        );
        assert_eq!(core.watch().0.revision, Revision(0));
        rpc.bind_provider(BindProviderRequest {
            authorization: ROOT_GRANT.0.to_vec(),
            enrollment: enrollment.canonical_bytes(),
        })
        .await
        .unwrap();
        assert_eq!(
            rpc.configure(request(&document, core.watch().0.revision.0))
                .await
                .unwrap()
                .revision,
            1
        );
        assert_eq!(core.iroh_addresses().len(), 1);
        let bound = core.iroh_endpoints().pop().unwrap();
        let mut invalid = core.watch().0.document;
        let Listener::Iroh {
            chain: Some(profile),
            ..
        } = invalid.listeners.get_mut("work").unwrap()
        else {
            unreachable!()
        };
        profile.genesis_json = "{}".into();
        assert!(rpc.configure(request(&invalid, 1)).await.is_err());
        assert_eq!(core.watch().0.revision, Revision(1));
        assert!(!bound.is_closed());
        let mut stopped = core.watch().0.document;
        stopped.listeners.clear();
        assert_eq!(
            rpc.configure(request(&stopped, 1)).await.unwrap().revision,
            2
        );
        assert!(
            bound.is_closed(),
            "Configure joins the removed listener before returning"
        );
        assert_eq!(
            rpc.configure(request(&document, core.watch().0.revision.0))
                .await
                .unwrap()
                .revision,
            3
        );
        assert_eq!(core.iroh_addresses().len(), 1);
        assert_eq!(
            serde_json::to_value(&core.watch().0.document.listeners).unwrap(),
            serde_json::to_value(&document.listeners).unwrap()
        );

        connection.close(0u32.into(), b"done");
        let _ = served.await;
        core.shutdown().await.unwrap();
        client.close().await;
        server.close().await;
        f.content.close().await;
        f.node.close().await;
    })
    .await;
}
