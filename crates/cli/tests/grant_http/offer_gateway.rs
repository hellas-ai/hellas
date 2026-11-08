use super::*;
use hellas_authority::model::grant::records::decode_enrollment;
use hellas_channel::test_support::actors::{FRIEND, ROOT};
use hellas_private::StoreLocation;

struct OfferHost {
    directory: tempfile::TempDir,
    https: Https,
    provider: Cli,
    client: Cli,
    node: Process,
    #[cfg(feature = "otel")]
    metrics: String,
    socket: PathBuf,
    provider_profile: PathBuf,
    client_profile: PathBuf,
    provider_enrollment: hellas_rpc::ProviderEnrollmentBundle,
    reader: hellas_auth::authority::GrantSpec,
    reader_grant: GrantId,
    root_grant: GrantId,
    signed_offer: hellas_authority::model::grant::records::SignedOffer,
    offer: PathBuf,
    id: GrantId,
    work_profile: PathBuf,
    exported_offer: std::process::Output,
    imported_offer: std::process::Output,
}
impl OfferHost {
    async fn start() -> Self {
        Self::start_with_metrics(None, None).await
    }
    async fn start_with_metrics(
        metrics_endpoint: Option<String>,
        metrics_address: Option<String>,
    ) -> Self {
        Self::start_with_identity(metrics_endpoint, metrics_address, None).await
    }
    async fn start_with_identity(
        metrics_endpoint: Option<String>,
        metrics_address: Option<String>,
        client_identity: Option<&Path>,
    ) -> Self {
        Self::start_with_policy(
            metrics_endpoint,
            metrics_address,
            client_identity,
            http_invocation_policy(),
        )
        .await
    }
    async fn start_with_policy(
        metrics_endpoint: Option<String>,
        metrics_address: Option<String>,
        client_identity: Option<&Path>,
        invocation_policy: hellas_rpc::protocol::invocation::InvocationPolicy,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        hellas_private::restrict_directory(root).unwrap();
        let https = Https::start(Some("Bearer fixture-key")).await;
        let mut provider = Cli::new(root, "provider", ROOT_PASSKEY);
        let mut client = Cli::new(root, "client", FRIEND_PASSKEY);
        if let Some(existing) = client_identity {
            std::fs::copy(existing, &client.identity).unwrap();
        }
        provider.metrics_endpoint = metrics_endpoint.clone();
        client.metrics_endpoint = metrics_endpoint;
        provider.metrics_address = metrics_address.clone();
        client.metrics_address = metrics_address;
        assert_eq!(provider.principal(), ROOT.principal());
        assert_eq!(client.principal(), FRIEND.principal());
        for cli in [&provider, &client] {
            cli.run(&["--software-root", "identity", "init"]).await;
        }
        let exported = provider.output(&["identity", "export-enrollment"]).await;
        assert!(exported.status.success());
        let provider_enrollment = decode_enrollment(&exported.stdout).unwrap();
        let location = StoreLocation::for_test(&provider.home);
        let (store, app_secret) = common_node::bootstrap_node_with_credential(
            &hellas_sdk::grant_config::GrantConfig::journal_dir(&location),
            hellas_authority::model::grant::grant_network(),
            Some(provider_enrollment.clone()),
            hellas_auth::authority::UnixMillis::now().unwrap_or_default(),
        )
        .await
        .unwrap();
        let authority = store.state().authority().authority();
        let root_grant = GrantId([0; 16]);
        let mut reader = store
            .state()
            .authority()
            .grant(root_grant)
            .unwrap()
            .spec()
            .clone();
        let contact = root.join("contact");
        client
            .run(&[
                "contact",
                "export",
                "--display-name",
                "Client",
                "--out",
                string(&contact),
            ])
            .await;
        provider
            .run(&["contact", "import", string(&contact), "--name", "client"])
            .await;
        let grantee = hellas_authority::model::grant::records::decode_contact_card(
            &std::fs::read(&contact).unwrap(),
        )
        .unwrap()
        .principal();
        reader.subject = grantee;
        reader.permissions = [hellas_auth::authority::Permission {
            operation: hellas_auth::authority::OperationId::new(
                hellas_authority::work_store::grant::WORK_ALLOWANCE_READ,
            )
            .unwrap(),
            resource: hellas_authority::node::machine_resource(authority),
        }]
        .into();
        reader.issuance = None;
        let reader_grant = GrantId([4; 16]);
        let coordinator = hellas_authority::node::NodeCoordinator::new(
            store,
            Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
        );
        let caller = hellas_authority::test_support::session(&coordinator, &app_secret).await;
        let (_, client_secret) = hellas_authority::test_support::credentials::issue_one(
            &coordinator,
            &caller,
            root_grant,
            reader.clone(),
            client.holder().await,
        )
        .await
        .unwrap();
        drop(coordinator);
        let control = provider.home.join("provider");
        std::fs::create_dir_all(&control).unwrap();
        let provider_profile = profile(&control, "control", authority, root_grant, &app_secret);
        let client_profile = profile(&control, "reader", authority, reader_grant, &client_secret);
        let socket = control.join("control.sock");
        let fetch = root.join("fetch.json");
        let resources = root.join("resources.json");
        let (_control_certificate, _control_private_key) = control_tls(&control);
        let secret = root.join("account.json");
        hellas_private::write_atomically(&secret, ".new", br#"{"access_token":"fixture-key"}"#)
            .unwrap();
        std::fs::write(&fetch,json!({"routes":[{"service":"http","method":"request","destination":{"type":"http","config":{
            "allowed_hosts":["localhost"],"allow_private_addresses":true,
            "credentials":{"glm-account":{"allowed_origins":[https.origin],"allowed_paths":["/v1/chat/completions"],"allowed_methods":["POST"],
            "trust_roots":{"mode":"certificates","der_base64":[https.root_der]},"header_name":"authorization","secret_file":secret,"secret_field":"access_token","prefix":"Bearer "}}
        }}}]}).to_string()).unwrap();
        std::fs::write(&resources,json!({"remote_control_peers":[client.run(&["identity", "show-node-id"]).await.trim()],"max_job_millis":10000,"machine":{"max_in_flight":2,"limits":[]},"accounts":[{"account":hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test account")),"max_in_flight":256,"limits":[]}],"resources":[{"resource":hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test resource")),"account":hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test account")),"revision":1,"pricing":{"revision":1,"rates":null},"name":"glm","invocation_policy":invocation_policy,
            "https":{"origin":https.origin,"paths":["/v1/chat/completions"],"methods":["POST"],"credential":"glm-account","tls":{"roots":{"mode":"certificates","der_base64":[https.root_der]},"spki_sha256":[]},"accounting":"openai-chat","max_output_tokens":8,"max_response_bytes":65536}}]}).to_string()).unwrap();
        let mut node = provider.spawn(
            &[
                "serve",
                #[cfg(feature = "otel")]
                "--metrics-port",
                #[cfg(feature = "otel")]
                "0",
                "--no-discovery",
                "--fetch-config",
                string(&fetch),
                "--grant-config",
                string(&resources),
            ],
            "provider.log",
        );
        node.wait_for("RPC server running.").await;
        #[cfg(feature = "otel")]
        let metrics = node
            .wait_for("prometheus metrics server listening on ")
            .await;
        let offer = root.join("offer");
        let id = GrantId([9; 16]);
        for definition in common_node::budgets(
            common_node::POOL,
            grantee,
            vec![Limit::new(Meter::OutputTokens, Window::Total, 20)],
            1,
        )
        .into_iter()
        // The grant config owns the account.
        .filter(|definition| !matches!(definition.node, BudgetNode::Account(_)))
        {
            admin(
                &provider,
                &provider_profile,
                &socket,
                WorkControlCommand::ConfigureBudget { definition },
            )
            .await;
        }
        admin(
            &provider,
            &provider_profile,
            &socket,
            WorkControlCommand::Create {
                id,
                terms: terms(grantee),
            },
        )
        .await;
        let export = request_file(root, &WorkControlCommand::Offers { id: Some(id) });
        let exported_offer = provider
            .output(&[
                "admin",
                "--profile",
                string(&provider_profile),
                "--control-socket",
                string(&socket),
                "work",
                string(&export),
                "--offer-out",
                string(&offer),
            ])
            .await;
        assert!(exported_offer.status.success());
        let signed_offer = hellas_authority::model::grant::records::SignedOffer::decode(
            &std::fs::read(&offer).unwrap(),
            hellas_auth::authority::UnixMillis(0),
        )
        .unwrap();
        let work_profile = issue_work_profile(
            &provider,
            &provider_profile,
            &socket,
            root,
            grantee,
            &client.holder_file().await,
            id,
        )
        .await;
        let import = client
            .output(&["offer", "import", string(&offer), "--name", "lan"])
            .await;
        assert!(
            import.status.success(),
            "{}",
            String::from_utf8_lossy(&import.stderr)
        );
        OfferHost {
            directory,
            https,
            provider,
            client,
            node,
            #[cfg(feature = "otel")]
            metrics,
            socket,
            provider_profile,
            client_profile,
            provider_enrollment,
            reader,
            reader_grant,
            root_grant,
            signed_offer,
            offer,
            id,
            work_profile,
            exported_offer,
            imported_offer: import,
        }
    }
    fn root(&self) -> &Path {
        self.directory.path()
    }
    async fn approve_trust(&self) -> PathBuf {
        let trust_root = self.root().join("caller-trust");
        let trust_source = self.root().join("caller-policy.json");
        std::fs::write(
            &trust_source,
            serde_json::to_vec(&hellas_sdk::trust_policy::TrustPolicy {
                provider_genesis: self.signed_offer.offer().provider.content_id(),
                assurance: hellas_rpc::Assurance::ProducerSigned,
                apple: None,
            })
            .unwrap(),
        )
        .unwrap();
        self.client
            .run(&[
                "trust",
                "--store",
                string(&trust_root),
                "approve",
                "lan",
                "--expected-revision",
                "0",
                "--policy",
                string(&trust_source),
                "--reason",
                "independent test provider approval",
            ])
            .await;
        trust_root
    }
    async fn gateway(&self) -> Gateway {
        let trust_root = self.approve_trust().await;
        let (profile, token) = gateway_profile(self.root()).await;
        let mut process = self.client.spawn(
            &[
                "gateway",
                #[cfg(feature = "otel")]
                "--metrics-port",
                #[cfg(feature = "otel")]
                "0",
                "--offer",
                "lan",
                "--trust-store",
                string(&trust_root),
                "--trust-policy",
                "lan",
                "--work-profile",
                string(&self.work_profile),
                "--port",
                "0",
                "--gateway-profile",
                string(&profile),
                "--zdr",
            ],
            "gateway.log",
        );
        let address = process.wait_for("gateway listening on ").await;
        #[cfg(feature = "otel")]
        let metrics = process
            .wait_for("prometheus metrics server listening on ")
            .await;
        Gateway {
            process,
            #[cfg(feature = "otel")]
            metrics,
            url: format!("http://{address}/v1/chat/completions"),
            http: gateway_client(&token),
        }
    }
    async fn stop(mut self) {
        self.node.stop().await;
    }
}
struct Gateway {
    process: Process,
    #[cfg(feature = "otel")]
    metrics: String,
    url: String,
    http: reqwest::Client,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offer_import_reports_the_exported_provider_identity() {
    let host = OfferHost::start().await;
    let fingerprint = format!(
        "Provider enrollment: {}",
        host.provider_enrollment.content_id()
    );
    assert!(String::from_utf8_lossy(&host.exported_offer.stderr).contains(&fingerprint));
    assert!(String::from_utf8_lossy(&host.imported_offer.stderr).contains(&fingerprint));
    assert_eq!(
        String::from_utf8_lossy(&host.imported_offer.stdout).trim(),
        hex::encode(host.id.0)
    );
    // Import is a public description, independent of execution authority.
    let stranger = Cli::new(host.root(), "stranger", STRANGER_PASSKEY);
    stranger
        .run(&[
            "offer",
            "import",
            string(&host.offer),
            "--name",
            "forwarded",
        ])
        .await;
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_admin_uses_the_explicit_reader_profile() {
    let host = OfferHost::start().await;
    let OfferHost {
        provider,
        client,
        provider_profile,
        client_profile,
        socket,
        reader,
        reader_grant,
        root_grant,
        signed_offer,
        ..
    } = &host;
    let root = host.root();
    let direct = &signed_offer.offer().addresses[0];
    let provider_node = root.join("provider-enrollment");
    provider
        .run(&[
            "identity",
            "export-enrollment",
            "--out",
            string(&provider_node),
        ])
        .await;
    let list = root.join("list-work.json");
    std::fs::write(
        &list,
        serde_json::to_vec(&WorkControlCommand::List).unwrap(),
    )
    .unwrap();
    let remote = [
        "admin",
        "--profile",
        string(client_profile),
        "--node",
        string(&provider_node),
        "--address",
        direct,
        "work",
        string(&list),
    ];
    let command = request_file(
        root,
        &hellas_auth::authority::GrantCommand::Issue {
            authorization: *root_grant,
            id: *reader_grant,
            spec: reader.clone(),
        },
    );
    provider
        .run(&[
            "admin",
            "--profile",
            string(provider_profile),
            "--control-socket",
            string(socket),
            "grant",
            string(&command),
        ])
        .await;
    let WorkControlReply::Allowances(listed) =
        serde_json::from_str(&client.run(&remote).await).unwrap()
    else {
        panic!("allowance list")
    };
    assert_eq!(listed.len(), 1);
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_requires_a_caller_approved_trust_policy() {
    let host = OfferHost::start().await;
    let trust_root = host.approve_trust().await;
    let (gateway_profile, _) = gateway_profile(host.root()).await;
    std::fs::remove_file(trust_root.join("lan.json")).unwrap();
    let before = host.https.calls.load(Ordering::SeqCst);
    let refused = host
        .client
        .output(&[
            "gateway",
            "--offer",
            "lan",
            "--work-profile",
            string(&host.work_profile),
            "--trust-store",
            string(&trust_root),
            "--trust-policy",
            "lan",
            "--gateway-profile",
            string(&gateway_profile),
            "--port",
            "0",
        ])
        .await;
    assert!(!refused.status.success());
    let error = String::from_utf8_lossy(&refused.stderr);
    assert_eq!(
        error.trim(),
        "error: No such file or directory (os error 2)"
    );
    assert_eq!(host.https.calls.load(Ordering::SeqCst), before);
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approved_offer_streams_from_the_private_ca_upstream() {
    let host = OfferHost::start().await;
    let mut gateway = host.gateway().await;
    let before = host.https.calls.load(Ordering::SeqCst);
    let response = post(
        &gateway.http,
        &gateway.url,
        json!({"messages":[],"stream":true}),
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let mut stream = response.bytes_stream();
    let first = tokio::time::timeout(hellas_authority::test_support::HANG_GUARD, stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&first).contains("hello"));
    host.https.finish.add_permits(1);
    while let Some(chunk) = stream.next().await {
        chunk.unwrap();
    }
    assert_eq!(host.https.calls.load(Ordering::SeqCst) - before, 1);
    gateway.process.stop().await;
    host.stop().await;
}

#[cfg(feature = "otel")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metrics_scrape_observes_gateway_and_serve_work() {
    let (collector, endpoint, mut exports) = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/v1/metrics", listener.local_addr().unwrap());
        let (send, receive) = tokio::sync::mpsc::unbounded_channel();
        let app = axum::Router::new().route(
            "/v1/metrics",
            axum::routing::post(move |body: axum::body::Bytes| {
                let send = send.clone();
                async move {
                    send.send(body).unwrap();
                    (
                        [("content-type", "application/x-protobuf")],
                        Vec::<u8>::new(),
                    )
                }
            }),
        );
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (task, endpoint, receive)
    };
    let host = OfferHost::start_with_metrics(Some(endpoint), Some("0.0.0.0".into())).await;
    let mut gateway = host.gateway().await;
    let http = reqwest::Client::new();
    for url in [&gateway.metrics, &host.metrics] {
        assert!(
            url.starts_with("http://0.0.0.0:"),
            "explicit bind address was ignored: {url}"
        );
    }
    let gateway_metrics = gateway.metrics.replace("0.0.0.0", "127.0.0.1");
    let serve_metrics = host.metrics.replace("0.0.0.0", "127.0.0.1");
    for url in [&gateway_metrics, &serve_metrics] {
        let body = http.get(url).send().await.unwrap().text().await.unwrap();
        assert!(
            !body.contains("hellas_gateway_http_requests_total{"),
            "{body}"
        );
        assert!(
            !body.contains("hellas_execution_executions_completed_total{"),
            "{body}"
        );
    }
    for count in 1..=2 {
        host.https.finish.add_permits(1);
        let response = post(
            &gateway.http,
            &gateway.url,
            json!({"messages":[],"stream":false}),
        )
        .await;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        response.bytes().await.unwrap();
        for (url, names) in [
            (
                &gateway_metrics,
                vec![
                    "hellas_gateway_http_requests_total",
                    "hellas_gateway_http_duration_seconds_count",
                ],
            ),
            (
                &serve_metrics,
                vec![
                    "hellas_execution_executions_started_total",
                    "hellas_execution_executions_completed_total",
                ],
            ),
        ] {
            let response = http.get(url).send().await.unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            assert_eq!(
                response.headers()["content-type"],
                "text/plain; version=0.0.4; charset=utf-8"
            );
            let body = response.text().await.unwrap();
            for name in names {
                assert!(
                    body.lines()
                        .any(|line| line.starts_with(&format!("{name}{{"))
                            && line.ends_with(&format!(" {count}"))),
                    "missing {name}={count}: {body}"
                );
            }
            {
                assert!(
                    body.lines()
                        .any(|line| line.starts_with("endpoint_net_report_reports_total ")),
                    "{body}"
                );
                assert!(
                    body.contains("# TYPE endpoint_net_report_reports_total counter\n"),
                    "{body}"
                );
            }
            assert!(
                !body.contains("# EOF"),
                "Prometheus text has no OpenMetrics terminator"
            );
        }
    }
    gateway.process.stop().await;
    host.stop().await;
    {
        // Check the real protobuf push stream, after shutdown has flushed both
        // providers, as well as the two pulls above.
        let mut names = vec![
            b"hellas.gateway.http.requests".as_slice(),
            b"hellas.execution.executions_completed".as_slice(),
        ];
        tokio::time::timeout(HANG_GUARD, async {
            while !names.is_empty() {
                let body = exports.recv().await.unwrap();
                names.retain(|name| !body.windows(name.len()).any(|window| window == *name));
            }
        })
        .await
        .expect("both instruments must also reach OTLP");
        collector.abort();
    }
}

/// Bootstrap an HTTP authority administered by the client's principal, with
/// the gateway's own bearer credential issued through the checked writer
/// before startup.
async fn controlled_gateway_profile(root: &Path) -> (PathBuf, PathBuf) {
    use hellas_auth::{Digest, authority::*};
    let subject = FRIEND.principal();
    let authority = AuthorityId(Digest::hash(b"CLI controlled HTTP authority"));
    let now = UnixMillis::now().unwrap_or_default();
    let validity = (now, UnixMillis(now.0 + 600_000));
    let permission =
        hellas_authority::operations::Operation::named(hellas_authority::node::GATEWAY_INVOKE)
            .unwrap()
            .permission(authority, None)
            .unwrap();
    let administrator = common_node::admin_spec(
        authority,
        subject,
        &[(hellas_authority::node::GATEWAY_INVOKE, permission.resource)],
        validity,
        (600_000, 0),
        &[],
    );
    let scope = GrantSpec {
        authority,
        subject,
        permissions: [permission].into(),
        issuance: None,
        delegation_depth: 0,
        not_before: validity.0,
        expires: validity.1,
    };
    let journal = root.join("controlled-authority");
    let root_grant = GrantId([0; 16]);
    let location = StoreLocation::for_test(&journal);
    let (store, admin_secret) = hellas_authority::work_store::grant::NodeStore::bootstrap(
        &location,
        hellas_authority::model::grant::grant_network(),
        root_grant,
        common_node::approval(
            Ownership::Bootstrap {
                root: root_grant,
                target: None,
            },
            administrator,
        ),
        None,
        now,
    )
    .await
    .unwrap();
    let coordinator = hellas_authority::node::NodeCoordinator::new(
        store,
        Arc::new(|| UnixMillis::now().unwrap_or_default()),
    );
    let caller = hellas_authority::test_support::session(&coordinator, &admin_secret).await;
    let (_, own) = hellas_authority::test_support::credentials::issue_one(
        &coordinator,
        &caller,
        root_grant,
        scope.clone(),
        CredentialHolder::Bearer,
    )
    .await
    .unwrap();
    drop(coordinator);
    let own_path = root.join("controlled-gateway.credential");
    hellas_sdk::node_control::profile::save_credential(
        hellas_private::private_tempfile(root, ".app-", ".issuing").unwrap(),
        &own_path,
        &own,
    )
    .unwrap();
    std::fs::write(
        root.join("agent-scope.json"),
        serde_json::to_vec(&scope).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("bearer.json"),
        serde_json::to_vec(&CredentialHolder::Bearer).unwrap(),
    )
    .unwrap();
    let control = root.join("gateway-control");
    hellas_private::create_dir_all_durable(&control).unwrap();
    hellas_private::restrict_directory(&control).unwrap();
    let (certificate, key) = control_tls(&control);
    let gateway = root.join("controlled-gateway-profile.json");
    hellas_private::write_atomically(&gateway, ".writing", &serde_json::to_vec(&json!({
        "journal": journal, "authority": authority, "authorization": GrantId([0; 16]),
        "credential": own_path,
        "control": {"socket": control.join("control.sock"), "certificate": certificate, "private_key": key},
    })).unwrap()).unwrap();
    let admin = profile(
        &control,
        "admin",
        authority,
        GrantId([0; 16]),
        &admin_secret,
    );
    (gateway, admin)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_control_issues_and_revokes_live_credentials() {
    let host = OfferHost::start().await;
    let root = host.root();
    let trust_root = host.approve_trust().await;
    let (gateway_profile, admin) = controlled_gateway_profile(root).await;
    let socket = root.join("gateway-control/control.sock");
    let mut process = host.client.spawn(
        &[
            "gateway",
            "--offer",
            "lan",
            "--trust-store",
            string(&trust_root),
            "--trust-policy",
            "lan",
            "--work-profile",
            string(&host.work_profile),
            "--port",
            "0",
            "--gateway-profile",
            string(&gateway_profile),
            "--zdr",
        ],
        "controlled-gateway.log",
    );
    let address = process.wait_for("gateway listening on ").await;
    let url = format!("http://{address}/v1/chat/completions");
    let issue = async |name: &str| {
        let out = root.join(format!("{name}.credential"));
        let issued: Value = serde_json::from_str(
            &host
                .client
                .run(&[
                    "admin",
                    "--profile",
                    string(&admin),
                    "--control-socket",
                    string(&socket),
                    "issue-credential",
                    "--scope",
                    string(&root.join("agent-scope.json")),
                    "--holder",
                    string(&root.join("bearer.json")),
                    "--credential-out",
                    string(&out),
                ])
                .await,
        )
        .unwrap();
        let bytes = std::fs::read(&out).unwrap();
        (
            issued["credential_id"].as_str().unwrap().to_owned(),
            hex::encode(bytes),
        )
    };
    let (first_id, first) = issue("agent-a").await;
    let (_, second) = issue("agent-b").await;
    let status = async |token: Option<&str>| {
        let client = reqwest::Client::new();
        let mut request = client.post(&url).json(&json!({"messages": []}));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.unwrap();
        let status = response.status();
        if status.is_server_error() {
            assert_http_response(
                response,
                reqwest::StatusCode::OK,
                &[&process.log, &host.node.log],
                &host.https,
            )
            .await;
        }
        status
    };
    assert_eq!(status(None).await, reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(status(Some(&first)).await, reqwest::StatusCode::OK);
    assert_eq!(status(Some(&second)).await, reqwest::StatusCode::OK);
    host.client
        .run(&[
            "admin",
            "--profile",
            string(&admin),
            "--control-socket",
            string(&socket),
            "revoke-credential",
            "--credential-id",
            &first_id,
            "--expected-revision",
            "1",
        ])
        .await;
    assert_eq!(
        status(Some(&first)).await,
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert_eq!(status(Some(&second)).await, reqwest::StatusCode::OK);
    process.stop().await;
    assert!(!socket.exists());
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restricted_administrator_can_share_and_the_recipient_can_import_renewal() {
    use hellas_auth::authority as auth;
    let host = OfferHost::start().await;
    let root = host.root();
    let authority = hellas_sdk::node_control::profile::ClientProfile::load(&host.provider_profile)
        .unwrap()
        .authority;
    let administrator = Cli::new(root, "sharing-admin", AGENT_PASSKEY);
    administrator
        .run(&["--software-root", "identity", "init"])
        .await;
    let authorization = GrantId([0x31; 16]);
    let now = auth::UnixMillis::now().unwrap();
    let machine = hellas_authority::node::machine_resource(authority);
    let scope = auth::GrantSpec {
        authority,
        subject: administrator.principal(),
        permissions: [
            (
                hellas_authority::work_store::grant::WORK_ALLOWANCE_READ,
                machine,
            ),
            (
                hellas_authority::work_store::grant::WORK_BUDGET_CONFIGURE,
                machine,
            ),
            (
                hellas_authority::work_store::grant::WORK_ALLOWANCE_CONFIGURE,
                machine,
            ),
            (
                hellas_authority::work_store::grant::WORK_OFFER_EXPORT,
                machine,
            ),
            (auth::GRANT_ISSUE, authority.resource()),
            (auth::GRANT_ADMINISTER, authority.resource()),
            (auth::CREDENTIAL_ISSUE, authority.resource()),
        ]
        .into_iter()
        .map(|(operation, resource)| auth::Permission {
            operation: auth::OperationId::new(operation).unwrap(),
            resource,
        })
        .collect(),
        not_before: now,
        expires: auth::UnixMillis(now.0 + 600_000),
        delegation_depth: 0,
        issuance: Some(auth::IssuanceCeiling {
            operations: [
                auth::OperationId::new(hellas_authority::grant_service::WORK_EXECUTE).unwrap(),
            ]
            .into(),
            resources: auth::CeilingResources::Authority,
            max_validity_ms: 600_000,
            max_delegation_depth: 0,
        }),
    };
    let command = request_file(
        root,
        &auth::GrantCommand::Issue {
            authorization: host.root_grant,
            id: authorization,
            spec: scope.clone(),
        },
    );
    host.provider
        .run(&[
            "admin",
            "--profile",
            string(&host.provider_profile),
            "--control-socket",
            string(&host.socket),
            "grant",
            string(&command),
        ])
        .await;
    let scope_file = root.join("sharing-admin-scope.json");
    std::fs::write(&scope_file, serde_json::to_vec(&scope).unwrap()).unwrap();
    let credential_file = root.join("sharing-admin.credential");
    host.provider
        .run(&[
            "admin",
            "--profile",
            string(&host.provider_profile),
            "--control-socket",
            string(&host.socket),
            "issue-credential",
            "--scope",
            string(&scope_file),
            "--holder",
            string(&administrator.holder_file().await),
            "--credential-out",
            string(&credential_file),
        ])
        .await;
    let secret = hellas_sdk::node_control::profile::read_credential(&credential_file).unwrap();
    let location = StoreLocation::for_test(&host.provider.home);
    let administrator_profile = profile(
        &hellas_sdk::grant_config::GrantConfig::provider_dir(&location),
        "sharing-admin-control",
        authority,
        authorization,
        &secret,
    );
    let query = request_file(root, &auth::InspectionQuery::Grant { id: authorization });
    let own = administrator
        .output(&[
            "admin",
            "--profile",
            string(&administrator_profile),
            "--control-socket",
            string(&host.socket),
            "inspect",
            string(&query),
        ])
        .await;
    assert!(
        !own.status.success(),
        "an execution-only ceiling must not expose the administrative assignment"
    );
    assert!(
        String::from_utf8_lossy(&own.stderr).contains("authorization failed"),
        "{}",
        String::from_utf8_lossy(&own.stderr)
    );
    let query = request_file(root, &auth::InspectionQuery::Grants { after: None });
    let visible: auth::AuthorityInspection = serde_json::from_str(
        &administrator
            .run(&[
                "admin",
                "--profile",
                string(&administrator_profile),
                "--control-socket",
                string(&host.socket),
                "inspect",
                string(&query),
            ])
            .await,
    )
    .unwrap();
    assert_eq!(visible.authority, authority);
    let auth::InspectionRecords::Grants { records, .. } = visible.records else {
        panic!()
    };
    assert!(!records.iter().any(|grant| grant.id() == authorization));

    let contact = root.join("contact");
    let holder = host.client.holder_file().await;
    let share = async |out: &Path, expires: &str| {
        let output = administrator
            .run(&[
                "admin",
                "--profile",
                string(&administrator_profile),
                "--control-socket",
                string(&host.socket),
                "share",
                "--contact",
                string(&contact),
                "--holder",
                string(&holder),
                "--resource",
                "glm",
                "--limit",
                "requests:total:100",
                "--max-job",
                "5s",
                "--expires",
                expires,
                "--out",
                string(out),
            ])
            .await;
        serde_json::from_str::<Value>(&output).unwrap()
    };
    let first_file = root.join("restricted.access");
    let first = share(&first_file, "5m").await;
    let first_import: Value = serde_json::from_str(
        &host
            .client
            .run(&[
                "offer",
                "import-bundle",
                string(&first_file),
                "--name",
                "restricted",
            ])
            .await,
    )
    .unwrap();
    assert_eq!(first_import["offers"][0]["name"], "restricted.glm");
    let renewed_file = root.join("restricted-renewed.access");
    let renewed = share(&renewed_file, "6m").await;
    for field in ["pool", "allowance", "grant"] {
        assert_eq!(first[field], renewed[field]);
    }
    assert!(renewed["expires"].as_u64().unwrap() > first["expires"].as_u64().unwrap());
    assert_ne!(first["credential_id"], renewed["credential_id"]);
    let same_alias = host
        .client
        .output(&[
            "offer",
            "import-bundle",
            string(&renewed_file),
            "--name",
            "restricted",
        ])
        .await;
    assert!(
        !same_alias.status.success(),
        "renewal must not overwrite the existing profile"
    );
    let imported: Value = serde_json::from_str(
        &host
            .client
            .run(&[
                "offer",
                "import-bundle",
                string(&renewed_file),
                "--name",
                "restricted-renewed",
            ])
            .await,
    )
    .unwrap();
    assert_eq!(imported["offers"][0]["name"], "restricted-renewed.glm");
    let auth::CredentialHolder::Node(holder) = host.client.holder().await else {
        panic!()
    };
    let installed = hellas_sdk::node_control::profile::ClientProfile::load_bound(
        Path::new(imported["work_profile"].as_str().unwrap()),
        &host.client.principal(),
        &holder,
    )
    .unwrap();
    assert_eq!(
        installed.credential.id().to_string(),
        renewed["credential_id"]
    );
    assert_eq!(installed.authorization.to_string(), renewed["grant"]);
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_access_bundle_shares_allowances_with_one_contact_device() {
    use hellas_auth::authority as auth;
    let mut policy = http_invocation_policy();
    policy
        .admissions
        .push(hellas_rpc::protocol::invocation::Admission::Compute {
            evaluator: hellas_rpc::protocol::invocation::compute::EVALUATOR.into(),
            programs: hellas_rpc::protocol::invocation::ComputePrograms::Any {},
        });
    let mut host = OfferHost::start_with_policy(None, None, None, policy).await;
    let root_path = host.root().to_path_buf();
    let root = root_path.as_path();
    let authority = hellas_sdk::node_control::profile::ClientProfile::load(&host.provider_profile)
        .unwrap()
        .authority;
    let bundle = root.join("client.access");
    let contact = root.join("contact");
    let export = |resource: String,
                  out: PathBuf,
                  holder: PathBuf,
                  limit: &'static str,
                  max_job: &'static str| {
        let (provider, profile, socket, contact) = (
            &host.provider,
            host.provider_profile.clone(),
            host.socket.clone(),
            contact.clone(),
        );
        async move {
            provider
                .output(&[
                    "admin",
                    "--profile",
                    string(&profile),
                    "--control-socket",
                    string(&socket),
                    "share",
                    "--contact",
                    string(&contact),
                    "--resource",
                    &resource,
                    "--limit",
                    limit,
                    "--max-job",
                    max_job,
                    "--expires",
                    "5m",
                    "--holder",
                    string(&holder),
                    "--out",
                    string(&out),
                ])
                .await
        }
    };
    let refused = export(
        "missing".into(),
        root.join("refused.access"),
        host.client.holder_file().await,
        "requests:total:100",
        "5s",
    )
    .await;
    assert!(!refused.status.success());
    assert!(!root.join("refused.access").exists());
    let holder_file = host.client.holder_file().await;
    // Failure after budgets were created is resumable: the corrected call
    // reuses them at revision 1 and creates only the missing allowance/grant.
    let interrupted = export(
        "glm".into(),
        root.join("interrupted.access"),
        holder_file.clone(),
        "requests:total:100",
        "11s",
    )
    .await;
    assert!(!interrupted.status.success());
    assert!(!root.join("interrupted.access").exists());
    let exported = export(
        "glm".into(),
        bundle.clone(),
        holder_file.clone(),
        "requests:total:100",
        "5s",
    )
    .await;
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let shared: Value = serde_json::from_slice(&exported.stdout).unwrap();
    let allowance: GrantId = shared["allowance"].as_str().unwrap().parse().unwrap();
    let grant: GrantId = shared["grant"].as_str().unwrap().parse().unwrap();
    assert_eq!(shared["authority"], authority.to_string());
    assert_eq!(shared["subject"], host.client.principal().to_string());
    let inspect = |query| {
        let path = request_file(root, &query);
        let host = &host;
        async move {
            serde_json::from_str::<auth::AuthorityInspection>(
                &host
                    .provider
                    .run(&[
                        "admin",
                        "--profile",
                        string(&host.provider_profile),
                        "--control-socket",
                        string(&host.socket),
                        "inspect",
                        string(&path),
                    ])
                    .await,
            )
            .unwrap()
        }
    };
    let grant_before = inspect(auth::InspectionQuery::Grant { id: grant }).await;
    let unchanged = export(
        "glm".into(),
        root.join("unchanged.access"),
        holder_file.clone(),
        "requests:total:100",
        "5s",
    )
    .await;
    assert!(
        unchanged.status.success(),
        "{}",
        String::from_utf8_lossy(&unchanged.stderr)
    );
    let repeated: Value = serde_json::from_slice(&unchanged.stdout).unwrap();
    for field in ["pool", "allowance", "grant", "expires"] {
        assert_eq!(shared[field], repeated[field]);
    }
    let grant_after = inspect(auth::InspectionQuery::Grant { id: grant }).await;
    let auth::InspectionRecords::Grants {
        records: before, ..
    } = grant_before.records
    else {
        panic!()
    };
    let auth::InspectionRecords::Grants { records: after, .. } = grant_after.records else {
        panic!()
    };
    assert_eq!(
        before, after,
        "an unchanged share does not revise the grant"
    );
    let WorkControlReply::Status {
        allowance: current, ..
    } = admin(
        &host.provider,
        &host.provider_profile,
        &host.socket,
        WorkControlCommand::Inspect { id: allowance },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(current.revision, auth::Revision(1));
    // Resume after the allowance was paused, and revise limits and max job on
    // the same identifiers rather than creating fresh counters.
    admin(
        &host.provider,
        &host.provider_profile,
        &host.socket,
        WorkControlCommand::Revise {
            id: allowance,
            expected_revision: current.revision,
            terms: AllowanceTerms {
                policies: current.policies.clone(),
                budget: current.budget,
                max_job_millis: std::num::NonZeroU64::new(5000).unwrap(),
                enabled: false,
                allow_account_backed: true,
            },
        },
    )
    .await;
    let revised = export(
        "glm".into(),
        root.join("revised.access"),
        holder_file.clone(),
        "requests:total:101",
        "6s",
    )
    .await;
    assert!(
        revised.status.success(),
        "{}",
        String::from_utf8_lossy(&revised.stderr)
    );
    let revised: Value = serde_json::from_slice(&revised.stdout).unwrap();
    for field in ["pool", "allowance", "grant"] {
        assert_eq!(shared[field], revised[field]);
    }
    let WorkControlReply::Status {
        allowance: current, ..
    } = admin(
        &host.provider,
        &host.provider_profile,
        &host.socket,
        WorkControlCommand::Inspect { id: allowance },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(current.revision, auth::Revision(3));
    let WorkControlReply::Budget { definition, .. } = admin(
        &host.provider,
        &host.provider_profile,
        &host.socket,
        WorkControlCommand::InspectBudget {
            node: current.budget,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(definition.revision, auth::Revision(2));
    assert_eq!(definition.limits[0].amount, 101);
    // An existing output is never replaced, even when the rest is resumable.
    assert!(
        !export(
            "glm".into(),
            bundle.clone(),
            holder_file,
            "requests:total:101",
            "6s"
        )
        .await
        .status
        .success()
    );
    // Another device of the same principal cannot import the credential.
    let other_device = Cli::new(root, "client-laptop", FRIEND_PASSKEY);
    other_device
        .run(&["--software-root", "identity", "init"])
        .await;
    let wrong = other_device
        .output(&[
            "offer",
            "import-bundle",
            string(&bundle),
            "--name",
            "shared",
        ])
        .await;
    assert!(!wrong.status.success());
    assert!(
        String::from_utf8_lossy(&wrong.stderr).contains("bound to another device"),
        "{}",
        String::from_utf8_lossy(&wrong.stderr)
    );
    // A second device gets its own credential on the same share. The first
    // device's original credential must continue to execute below.
    let laptop = export(
        "glm".into(),
        root.join("laptop.access"),
        other_device.holder_file().await,
        "requests:total:101",
        "6s",
    )
    .await;
    assert!(
        laptop.status.success(),
        "{}",
        String::from_utf8_lossy(&laptop.stderr)
    );
    let laptop: Value = serde_json::from_slice(&laptop.stdout).unwrap();
    assert_eq!(laptop["grant"], shared["grant"]);
    assert_eq!(laptop["allowance"], shared["allowance"]);
    assert_ne!(laptop["credential_id"], shared["credential_id"]);
    let imported: Value = serde_json::from_str(
        &host
            .client
            .run(&[
                "offer",
                "import-bundle",
                string(&bundle),
                "--name",
                "shared",
            ])
            .await,
    )
    .unwrap();
    assert_eq!(imported["offers"][0]["name"], "shared.glm");
    assert_eq!(imported["offers"][0]["grant"], hex::encode(allowance.0));
    // The same imported bundle works directly through the CLI, without an
    // HTTP gateway or any chain funding. Retry must not consume it twice.
    let request = hellas_rpc::http_fetch::HttpFetchRequest {
        url: format!("{}/v1/chat/completions", host.https.origin),
        method: "POST".into(),
        headers: vec![("content-type".into(), "application/json".into())],
        body_base64: STANDARD.encode(br#"{"messages":[],"max_tokens":8}"#),
        tls: hellas_rpc::http_fetch::HttpTls {
            roots: hellas_rpc::http_fetch::HttpTrustRoots::Certificates {
                der_base64: vec![host.https.root_der.clone()],
            },
            spki_sha256: vec![],
        },
        credential: Some("glm-account".into()),
        max_response_bytes: 65536,
    };
    let job = hellas_sdk::job::Job::fetch(
        20,
        hellas_rpc::FetchContract::http().unwrap(),
        "http".into(),
        "request".into(),
        serde_json::to_vec(&request).unwrap(),
        hellas_rpc::Assurance::ProducerSigned,
    )
    .unwrap();
    let job_dir = root.join("grant-job");
    job.save(&job_dir).unwrap();
    let provider = shared["provider"].as_str().unwrap().to_owned();
    assert_eq!(
        provider,
        hellas_sdk::client::ProviderAddress::of(&host.provider_enrollment)
            .unwrap()
            .to_string()
    );
    let attempt = root.join("grant-attempt.json");
    let result_dir = root.join("grant-result");
    let args = [
        "transact",
        "--offer",
        "shared.glm",
        "--attempt",
        string(&attempt),
        "--job",
        string(&job_dir),
        "--output",
        string(&result_dir),
    ];
    let wrong_provider = hellas_sdk::client::ProviderAddress {
        enrollment: hellas_rpc::ContentId::from_bytes([99; 32]),
        node: hellas_sdk::client::ProviderAddress::of(&host.provider_enrollment)
            .unwrap()
            .node,
    }
    .to_string();
    let mut refused = args.to_vec();
    refused.extend(["--provider", &wrong_provider]);
    assert!(!host.client.output(&refused).await.status.success());
    assert!(!attempt.exists());
    assert!(!other_device.output(&args).await.status.success());
    assert_eq!(host.https.calls.load(Ordering::SeqCst), 0);
    for _ in 0..2 {
        host.client.run(&args).await;
        let metadata: Value =
            serde_json::from_slice(&std::fs::read(result_dir.join("result.json")).unwrap())
                .unwrap();
        assert_eq!(metadata["funding"], "grant");
        assert_eq!(metadata["provider"], provider);
        let resource: hellas_auth::authority::ResourceId =
            metadata["resource"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            resource,
            host.signed_offer.offer().grant.policies[0].resource
        );
        assert!(metadata.get("paid").is_none());
        let response: Value =
            serde_json::from_slice(&std::fs::read(result_dir.join("output-0000")).unwrap())
                .unwrap();
        assert_eq!(response["choices"][0]["message"]["content"], "hello");
        assert_eq!(host.https.calls.load(Ordering::SeqCst), 1);
    }
    let mut changed_input = job.input().clone();
    let hellas_sdk::job::JobInput::Fetch { request, .. } = &mut changed_input else {
        unreachable!()
    };
    let mut changed_request: hellas_rpc::http_fetch::HttpFetchRequest =
        serde_json::from_slice(request).unwrap();
    changed_request.body_base64 = STANDARD.encode(br#"{"messages":[],"max_tokens":7}"#);
    *request = serde_json::to_vec(&changed_request).unwrap();
    let changed_dir = root.join("changed-grant-job");
    hellas_sdk::job::Job::from_input(20, changed_input)
        .unwrap()
        .save(&changed_dir)
        .unwrap();
    let mut changed_args = args.to_vec();
    let at = changed_args.iter().position(|arg| *arg == "--job").unwrap();
    changed_args[at + 1] = string(&changed_dir);
    assert!(!host.client.output(&changed_args).await.status.success());
    assert_eq!(host.https.calls.load(Ordering::SeqCst), 1);
    let trust_root = host.approve_trust().await;
    let pool = root.join("grant-pool.json");
    std::fs::write(
        &pool,
        serde_json::to_vec(&json!({"channels": [{
            "offer": "shared.glm", "work_profile": "shared", "trust_policy": "lan",
            "resources": [host.signed_offer.offer().grant.policies[0].resource.0.to_string()]
        }]}))
        .unwrap(),
    )
    .unwrap();
    let (gateway_profile, token) = gateway_profile(root).await;
    let mut gateway = host.client.spawn(
        &[
            "gateway",
            "--grant-pool-config",
            string(&pool),
            "--trust-store",
            string(&trust_root),
            "--port",
            "0",
            "--gateway-profile",
            string(&gateway_profile),
            "--zdr",
        ],
        "bundle-gateway.log",
    );
    let address = gateway.wait_for("gateway listening on ").await;
    let response = post(
        &gateway_client(&token),
        &format!("http://{address}/v1/chat/completions"),
        json!({"messages":[]}),
    )
    .await;
    assert_http_response(
        response,
        reqwest::StatusCode::OK,
        &[&gateway.log, &host.node.log],
        &host.https,
    )
    .await;
    gateway.stop().await;
    assert_eq!(host.https.calls.load(Ordering::SeqCst), 2);
    let next_attempt = root.join("next-grant-attempt.json");
    let mut next_args = args.to_vec();
    let at = next_args
        .iter()
        .position(|arg| *arg == "--attempt")
        .unwrap();
    next_args[at + 1] = string(&next_attempt);
    host.client.run(&next_args).await;
    assert_eq!(host.https.calls.load(Ordering::SeqCst), 3);
    // The run helper saves a zero-price job and uses the same grant path.
    // A signed compilation failure remains a failed command on replay.
    let invalid_source = root.join("invalid.hex");
    std::fs::write(&invalid_source, b"invalid Hex source").unwrap();
    let invalid_dir = root.join("invalid-compute-job");
    let failed_result = root.join("failed-compute-result");
    let failed_args = [
        "run",
        "--source",
        string(&invalid_source),
        "--entry",
        "main",
        "--returns",
        "u64",
        "--offer",
        "shared.glm",
        "--save-job",
        string(&invalid_dir),
        "--output",
        string(&failed_result),
    ];
    for _ in 0..2 {
        let failed = host.client.output(&failed_args).await;
        assert!(
            !failed.status.success(),
            "a failed computation returned success"
        );
        assert!(
            String::from_utf8_lossy(&failed.stderr).contains("Compilation"),
            "{}",
            String::from_utf8_lossy(&failed.stderr)
        );
        assert!(!String::from_utf8_lossy(&failed.stdout).contains("completed"));
    }
    assert_eq!(hellas_sdk::job::Job::load(&invalid_dir).unwrap().price(), 0);
    let retained = std::fs::read(failed_result.join("result.json")).unwrap();
    let mut replay_command = host.client.command(&failed_args);
    let retained_path = failed_result.join("result.json");
    host.node.stop().await;
    let replay = replay_command.output().await.unwrap();
    assert!(!replay.status.success());
    assert!(String::from_utf8_lossy(&replay.stderr).contains("Compilation"));
    assert_eq!(std::fs::read(retained_path).unwrap(), retained);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_gateway_opens_two_independent_providers() {
    use hellas_auth::authority::{CredentialHolder, UnixMillis};
    use hellas_sdk::access_bundle::AccessBundle;
    use hellas_sdk::node_control::profile::ClientProfile;
    use hellas_sdk::trust_policy::{TrustPolicy, TrustPolicyStore};

    let first = OfferHost::start().await;
    let second = OfferHost::start_with_identity(None, None, Some(&first.client.identity)).await;
    let root = first.root();
    let CredentialHolder::Node(holder) = first.client.holder().await else {
        panic!("expected node-bound client");
    };
    assert_eq!(first.client.holder().await, second.client.holder().await);
    let trust_root = root.join("pool-trust");
    let mut channels = Vec::new();
    for (host, name) in [(&first, "first"), (&second, "second")] {
        let profile = ClientProfile::load(&host.work_profile).unwrap();
        let bundle = AccessBundle {
            offers: vec![host.signed_offer.clone()],
            authority: profile.authority,
            authorization: profile.authorization,
            subject: first.client.principal(),
            holder,
            credential: profile.credential,
            expires: UnixMillis(UnixMillis::now().unwrap().0 + 600_000),
            label: None,
        };
        let path = root.join(format!("{name}.access"));
        bundle.save(&path).unwrap();
        first
            .client
            .run(&["offer", "import-bundle", string(&path), "--name", name])
            .await;
        TrustPolicyStore::new(&trust_root)
            .approve(
                name,
                0,
                TrustPolicy {
                    provider_genesis: host.provider_enrollment.content_id(),
                    assurance: hellas_rpc::Assurance::ProducerSigned,
                    apple: None,
                },
                "independent provider approval".into(),
            )
            .unwrap();
        channels.push(json!({
            "offer": format!("{name}.glm"), "work_profile": name, "trust_policy": name,
            "resources": [host.signed_offer.offer().grant.policies[0].resource.0.to_string()]
        }));
    }
    let pool = root.join("two-provider-pool.json");
    std::fs::write(
        &pool,
        serde_json::to_vec(&json!({"channels": channels})).unwrap(),
    )
    .unwrap();
    let (profile, token) = gateway_profile(root).await;
    let mut gateway = first.client.spawn(
        &[
            "gateway",
            "--grant-pool-config",
            string(&pool),
            "--trust-store",
            string(&trust_root),
            "--port",
            "0",
            "--gateway-profile",
            string(&profile),
            "--zdr",
        ],
        "two-provider-gateway.log",
    );
    let address = gateway.wait_for("gateway listening on ").await;
    let response = post(
        &gateway_client(&token),
        &format!("http://{address}/v1/chat/completions"),
        json!({"messages":[]}),
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        first.https.calls.load(Ordering::SeqCst) + second.https.calls.load(Ordering::SeqCst),
        1
    );
    gateway.stop().await;
    second.stop().await;
    first.stop().await;
}
