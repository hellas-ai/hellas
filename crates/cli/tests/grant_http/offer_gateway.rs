use super::*;
use hellas_authority::model::grant::records::decode_enrollment;
use hellas_channel::test_support::actors::{FRIEND, ROOT};

struct OfferHost {
    directory: tempfile::TempDir,
    https: Https,
    provider: Cli,
    client: Cli,
    node: Process,
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
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        hellas_private::restrict_directory(root).unwrap();
        let https = Https::start(Some("Bearer fixture-key")).await;
        let mut provider = Cli::new(root, "provider", ROOT_PASSKEY);
        let mut client = Cli::new(root, "client", FRIEND_PASSKEY);
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
        let (store, app_secret) = common_node::bootstrap_node_with_credential(
            &root
                .join("grants")
                .join(format!(
                    "p256-{}",
                    hex::encode(provider.principal().as_bytes())
                ))
                .join("provider"),
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
        let provider_profile = profile(root, "control", authority, root_grant, &app_secret);
        let client_profile = profile(root, "reader", authority, reader_grant, &client_secret);
        let socket = root.join("control.sock");
        let fetch = root.join("fetch.json");
        let resources = root.join("resources.json");
        let (control_certificate, control_private_key) = control_tls(root);
        let secret = root.join("account.json");
        hellas_private::write_atomically(&secret, ".new", br#"{"access_token":"fixture-key"}"#)
            .unwrap();
        std::fs::write(&fetch,json!({"routes":[{"service":"http","method":"request","destination":{"type":"http","config":{
            "allowed_hosts":["localhost"],"allow_private_addresses":true,
            "credentials":{"glm-account":{"allowed_origins":[https.origin],"allowed_paths":["/v1/chat/completions"],"allowed_methods":["POST"],
            "trust_roots":{"mode":"certificates","der_base64":[https.root_der]},"header_name":"authorization","secret_file":secret,"secret_field":"access_token","prefix":"Bearer "}}
        }}}]}).to_string()).unwrap();
        std::fs::write(&resources,json!({"remote_control_peers":[client.run(&["identity", "show-node-id"]).await.trim()],"control_socket":socket,"control_certificate":control_certificate,"control_private_key":control_private_key,"max_job_millis":10000,"resources":[{"resource":hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test resource")),"account":hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test account")),"revision":1,"pricing":{"revision":1,"rates":null},"name":"glm","invocation_policy":http_invocation_policy(),
            "https":{"origin":https.origin,"paths":["/v1/chat/completions"],"methods":["POST"],"credential":"glm-account","tls":{"roots":{"mode":"certificates","der_base64":[https.root_der]},"spki_sha256":[]},"accounting":"openai-chat","max_output_tokens":8,"max_response_bytes":65536}}]}).to_string()).unwrap();
        let mut node = provider.spawn(
            &[
                "serve",
                "--metrics-port",
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
        let metrics = node
            .wait_for("prometheus metrics server listening on ")
            .await;
        let limits = root.join("machine-limits.json");
        std::fs::write(&limits, b"[]").unwrap();
        provider
            .run(&[
                "admin",
                "--profile",
                string(&provider_profile),
                "--control-socket",
                string(&socket),
                "set-capacity",
                "--expected-revision",
                "0",
                "--max-in-flight",
                "2",
                "--limits",
                string(&limits),
            ])
            .await;
        let offer = root.join("offer");
        let id = GrantId([9; 16]);
        for definition in common_node::budgets(
            common_node::POOL,
            grantee,
            vec![Limit {
                meter: Meter::OutputTokens,
                window: Window::Total,
                amount: 20,
            }],
            1,
        ) {
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
            WorkControlCommand::ConfigureResource {
                policy: "glm".into(),
            },
        )
        .await;
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
                "--metrics-port",
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
                "--archive-dir",
                string(&self.root().join("archive")),
                "--zdr",
            ],
            "gateway.log",
        );
        let address = process.wait_for("gateway listening on ").await;
        let metrics = process
            .wait_for("prometheus metrics server listening on ")
            .await;
        Gateway {
            process,
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
    let first = tokio::time::timeout(hellas_authority::test_support::WAIT, stream.next())
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metrics_scrape_observes_gateway_and_serve_work() {
    #[cfg(feature = "otel")]
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
    #[cfg(feature = "otel")]
    let host = OfferHost::start_with_metrics(Some(endpoint), Some("0.0.0.0".into())).await;
    #[cfg(not(feature = "otel"))]
    let host = OfferHost::start_with_metrics(None, Some("0.0.0.0".into())).await;
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
            #[cfg(feature = "otel")]
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
    #[cfg(feature = "otel")]
    {
        // Check the real protobuf push stream, after shutdown has flushed both
        // providers, as well as the two pulls above.
        let mut names = vec![
            b"hellas.gateway.http.requests".as_slice(),
            b"hellas.execution.executions_completed".as_slice(),
        ];
        tokio::time::timeout(Duration::from_secs(10), async {
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
    let (store, admin_secret) = hellas_authority::work_store::grant::NodeStore::bootstrap(
        &journal,
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
async fn an_access_bundle_shares_allowances_with_one_contact_device() {
    use hellas_auth::authority as auth;
    let host = OfferHost::start().await;
    let root = host.root();
    let authority = hellas_sdk::node_control::profile::ClientProfile::load(&host.provider_profile)
        .unwrap()
        .authority;
    let now = auth::UnixMillis::now().unwrap_or_default();
    let scope = auth::GrantSpec {
        authority,
        subject: host.client.principal(),
        permissions: [auth::Permission {
            operation: auth::OperationId::new(hellas_authority::grant_service::WORK_EXECUTE)
                .unwrap(),
            resource: hellas_authority::grant_service::allowance_resource(authority, host.id),
        }]
        .into(),
        not_before: now,
        expires: auth::UnixMillis(now.0 + 600_000),
        delegation_depth: 0,
        issuance: None,
    };
    let shared = GrantId([5; 16]);
    let grant = request_file(
        root,
        &auth::GrantCommand::Issue {
            authorization: host.root_grant,
            id: shared,
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
            string(&grant),
        ])
        .await;
    let scope_file = root.join("bundle-scope.json");
    std::fs::write(&scope_file, serde_json::to_vec(&scope).unwrap()).unwrap();
    let bundle = root.join("client.access");
    let export = |allowance: String, out: PathBuf, holder: PathBuf| {
        let (provider, profile, socket, scope_file) = (
            &host.provider,
            host.provider_profile.clone(),
            host.socket.clone(),
            scope_file.clone(),
        );
        async move {
            provider
                .output(&[
                    "admin",
                    "--profile",
                    string(&profile),
                    "--control-socket",
                    string(&socket),
                    "export-bundle",
                    "--allowance",
                    &allowance,
                    "--grant-id",
                    &hex::encode(shared.0),
                    "--credential-scope",
                    string(&scope_file),
                    "--holder",
                    string(&holder),
                    "--out",
                    string(&out),
                ])
                .await
        }
    };
    // A scope without work.execute on an allowance cannot share it.
    let refused = export(
        hex::encode([77; 16]),
        root.join("refused.access"),
        host.client.holder_file().await,
    )
    .await;
    assert!(!refused.status.success());
    assert!(!root.join("refused.access").exists());
    let exported = export(
        hex::encode(host.id.0),
        bundle.clone(),
        host.client.holder_file().await,
    )
    .await;
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
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
    assert_eq!(imported["offers"][0]["grant"], hex::encode(host.id.0));
    let profile = PathBuf::from(imported["work_profile"].as_str().unwrap());
    let trust_root = host.approve_trust().await;
    let (gateway_profile, token) = gateway_profile(root).await;
    let mut gateway = host.client.spawn(
        &[
            "gateway",
            "--offer",
            "shared.glm",
            "--trust-store",
            string(&trust_root),
            "--trust-policy",
            "lan",
            "--work-profile",
            string(&profile),
            "--port",
            "0",
            "--gateway-profile",
            string(&gateway_profile),
            "--archive-dir",
            string(&root.join("bundle-archive")),
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
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    gateway.stop().await;
    host.stop().await;
}
