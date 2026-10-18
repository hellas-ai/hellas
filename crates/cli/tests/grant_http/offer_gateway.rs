use super::*;
use hellas_work::model::grant::records::{decode_contact, grant_transport, principal_id};

struct OfferHost {
    directory: tempfile::TempDir,
    https: Https,
    provider: Cli,
    client: Cli,
    node: Process,
    socket: PathBuf,
    provider_profile: PathBuf,
    client_profile: PathBuf,
    provider_principal: hellas_rpc::ProviderEnrollmentBundle,
    reader: hellas_auth::authority::GrantSpec,
    reader_grant: GrantId,
    root_grant: GrantId,
    signed_offer: hellas_work::model::grant::records::SignedOffer,
    offer: PathBuf,
    id: GrantId,
    work_profile: PathBuf,
    exported_offer: std::process::Output,
    imported_offer: std::process::Output,
}
impl OfferHost {
    async fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        hellas_private::restrict_directory(root).unwrap();
        let https = Https::start(Some("Bearer fixture-key")).await;
        let provider = Cli::new(root, "provider");
        let client = Cli::new(root, "client");
        for cli in [&provider, &client] {
            cli.run(&["--software-root", "identity", "init"]).await;
        }
        let exported = provider.output(&["contact", "export"]).await;
        assert!(exported.status.success());
        let provider_principal = decode_contact(&exported.stdout).unwrap();
        let (store, app_secret) = common_node::bootstrap_node_with_credential(
            &root
                .join("grants")
                .join(hex::encode(
                    principal_id(&provider_principal).unwrap().as_bytes(),
                ))
                .join("provider"),
            hellas_work::model::grant::grant_network(),
            Some(provider_principal.clone()),
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
        let exported_contact = client
            .output(&["contact", "export", "--out", string(&contact)])
            .await;
        assert!(exported_contact.status.success());
        let imported_contact = provider
            .output(&["contact", "import", string(&contact), "--name", "client"])
            .await;
        assert!(imported_contact.status.success());
        let grantee = decode_contact(&std::fs::read(&contact).unwrap()).unwrap();
        reader.subject = hellas_auth::authority::PrincipalId::from_public_key(
            grantee.genesis.statement.producer_public_key,
        )
        .unwrap();
        reader.permissions = [hellas_auth::authority::Permission {
            operation: hellas_auth::authority::OperationId::new(
                hellas_work::work_store::grant::WORK_ALLOWANCE_READ,
            )
            .unwrap(),
            resource: hellas_work::node::machine_resource(authority),
        }]
        .into();
        reader.issuance = None;
        let reader_grant = GrantId([4; 16]);
        let coordinator = hellas_work::node::NodeCoordinator::new(
            store,
            Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
        );
        let caller = coordinator.authenticate(&app_secret).await.unwrap();
        let (_, client_secret) = coordinator
            .issue_credential(&caller, root_grant, reader.clone())
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
        std::fs::write(&resources,json!({"remote_control_peers":[iroh::EndpointId::from_bytes(&grant_transport(&grantee).unwrap()).unwrap().to_string()],"control_socket":socket,"control_certificate":control_certificate,"control_private_key":control_private_key,"max_job_millis":10000,"resources":[{"resource":hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test resource")),"account":hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test account")),"revision":1,"pricing":{"revision":1,"rates":null},"name":"glm","fetch":{ "contract":hellas_rpc::FetchContract::http().unwrap(),
            "allowed_environment":hellas_rpc::FetchContract::http().unwrap().manifest_id().to_string(),"service":"http","method":"request","max_request_body_bytes":65536,"max_output_events":256,"max_output_bytes":65536,"max_spool_bytes":262144,"max_encoded_result_frame":262144,"max_encoded_prepared_input":262144},
            "https":{"origin":https.origin,"paths":["/v1/chat/completions"],"methods":["POST"],"credential":"glm-account","tls":{"roots":{"mode":"certificates","der_base64":[https.root_der]},"spki_sha256":[]},"accounting":"openai-chat","max_output_tokens":8,"max_response_bytes":65536}}]}).to_string()).unwrap();
        let mut node = provider.spawn(
            &[
                "serve",
                "--no-discovery",
                "--fetch-config",
                string(&fetch),
                "--grant-config",
                string(&resources),
            ],
            "provider.log",
        );
        node.wait_for("RPC server running.").await;
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
            principal_id(&grantee).unwrap(),
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
                terms: terms(principal_id(&grantee).unwrap()),
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
        let signed_offer = hellas_work::model::grant::records::SignedOffer::decode(
            &std::fs::read(&offer).unwrap(),
            hellas_auth::authority::UnixMillis(0),
        )
        .unwrap();
        let work_profile = issue_work_profile(
            &provider,
            &provider_profile,
            &socket,
            root,
            principal_id(&grantee).unwrap(),
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
            socket,
            provider_profile,
            client_profile,
            provider_principal,
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
                environments: self
                    .signed_offer
                    .offer()
                    .grant
                    .policies
                    .iter()
                    .map(|p| p.work.allowed_environment())
                    .collect(),
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
        Gateway {
            process,
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
    url: String,
    http: reqwest::Client,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offer_import_reports_the_exported_provider_identity() {
    let host = OfferHost::start().await;
    let fingerprint = format!(
        "Provider fingerprint: {}",
        principal_id(&host.provider_principal)
            .unwrap()
            .fingerprint()
    );
    assert!(String::from_utf8_lossy(&host.exported_offer.stderr).contains(&fingerprint));
    assert!(String::from_utf8_lossy(&host.imported_offer.stderr).contains(&fingerprint));
    assert_eq!(
        String::from_utf8_lossy(&host.imported_offer.stdout).trim(),
        hex::encode(host.id.0)
    );
    // Import is a public description, independent of execution authority.
    let stranger = Cli::new(host.root(), "stranger");
    stranger.run(&["--software-root", "identity", "init"]).await;
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
    let provider_contact = root.join("provider-contact");
    provider
        .run(&["contact", "export", "--out", string(&provider_contact)])
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
        "--contact",
        string(&provider_contact),
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
    let first = tokio::time::timeout(hellas_work::test_support::WAIT, stream.next())
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
