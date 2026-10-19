use super::*;
use hellas_work::model::grant::records::{decode_enrollment, principal_id};

struct Managed {
    task: tokio::task::JoinHandle<hellas_cloud::agent::Result<()>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}
impl Drop for Managed {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Managed {
    async fn stop(&mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(15), &mut self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

struct ManagedWorker {
    root: tempfile::TempDir,
    owner: Cli,
    managed: Managed,
    _upstream: Https,
    work_address: std::net::SocketAddr,
    work_profile: PathBuf,
    trust_root: PathBuf,
    gateway_profile: PathBuf,
    gateway_token: String,
}
impl ManagedWorker {
    async fn start() -> Self {
        use hellas_cloud::agent::{self, AgentOptions};
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        hellas_private::restrict_directory(root).unwrap();
        let owner = Cli::new(root, "owner");
        owner.run(&["--software-root", "identity", "init"]).await;
        let (admin_address, credentials) = prepare_machine(&owner, "worker").await;
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let work_address = udp.local_addr().unwrap();
        drop(udp);
        let data = root.join("worker");
        let private = root.join("private");
        // Ordinary agent startup opens existing authority; provision the fixture offline.
        hellas_private::create_dir_all_durable(&data).unwrap();
        hellas_private::create_dir_all_durable(&private).unwrap();
        let worker = Cli::new(&data, "identity");
        worker.run(&["--software-root", "identity", "init"]).await;
        let exported = worker.output(&["contact", "export"]).await;
        assert!(exported.status.success());
        let provider = decode_enrollment(&exported.stdout).unwrap();
        use hellas_auth::authority as auth;
        let authority = auth::AuthorityId(hellas_auth::Digest::hash(b"managed control fixture"));
        let root_grant = auth::GrantId([1; 16]);
        let now = hellas_auth::authority::UnixMillis::now().unwrap_or_default();
        let extra: Vec<_> = [
            hellas_work::node::WORK_CAPACITY_CONFIGURE,
            hellas_work::work_store::grant::WORK_ALLOWANCE_CONFIGURE,
            hellas_work::work_store::grant::WORK_BUDGET_CONFIGURE,
            hellas_work::work_store::grant::WORK_RESOURCE_CONFIGURE,
        ]
        .into_iter()
        .map(|op| (op, hellas_work::node::machine_resource(authority)))
        .chain([(
            hellas_work::node::HOST_STATUS,
            hellas_work::node::host_resource(authority),
        )])
        .collect();
        let administrator = common_node::admin_spec(
            authority,
            auth::PrincipalId::from_public_key(provider.genesis.statement.producer_public_key)
                .unwrap(),
            &extra,
            (now, auth::UnixMillis(now.0 + 3_600_000)),
            (3_600_000, 8),
            &[hellas_work::grant_service::WORK_EXECUTE],
        );
        // Give the readiness application only status, even though the offline root
        // can grant other authority rights. Both are explicit native transitions.
        let mut application = administrator.clone();
        application.issuance = None;
        application
            .permissions
            .retain(|p| p.operation.as_str() == hellas_work::node::HOST_STATUS);
        let (store, secret) = hellas_work::work_store::grant::NodeStore::bootstrap(
            &private.join("grants"),
            hellas_work::model::grant::grant_network(),
            root_grant,
            administrator.clone(),
            administrator,
            Some(provider.clone()),
            now,
        )
        .await
        .unwrap();
        let operator_profile = profile(&private, "operator", authority, root_grant, &secret);
        let node = hellas_work::node::NodeCoordinator::new(
            store,
            Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
        );
        let caller = node.authenticate(&secret).await.unwrap();
        let (_, secret) = node
            .issue_credential(&caller, root_grant, application)
            .await
            .unwrap();
        drop(node);
        // The agent's readiness check reads this fixed profile name.
        profile(&private, "control", authority, root_grant, &secret);
        control_tls(&private);
        let cli = PathBuf::from(env!("CARGO_BIN_EXE_hellas-cli"));
        let mut serve_args = vec![
            "--port".into(),
            work_address.port().to_string(),
            "--no-discovery".into(),
        ];
        if cfg!(feature = "evaluate") {
            serve_args.extend([
                "--store-dir".into(),
                data.join("store").to_string_lossy().into_owned(),
            ]);
        }
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(agent::run_until(
            AgentOptions {
                credentials,
                data: data.clone(),
                configuration_dir: Some(private.clone()),
                cli: cli.clone(),
                launcher: vec![cli.to_string_lossy().into_owned(), "serve".into()],
                serve_args,
                bind: Some(admin_address),
                no_relay: true,
            },
            async {
                let _ = stopped.await;
            },
        ));
        let mut managed = Managed {
            task,
            stop: Some(stop),
        };
        let control = private.join("control.sock");
        tokio::time::timeout(Duration::from_secs(30), async {
            while !control.exists() {
                if managed.task.is_finished() {
                    panic!("agent failed: {:?}", (&mut managed.task).await);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        let https = Https::start(None).await;
        let fetch = root.join("managed-fetch.json");
        let resources = root.join("managed-resources.json");
        std::fs::write(&fetch, json!({"routes":[{"service":"http","method":"request","destination":{"type":"http","config":{"allowed_hosts":["localhost"],"allow_private_addresses":true}}}]}).to_string()).unwrap();
        std::fs::write(&resources, json!({"max_job_millis":10000,"resources":[{"resource":hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test resource")),"account":hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test account")),"revision":1,"pricing":{"revision":1,"rates":null},"name":"glm","fetch":{ "contract":hellas_rpc::FetchContract::http().unwrap(),
        "allowed_environment":hellas_rpc::FetchContract::http().unwrap().manifest_id().to_string(),"service":"http","method":"request","max_request_body_bytes":65536,"max_output_events":256,"max_output_bytes":65536,"max_spool_bytes":262144,"max_encoded_result_frame":262144,"max_encoded_prepared_input":262144},
        "https":{"origin":https.origin,"paths":["/v1/chat/completions"],"methods":["POST"],"credential":null,"tls":{"roots":{"mode":"certificates","der_base64":[https.root_der]},"spki_sha256":[]},"accounting":"openai-chat","max_output_tokens":8,"max_response_bytes":65536}}]}).to_string()).unwrap();
        owner
            .run(&[
                "machines",
                "configure",
                "worker",
                "--fetch-config",
                string(&fetch),
                "--grant-config",
                string(&resources),
            ])
            .await;
        let limits = root.join("machine-limits.json");
        std::fs::write(
            &limits,
            br#"[{"meter":"OutputTokens","window":"Total","amount":10}]"#,
        )
        .unwrap();
        worker
            .run(&[
                "admin",
                "--profile",
                string(&operator_profile),
                "--control-socket",
                string(&control),
                "set-capacity",
                "--expected-revision",
                "0",
                "--max-in-flight",
                "2",
                "--limits",
                string(&limits),
            ])
            .await;
        let exported = owner.output(&["contact", "export"]).await;
        let principal = decode_enrollment(&exported.stdout).unwrap();
        let work_subject = principal_id(&principal).unwrap();
        let work_allowance = hellas_work::model::grant::owner_grant_id(
            hellas_work::model::grant::grant_network(),
            provider.content_id(),
            work_subject,
        );
        for definition in common_node::budgets(
            common_node::POOL,
            work_subject,
            vec![Limit {
                meter: Meter::OutputTokens,
                window: Window::Total,
                amount: 10,
            }],
            1,
        ) {
            admin(
                &worker,
                &operator_profile,
                &control,
                WorkControlCommand::ConfigureBudget { definition },
            )
            .await;
        }
        admin(
            &worker,
            &operator_profile,
            &control,
            WorkControlCommand::ConfigureResource {
                policy: "glm".into(),
            },
        )
        .await;
        admin(
            &worker,
            &operator_profile,
            &control,
            WorkControlCommand::Create {
                id: work_allowance,
                terms: terms(work_subject),
            },
        )
        .await;
        let work_profile = issue_work_profile(
            &worker,
            &operator_profile,
            &control,
            root,
            work_subject,
            work_allowance,
        )
        .await;
        let (gateway_profile, gateway_token) = gateway_profile(root).await;
        let trust_root = approve(
            root,
            "worker",
            provider.content_id(),
            vec![hellas_rpc::FetchContract::http().unwrap().manifest_id()],
        );
        Self {
            root: directory,
            owner,
            managed,
            _upstream: https,
            work_address,
            work_profile,
            trust_root,
            gateway_profile,
            gateway_token,
        }
    }
    async fn enrollment(&self) -> Value {
        serde_json::from_str(&self.owner.run(&["machines", "resolve", "worker"]).await).unwrap()
    }
    async fn fetch(&self) {
        let mut gateway = self.owner.spawn(
            &[
                "gateway",
                "--trust-store",
                string(&self.trust_root),
                "--trust-policy",
                "worker",
                "--machine",
                "worker",
                "--work-profile",
                string(&self.work_profile),
                "--address",
                &self.work_address.to_string(),
                "--port",
                "0",
                "--gateway-profile",
                string(&self.gateway_profile),
                "--archive-dir",
                string(&self.root.path().join("archive")),
                "--zdr",
            ],
            "managed-gateway.log",
        );
        let address = gateway.wait_for("gateway listening on ").await;
        let response = post(
            &gateway_client(&self.gateway_token),
            &format!("http://{address}/v1/chat/completions"),
            json!({"messages":[]}),
        )
        .await;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert!(response.text().await.unwrap().contains("hello"));
        gateway.stop().await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_worker_reconnects_through_its_original_enrollment() {
    let mut worker = ManagedWorker::start().await;
    let before = worker.enrollment().await;
    worker.fetch().await;
    worker.owner.run(&["machines", "restart", "worker"]).await;
    assert_eq!(worker.enrollment().await, before);
    worker.fetch().await;
    worker.managed.stop().await;
}
