use super::*;
use hellas_auth::authority as auth;
use hellas_sdk::node_control::{bootstrap::Invitation, configuration::*};
use hellas_work::model::grant::records::decode_enrollment;

struct ManagedWorker {
    root: tempfile::TempDir,
    owner: Cli,
    node: Process,
    _upstream: Https,
    pin: String,
    address: String,
    profile: PathBuf,
    work_profile: PathBuf,
    trust_root: PathBuf,
    gateway_profile: PathBuf,
    gateway_token: String,
}
impl ManagedWorker {
    async fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        hellas_private::restrict_directory(root).unwrap();
        let owner = Cli::new(root, "owner", AGENT_PASSKEY);
        owner.run(&["--software-root", "identity", "init"]).await;
        let state = root.join("worker");
        hellas_private::create_dir_all_durable(&state).unwrap();
        let worker = Cli::new(&state, "identity", ROOT_PASSKEY);
        worker.run(&["--software-root", "identity", "init"]).await;
        let exported = worker.output(&["identity", "export-enrollment"]).await;
        assert!(exported.status.success());
        let provider = decode_enrollment(&exported.stdout).unwrap();
        let https = Https::start(None).await;
        let resources = root.join("resources.json");
        std::fs::write(&resources, json!({
            "journal_root":state.join("provider"),"control_socket":state.join("control.sock"),
            "control_certificate":state.join("control.cert.der"),"control_private_key":state.join("control.key.der"),
            "max_job_millis":10000,"resources":[{
                "resource":auth::ResourceId(hellas_auth::Digest::hash(b"test resource")),
                "account":auth::ResourceId(hellas_auth::Digest::hash(b"test account")),"revision":1,
                "pricing":{"revision":1,"rates":null},"name":"glm",
                "fetch":{"contract":hellas_rpc::FetchContract::http().unwrap(),
                    "allowed_environment":hellas_rpc::FetchContract::http().unwrap().manifest_id().to_string(),
                    "service":"http","method":"request","max_request_body_bytes":65536,
                    "max_output_events":256,"max_output_bytes":65536,"max_spool_bytes":262144,
                    "max_encoded_result_frame":262144,"max_encoded_prepared_input":262144},
                "https":{"origin":https.origin,"paths":["/v1/chat/completions"],"methods":["POST"],
                    "credential":null,"tls":{"roots":{"mode":"certificates","der_base64":[https.root_der]},"spki_sha256":[]},
                    "accounting":"openai-chat","max_output_tokens":8,"max_response_bytes":65536}
            }]
        }).to_string()).unwrap();
        // The installed policy must name an available route at startup. Remote
        // administration will enable private-address access before the first job.
        std::fs::write(
            state.join("fetch.json"),
            json!({"revision":0,"routes":[{
                "service":"http","method":"request","destination":{"type":"http",
                "config":{"allowed_hosts":["localhost"],"allow_private_addresses":false}}
            }]})
            .to_string(),
        )
        .unwrap();
        let mut node = worker.spawn(
            &[
                "serve",
                "--await-owner",
                string(&state),
                "--grant-config",
                string(&resources),
                "--port",
                "0",
                "--no-discovery",
            ],
            "node.log",
        );
        let invitation = invitation(&mut node).await;
        let pin = invitation.node.to_string();
        let address = invitation
            .addresses
            .iter()
            .find(|address| address.is_ipv4())
            .unwrap()
            .to_string();
        let invitation_file = root.join("invitation.json");
        std::fs::write(&invitation_file, serde_json::to_vec(&invitation).unwrap()).unwrap();
        let authority = auth::AuthorityId(hellas_auth::Digest::hash(b"normal host fixture"));
        let now = auth::UnixMillis::now().unwrap();
        let extra: Vec<_> = hellas_work::operations::OPERATIONS
            .iter()
            .filter(|operation| {
                !matches!(operation.scope, hellas_work::operations::Scope::Allowance)
            })
            .map(|operation| {
                (
                    operation.name,
                    operation.permission(authority, None).unwrap().resource,
                )
            })
            .collect();
        let administrator = common_node::admin_spec(
            authority,
            owner.principal(),
            &extra,
            (now, auth::UnixMillis(now.0 + 3_600_000)),
            (3_600_000, 8),
            &[hellas_work::grant_service::WORK_EXECUTE],
        );
        let administrator_file = root.join("administrator.json");
        let scope_file = root.join("scope.json");
        std::fs::write(
            &administrator_file,
            serde_json::to_vec(&administrator).unwrap(),
        )
        .unwrap();
        let scope = administrator;
        std::fs::write(&scope_file, serde_json::to_vec(&scope).unwrap()).unwrap();
        let profile_dir = root.join("administration");
        let bootstrap = owner
            .output(&[
                "admin",
                "bootstrap-remote",
                "--invitation",
                string(&invitation_file),
                "--root-grant",
                &GrantId([0; 16]).to_string(),
                "--administrator",
                string(&administrator_file),
                "--credential-scope",
                string(&scope_file),
                "--profile-out",
                string(&profile_dir),
            ])
            .await;
        assert!(
            bootstrap.status.success(),
            "bootstrap failed: {}; node: {}",
            String::from_utf8_lossy(&bootstrap.stderr),
            std::fs::read_to_string(&node.log).unwrap()
        );
        let initialized: Value = serde_json::from_slice(&bootstrap.stdout).unwrap();
        assert_eq!(initialized["node_id"], pin);
        let profile = PathBuf::from(initialized["profile"].as_str().unwrap());
        node.wait_for("RPC server running.").await;
        let connection = ["--node", pin.as_str(), "--address", address.as_str()];
        let base = ["admin", "--profile", string(&profile)];
        let run = |tail: Vec<String>| {
            let mut args: Vec<String> = base
                .iter()
                .chain(connection.iter())
                .map(|s| (*s).into())
                .collect();
            args.extend(tail);
            args
        };
        let update = ProviderUpdate {
            expected_revision: 0,
            change: Some(UpstreamChange::SetEndpoint(UpstreamEndpoint {
                service: "http".into(),
                method: "request".into(),
                allowed_hosts: vec!["localhost".into()],
                allow_private_addresses: true,
            })),
        };
        let command = request_file(root, &update);
        let args = run(vec!["configure-provider".into(), string(&command).into()]);
        owner
            .run(&args.iter().map(String::as_str).collect::<Vec<_>>())
            .await;
        let limits = root.join("limits.json");
        std::fs::write(
            &limits,
            br#"[{"meter":"OutputTokens","window":"Total","amount":10}]"#,
        )
        .unwrap();
        let args = run(vec![
            "set-capacity".into(),
            "--expected-revision".into(),
            "0".into(),
            "--max-in-flight".into(),
            "2".into(),
            "--limits".into(),
            string(&limits).into(),
        ]);
        owner
            .run(&args.iter().map(String::as_str).collect::<Vec<_>>())
            .await;
        let subject = owner.principal();
        let allowance = hellas_work::model::grant::owner_grant_id(
            hellas_work::model::grant::grant_network(),
            provider.content_id(),
            subject,
        );
        let mut commands: Vec<_> = common_node::budgets(
            common_node::POOL,
            subject,
            vec![Limit {
                meter: Meter::OutputTokens,
                window: Window::Total,
                amount: 10,
            }],
            1,
        )
        .into_iter()
        .map(|definition| WorkControlCommand::ConfigureBudget { definition })
        .collect();
        commands.extend([
            WorkControlCommand::ConfigureResource {
                policy: "glm".into(),
            },
            WorkControlCommand::Create {
                id: allowance,
                terms: terms(subject),
            },
        ]);
        for command in commands {
            let file = request_file(root, &command);
            let args = run(vec!["work".into(), string(&file).into()]);
            owner
                .run(&args.iter().map(String::as_str).collect::<Vec<_>>())
                .await;
        }
        let work_profile = issue_work_profile_at(
            &owner,
            &profile,
            &connection,
            root,
            subject,
            &owner.holder_file().await,
            allowance,
        )
        .await;
        let offer = root.join("worker.offer");
        let command = request_file(
            root,
            &WorkControlCommand::Offers {
                id: Some(allowance),
            },
        );
        let args = run(vec![
            "work".into(),
            string(&command).into(),
            "--offer-out".into(),
            string(&offer).into(),
        ]);
        owner
            .run(&args.iter().map(String::as_str).collect::<Vec<_>>())
            .await;
        owner
            .run(&["offer", "import", string(&offer), "--name", "worker"])
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
            node,
            _upstream: https,
            pin,
            address,
            profile,
            work_profile,
            trust_root,
            gateway_profile,
            gateway_token,
        }
    }
    async fn control(&self, command: &[&str]) -> Value {
        let mut args = vec![
            "admin",
            "--node",
            &self.pin,
            "--address",
            &self.address,
            "--profile",
            string(&self.profile),
        ];
        args.extend_from_slice(command);
        serde_json::from_str(&self.owner.run(&args).await).unwrap()
    }
    async fn gateway(&self) -> (Process, String) {
        let mut gateway = self.owner.spawn(
            &[
                "gateway",
                "--trust-store",
                string(&self.trust_root),
                "--trust-policy",
                "worker",
                "--offer",
                "worker",
                "--work-profile",
                string(&self.work_profile),
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
        (gateway, address)
    }
    async fn fetch(&self) {
        let (mut gateway, address) = self.gateway().await;
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

async fn invitation(node: &mut Process) -> Invitation {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let log = std::fs::read_to_string(&node.log).unwrap();
        if let Some(invitation) = log
            .lines()
            .find_map(|line| serde_json::from_str::<Invitation>(line).ok())
        {
            return invitation;
        }
        assert!(
            node.child.try_wait().unwrap().is_none(),
            "node exited: {log}"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "pairing invitation missing: {log}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn normal_host_reconnects_through_its_original_enrollment() {
    let mut worker = ManagedWorker::start().await;
    let before = worker.control(&["status"]).await;
    assert_eq!(before["configuration"]["revision"], 1);
    let stranger = Cli::new(worker.root.path(), "stranger", STRANGER_PASSKEY);
    stranger.run(&["--software-root", "identity", "init"]).await;
    let refused = stranger
        .output(&[
            "admin",
            "--node",
            &worker.pin,
            "--address",
            &worker.address,
            "--profile",
            string(&worker.profile),
            "status",
        ])
        .await;
    assert!(
        !refused.status.success(),
        "a foreign passkey must not use the owner's credential"
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr)
            .to_lowercase()
            .contains("denied"),
        "the live server must refuse authentication: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
    worker.fetch().await;
    worker
        .control(&["set-provider-state", "--enabled", "false"])
        .await;
    worker
        .control(&["set-provider-state", "--enabled", "true"])
        .await;
    let after = worker.control(&["status"]).await;
    assert_eq!(after["endpoint"], before["endpoint"]);
    assert_eq!(after["authority"], before["authority"]);
    assert_eq!(after["configuration"], before["configuration"]);
    worker.fetch().await;
    assert_eq!(worker._upstream.calls.load(Ordering::SeqCst), 2);
    worker.node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_configuration_restores_the_route_and_requires_explicit_restart() {
    let mut worker = ManagedWorker::start().await;
    worker.fetch().await;
    let path = worker.root.path().join("worker/fetch.json");
    let original = std::fs::read(&path).unwrap();
    let command = request_file(
        worker.root.path(),
        &ProviderUpdate {
            expected_revision: 1,
            change: Some(UpstreamChange::RemoveEndpoint(UpstreamRoute {
                service: "http".into(),
                method: "request".into(),
            })),
        },
    );
    // Removing a route required by the installed Work policy passes parsing,
    // then fails actual provider startup. It must not become durable config.
    let refused = worker
        .owner
        .output(&[
            "admin",
            "--node",
            &worker.pin,
            "--address",
            &worker.address,
            "--profile",
            string(&worker.profile),
            "configure-provider",
            string(&command),
        ])
        .await;
    assert!(!refused.status.success());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    let failed = worker.control(&["status"]).await;
    assert_eq!(
        failed["provider_state"],
        hellas_rpc::pb::host::RuntimeState::Failed as i32
    );
    assert_eq!(worker._upstream.calls.load(Ordering::SeqCst), 1);
    worker
        .control(&["set-provider-state", "--enabled", "true"])
        .await;
    let recovered = worker.control(&["status"]).await;
    assert_eq!(recovered["configuration"]["revision"], 1);
    worker.fetch().await;
    assert_eq!(worker._upstream.calls.load(Ordering::SeqCst), 2);
    worker.node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejected_configuration_keeps_running_and_valid_configuration_keeps_stopped() {
    let mut worker = ManagedWorker::start().await;
    let path = worker.root.path().join("worker/fetch.json");
    let original = std::fs::read(&path).unwrap();
    let endpoint = || {
        UpstreamChange::SetEndpoint(UpstreamEndpoint {
            service: "http".into(),
            method: "request".into(),
            allowed_hosts: vec!["localhost".into()],
            allow_private_addresses: true,
        })
    };
    for (revision, change) in [
        (0, endpoint()),
        (
            1,
            UpstreamChange::RemoveEndpoint(UpstreamRoute {
                service: "missing".into(),
                method: "request".into(),
            }),
        ),
        (
            1,
            UpstreamChange::AddKey(UpstreamKey {
                service: "http".into(),
                method: "request".into(),
                key: "invalid".into(),
                allowed_origins: vec!["https://localhost".into()],
                allowed_paths: vec!["/v1".into()],
                allowed_methods: vec!["POST".into()],
                header_name: "invalid header name".into(),
                prefix: "Bearer ".into(),
                secret: "abandoned-key".into(),
            }),
        ),
    ] {
        let command = request_file(
            worker.root.path(),
            &ProviderUpdate {
                expected_revision: revision,
                change: Some(change),
            },
        );
        let result = worker
            .owner
            .output(&[
                "admin",
                "--node",
                &worker.pin,
                "--address",
                &worker.address,
                "--profile",
                string(&worker.profile),
                "configure-provider",
                string(&command),
            ])
            .await;
        assert!(!result.status.success());
        assert_eq!(
            worker.control(&["status"]).await["provider_state"],
            hellas_rpc::pb::host::RuntimeState::Running as i32
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
    let permissions = std::fs::metadata(&path).unwrap().permissions();
    let mut readonly = permissions.clone();
    readonly.set_readonly(true);
    std::fs::set_permissions(&path, readonly).unwrap();
    let command = request_file(
        worker.root.path(),
        &ProviderUpdate {
            expected_revision: 1,
            change: Some(endpoint()),
        },
    );
    let result = worker
        .owner
        .output(&[
            "admin",
            "--node",
            &worker.pin,
            "--address",
            &worker.address,
            "--profile",
            string(&worker.profile),
            "configure-provider",
            string(&command),
        ])
        .await;
    assert!(!result.status.success());
    std::fs::set_permissions(&path, permissions).unwrap();
    assert_eq!(
        worker.control(&["status"]).await["provider_state"],
        hellas_rpc::pb::host::RuntimeState::Running as i32
    );
    worker.fetch().await;
    worker
        .control(&["set-provider-state", "--enabled", "false"])
        .await;
    worker
        .control(&["configure-provider", string(&command)])
        .await;
    let status = worker.control(&["status"]).await;
    assert_eq!(
        status["provider_state"],
        hellas_rpc::pb::host::RuntimeState::Stopped as i32
    );
    assert_eq!(status["configuration"]["revision"], 2);
    worker
        .control(&["set-provider-state", "--enabled", "true"])
        .await;
    worker.fetch().await;
    worker.node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_shutdown_finishes_remote_work_before_closing_its_transport() {
    let mut worker = ManagedWorker::start().await;
    let (mut gateway, address) = worker.gateway().await;
    let client = gateway_client(&worker.gateway_token);
    let response = tokio::spawn(async move {
        let response = post(
            &client,
            &format!("http://{address}/v1/chat/completions"),
            json!({"messages":[], "stream":true}),
        )
        .await;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        response.text().await.unwrap()
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        while worker._upstream.calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    unsafe {
        libc::kill(worker.node.child.id().unwrap() as i32, libc::SIGTERM);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), worker.node.child.wait())
            .await
            .is_err(),
        "host exited before accepted Work completed"
    );
    assert!(!response.is_finished());
    worker._upstream.finish.add_permits(1);
    let body = tokio::time::timeout(Duration::from_secs(10), response)
        .await
        .unwrap()
        .unwrap();
    assert!(body.contains("hello"));
    assert!(body.contains("[DONE]"));
    let status = tokio::time::timeout(Duration::from_secs(15), worker.node.child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(
        status.success(),
        "{}",
        std::fs::read_to_string(&worker.node.log).unwrap()
    );
    gateway.stop().await;
}
