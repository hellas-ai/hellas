#![cfg(all(unix, feature = "node", feature = "gateway"))]
#[cfg(feature = "cloud")]
#[path = "grant_http/native_owner.rs"]
mod native_owner;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::StreamExt;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::Semaphore,
};

struct Https {
    origin: String,
    root_der: String,
    missing_usage: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
    finish: Arc<Semaphore>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Https {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Https {
    async fn start(credential: Option<&'static str>) -> Self {
        use rcgen::*;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        let key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .signed_by(&key, &ca)
            .unwrap();
        let root_der = STANDARD.encode(ca.as_ref().der());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let missing_usage = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let finish = Arc::new(Semaphore::new(0));
        let (faults, count, release) = (missing_usage.clone(), calls.clone(), finish.clone());
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (acceptor, faults, count, release) = (
                    acceptor.clone(),
                    faults.clone(),
                    count.clone(),
                    release.clone(),
                );
                tokio::spawn(async move {
                    let Ok(mut socket) = acceptor.accept(socket).await else {
                        return;
                    };
                    let mut headers = vec![];
                    while !headers.ends_with(b"\r\n\r\n") && headers.len() < 32768 {
                        headers.push(socket.read_u8().await.unwrap());
                    }
                    let text = String::from_utf8(headers).unwrap();
                    let authorization = text.lines().find_map(|line| {
                        line.split_once(':')
                            .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                            .map(|(_, value)| value.trim())
                    });
                    assert_eq!(authorization, credential);
                    assert!(text.starts_with("POST /v1/chat/completions "));
                    let length: usize = text
                        .lines()
                        .find_map(|line| {
                            line.split_once(':')
                                .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                                .map(|(_, v)| v.trim().parse().unwrap())
                        })
                        .unwrap();
                    assert!(length < 65536);
                    let mut body = vec![0; length];
                    socket.read_exact(&mut body).await.unwrap();
                    let body: Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(body["max_tokens"], 8, "cap must be repaired before signing");
                    count.fetch_add(1, Ordering::SeqCst);
                    let usage = if faults.load(Ordering::SeqCst) {
                        Value::Null
                    } else {
                        json!({"prompt_tokens":3,"completion_tokens":2,"total_tokens":5})
                    };
                    let streaming = body["stream"] == true;
                    let (content_type, bytes) = if streaming {
                        assert_eq!(body["stream_options"]["include_usage"], true);
                        let mut bytes =
                            "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n"
                                .to_owned();
                        if !usage.is_null() {
                            bytes.push_str(&format!(
                                "data: {}\n\n",
                                json!({"choices":[],"usage":usage})
                            ));
                        }
                        bytes.push_str("data: [DONE]\n\n");
                        ("text/event-stream", bytes)
                    } else {
                        let mut value = json!({"choices":[{"message":{"content":"hello"}}]});
                        if !usage.is_null() {
                            value["usage"] = usage;
                        }
                        ("application/json", value.to_string())
                    };
                    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).as_bytes()).await.unwrap();
                    if streaming {
                        let split = bytes.find("\n\n").unwrap() + 2;
                        socket.write_all(&bytes.as_bytes()[..split]).await.unwrap();
                        socket.flush().await.unwrap();
                        release.acquire().await.unwrap().forget();
                        socket.write_all(&bytes.as_bytes()[split..]).await.unwrap();
                    } else {
                        socket.write_all(bytes.as_bytes()).await.unwrap();
                    }
                    socket.shutdown().await.unwrap();
                });
            }
        });
        Self {
            origin,
            root_der,
            missing_usage,
            calls,
            finish,
            task,
        }
    }
}
struct Cli {
    root: PathBuf,
    identity: PathBuf,
}
impl Cli {
    fn new(root: &Path, name: &str) -> Self {
        Self {
            root: root.into(),
            identity: root.join(name),
        }
    }
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hellas-cli"));
        command
            .arg("--identity")
            .arg(&self.identity)
            .args(args)
            .env("HELLAS_GRANT_DATA_DIR", self.root.join("grants"))
            .env("HELLAS_STORE_DIR", self.root.join("store"))
            .env("HELLAS_MACHINES_DIR", self.root.join("machines"))
            .env("RUST_LOG", "hellas_gateway=info")
            .env("OTEL_SDK_DISABLED", "true")
            .stdin(Stdio::null())
            .kill_on_drop(true);
        if cfg!(feature = "evaluate") && matches!(args.first(), Some(&"serve" | &"gateway")) {
            command.arg("--store-dir").arg(self.root.join("store"));
        }
        command
    }
    async fn output(&self, args: &[&str]) -> std::process::Output {
        tokio::time::timeout(Duration::from_secs(30), self.command(args).output())
            .await
            .unwrap()
            .unwrap()
    }
    async fn run(&self, args: &[&str]) -> String {
        let output = self.output(args).await;
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }
    fn spawn(&self, args: &[&str], name: &str) -> Process {
        let log = self.root.join(name);
        let file = std::fs::File::create(&log).unwrap();
        let child = self
            .command(args)
            .stdout(file.try_clone().unwrap())
            .stderr(file)
            .spawn()
            .unwrap();
        Process { child, log }
    }
}
struct Process {
    child: Child,
    log: PathBuf,
}
impl Process {
    async fn wait_for(&mut self, marker: &str) -> String {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let log = std::fs::read_to_string(&self.log).unwrap();
            if let Some((_, tail)) = log.split_once(marker) {
                return tail.lines().next().unwrap_or_default().trim().into();
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "process exited: {log}"
            );
            assert!(
                tokio::time::Instant::now() < deadline,
                "waiting for {marker}: {log}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    async fn stop(&mut self) {
        unsafe {
            libc::kill(self.child.id().unwrap() as i32, libc::SIGTERM);
        }
        let status = tokio::time::timeout(Duration::from_secs(15), self.child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(
            status.success(),
            "{}",
            std::fs::read_to_string(&self.log).unwrap()
        );
    }
}
fn string(path: &Path) -> &str {
    path.to_str().unwrap()
}
async fn grant(provider: &Cli, socket: &Path, args: &[&str]) -> Value {
    let mut command = vec!["grant", "--control-socket", string(socket)];
    command.extend_from_slice(args);
    serde_json::from_str(&provider.run(&command).await).unwrap()
}
async fn used(provider: &Cli, socket: &Path, id: &str) -> u64 {
    let status = grant(provider, socket, &["usage", id]).await;
    let node = status["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["node"].is_object())
        .unwrap();
    node["counters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["meter"] == "OutputTokens" && c["window"] == "Total")
        .unwrap()["used"]
        .as_u64()
        .unwrap()
}
async fn post(client: &reqwest::Client, url: &str, body: Value) -> reqwest::Response {
    client
        .post(url)
        .bearer_auth("11".repeat(32))
        .json(&body)
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn contact_grant_offer_gateway_uses_private_ca_and_durable_allowances() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    hellas_private::restrict_directory(root).unwrap();
    let https = Https::start(Some("Bearer fixture-key")).await;
    let provider = Cli::new(root, "provider");
    let client = Cli::new(root, "client");
    let stranger = Cli::new(root, "stranger");
    for cli in [&provider, &client, &stranger] {
        cli.run(&["--software-root", "identity", "init"]).await;
    }
    let contact = root.join("contact");
    client
        .run(&["contact", "export", "--out", string(&contact)])
        .await;
    provider
        .run(&["contact", "import", string(&contact), "--name", "client"])
        .await;
    let socket = root.join("control.sock");
    let fetch = root.join("fetch.json");
    let resources = root.join("resources.json");
    let secret = root.join("account.json");
    hellas_private::write_atomically(&secret, ".new", br#"{"access_token":"fixture-key"}"#)
        .unwrap();
    std::fs::write(&fetch,json!({"routes":[{"service":"http","method":"request","destination":{"type":"http","config":{
        "allowed_hosts":["localhost"],"allow_private_addresses":true,
        "credentials":{"glm-account":{"allowed_origins":[https.origin],"allowed_paths":["/v1/chat/completions"],"allowed_methods":["POST"],
        "trust_roots":{"mode":"certificates","der_base64":[https.root_der]},"header_name":"authorization","secret_file":secret,"secret_field":"access_token","prefix":"Bearer "}}
    }}}]}).to_string()).unwrap();
    std::fs::write(&resources,json!({"control_socket":socket,"machine_limits":[],"max_in_flight":2,"max_job_millis":10000,"resources":[{"name":"glm","fetch":{
        "allowed_environment":hellas_rpc::FetchEnvironment::Http.manifest_id().to_string(),"service":"http","method":"request","max_request_body_bytes":65536,"max_output_events":256,"max_output_bytes":65536,"max_spool_bytes":262144,"max_encoded_result_frame":262144,"max_encoded_prepared_input":262144},
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
    let offer = root.join("offer");
    let created = grant(
        &provider,
        &socket,
        &[
            "create",
            "--to",
            "client",
            "--policy",
            "glm",
            "--limit",
            "output-tokens=20/total",
            "--allow-account-backed",
            "--max-job",
            "5s",
            "--offer-out",
            string(&offer),
        ],
    )
    .await;
    let id = created["grant_id"].as_str().unwrap();
    client
        .run(&["offer", "import", string(&offer), "--name", "lan"])
        .await;
    assert!(
        !stranger
            .output(&["offer", "import", string(&offer), "--name", "forwarded"])
            .await
            .status
            .success()
    );
    let bearer = root.join("bearer");
    hellas_private::write_atomically(&bearer, ".token", "11".repeat(32).as_bytes()).unwrap();
    let archive = root.join("archive");
    let mut gateway = client.spawn(
        &[
            "gateway",
            "--offer",
            "lan",
            "--port",
            "0",
            "--bearer-token-file",
            string(&bearer),
            "--archive-dir",
            string(&archive),
            "--zdr",
        ],
        "gateway.log",
    );
    let address = gateway.wait_for("gateway listening on ").await;
    let url = format!("http://{address}/v1/chat/completions");
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let response = post(&http, &url, json!({"messages":[]})).await;
    assert_eq!(response.status(), 200);
    assert!(response.text().await.unwrap().contains("hello"));
    assert_eq!(used(&provider, &socket, id).await, 2);
    let response = post(&http, &url, json!({"messages":[],"stream":true})).await;
    assert_eq!(response.status(), 200);
    let mut stream = response.bytes_stream();
    let first = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&first).contains("hello"));
    assert_eq!(
        used(&provider, &socket, id).await,
        2,
        "streaming job is still reserved"
    );
    https.finish.add_permits(1);
    while let Some(chunk) = stream.next().await {
        chunk.unwrap();
    }
    assert_eq!(used(&provider, &socket, id).await, 4);
    assert_eq!(
        post(&http, &url, json!({"messages":[],"max_tokens":9}))
            .await
            .status(),
        400
    );
    assert_eq!(https.calls.load(Ordering::SeqCst), 2);
    for _ in 0..5 {
        let response = post(&http, &url, json!({"messages":[]})).await;
        assert_eq!(response.status(), 200);
        response.bytes().await.unwrap();
    }
    assert_eq!(used(&provider, &socket, id).await, 14);
    assert_eq!(
        post(&http, &url, json!({"messages":[]})).await.status(),
        429
    );
    grant(
        &provider,
        &socket,
        &[
            "revise",
            id,
            "--policy",
            "glm",
            "--limit",
            "output-tokens=100/total",
            "--allow-account-backed",
            "--max-job",
            "5s",
        ],
    )
    .await;
    assert_eq!(used(&provider, &socket, id).await, 14);
    https.missing_usage.store(true, Ordering::SeqCst);
    for _ in 0..3 {
        let response = post(&http, &url, json!({"messages":[]})).await;
        assert_eq!(response.status(), 200);
        response.bytes().await.unwrap();
    }
    assert_eq!(used(&provider, &socket, id).await, 38);
    assert_eq!(
        post(&http, &url, json!({"messages":[]})).await.status(),
        403
    );
    grant(&provider, &socket, &["repair-resource", "glm"]).await;
    https.missing_usage.store(false, Ordering::SeqCst);
    grant(&provider, &socket, &["pause", id]).await;
    assert_eq!(
        post(&http, &url, json!({"messages":[]})).await.status(),
        403
    );
    grant(&provider, &socket, &["resume", id]).await;
    let response = post(&http, &url, json!({"messages":[]})).await;
    assert_eq!(response.status(), 200);
    response.bytes().await.unwrap();
    assert_eq!(used(&provider, &socket, id).await, 40);
    grant(
        &provider,
        &socket,
        &[
            "revise",
            id,
            "--policy",
            "glm",
            "--limit",
            "output-tokens=100/total",
            "--allow-account-backed",
            "--max-job",
            "5s",
            "--expires",
            "1ms",
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        post(&http, &url, json!({"messages":[]})).await.status(),
        403
    );
    grant(&provider, &socket, &["revoke", id]).await;
    assert_eq!(
        post(&http, &url, json!({"messages":[]})).await.status(),
        403
    );
    assert_eq!(https.calls.load(Ordering::SeqCst), 11);
    gateway.stop().await;
    node.stop().await;
}

#[cfg(feature = "cloud")]
struct Managed {
    task: tokio::task::JoinHandle<hellas_cloud::agent::Result<()>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}
#[cfg(feature = "cloud")]
impl Drop for Managed {
    fn drop(&mut self) {
        self.task.abort();
    }
}
#[cfg(feature = "cloud")]
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

#[cfg(feature = "cloud")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_owner_bootstrap_standing_fetch_and_restart_preserve_allowances() {
    use hellas_cloud::{
        agent::{self, AgentOptions},
        config::Credentials,
    };
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    hellas_private::restrict_directory(root).unwrap();
    let owner = Cli::new(root, "owner");
    owner.run(&["--software-root", "identity", "init"]).await;
    let bootstrap = root.join("bootstrap.json");
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let admin_address = udp.local_addr().unwrap();
    drop(udp);
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let work_address = udp.local_addr().unwrap();
    drop(udp);
    owner
        .run(&[
            "machines",
            "prepare",
            "worker",
            "--bootstrap-file",
            string(&bootstrap),
            "--admin-addr",
            &admin_address.to_string(),
        ])
        .await;
    let settings: std::collections::BTreeMap<String, String> =
        hellas_cloud::config::read_json(&bootstrap).unwrap();
    let credentials = Credentials {
        admin_secret: settings["HELLAS_REMOTE_KEY"].clone(),
        token: settings["HELLAS_REMOTE_TOKEN"].clone(),
        owner: Some(settings["HELLAS_REMOTE_OWNER"].clone()),
        owner_enrollment: Some(settings["HELLAS_REMOTE_OWNER_ENROLLMENT"].clone()),
    };
    let data = root.join("worker");
    let private = root.join("private");
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
    let before: Value =
        serde_json::from_str(&owner.run(&["machines", "resolve", "worker"]).await).unwrap();
    let https = Https::start(None).await;
    let fetch = root.join("managed-fetch.json");
    let resources = root.join("managed-resources.json");
    std::fs::write(&fetch, json!({"routes":[{"service":"http","method":"request","destination":{"type":"http","config":{"allowed_hosts":["localhost"],"allow_private_addresses":true}}}]}).to_string()).unwrap();
    std::fs::write(&resources, json!({"machine_limits":[{"meter":"OutputTokens","window":"Total","amount":10}],"max_in_flight":2,"max_job_millis":10000,"resources":[{"name":"glm","fetch":{
        "allowed_environment":hellas_rpc::FetchEnvironment::Http.manifest_id().to_string(),"service":"http","method":"request","max_request_body_bytes":65536,"max_output_events":256,"max_output_bytes":65536,"max_spool_bytes":262144,"max_encoded_result_frame":262144,"max_encoded_prepared_input":262144},
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
    let bearer = root.join("bearer");
    hellas_private::write_atomically(&bearer, ".token", "11".repeat(32).as_bytes()).unwrap();
    let mut gateway = owner.spawn(
        &[
            "gateway",
            "--machine",
            "worker",
            "--node-addr",
            &work_address.to_string(),
            "--port",
            "0",
            "--bearer-token-file",
            string(&bearer),
            "--archive-dir",
            string(&root.join("archive")),
            "--zdr",
        ],
        "managed-gateway.log",
    );
    let address = gateway.wait_for("gateway listening on ").await;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let url = format!("http://{address}/v1/chat/completions");
    let response = post(&http, &url, json!({"messages":[]})).await;
    assert_eq!(response.status(), 200);
    response.bytes().await.unwrap();
    gateway.stop().await;
    owner.run(&["machines", "restart", "worker"]).await;
    let after: Value =
        serde_json::from_str(&owner.run(&["machines", "resolve", "worker"]).await).unwrap();
    assert_eq!(
        before, after,
        "enrollment must survive configuration and restart"
    );
    let mut gateway = owner.spawn(
        &[
            "gateway",
            "--machine",
            "worker",
            "--node-addr",
            &work_address.to_string(),
            "--port",
            "0",
            "--bearer-token-file",
            string(&bearer),
            "--archive-dir",
            string(&root.join("archive")),
            "--zdr",
        ],
        "managed-gateway-restarted.log",
    );
    let address = gateway.wait_for("gateway listening on ").await;
    let url = format!("http://{address}/v1/chat/completions");
    let response = post(&http, &url, json!({"messages":[]})).await;
    assert_eq!(response.status(), 200);
    response.bytes().await.unwrap();
    assert_eq!(
        post(&http, &url, json!({"messages":[]})).await.status(),
        429,
        "two jobs used four tokens; reserving eight more must exceed ten even after restart"
    );
    assert_eq!(https.calls.load(Ordering::SeqCst), 2);
    gateway.stop().await;
    managed.stop().await;
}

#[cfg(feature = "evaluate")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_owner_gateway_preserves_machine_limits_and_refuses_before_gpu_execution() {
    use hellas_rpc::{
        CausalLmEnvironment, ContentId, ContentRef,
        protocol::work_grant::{budget::*, grant_network, owner_grant_id, records::Principal},
    };
    use hellas_work::work_store::grant::GrantStore;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    hellas_private::restrict_directory(root).unwrap();
    let owner = Cli::new(root, "owner");
    owner.run(&["--software-root", "identity", "init"]).await;
    let export = owner.output(&["contact", "export"]).await;
    assert!(export.status.success());
    let principal = Principal::decode(&export.stdout).unwrap();
    let journal = root
        .join("grants")
        .join(principal.id().0.to_string())
        .join("provider");
    let now = hellas_work::grant_service::wall_clock();
    let mut store =
        GrantStore::open(&journal, grant_network(), principal.bundle().clone(), now).unwrap();
    store
        .configure_machine(
            vec![Limit {
                meter: Meter::Requests,
                window: Window::Total,
                amount: 0,
            }],
            1,
            now,
        )
        .unwrap();
    drop(store);
    let environment = CausalLmEnvironment::new(
        ContentRef::new(ContentId::from_bytes([8; 32]), 1024),
        "model",
        vec![],
        vec![],
        vec![],
        256,
        1024,
        hellas_rpc::CausalLmGenerationSchedule {
            fixed_capacity: 1024,
            prefill_chunk_tokens: 64,
        },
    )
    .unwrap();
    let environment_file = root.join("model.environment");
    std::fs::write(&environment_file, environment.canonical_bytes()).unwrap();
    let tokenizer = root.join("tokenizer.json");
    std::fs::write(&tokenizer, br#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":{"type":"Whitespace"},"post_processor":null,"decoder":null,"model":{"type":"WordLevel","vocab":{"hello":0,"<unk>":1},"unk_token":"<unk>"}}"#).unwrap();
    let bearer = root.join("bearer");
    hellas_private::write_atomically(&bearer, ".token", "11".repeat(32).as_bytes()).unwrap();
    let mut gateway = owner.spawn(
        &[
            "gateway",
            "--local",
            "--environment",
            string(&environment_file),
            "--content",
            string(&environment_file),
            "--tokenizer",
            string(&tokenizer),
            "--model",
            "fixture",
            "--port",
            "0",
            "--bearer-token-file",
            string(&bearer),
            "--archive-dir",
            string(&root.join("archive")),
            "--zdr",
        ],
        "local-gateway.log",
    );
    let address = gateway.wait_for("gateway listening on ").await;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let response = post(
        &http,
        &format!("http://{address}/v1/completions"),
        json!({"model":"fixture","prompt":"hello","max_tokens":1}),
    )
    .await;
    assert_eq!(response.status(), 429, "{}", response.text().await.unwrap());
    let response = post(
        &http,
        &format!("http://{address}/v1/completions"),
        json!({"model":"fixture","prompt":"hello","max_tokens":1,"stream":true}),
    )
    .await;
    assert_eq!(response.status(), 429, "{}", response.text().await.unwrap());
    let response = post(
        &http,
        &format!("http://{address}/v1/completions"),
        json!({"model":"fixture","prompt":"hello","max_tokens":1024}),
    )
    .await;
    assert_eq!(response.status(), 400, "{}", response.text().await.unwrap());
    gateway.stop().await;
    let store = GrantStore::open(
        &journal,
        grant_network(),
        principal.bundle().clone(),
        hellas_work::grant_service::wall_clock(),
    )
    .unwrap();
    let owner_id = owner_grant_id(
        grant_network(),
        principal.bundle().content_id(),
        principal.id(),
    );
    assert_eq!(
        store.state().grant(owner_id).unwrap().policies[0]
            .work
            .allowed_environment(),
        environment.manifest().content_id()
    );
    assert_eq!(
        store
            .state()
            .ledger()
            .node(BudgetNode::Machine)
            .unwrap()
            .counter(Meter::Requests, Window::Total)
            .used,
        0
    );
}
