#![cfg(unix)]
mod contact;
#[cfg(feature = "evaluate")]
mod local_evaluate;
mod managed;
mod native_owner;
mod offer_gateway;

use hellas_work::test_support::common_node;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::StreamExt;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
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
        let (ca, acceptor) = hellas_providers::test_support::private_ca_acceptor();
        let root_der = STANDARD.encode(ca.as_ref().der());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let finish = Arc::new(Semaphore::new(0));
        let (count, release) = (calls.clone(), finish.clone());
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (acceptor, count, release) = (acceptor.clone(), count.clone(), release.clone());
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
                    let usage = json!({"prompt_tokens":3,"completion_tokens":2,"total_tokens":5});
                    let streaming = body["stream"] == true;
                    let (content_type, bytes) = if streaming {
                        assert_eq!(body["stream_options"]["include_usage"], true);
                        let mut bytes =
                            "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n"
                                .to_owned();
                        bytes.push_str(&format!(
                            "data: {}\n\n",
                            json!({"choices":[],"usage":usage})
                        ));
                        bytes.push_str("data: [DONE]\n\n");
                        ("text/event-stream", bytes)
                    } else {
                        let mut value = json!({"choices":[{"message":{"content":"hello"}}]});
                        value["usage"] = usage;
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
        if args.first() != Some(&"trust") {
            command.arg("--identity").arg(&self.identity);
        }
        command
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
use hellas_auth::authority::GrantId;
use hellas_work::model::grant::{admin::*, budget::*};

fn request_file(root: &Path, command: &impl serde::Serialize) -> PathBuf {
    let path = root.join("work-command.json");
    std::fs::write(&path, serde_json::to_vec(command).unwrap()).unwrap();
    path
}
async fn admin(
    cli: &Cli,
    profile: &Path,
    socket: &Path,
    command: WorkControlCommand,
) -> WorkControlReply {
    let command = request_file(&cli.root, &command);
    serde_json::from_str(
        &cli.run(&[
            "admin",
            "--profile",
            string(profile),
            "--control-socket",
            string(socket),
            "work",
            string(&command),
        ])
        .await,
    )
    .unwrap()
}
fn profile(
    root: &Path,
    name: &str,
    authority: hellas_auth::authority::AuthorityId,
    authorization: GrantId,
    secret: &hellas_auth::authority::CredentialSecret,
) -> PathBuf {
    let credential = format!("{name}.credential");
    let output = hellas_private::private_tempfile(root, ".app-", ".issuing").unwrap();
    hellas_sdk::node_control::profile::save_credential(output, &root.join(&credential), secret)
        .unwrap();
    let path = root.join(format!("{name}-profile.json"));
    hellas_private::write_atomically(
        &path,
        ".writing",
        &serde_json::to_vec(&json!({
            "authority": authority, "authorization": authorization, "credential": credential,
            "local": {"certificate": "control.cert.der", "server_name": "localhost"},
        }))
        .unwrap(),
    )
    .unwrap();
    path
}
/// Write the local control TLS pair that `profile` and the grant config name.
fn control_tls(root: &Path) -> (PathBuf, PathBuf) {
    let tls = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (certificate, key) = (root.join("control.cert.der"), root.join("control.key.der"));
    hellas_private::write_atomically(&certificate, ".writing", tls.cert.der()).unwrap();
    hellas_private::write_atomically(&key, ".writing", &tls.signing_key.serialize_der()).unwrap();
    (certificate, key)
}
fn terms(subject: hellas_auth::authority::PrincipalId) -> AllowanceTerms {
    AllowanceTerms {
        policies: vec!["glm".into()],
        budget: BudgetNode::Subject {
            pool: common_node::POOL,
            subject,
        },
        max_job_millis: std::num::NonZeroU64::new(5000).unwrap(),
        enabled: true,
        allow_account_backed: true,
    }
}
fn work_profile(
    root: &Path,
    authority: hellas_auth::authority::AuthorityId,
    secret: &hellas_auth::authority::CredentialSecret,
) -> PathBuf {
    hellas_sdk::node_control::profile::save_credential(
        hellas_private::private_tempfile(root, ".app-", ".issuing").unwrap(),
        &root.join("work.credential"),
        secret,
    )
    .unwrap();
    let path = root.join("work-profile.json");
    hellas_private::write_atomically(
        &path,
        ".writing",
        &serde_json::to_vec(&json!({
            "authority": authority, "authorization": common_node::EXECUTION_AUTHORIZATION,
            "credential": "work.credential",
        }))
        .unwrap(),
    )
    .unwrap();
    path
}
async fn issue_work_profile(
    cli: &Cli,
    administrator: &Path,
    socket: &Path,
    root: &Path,
    subject: hellas_auth::authority::PrincipalId,
    allowance: GrantId,
) -> PathBuf {
    use hellas_auth::authority as auth;
    let profile = hellas_sdk::node_control::profile::ClientProfile::load(administrator).unwrap();
    let now = hellas_auth::authority::UnixMillis::now().unwrap_or_default();
    let scope = auth::GrantSpec {
        authority: profile.authority,
        subject,
        permissions: [auth::Permission {
            operation: auth::OperationId::new(hellas_work::grant_service::WORK_EXECUTE).unwrap(),
            resource: hellas_work::grant_service::allowance_resource(profile.authority, allowance),
        }]
        .into(),
        not_before: now,
        expires: auth::UnixMillis(now.0 + 600_000),
        delegation_depth: 0,
        issuance: None,
    };
    let command = request_file(
        root,
        &auth::GrantCommand::Issue {
            authorization: profile.authorization,
            id: common_node::EXECUTION_AUTHORIZATION,
            spec: scope.clone(),
        },
    );
    cli.run(&[
        "admin",
        "--profile",
        string(administrator),
        "--control-socket",
        string(socket),
        "grant",
        string(&command),
    ])
    .await;
    let scope = request_file(root, &scope);
    let output = root.join("issued-work.credential");
    let issued = cli
        .run(&[
            "admin",
            "--profile",
            string(administrator),
            "--control-socket",
            string(socket),
            "issue-credential",
            "--scope",
            string(&scope),
            "--credential-out",
            string(&output),
        ])
        .await;
    let issued: Value = serde_json::from_str(&issued).unwrap();
    assert_eq!(issued["subject"], hex::encode(subject.as_bytes()));
    assert_eq!(issued["subject_fingerprint"], subject.fingerprint());
    assert_eq!(
        issued["authority"],
        hex::encode(profile.authority.0.as_bytes())
    );
    work_profile(
        root,
        profile.authority,
        &hellas_sdk::node_control::profile::read_credential(&output).unwrap(),
    )
}
async fn gateway_profile(root: &Path) -> (PathBuf, String) {
    use hellas_auth::{Digest, authority::*};
    let authority = AuthorityId(Digest::hash(b"CLI HTTP authority"));
    let subject = hellas_work::test_support::principal(1).0;
    let now = UnixMillis::now().unwrap_or_default();
    let permission = hellas_work::operations::Operation::named(hellas_work::node::GATEWAY_INVOKE)
        .unwrap()
        .permission(authority, None)
        .unwrap();
    let administrator = common_node::admin_spec(
        authority,
        subject,
        &[(hellas_work::node::GATEWAY_INVOKE, permission.resource)],
        (now, UnixMillis(now.0 + 600_000)),
        (600_000, 0),
        &[],
    );
    let scope = GrantSpec {
        authority,
        subject,
        permissions: [permission].into(),
        issuance: None,
        delegation_depth: 0,
        not_before: now,
        expires: UnixMillis(now.0 + 600_000),
    };
    let journal = root.join("gateway-authority");
    let (store, credential) = hellas_work::work_store::grant::NodeStore::bootstrap(
        &journal,
        hellas_work::model::grant::grant_network(),
        GrantId([0; 16]),
        administrator,
        scope,
        None,
        now,
    )
    .await
    .unwrap();
    drop(store);
    let mut bytes = credential.id().0.to_vec();
    bytes.extend_from_slice(credential.expose_secret());
    let credential_path = root.join("gateway.credential");
    hellas_private::write_atomically(&credential_path, ".writing", &bytes).unwrap();
    let profile = root.join("gateway-profile.json");
    hellas_private::write_atomically(&profile,".writing",&serde_json::to_vec(&json!({
        "journal":journal,"authority":authority,"authorization":GrantId([0;16]),"credential":credential_path
    })).unwrap()).unwrap();
    (profile, hex::encode(bytes))
}
fn gateway_client(token: &str) -> reqwest::Client {
    let bearer = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).unwrap();
    reqwest::Client::builder()
        .default_headers(
            [(reqwest::header::AUTHORIZATION, bearer)]
                .into_iter()
                .collect(),
        )
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}
/// Record an independent caller approval of one provider and its environments.
fn approve(
    root: &Path,
    name: &str,
    provider_genesis: hellas_rpc::ContentId,
    environments: Vec<hellas_rpc::ContentId>,
) -> PathBuf {
    let trust_root = root.join(format!("{name}-trust"));
    hellas_sdk::trust_policy::TrustPolicyStore::new(&trust_root)
        .approve(
            name,
            0,
            hellas_sdk::trust_policy::TrustPolicy {
                provider_genesis,
                assurance: hellas_rpc::Assurance::ProducerSigned,
                environments,
                apple: None,
            },
            "independent test approval".into(),
        )
        .unwrap();
    trust_root
}
async fn prepare_machine(
    owner: &Cli,
    name: &str,
) -> (std::net::SocketAddr, hellas_cloud::config::Credentials) {
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let admin_address = udp.local_addr().unwrap();
    drop(udp);
    let bootstrap = owner.root.join(format!("{name}-bootstrap.json"));
    owner
        .run(&[
            "machines",
            "prepare",
            name,
            "--bootstrap-file",
            string(&bootstrap),
            "--admin-addr",
            &admin_address.to_string(),
        ])
        .await;
    let settings: std::collections::BTreeMap<String, String> =
        hellas_cloud::config::read_json(&bootstrap).unwrap();
    let credentials = hellas_cloud::config::Credentials {
        admin_secret: settings["HELLAS_REMOTE_KEY"].clone(),
        token: settings["HELLAS_REMOTE_TOKEN"].clone(),
        owner: Some(settings["HELLAS_REMOTE_OWNER"].clone()),
        owner_enrollment: Some(settings["HELLAS_REMOTE_OWNER_ENROLLMENT"].clone()),
    };
    (admin_address, credentials)
}
async fn post(client: &reqwest::Client, url: &str, body: Value) -> reqwest::Response {
    client.post(url).json(&body).send().await.unwrap()
}
