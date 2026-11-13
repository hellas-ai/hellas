#![expect(
    clippy::disallowed_methods,
    reason = "inventory class A/B/C: test timing fixtures pending their rollout"
)]
#![cfg(unix)]
mod contact;
mod local_compute;
mod local_flux;
mod local_text;
mod local_whisper;
mod managed;
mod offer_gateway;

use hellas_authority::test_support::common_node;

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

/// Bound for a hung process or request, not a performance requirement. These
/// tests start real nodes that compile, sign and journal while CI runs many
/// suites at once; the properties under test never depend on how fast that is.
const HANG_GUARD: Duration = Duration::from_secs(120);

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
                    let address = socket.local_addr();
                    let mut socket = match acceptor.accept(socket).await {
                        Ok(socket) => socket,
                        Err(error) => {
                            eprintln!("upstream TLS handshake at {address:?} failed: {error:?}");
                            return;
                        }
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
/// Software passkeys of fixture actors, so in-process fixtures can approve and
/// open sessions for the same principals the CLI acts for. `ROOT` is the
/// administrator the `common_node` bootstrap names.
const ROOT_PASSKEY: [u8; 32] = [0x11; 32];
const FRIEND_PASSKEY: [u8; 32] = [0x13; 32];
const AGENT_PASSKEY: [u8; 32] = [0x14; 32];

/// One CLI user: a node identity, acting for the principal of its own
/// software passkey file.
struct Cli {
    root: PathBuf,
    home: PathBuf,
    identity: PathBuf,
    passkey: PathBuf,
    metrics_endpoint: Option<String>,
    metrics_address: Option<String>,
}
impl Cli {
    fn new(root: &Path, name: &str, passkey: [u8; 32]) -> Self {
        let path = root.join(format!("{name}.passkey"));
        std::fs::write(&path, hex::encode(passkey)).unwrap();
        let home = root.join(name);
        std::fs::create_dir_all(&home).unwrap();
        Self {
            root: root.into(),
            identity: home.join("identity"),
            home,
            passkey: path,
            metrics_endpoint: None,
            metrics_address: None,
        }
    }
    fn principal(&self) -> hellas_auth::authority::PrincipalId {
        let scalar: [u8; 32] = hex::decode(std::fs::read(&self.passkey).unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let passkey = hellas_kernel::SoftPasskey::from_secret_scalar(scalar).unwrap();
        hellas_auth::authority::PrincipalId::from_public_key(hellas_auth::PublicKey::P256(
            passkey.party_key().to_bytes(),
        ))
        .unwrap()
    }
    /// This CLI's `hellas contact` string, named after its home.
    async fn contact(&self) -> String {
        let name = self
            .home
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        self.run(&["contact", "--name", &name])
            .await
            .trim()
            .to_owned()
    }
    /// The holder naming this CLI's node key, as its contact names it.
    async fn holder(&self) -> hellas_auth::authority::CredentialHolder {
        hellas_auth::authority::CredentialHolder::Node(
            hellas_sdk::contact::Contact::decode(&self.contact().await)
                .unwrap()
                .holder,
        )
    }
    async fn holder_file(&self) -> PathBuf {
        let path = self.root.join(format!(
            "{}-holder.json",
            self.home.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&path, serde_json::to_vec(&self.holder().await).unwrap()).unwrap();
        path
    }
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hellas"));
        command.arg("--home").arg(&self.home);
        if args.first() != Some(&"trust") {
            command.arg("--passkey").arg(&self.passkey);
        }
        command
            .args(args)
            .env("RUST_LOG", "warn,hellas_gateway=info,hellas::metrics=info")
            .env("OTEL_SDK_DISABLED", "true")
            .stdin(Stdio::null())
            .kill_on_drop(true);
        if let Some(address) = &self.metrics_address
            && args.contains(&"--metrics-port")
            && !args.contains(&"--wrap")
        {
            command.args(["--metrics-addr", address]);
        }
        if let Some(endpoint) = &self.metrics_endpoint {
            command
                .env("OTEL_SDK_DISABLED", "false")
                .env("OTEL_TRACES_EXPORTER", "none")
                .env("OTEL_METRICS_EXPORTER", "otlp")
                .env("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", endpoint)
                .env("OTEL_METRIC_EXPORT_INTERVAL", "100");
        }
        command
    }
    async fn output(&self, args: &[&str]) -> std::process::Output {
        tokio::time::timeout(HANG_GUARD, self.command(args).output())
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
    async fn gateway(&self, models: &[String], log: &str) -> (Process, String, String) {
        let mut args = vec!["gateway", "--bind", "127.0.0.1:0"];
        #[cfg(feature = "otel")]
        args.extend(["--metrics-port", "0"]);
        #[cfg(feature = "otel")]
        if let Some(address) = &self.metrics_address {
            args.extend(["--metrics-addr", address]);
        }
        for model in models {
            args.extend(["--model", model]);
        }
        args.extend(["--wrap", "sh", "--", "-c", "printf 'gateway listening on %s\n' \"$ANTHROPIC_BASE_URL\"; printf 'gateway token %s\n' \"$OPENAI_API_KEY\"; exec cat"]);
        let mut process = self.spawn(&args, log);
        let url = process.wait_for("gateway listening on ").await;
        let token = process.wait_for("gateway token ").await;
        (process, url.strip_prefix("http://").unwrap().into(), token)
    }
    fn spawn(&self, args: &[&str], name: &str) -> Process {
        let log = self.root.join(name);
        let file = std::fs::File::create(&log).unwrap();
        let child = self
            .command(args)
            .stdin(Stdio::piped())
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
        let deadline = tokio::time::Instant::now() + HANG_GUARD;
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
        let status = tokio::time::timeout(HANG_GUARD, self.child.wait())
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
use hellas_authority::model::grant::{admin::*, budget::*};

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
    holder: &Path,
    allowance: GrantId,
) -> PathBuf {
    issue_work_profile_at(
        cli,
        administrator,
        &["--control-socket", string(socket)],
        root,
        subject,
        holder,
        allowance,
    )
    .await
}

async fn issue_work_profile_at(
    cli: &Cli,
    administrator: &Path,
    connection: &[&str],
    root: &Path,
    subject: hellas_auth::authority::PrincipalId,
    holder: &Path,
    allowance: GrantId,
) -> PathBuf {
    use hellas_auth::authority as auth;
    let profile = hellas_sdk::node_control::profile::ClientProfile::load(administrator).unwrap();
    let now = hellas_auth::authority::UnixMillis::now().unwrap_or_default();
    let scope = auth::GrantSpec {
        authority: profile.authority,
        subject,
        permissions: [auth::Permission {
            operation: auth::OperationId::new(hellas_authority::grant_service::WORK_EXECUTE)
                .unwrap(),
            resource: hellas_authority::grant_service::allowance_resource(
                profile.authority,
                allowance,
            ),
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
    let mut args = vec!["admin", "--profile", string(administrator)];
    args.extend_from_slice(connection);
    let mut grant_args = args.clone();
    grant_args.extend(["grant", string(&command)]);
    cli.run(&grant_args).await;
    let scope = request_file(root, &scope);
    let output = root.join("issued-work.credential");
    args.extend([
        "issue-credential",
        "--scope",
        string(&scope),
        "--holder",
        string(holder),
        "--credential-out",
        string(&output),
    ]);
    let issued = cli.run(&args).await;
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
/// An HTTP authority whose administrator issues the gateway a separate
/// bearer credential; the bootstrap credential is never the bearer.
fn gateway_client(token: &str) -> reqwest::Client {
    let bearer = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).unwrap();
    reqwest::Client::builder()
        .default_headers(
            [(reqwest::header::AUTHORIZATION, bearer)]
                .into_iter()
                .collect(),
        )
        .timeout(HANG_GUARD)
        .build()
        .unwrap()
}
/// The HTTP Fetch invocation policy the grant resource fixtures admit.
fn http_invocation_policy() -> hellas_rpc::protocol::invocation::InvocationPolicy {
    use hellas_rpc::protocol::invocation::{
        Admission, InvocationPolicy, Limits,
        fetch::{FetchAdmission, FetchLimits, FetchRoutePolicy},
    };
    InvocationPolicy {
        admissions: vec![Admission::Fetch {
            admission: FetchAdmission {
                contract: hellas_rpc::FetchContract::http().unwrap(),
                route: FetchRoutePolicy::sealed_route("http", "request").unwrap(),
                limits: FetchLimits {
                    max_request_body_bytes: 65536,
                    max_output_events: 256,
                    max_spool_bytes: 262144,
                    max_encoded_result_frame: 262144,
                    max_encoded_prepared_input: 262144,
                },
            },
        }],
        limits: Limits {
            max_upload_bytes: 262144,
            max_output_bytes: 65536,
            max_steps: 1,
            execution_timeout_ms: 10_000,
        },
    }
}
async fn post(client: &reqwest::Client, url: &str, body: Value) -> reqwest::Response {
    client.post(url).json(&body).send().await.unwrap()
}

async fn assert_http_response(
    response: reqwest::Response,
    expected: reqwest::StatusCode,
    logs: &[&Path],
    upstream: &Https,
) -> String {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap();
    if status != expected {
        let logs: Vec<_> = logs
            .iter()
            .map(|path| {
                format!(
                    "{}:\n{}",
                    path.display(),
                    std::fs::read_to_string(path).unwrap()
                )
            })
            .collect();
        panic!(
            "HTTP {status}, expected {expected}\nheaders: {headers:?}\nbody: {body}\nupstream {}: {} requests\n{}",
            upstream.origin,
            upstream.calls.load(Ordering::SeqCst),
            logs.join("\n")
        );
    }
    body
}

/// A provider's signed offer and the Work profile it issued, as one access
/// file for `client`'s device: what `hellas share` writes.
async fn access_file(
    client: &Cli,
    offer: &hellas_authority::model::grant::records::SignedOffer,
    work_profile: &Path,
    out: &Path,
) -> PathBuf {
    let hellas_auth::authority::CredentialHolder::Node(holder) = client.holder().await else {
        panic!("a device holds the credential")
    };
    let profile = hellas_sdk::node_control::profile::ClientProfile::load(work_profile).unwrap();
    hellas_sdk::access_bundle::AccessBundle {
        offers: vec![offer.clone()],
        authority: profile.authority,
        authorization: profile.authorization,
        subject: client.principal(),
        holder,
        credential: profile.credential,
        expires: offer.offer().valid_until,
        label: None,
    }
    .save(out)
    .unwrap();
    out.to_owned()
}
