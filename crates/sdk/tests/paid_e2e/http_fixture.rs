//! Local TLS upstream and bearer authority shared by the paid HTTP tests.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hellas_authority::{node::NodeCoordinator, work_store::grant::NodeStore};
use hellas_rpc::http_fetch::{HttpTls, HttpTrustRoots};
use hellas_sdk::daemon_config::{Backend, BackendKind, Credential, Upstream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
pub(super) const SECRET: &str = "local-mock-seller-secret";
pub(super) struct Reply {
    pub status: u16,
    pub content: &'static str,
    pub bytes: Vec<u8>,
    pub chunked: bool,
}

pub(super) struct Mock {
    pub(super) origin: String,
    pub(super) tls: HttpTls,
    pub(super) seen: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Mock {
    pub(super) async fn start(response: fn(&str) -> Reply) -> Self {
        let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = key.cert.der().clone();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = seen.clone();
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (acceptor, capture) = (acceptor.clone(), capture.clone());
                tokio::spawn(async move {
                    let mut stream = acceptor.accept(socket).await.unwrap();
                    let mut request = Vec::new();
                    let mut buf = [0; 8192];
                    let header_end = loop {
                        let n = stream.read(&mut buf).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        request.extend_from_slice(&buf[..n]);
                        if let Some(i) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                    };
                    let header = String::from_utf8(request[..header_end].to_vec()).unwrap();
                    let length = header
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(|n| n.parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    while request.len() < header_end + length {
                        let n = stream.read(&mut buf).await.unwrap();
                        assert!(n > 0);
                        request.extend_from_slice(&buf[..n]);
                    }
                    capture.lock().unwrap().push(request);
                    let target = header.split_whitespace().nth(1).unwrap();
                    let authorized = header
                        .to_ascii_lowercase()
                        .contains(&format!("x-hosted-key: {SECRET}\r\n"));
                    assert!(authorized);
                    let Reply {
                        status,
                        content,
                        bytes,
                        chunked,
                    } = response(target);
                    if !chunked {
                        let head = format!(
                            "HTTP/1.1 {status} Test\r\ncontent-type: {content}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                            bytes.len()
                        );
                        let _ = stream.write_all(head.as_bytes()).await;
                        let _ = stream.write_all(&bytes).await;
                        let _ = stream.shutdown().await;
                        return;
                    }
                    let head = format!(
                        "HTTP/1.1 {status} Test\r\ncontent-type: {content}\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n"
                    );
                    if stream.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    for chunk in bytes.chunks(16384) {
                        if stream
                            .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                            .await
                            .is_err()
                        {
                            return;
                        }
                        if stream.write_all(chunk).await.is_err() {
                            return;
                        }
                        if stream.write_all(b"\r\n").await.is_err() {
                            return;
                        }
                        if stream.flush().await.is_err() {
                            return;
                        }
                    }
                    let _ = stream.write_all(b"0\r\n\r\n").await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            origin,
            tls: HttpTls {
                roots: HttpTrustRoots::Certificates {
                    der_base64: vec![STANDARD.encode(cert)],
                },
                spki_sha256: vec![],
            },
            seen,
            task,
        }
    }
    pub(super) fn backend(&self, paths: &[&str]) -> Backend {
        Backend {
            max_in_flight: std::num::NonZeroUsize::MIN,
            kind: BackendKind::Fetch {
                service: "openai".into(),
                method: "responses".into(),
                upstream: Upstream::Http {
                    plain_http_hosts: vec![],
                    allowed_hosts: vec!["localhost".into()],
                    allow_private_addresses: true,
                    credentials: vec![Credential {
                        trust_roots: self.tls.roots.clone(),
                        allowed_origins: vec![self.origin.clone()],
                        allowed_paths: paths.iter().map(|path| (*path).into()).collect(),
                        allowed_methods: vec!["POST".into()],
                        header_name: "x-hosted-key".into(),
                        secret: Some(SECRET.into()),
                    }],
                },
            },
        }
    }
}

pub(super) async fn access(
    root: &std::path::Path,
) -> (NodeCoordinator, hellas_gateway::GatewayAccess) {
    use auth::*;
    use hellas_authority::{
        node::{GATEWAY_INVOKE, host_resource},
        test_support::{TestClock, common_node, ids::ROOT_GRANT},
    };
    let authority = AuthorityId(Digest::hash(b"audio gateway probe"));
    let now = UnixMillis(1000);
    let spec = common_node::admin_spec(
        authority,
        ROOT.principal(),
        &[(GATEWAY_INVOKE, host_resource(authority))],
        (now, UnixMillis(100_000)),
        (99_000, 0),
        &[],
    );
    let (store, admin) = NodeStore::bootstrap(
        &StoreLocation::for_test(root),
        hellas_authority::model::grant::grant_network(),
        ROOT_GRANT,
        common_node::approval_for(
            Ownership::Bootstrap {
                root: ROOT_GRANT,
                target: None,
            },
            spec.clone(),
            spec,
        ),
        None,
        now,
    )
    .await
    .unwrap();
    let node = NodeCoordinator::new(store, TestClock::new(now).source());
    let caller = hellas_authority::test_support::session(&node, &admin).await;
    let scope = hellas_channel::test_support::Rights::new(authority, ROOT)
        .allow(GATEWAY_INVOKE, host_resource(authority))
        .valid_from(now)
        .valid_until(UnixMillis(90_000))
        .build();
    let grant = GrantId([104; 16]);
    node.grant(
        &caller,
        GrantCommand::Issue {
            authorization: ROOT_GRANT,
            id: grant,
            spec: scope.clone(),
        },
    )
    .await
    .unwrap();
    let (_, credential) = hellas_authority::test_support::credentials::issue_one(
        &node,
        &caller,
        ROOT_GRANT,
        scope,
        CredentialHolder::Bearer,
    )
    .await
    .unwrap();
    let access = hellas_gateway::GatewayAccess::new(node.clone(), grant, credential)
        .await
        .unwrap();
    (node, access)
}
