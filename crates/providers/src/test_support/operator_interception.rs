//! Exercise the real client factory with hostile process configuration in a child.
//! No production endpoint, credential or machine trust store is changed.
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const CHILD_URL: &str = "HELLAS_TEST_RESPONSES_EGRESS_URL";

async fn headers<S: AsyncReadExt + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 16_384, "fixture request exceeded its bound");
        bytes.push(stream.read_u8().await.unwrap());
    }
    bytes
}

pub async fn rejects_operator_interception<F, Fut>(test_name: &str, attempts: usize, run: F)
where
    F: FnOnce(reqwest::Url) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    if let Ok(url) = std::env::var(CHILD_URL) {
        // This control proves the proxy is reachable and its fixture CA is valid.
        let ca = reqwest::Certificate::from_pem(
            &std::fs::read(std::env::var("SSL_CERT_FILE").unwrap()).unwrap(),
        )
        .unwrap();
        let control = reqwest::Client::builder()
            .tls_certs_only([ca])
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let response = control.post(&url).body("CONTROL").send().await.unwrap();
        assert!(response.status().is_success());
        drop(response);
        drop(control);
        assert!(
            run(url.parse().unwrap()).await,
            "operator trust configuration admitted private egress"
        );
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let (ca, acceptor) = super::private_ca_acceptor();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let url = format!("https://localhost:{}/v1/responses", address.port());
    let upstream = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..=attempts {
            let (socket, _) = listener.accept().await.unwrap();
            let Ok(mut socket) = acceptor.accept(socket).await else {
                continue;
            };
            let head = headers(&mut socket).await;
            let text = std::str::from_utf8(&head).unwrap();
            let length: usize = text
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            assert!(length < 1024);
            let mut body = vec![0; length];
            socket.read_exact(&mut body).await.unwrap();
            requests.push((head, body));
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 12\r\nConnection: close\r\n\r\ndata: done\n\n").await.unwrap();
            socket.shutdown().await.unwrap();
        }
        requests
    });
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    let proxy_hits = Arc::new(AtomicUsize::new(0));
    let seen = proxy_hits.clone();
    let proxy_task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = proxy.accept().await.unwrap();
            let request = headers(&mut socket).await;
            assert!(request.starts_with(
                format!("CONNECT localhost:{} HTTP/1.1\r\n", address.port()).as_bytes()
            ));
            seen.fetch_add(1, Ordering::SeqCst);
            let mut remote = TcpStream::connect(address).await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut socket, &mut remote).await;
        }
    });
    let certificate = directory.path().join("operator.pem");
    std::fs::write(&certificate, ca.pem()).unwrap();
    let certificates = directory.path().join("roots");
    std::fs::create_dir(&certificates).unwrap();
    let keylog = directory.path().join("tls-keys.log");
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap());
    child
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_URL, url)
        .env("SSL_CERT_FILE", certificate)
        .env("SSL_CERT_DIR", certificates)
        .env("SSLKEYLOGFILE", &keylog)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .kill_on_drop(true);
    for variable in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        child.env(variable, format!("http://{proxy_address}"));
    }
    let result = tokio::time::timeout(Duration::from_secs(30), child.output())
        .await
        .unwrap()
        .unwrap();
    let requests = tokio::time::timeout(Duration::from_secs(5), upstream)
        .await
        .unwrap()
        .unwrap();
    proxy_task.abort();
    assert!(proxy_task.await.unwrap_err().is_cancelled());
    assert!(
        requests.iter().all(
            |(head, body)| !String::from_utf8_lossy(body).contains("PRIVATE_")
                && !String::from_utf8_lossy(head).contains("PRIVATE_")
        ),
        "interception fixture received private request bytes: {} proxy tunnels, {} HTTP requests",
        proxy_hits.load(Ordering::SeqCst),
        requests.len()
    );
    assert!(
        result.status.success(),
        "child rejected the egress invariant: {} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        proxy_hits.load(Ordering::SeqCst),
        1,
        "only the control may use the operator proxy"
    );
    assert_eq!(
        requests.len(),
        1,
        "only the control may trust the operator CA"
    );
    assert_eq!(requests[0].1, b"CONTROL");
    assert!(
        !keylog.exists(),
        "the private client must not export TLS session keys"
    );
}
