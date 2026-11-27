//! Loopback Hub used to exercise the ordinary provider acquisition protocol.
#[cfg(feature = "test-support")]
use super::*;
use std::{
    io::{BufRead, Write},
    net::TcpListener,
};
#[cfg(test)]
pub(crate) fn hub(
    responses: impl FnOnce(&str) -> Vec<(String, u16, Vec<u8>)>,
) -> (String, std::thread::JoinHandle<()>) {
    counted_hub(responses, std::sync::Arc::default())
}
fn counted_hub(
    responses: impl FnOnce(&str) -> Vec<(String, u16, Vec<u8>)>,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let responses = responses(&base);
    let serving = std::thread::spawn(move || {
        for (expected, status, body) in responses {
            let (mut socket, _) = listener.accept().unwrap();
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut input = std::io::BufReader::new(socket.try_clone().unwrap());
            let mut first = String::new();
            input.read_line(&mut first).unwrap();
            assert!(
                first.starts_with(&format!("GET {expected} ")),
                "unexpected Hub request path"
            );
            loop {
                let mut line = String::new();
                input.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                assert!(
                    !line.to_ascii_lowercase().starts_with("authorization:"),
                    "a non-HF origin received a credential"
                );
            }
            write!(
                socket,
                "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            socket.write_all(&body).unwrap();
        }
    });
    (base, serving)
}

#[cfg(feature = "test-support")]
pub struct AvailableHubFile {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    server: std::thread::JoinHandle<()>,
    store: DiskStore,
    file: crate::hf::PinnedFile,
}

#[cfg(feature = "test-support")]
impl AvailableHubFile {
    fn serve(store: &mut DiskStore, repo: &str, path: &str, bytes: &[u8]) -> Self {
        let sha = "a".repeat(40);
        let calls = std::sync::Arc::default();
        let (url, server) = counted_hub(
            |_| {
                vec![
                    (
                        format!("/api/models/{repo}/tree/{sha}?recursive=true"),
                        200,
                        serde_json::to_vec(
                            &serde_json::json!([{"type":"file","path":path,"size":bytes.len()}]),
                        )
                        .unwrap(),
                    ),
                    (format!("/{repo}/resolve/{sha}/{path}"), 200, bytes.to_vec()),
                ]
            },
            std::sync::Arc::clone(&calls),
        );
        store.core.hf_hub = Some(url);
        let file = crate::hf::PinnedFile::new(
            format!("hf://{repo}@{sha}")
                .parse::<crate::hf::Repo>()
                .unwrap(),
            path.into(),
            ContentRef::for_bytes(bytes),
        );
        Self {
            calls,
            server,
            store: store.clone(),
            file,
        }
    }

    async fn acquire(self) -> ContentRef {
        self.file.acquire(&self.store).await.unwrap();
        self.server.join().unwrap();
        self.file.object
    }

    /// Provide a live, allow-listed Hub source without acquiring its file.
    pub fn new(store: &mut DiskStore, repo: &str, path: &str, bytes: &[u8]) -> Self {
        let served = Self::serve(store, repo, path, bytes);
        let object = served.file.object;
        store
            .set_on_miss(std::sync::Arc::new(AllowList {
                fixed: [(object.id(), (object.bytes(), served.file.source()))].into(),
                hints: None,
            }))
            .unwrap();
        served
    }
    /// Check no provider requests occurred, then read the fixture to prove that it was available.
    pub async fn assert_unused(self) {
        use std::sync::atomic::Ordering;
        assert_eq!(
            self.calls.load(Ordering::SeqCst),
            0,
            "admission contacted the Hub"
        );
        self.acquire().await;
    }
}
