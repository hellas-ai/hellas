//! Loopback Hub used to exercise the ordinary provider acquisition protocol.
#[cfg(feature = "test-support")]
use super::*;
use std::{
    io::{BufRead, Write},
    net::TcpListener,
};
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

/// Fetch one Git-backed file from a real pinned Hub listing and resolution response.
#[cfg(feature = "test-support")]
pub async fn acquire_git_file(
    store: &DiskStore,
    repo: &str,
    path: &str,
    bytes: &[u8],
) -> ContentRef {
    let sha = "a".repeat(40);
    let (url, server) = hub(|_| routes(repo, path, &sha, bytes));
    let mut receiving = store.clone();
    receiving.core.hf_hub = Some(url);
    let object = ContentRef::for_bytes(bytes);
    receiving
        .acquire(
            &Scope::Owner,
            Source::HfXet {
                repo: crate::hf::Repo::from_uri(&format!("hf://{repo}@{sha}")).unwrap(),
                commit: sha,
                path: Some(path.into()),
            },
            Some(object),
            PinTarget {
                name: PinName::new(format!("models/{}", object.id())).unwrap(),
                policy: PinPolicy::Jobs,
            },
        )
        .await
        .unwrap();
    server.join().unwrap();
    object
}

#[cfg(feature = "test-support")]
fn routes(repo: &str, path: &str, sha: &str, bytes: &[u8]) -> Vec<(String, u16, Vec<u8>)> {
    vec![
        (
            format!("/api/models/{repo}/tree/{sha}?recursive=true"),
            200,
            serde_json::json!([{"type":"file","path":path,"size":bytes.len()}])
                .to_string()
                .into_bytes(),
        ),
        (format!("/{repo}/resolve/{sha}/{path}"), 200, bytes.to_vec()),
    ]
}

#[cfg(feature = "test-support")]
pub struct AvailableHubFile {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    server: std::thread::JoinHandle<()>,
    cas: crate::hf::HfCas,
    path: String,
    object: ContentRef,
}
#[cfg(feature = "test-support")]
impl AvailableHubFile {
    /// Provide a live, allow-listed Hub source without acquiring its file.
    pub fn new(store: &mut DiskStore, repo: &str, path: &str, bytes: &[u8]) -> Self {
        let sha = "a".repeat(40);
        let calls = std::sync::Arc::default();
        let (url, server) = counted_hub(
            |_| routes(repo, path, &sha, bytes),
            std::sync::Arc::clone(&calls),
        );
        let repo = crate::hf::Repo::from_uri(&format!("hf://{repo}@{sha}")).unwrap();
        let object = ContentRef::for_bytes(bytes);
        let source = Source::HfXet {
            repo: repo.clone(),
            commit: sha,
            path: Some(path.into()),
        };
        store
            .set_on_miss(std::sync::Arc::new(AllowList(
                [(object.id(), (object.bytes(), source))].into(),
            )))
            .unwrap();
        store.core.hf_hub = Some(url.clone());
        Self {
            calls,
            server,
            cas: crate::hf::HfCas::new(repo).with_hub(url),
            path: path.into(),
            object,
        }
    }
    /// Check no provider requests occurred, then read the fixture to prove that it was available.
    pub async fn assert_unused(self) {
        use std::sync::atomic::Ordering;
        assert_eq!(
            self.calls.load(Ordering::SeqCst),
            0,
            "admission contacted the Hub"
        );
        tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let (listing, _charges) = self.cas.files(&Reservations::ram(16 << 20)).unwrap();
            assert_eq!(listing[0].path, self.path);
            let mut bytes = Vec::new();
            self.cas
                .small_file(&self.path)
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            assert_eq!(ContentRef::for_bytes(&bytes), self.object);
            self.server.join().unwrap();
            assert_eq!(self.calls.load(Ordering::SeqCst), 2);
        })
        .await
        .unwrap();
    }
}
