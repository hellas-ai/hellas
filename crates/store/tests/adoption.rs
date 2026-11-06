//! Adopting a HuggingFace cache, and remembering the work across a
//! restart.
//!
//! Two claims are load-bearing here. Adopting must find the content and
//! not the debris, hashing each blob once rather than once per snapshot
//! symlink pointing at it. And a persisted fastresume record must
//! survive a restart *without* becoming a way to serve a stale id — it
//! is a cache of work, never a source of truth.

use std::io::Write as _;
use std::path::PathBuf;

use futures::StreamExt as _;
use hellas_rpc::ContentRef;
use hellas_store::content::*;

fn bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u8
        })
        .collect()
}

struct Cache(PathBuf);

impl Cache {
    /// Builds a cache with the real hub layout, symlinks included.
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "hellas-hfcache-{}-{name}-{:?}",
            std::process::id(),
            std::thread::current().id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        Self(root)
    }

    fn repo(&self, repo: &str, commit: &str, files: &[(&str, &[u8])]) {
        let base = self.0.join(repo);
        std::fs::create_dir_all(base.join("blobs")).expect("blobs");
        std::fs::create_dir_all(base.join("refs")).expect("refs");
        std::fs::create_dir_all(base.join("snapshots").join(commit)).expect("snapshots");
        std::fs::write(base.join("refs/main"), commit).expect("ref");

        for (name, content) in files {
            // Blobs are named by etag; the exact name does not matter to
            // us, only that the bytes live there once.
            let etag = format!("{:016x}", content.len() as u64 * 2_654_435_761);
            let blob = base.join("blobs").join(&etag);
            let mut file = std::fs::File::create(&blob).expect("blob");
            file.write_all(content).expect("write");
            file.sync_all().expect("sync");
            // Lock files live alongside blobs — this is the debris that
            // a naive indexer ingests.
            std::fs::write(base.join("blobs").join(format!("{etag}.lock")), b"").expect("lock");
            // Snapshot links need symlinks, which Windows hands out only
            // with a privilege; the blobs alone are what adoption indexes.
            #[cfg(unix)]
            std::os::unix::fs::symlink(
                PathBuf::from("../../blobs").join(&etag),
                base.join("snapshots").join(commit).join(name),
            )
            .expect("symlink");
            #[cfg(not(unix))]
            let _ = name;
        }
        std::fs::create_dir_all(base.join(".no_exist").join(commit)).expect("no_exist");
        std::fs::write(
            base.join(".no_exist").join(commit).join("adapter.json"),
            b"",
        )
        .expect("marker");
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn an_hf_cache_is_an_ordinary_read_only_lower() {
    let cache = Cache::new("lower");
    let weights = bytes(300_000, 1);
    let config = br#"{"architectures":["Test"]}"#;
    cache.repo(
        "models--org--name",
        "0123456789abcdef0123456789abcdef01234567",
        &[("model.safetensors", &weights), ("config.json", config)],
    );
    let debris = cache.0.join("download.incomplete");
    std::fs::write(&debris, b"unfinished").unwrap();
    let upper = tempfile::tempdir().unwrap();
    let store = DiskStore::open(
        upper.path().into(),
        vec![cache.0.clone()],
        IndexMode::Resume,
        None,
        Reservations::ram(32 << 20),
    )
    .await
    .unwrap();
    store.finish_recovery().await.unwrap();
    let name = PinName::new("weights".into()).unwrap();
    let object = ContentRef::for_bytes(&weights);
    store
        .set_pin(
            &Scope::Owner,
            &name,
            None,
            Some(PinValue {
                target: Target::Object(object),
                policy: PinPolicy::Jobs,
                expires: None,
            }),
        )
        .await
        .unwrap();
    let mut read = store
        .read(
            &Scope::Owner,
            &Path::new(name, String::new()).unwrap(),
            0..object.bytes(),
        )
        .await
        .unwrap();
    let mut actual = Vec::new();
    while let Some(chunk) = read.bytes.next().await {
        actual.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(actual, weights);
    drop(read);
    assert_eq!(
        store.stats().unwrap().used,
        0,
        "lower bytes must not be copied to the upper"
    );
    for bytes in [b"".as_slice(), b"unfinished".as_slice()] {
        let missing = PinName::new("debris".into()).unwrap();
        assert!(
            store
                .set_pin(
                    &Scope::Owner,
                    &missing,
                    None,
                    Some(PinValue {
                        target: Target::Object(ContentRef::for_bytes(bytes)),
                        policy: PinPolicy::Owner,
                        expires: None,
                    })
                )
                .await
                .is_err()
        );
    }
    store.collect(&Scope::Owner).await.unwrap();
    assert_eq!(std::fs::read(&debris).unwrap(), b"unfinished");
    let blob = cache
        .0
        .join("models--org--name/blobs")
        .join(format!("{:016x}", weights.len() as u64 * 2_654_435_761));
    assert_eq!(std::fs::read(blob).unwrap(), weights);
    store.close().await;
}
