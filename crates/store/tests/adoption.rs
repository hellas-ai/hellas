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
use std::sync::Arc;

use hellas_store::ContentStore;
use hellas_store::hf_cache::HfCache;
use hellas_xet::XetHash;

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

#[test]
fn adopting_a_cache_finds_the_content_and_not_the_debris() {
    let cache = Cache::new("adopt");
    let weights = bytes(300_000, 1);
    let config = br#"{"architectures":["Test"]}"#.to_vec();
    cache.repo(
        "models--org--name",
        "0123456789abcdef0123456789abcdef01234567",
        &[("model.safetensors", &weights), ("config.json", &config)],
    );

    let store = ContentStore::new();
    let source = HfCache::new(&cache.0);
    let adopted = source.adopt_into(&store).expect("adopt");

    assert_eq!(adopted, 2, "two blobs, no locks and no 404 markers");
    assert!(store.have(XetHash::hash(&weights)));
    assert!(store.have(XetHash::hash(&config)));
}

/// Only `blobs/` is walked, so content shared between two revisions is
/// one entry rather than one per snapshot pointing at it.
#[test]
fn a_blob_shared_by_two_revisions_is_indexed_once() {
    let cache = Cache::new("shared");
    let shared = bytes(120_000, 7);
    cache.repo(
        "models--org--name",
        "1111111111111111111111111111111111111111",
        &[("model.safetensors", &shared)],
    );
    // A second snapshot pointing at the same blob.
    let base = cache.0.join("models--org--name");
    let second = base.join("snapshots/2222222222222222222222222222222222222222");
    std::fs::create_dir_all(&second).expect("second snapshot");
    #[cfg(unix)]
    let etag = format!("{:016x}", shared.len() as u64 * 2_654_435_761);
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        PathBuf::from("../../blobs").join(&etag),
        second.join("model.safetensors"),
    )
    .expect("symlink");

    let store = ContentStore::new();
    let adopted = HfCache::new(&cache.0).adopt_into(&store).expect("adopt");
    assert_eq!(adopted, 1, "one blob, however many snapshots point at it");
    assert_eq!(store.len(), 1);
}

/// The cache answers as a substituter for content it holds, without the
/// store having to own or copy the bytes.
#[test]
fn the_cache_substitutes_for_content_it_holds() {
    let cache = Cache::new("substitute");
    let weights = bytes(80_000, 11);
    cache.repo(
        "models--org--name",
        "3333333333333333333333333333333333333333",
        &[("model.safetensors", &weights)],
    );

    let source = Arc::new(HfCache::new(&cache.0));
    let store = ContentStore::new();
    source.adopt_into(&store).expect("adopt");

    let id = XetHash::hash(&weights);
    let fresh = ContentStore::new().with_substituter(source.clone());
    assert!(fresh.have(id), "a fresh store substitutes from the cache");
    assert!(fresh.locate(id).is_some_and(|path| path.exists()));
}

/// A persisted record must survive a restart, and must still be
/// validated against the live file rather than trusted.
// Windows remembers nothing (see fastresume); nothing to persist or reuse.
#[cfg(unix)]
#[test]
fn fastresume_survives_a_restart_but_is_still_checked() {
    let cache = Cache::new("persist");
    let weights = bytes(400_000, 21);
    cache.repo(
        "models--org--name",
        "4444444444444444444444444444444444444444",
        &[("model.safetensors", &weights)],
    );
    let db = cache.0.join("fastresume.bin");

    let store = ContentStore::new();
    HfCache::new(&cache.0).adopt_into(&store).expect("adopt");
    let remembered = store.records().remembered();
    assert!(remembered >= 1);

    let saved = store.records().save(&db).expect("save");
    assert_eq!(saved, remembered);

    // Restart: a brand new store, which remembers nothing until it
    // reads the record file.
    let restarted = ContentStore::new();
    assert_eq!(restarted.records().remembered(), 0);
    assert_eq!(restarted.records().load(&db), saved, "records come back");
    assert_eq!(restarted.records().remembered(), saved);

    HfCache::new(&cache.0)
        .adopt_into(&restarted)
        .expect("re-adopt");
    assert!(restarted.have(XetHash::hash(&weights)));
}

/// A file changed while the record was on disk must not be served from
/// that record. This is the whole reason the key is an identity and not
/// a path.
// Windows remembers nothing (see fastresume); nothing to persist or reuse.
#[cfg(unix)]
#[test]
fn a_record_for_a_changed_file_is_not_used() {
    let cache = Cache::new("stale");
    let first = bytes(200_000, 31);
    cache.repo(
        "models--org--name",
        "5555555555555555555555555555555555555555",
        &[("model.safetensors", &first)],
    );
    let db = cache.0.join("fastresume.bin");

    let store = ContentStore::new();
    HfCache::new(&cache.0).adopt_into(&store).expect("adopt");
    store.records().save(&db).expect("save");

    // Replace the blob's contents, keeping the length identical.
    let blob = std::fs::read_dir(cache.0.join("models--org--name/blobs"))
        .expect("blobs")
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.extension().is_none_or(|ext| ext != "lock"))
        .expect("a blob");
    let second = bytes(200_000, 32);
    std::fs::write(&blob, &second).expect("rewrite");

    let after = ContentStore::new();
    assert_eq!(after.records().load(&db), 1, "the stale record loads");
    HfCache::new(&cache.0).adopt_into(&after).expect("re-adopt");
    assert!(
        after.have(XetHash::hash(&second)),
        "the new content must be indexed",
    );
    assert!(
        !after.have(XetHash::hash(&first)),
        "the stale record must not survive the file changing",
    );
}

/// A corrupt or foreign fastresume file must be ignored, not guessed at.
#[test]
fn an_unreadable_record_file_yields_nothing() {
    let cache = Cache::new("corrupt");
    let db = cache.0.join("bad.bin");

    let store = ContentStore::new();
    assert_eq!(store.records().load(&cache.0.join("absent.bin")), 0);
    std::fs::write(&db, b"not a fastresume file at all").expect("write");
    assert_eq!(store.records().load(&db), 0);
    std::fs::write(&db, b"HELLASFR\x09\x00\x00\x00").expect("write");
    assert_eq!(
        store.records().load(&db),
        0,
        "a future version is discarded"
    );
}

/// Windows has no identity strong enough to key remembered work, so a scan
/// records nothing and every later scan re-hashes.
#[cfg(windows)]
#[test]
fn windows_remembers_no_hashing_work() {
    let cache = Cache::new("windows");
    let weights = bytes(100_000, 41);
    cache.repo(
        "models--org--name",
        "6666666666666666666666666666666666666666",
        &[("model.safetensors", &weights)],
    );
    let store = ContentStore::new();
    HfCache::new(&cache.0).adopt_into(&store).expect("adopt");
    assert!(
        store.have(XetHash::hash(&weights)),
        "adopted content is available"
    );
    assert_eq!(store.records().remembered(), 0);
}
