//! What the store must actually do, as opposed to appear to do.
//!
//! Three claims are load-bearing and each is asserted here rather than
//! described: an id identifies content and not a path; adopting a
//! directory is enough to answer `have`; and indexing keeps the chunk
//! list, because that is the half that makes a partial fetch
//! verifiable.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hellas_store::{ContentStore, StoreError, Substituter};
use hellas_xet::{XetHash, file_hash};

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

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "hellas-store-{}-{name}-{:?}",
            std::process::id(),
            std::thread::current().id(),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    fn write(&self, relative: &str, content: &[u8]) -> PathBuf {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent");
        }
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(content).expect("write");
        file.sync_all().expect("sync");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The defining property: identity is the content, not the location.
/// Two paths holding the same bytes are one entry.
#[test]
fn the_same_bytes_at_two_paths_are_one_content() {
    let fixture = Fixture::new("same-bytes");
    let content = bytes(300_000, 1);
    let left = fixture.write("a/weights.bin", &content);
    let right = fixture.write("b/copied-elsewhere.bin", &content);

    let store = ContentStore::new();
    let first = store.index(&left).expect("index left");
    let second = store.index(&right).expect("index right");

    assert_eq!(first.id, second.id, "content id must not depend on path");
    assert_eq!(first.chunks, second.chunks);
    assert_eq!(first.len, content.len() as u64);
    assert_eq!(store.len(), 1, "one content, however many paths hold it");
    assert!(store.have(first.id));
}

/// The id must be the Xet file hash of the bytes — the same value
/// HuggingFace publishes — not merely self-consistent.
#[test]
fn the_id_is_the_xet_file_hash_of_the_content() {
    let fixture = Fixture::new("id-is-xet");
    for size in [0, 1, 8_192, 200_000, 2 * 1024 * 1024 + 7] {
        let content = bytes(size, size as u64);
        let path = fixture.write(&format!("f{size}"), &content);
        let indexed = ContentStore::new().index(&path).expect("index");
        assert_eq!(indexed.id, XetHash::hash(&content), "size {size}");
        assert_eq!(file_hash(&indexed.chunks), indexed.id, "size {size} chunks");
    }
}

/// Adopting a directory is what makes an existing HuggingFace cache a
/// populated store — no copy, no download.
#[test]
fn adopting_a_directory_answers_have_for_everything_in_it() {
    let fixture = Fixture::new("adopt");
    let one = bytes(150_000, 10);
    let two = bytes(90_000, 11);
    fixture.write("models--org--name/blobs/aaa", &one);
    fixture.write("models--org--name/blobs/bbb", &two);

    let store = ContentStore::new();
    let adopted = store.adopt(&fixture.0).expect("adopt");

    assert_eq!(adopted.len(), 2);
    assert!(store.have(XetHash::hash(&one)));
    assert!(store.have(XetHash::hash(&two)));
    assert!(!store.have(XetHash::hash(&bytes(1000, 999))));
}

/// Only regular files are content.
///
/// A cache is a directory we do not own. A fifo under `blobs/` blocks
/// adoption of everything after it, on `open`, forever; a symlink to
/// `/dev/zero` reads until the disk fills; a symlink to an unrelated
/// readable file indexes bytes from outside the cache under an id this
/// node then claims to hold.
#[cfg(unix)]
#[test]
fn adoption_indexes_regular_files_and_nothing_else() {
    let fixture = Fixture::new("file-types");
    let real = bytes(50_000, 60);
    fixture.write("blobs/abcdef", &real);

    // Something outside the cache that a symlink could reach.
    let outside = fixture.write("outside/secrets.bin", b"not this cache's content");
    std::os::unix::fs::symlink(&outside, fixture.0.join("blobs/linked")).expect("symlink");
    // And a snapshot symlink, which points at a blob that is indexed
    // under its own name anyway.
    std::os::unix::fs::symlink(
        fixture.0.join("blobs/abcdef"),
        fixture.0.join("blobs/snapshot-style"),
    )
    .expect("symlink");

    // A fifo: `open` on it blocks until somebody writes, which for an
    // adoption walk is forever.
    let fifo = fixture.0.join("blobs/pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success(), "the fixture needs a fifo");

    // Adoption runs on another thread and the timeout is an assertion:
    // without the file-type check, `open` on the fifo never returns and
    // this test hangs rather than failing.
    let store = ContentStore::new();
    let walker = store.clone();
    let blobs = fixture.0.join("blobs");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(walker.adopt(&blobs).map(|found| found.len()));
    });
    let adopted = receiver
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("adoption blocked on something that is not a regular file")
        .expect("adopt");

    assert_eq!(adopted, 1, "one regular file under blobs/");
    assert!(store.have(XetHash::hash(&real)));
    assert!(
        !store.have(XetHash::hash(b"not this cache's content")),
        "a symlink out of the cache must not put its target in the store",
    );
}

/// Explicit paths may follow a symlink to ordinary content, but neither that
/// convenience nor the adoption walk's earlier `file_type` observation may
/// turn a FIFO or device into a blocking content read.
#[cfg(unix)]
#[test]
fn explicit_indexing_opens_only_regular_file_descriptors() {
    let fixture = Fixture::new("explicit-file-types");
    let content = b"ordinary content reached through a symlink";
    let target = fixture.write("blobs/ordinary", content);
    let regular_link = fixture.0.join("regular-link");
    std::os::unix::fs::symlink(&target, &regular_link).expect("regular symlink");
    let store = ContentStore::new();
    let indexed = store
        .index(&regular_link)
        .expect("an explicit symlink to a regular file remains supported");
    assert_eq!(indexed.id, XetHash::hash(content));

    let fifo = fixture.0.join("pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success(), "the fixture needs a fifo");
    let fifo_link = fixture.0.join("fifo-link");
    std::os::unix::fs::symlink(&fifo, &fifo_link).expect("fifo symlink");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(ContentStore::new().index(&fifo_link));
    });
    let error = receiver
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("indexing blocked while opening a FIFO")
        .expect_err("a FIFO is not content");
    assert!(
        matches!(error, StoreError::Read { source, .. } if source.kind() == std::io::ErrorKind::InvalidInput)
    );

    let fifo_replacement = fixture.0.join("fifo-replacement");
    std::os::unix::fs::symlink(&fifo, &fifo_replacement).expect("replacement symlink");
    std::fs::rename(&fifo_replacement, &regular_link).expect("replace indexed path");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(store.open_verified(indexed.id, indexed.len));
    });
    let error = receiver
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("opening an indexed path blocked on its FIFO replacement")
        .expect_err("a FIFO replacement is not verified content");
    assert!(
        matches!(error, StoreError::Read { source, .. } if source.kind() == std::io::ErrorKind::InvalidInput)
    );

    if Path::new("/dev/zero").exists() {
        let error = ContentStore::new()
            .index(Path::new("/dev/zero"))
            .expect_err("a character device is not content");
        assert!(
            matches!(error, StoreError::Read { source, .. } if source.kind() == std::io::ErrorKind::InvalidInput)
        );
    }
}

/// A HuggingFace cache is littered with things that are not content.
/// Indexing them would put ids of lock files and half-downloads into a
/// store whose whole value is that an id means the bytes.
#[test]
fn cache_debris_is_never_indexed() {
    let fixture = Fixture::new("debris");
    let real = bytes(50_000, 20);
    fixture.write("blobs/abcdef", &real);
    fixture.write("blobs/abcdef.lock", b"lock");
    fixture.write("download/x.etag.incomplete", &bytes(40_000, 21));
    fixture.write(".no_exist/sha/adapter_config.json", b"");

    let store = ContentStore::new();
    let adopted = store.adopt(&fixture.0).expect("adopt");

    assert_eq!(adopted.len(), 1, "only the real blob is content");
    assert_eq!(adopted[0].id, XetHash::hash(&real));
    assert!(store.index(&fixture.0.join("blobs/abcdef.lock")).is_err());
}

/// Indexing must keep the metainfo, not just the id. Without the chunk
/// list a partial fetch from an untrusted peer cannot be verified until
/// the whole file is reassembled.
#[test]
fn indexing_keeps_the_chunk_list() {
    let fixture = Fixture::new("chunks");
    // Several chunks, so the list is not trivially one entry.
    let content = bytes(5 * 131_072 + 999, 30);
    let path = fixture.write("big.bin", &content);

    let store = ContentStore::new();
    let indexed = store.index(&path).expect("index");
    assert!(indexed.chunks.len() > 3, "fixture must span several chunks");

    let held = store.chunks(indexed.id).expect("chunks are retained");
    assert_eq!(held, indexed.chunks);
    assert_eq!(file_hash(&held), indexed.id);
    assert_eq!(
        held.iter().map(|chunk| chunk.data_len).sum::<u64>(),
        content.len() as u64,
        "chunk lengths must account for every byte",
    );
}

/// A substituter answers for content the store never indexed. This is
/// how "somewhere else already has it" becomes usable without copying.
#[test]
fn a_substituter_can_answer_for_content_the_store_lacks() {
    struct Fixed(XetHash, PathBuf);
    impl Substituter for Fixed {
        fn name(&self) -> &str {
            "fixed"
        }
        fn locate(&self, id: XetHash) -> Option<PathBuf> {
            (id == self.0).then(|| self.1.clone())
        }
    }

    let fixture = Fixture::new("substituter");
    let content = bytes(1_000, 40);
    let path = fixture.write("elsewhere.bin", &content);
    let id = XetHash::hash(&content);

    let bare = ContentStore::new();
    assert!(!bare.have(id), "nothing indexed, nothing substituted");

    let store = ContentStore::new().with_substituter(Arc::new(Fixed(id, path.clone())));
    assert!(store.have(id));
    assert_eq!(store.locate(id).as_deref(), Some(path.as_path()));
    assert!(!store.have(XetHash::hash(b"something else")));

    let verified = store
        .open_verified(id, content.len() as u64)
        .expect("verify the substituter hit")
        .expect("the content is local");
    assert_eq!(verified.id(), id);
    assert_eq!(verified.len(), content.len() as u64);
    assert!(!verified.is_empty());
    let mut file = verified.into_file();
    let mut read = Vec::new();
    file.read_to_end(&mut read)
        .expect("read verified descriptor");
    assert_eq!(read, content);
    // Windows keeps no fastresume records (see `fastresume`); there the
    // content is proven by hashing instead of by a remembered identity.
    if hellas_store::fastresume::FileIdentity::REMEMBERS {
        assert_eq!(
            store.records().remembered(),
            1,
            "a substituter's answer must be indexed before it is lent",
        );
    }
}

/// Opening an entry the store already indexed is an identity check, not a
/// second content hash.
#[test]
fn opening_unchanged_indexed_content_does_not_rehash_it() {
    let fixture = Fixture::new("open-without-rehash");
    let content = bytes(200_000, 41);
    let path = fixture.write("weights.bin", &content);
    let store = ContentStore::new();
    let indexed = store.index(&path).expect("index");

    // Emptying fast-resume makes an accidental call back through `index`
    // observable: it would hash the file and repopulate this table.
    store.records().force_recheck();
    assert_eq!(store.records().remembered(), 0);
    let verified = store
        .open_verified(indexed.id, indexed.len)
        .expect("open")
        .expect("indexed content");

    assert_eq!(verified.id(), indexed.id);
    assert_eq!(store.records().remembered(), 0, "must not hash again");
}

/// Length is part of the lending contract, even when the id itself is known.
#[test]
fn opening_verified_content_refuses_the_wrong_length() {
    let fixture = Fixture::new("wrong-open-length");
    let content = bytes(20_000, 42);
    let path = fixture.write("weights.bin", &content);
    let store = ContentStore::new();
    let indexed = store.index(&path).expect("index");

    assert!(matches!(
        store.open_verified(indexed.id, indexed.len + 1),
        Err(StoreError::WrongLength {
            expected,
            actual,
            ..
        }) if expected == indexed.len + 1 && actual == indexed.len
    ));
}

/// Content-addressed metadata has no redundant declared length, but its
/// decoder's allocation budget must be enforced before bytes are read.
#[test]
fn opening_verified_content_with_a_bound_refuses_oversize_files() {
    let fixture = Fixture::new("bounded-open");
    let content = bytes(20_000, 43);
    let path = fixture.write("environment.cbor", &content);
    let store = ContentStore::new();
    let indexed = store.index(&path).expect("index");

    let verified = store
        .open_verified_bounded(indexed.id, indexed.len)
        .expect("open at the bound")
        .expect("indexed content");
    assert_eq!(verified.len(), indexed.len);

    assert!(matches!(
        store.open_verified_bounded(indexed.id, indexed.len - 1),
        Err(StoreError::TooLarge {
            maximum,
            actual,
            ..
        }) if maximum == indexed.len - 1 && actual == indexed.len
    ));
}

/// A substituter supplies a candidate path, never evidence that the bytes at
/// that path have the id it claimed.
#[test]
fn opening_verified_content_refuses_a_lying_substituter() {
    struct Lying(XetHash, PathBuf);
    impl Substituter for Lying {
        fn name(&self) -> &str {
            "lying"
        }
        fn locate(&self, id: XetHash) -> Option<PathBuf> {
            (id == self.0).then(|| self.1.clone())
        }
    }

    let fixture = Fixture::new("lying-open-substituter");
    let wanted = XetHash::hash(b"the requested weights");
    let other = b"a different set of weights";
    let path = fixture.write("elsewhere.bin", other);
    let store = ContentStore::new().with_substituter(Arc::new(Lying(wanted, path)));

    assert!(matches!(
        store.open_verified(wanted, other.len() as u64),
        Err(StoreError::WrongContent { .. })
    ));
}

/// `have` must not claim content that has been deleted underneath it.
#[test]
fn have_is_false_once_the_file_is_gone() {
    let fixture = Fixture::new("vanish");
    let content = bytes(20_000, 50);
    let path = fixture.write("temporary.bin", &content);

    let store = ContentStore::new();
    let indexed = store.index(&path).expect("index");
    assert!(store.have(indexed.id));

    std::fs::remove_file(&path).expect("remove");
    assert!(
        !store.have(indexed.id),
        "an index entry is not evidence the bytes are still there",
    );
    assert_eq!(store.locate(indexed.id), None);
}

/// `have` must not claim content that was overwritten either. The file
/// is still there, the name is still there, and the bytes the id is
/// about are gone — which is the ordinary case, not the exotic one.
#[test]
fn have_is_false_once_the_file_is_rewritten() {
    let fixture = Fixture::new("rewrite");
    let content = bytes(20_000, 51);
    let path = fixture.write("shard.bin", &content);

    let store = ContentStore::new();
    let indexed = store.index(&path).expect("index");
    assert!(store.have(indexed.id));

    // Same name, same length, different bytes: nothing a check for
    // existence could ever notice.
    let replacement = bytes(20_000, 52);
    fixture.write("shard.bin", &replacement);
    assert!(path.exists());
    assert!(
        !store.have(indexed.id),
        "an index entry is a claim about bytes, not about a path",
    );

    // And the new bytes are findable under their own id.
    let reindexed = store.index(&path).expect("index again");
    assert_eq!(reindexed.id, XetHash::hash(&replacement));
    assert!(store.have(reindexed.id));
}

/// A substituter is another source's answer, and a source can be wrong.
/// `materialize(a)` must never return content `b`.
#[test]
fn materializing_refuses_a_source_that_answers_with_other_content() {
    struct Lying(XetHash, PathBuf);
    impl Substituter for Lying {
        fn name(&self) -> &str {
            "lying"
        }
        fn locate(&self, id: XetHash) -> Option<PathBuf> {
            (id == self.0).then(|| self.1.clone())
        }
    }

    struct Unreachable;
    impl hellas_store::Fetcher for Unreachable {
        fn name(&self) -> &str {
            "unreachable"
        }
        fn fetch(
            &self,
            _id: XetHash,
            _dest: &Path,
            _expected: Option<&[hellas_xet::Chunk]>,
        ) -> Result<u64, hellas_store::hf::FetchError> {
            panic!("a local answer must not be followed by a fetch");
        }
    }

    let fixture = Fixture::new("lying-substituter");
    let wanted = XetHash::hash(b"the content that was asked for");
    let elsewhere = fixture.write("elsewhere.bin", b"something else entirely");

    let store = ContentStore::new().with_substituter(Arc::new(Lying(wanted, elsewhere)));
    assert!(store.have(wanted), "the source claims to hold it");
    assert!(
        store
            .materialize(wanted, &fixture.0.join("dest.bin"), &Unreachable)
            .is_err(),
        "content that is not what was asked for must not be returned as if it were",
    );
}

/// Cleaning up after a failed fetch means cleaning up what we made
/// appear. A destination that was already there belongs to whoever put
/// it there.
#[test]
fn a_destination_that_was_already_there_is_not_deleted() {
    struct Liar;
    impl hellas_store::Fetcher for Liar {
        fn name(&self) -> &str {
            "liar"
        }
        fn fetch(
            &self,
            _id: XetHash,
            dest: &Path,
            _expected: Option<&[hellas_xet::Chunk]>,
        ) -> Result<u64, hellas_store::hf::FetchError> {
            std::fs::write(dest, b"not the content you asked for").expect("write");
            Ok(29)
        }
    }

    let fixture = Fixture::new("existing-dest");
    let dest = fixture.write("dest.bin", b"someone else's file");
    let store = ContentStore::new();

    assert!(
        store
            .materialize(XetHash::hash(b"the real content"), &dest, &Liar)
            .is_err(),
    );
    assert!(
        dest.exists(),
        "a file we did not create is not ours to delete"
    );
}

/// Empty content has a defined id and is not special-cased into
/// existence.
#[test]
fn empty_content_is_addressable() {
    let fixture = Fixture::new("empty");
    let path = fixture.write("empty.bin", b"");
    let store = ContentStore::new();
    let indexed = store.index(Path::new(&path)).expect("index");
    assert_eq!(indexed.id, XetHash::ZERO);
    assert_eq!(indexed.len, 0);
    assert!(indexed.chunks.is_empty());
}
