use super::*;
use std::fs::OpenOptions;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "hellas-store-binding-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn opened(path: &Path) -> (std::fs::File, fastresume::FileIdentity) {
    let file = std::fs::File::open(path).expect("open");
    let identity = fastresume::FileIdentity::of(&file.metadata().expect("fstat"));
    (file, identity)
}

/// Hashing is bounded by the descriptor length captured before the read.
/// Mutations are injected between real file reads, so growth is found by
/// the one-byte sentinel and truncation by an early EOF.
#[test]
fn mid_hash_growth_and_truncation_are_bounded_and_rejected() {
    use std::io::{Seek as _, SeekFrom, Write as _};

    enum Mutation {
        Grow,
        Truncate(u64),
    }

    struct MutatingFile {
        reader: std::fs::File,
        writer: std::fs::File,
        mutation: Option<Mutation>,
    }

    impl std::io::Read for MutatingFile {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let read = self.reader.read(buffer)?;
            if read != 0 {
                match self.mutation.take() {
                    Some(Mutation::Grow) => {
                        self.writer.seek(SeekFrom::End(0))?;
                        self.writer.write_all(b"growth after hashing began")?;
                        self.writer.flush()?;
                    }
                    Some(Mutation::Truncate(len)) => self.writer.set_len(len)?,
                    None => {}
                }
            }
            Ok(read)
        }
    }

    let dir = scratch("bounded-hash");
    let original = vec![0x5a; STREAM_BUFFER * 2 + 17];

    let grow_path = dir.join("grow");
    std::fs::write(&grow_path, &original).expect("write growing file");
    let grow_reader = open_regular_file(&grow_path).expect("open growing file");
    let grow_len = grow_reader.metadata().expect("metadata").len();
    let grow_writer = OpenOptions::new()
        .write(true)
        .open(&grow_path)
        .expect("open growth writer");
    let mut growing = MutatingFile {
        reader: grow_reader,
        writer: grow_writer,
        mutation: Some(Mutation::Grow),
    };
    assert!(
        hash_exact_length(&mut growing, grow_len)
            .expect("bounded growth read")
            .is_none(),
        "a byte beyond the captured length must reject growth",
    );

    let truncate_path = dir.join("truncate");
    std::fs::write(&truncate_path, &original).expect("write truncated file");
    let truncate_reader = open_regular_file(&truncate_path).expect("open truncated file");
    let truncate_len = truncate_reader.metadata().expect("metadata").len();
    let truncate_writer = OpenOptions::new()
        .write(true)
        .open(&truncate_path)
        .expect("open truncation writer");
    let mut truncating = MutatingFile {
        reader: truncate_reader,
        writer: truncate_writer,
        mutation: Some(Mutation::Truncate(STREAM_BUFFER as u64)),
    };
    assert!(
        hash_exact_length(&mut truncating, truncate_len)
            .expect("bounded truncation read")
            .is_none(),
        "EOF before the captured length must reject truncation",
    );

    let mut stable = std::io::Cursor::new(&original);
    let indexed = hash_exact_length(&mut stable, original.len() as u64)
        .expect("stable hash")
        .expect("stable length");
    assert_eq!(indexed.id, XetHash::hash(&original));
    assert_eq!(indexed.len, original.len() as u64);

    struct Endless {
        bytes_read: u64,
    }
    impl std::io::Read for Endless {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            buffer.fill(0xa5);
            self.bytes_read += buffer.len() as u64;
            Ok(buffer.len())
        }
    }
    let bounded_len = STREAM_BUFFER as u64 * 3 + 23;
    let mut endless = Endless { bytes_read: 0 };
    assert!(
        hash_exact_length(&mut endless, bounded_len)
            .expect("bounded endless read")
            .is_none(),
    );
    assert_eq!(
        endless.bytes_read,
        bounded_len + 1,
        "even a source that never reaches EOF gets one bounded prefix and one sentinel byte",
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The binding, asserted where it can be made to happen rather than
/// raced for: an id is about a descriptor, and recording it against a
/// name requires the name to still mean that descriptor.
#[test]
fn what_was_read_is_bound_to_the_name_it_is_recorded_against() {
    use std::io::Write as _;

    let dir = scratch("binding");
    let path = dir.join("shard.bin");
    std::fs::write(&path, b"the bytes that were read").expect("write");

    // Nothing moved.
    let (file, identity) = opened(&path);
    still_the_file_that_was_read(&path, identity, &file).expect("an untouched file");

    // Rewritten under the descriptor: the id would cover bytes that
    // were never on disk together.
    let (file, identity) = opened(&path);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("reopen")
        .write_all(b" and some more")
        .expect("append");
    assert!(matches!(
        still_the_file_that_was_read(&path, identity, &file),
        Err(StoreError::Raced { .. }),
    ));

    // Renamed over. On Linux the descriptor does see this — the
    // rename unlinks the old name, the link count changes, and that
    // moves the replaced inode's ctime — so it is refused by the
    // first check rather than the second. Either refusal will do;
    // resolving as content is what must not happen.
    let (file, identity) = opened(&path);
    let other = dir.join("other.bin");
    std::fs::write(&other, b"different bytes entirely").expect("write");
    std::fs::rename(&other, &path).expect("rename over");
    assert!(matches!(
        still_the_file_that_was_read(&path, identity, &file),
        Err(StoreError::Raced { .. } | StoreError::Replaced { .. }),
    ));

    // The case the descriptor genuinely cannot see, and the one a
    // HuggingFace cache is made of: the name is a symlink into
    // `blobs/`, and it is repointed at another blob. Nothing happens
    // to the file that was read — no write, no link count change —
    // so only stat-ing the *name* can tell.
    let blobs = dir.join("blobs");
    std::fs::create_dir_all(&blobs).expect("blobs");
    std::fs::write(blobs.join("a"), b"blob a").expect("blob a");
    std::fs::write(blobs.join("b"), b"blob b").expect("blob b");
    let link = dir.join("snapshot-shard.bin");
    std::os::unix::fs::symlink(blobs.join("a"), &link).expect("symlink");

    let (file, identity) = opened(&link);
    let swap = dir.join("swap");
    std::os::unix::fs::symlink(blobs.join("b"), &swap).expect("symlink");
    std::fs::rename(&swap, &link).expect("repoint the symlink");
    assert_eq!(
        fastresume::FileIdentity::of(&file.metadata().expect("fstat")),
        identity,
        "the descriptor must be untouched, or this case tests the wrong thing",
    );
    assert!(matches!(
        still_the_file_that_was_read(&link, identity, &file),
        Err(StoreError::Replaced { .. }),
    ));

    let _ = std::fs::remove_dir_all(&dir);
}

/// The path lookup and the descriptor open are deliberately separate in
/// `open_verified`; exercise both sides of that boundary without hoping to
/// win a scheduler race.
#[test]
fn a_path_replacement_cannot_change_the_inode_being_lent() {
    use std::io::Read as _;

    let dir = scratch("verified-open-replacement");
    let blobs = dir.join("blobs");
    std::fs::create_dir_all(&blobs).expect("blobs");
    let original = b"blob a";
    std::fs::write(blobs.join("a"), original).expect("blob a");
    std::fs::write(blobs.join("b"), b"blob b").expect("blob b");
    let link = dir.join("weights.bin");
    std::os::unix::fs::symlink(blobs.join("a"), &link).expect("symlink");

    let store = ContentStore::new();
    let indexed = store.index(&link).expect("index through link");
    let entry = store
        .index
        .read()
        .expect("index lock")
        .get(&indexed.id)
        .expect("entry")
        .clone();

    // This descriptor models replacement after `open`: repointing the
    // symlink does not and cannot retarget an already-open file.
    let opened_before_replacement = std::fs::File::open(&link).expect("open original");
    let swap = dir.join("swap");
    std::os::unix::fs::symlink(blobs.join("b"), &swap).expect("replacement link");
    std::fs::rename(&swap, &link).expect("replace link");

    let verified = verify_opened_indexed_file(
        indexed.id,
        LengthContract::Exact(indexed.len),
        &entry,
        opened_before_replacement,
    )
    .expect("verify open descriptor")
    .expect("the old inode is still verified");
    let mut file = verified.into_file();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("read old inode");
    assert_eq!(bytes, original);

    // This call models replacement between lookup and `open`: opening the
    // stale name reaches blob b, whose descriptor identity is refused.
    assert!(
        open_indexed_file(indexed.id, LengthContract::Exact(indexed.len), &entry)
            .expect("inspect replacement")
            .is_none(),
        "the replacement inode must not be lent under blob a's id",
    );
    assert!(
        store
            .open_verified(indexed.id, indexed.len)
            .expect("public open")
            .is_none(),
        "a stale index entry becomes a local miss",
    );

    let _ = std::fs::remove_dir_all(&dir);
}
