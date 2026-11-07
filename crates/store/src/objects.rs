use hellas_private::StoreLocation;
use std::fs;
use std::io::{Read, Write};

use crate::{ContentStore, Indexed};

/// Atomic publication shared by objects and their indexes. Callers serialize
/// index replacement; object publication uses a no-clobber hard link.
pub(crate) fn publish(path: &StoreLocation, bytes: &[u8], immutable: bool) -> std::io::Result<()> {
    let parent = path.parent().expect("store object has a parent");
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    path.durability().sync_file(temporary.as_file())?;
    if immutable {
        match fs::hard_link(temporary.path(), path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                sync_existing(path)?;
            }
            Err(error) => return Err(error),
        }
    } else {
        temporary.persist(path).map_err(|error| error.error)?;
    }
    #[cfg(unix)]
    path.durability().sync_directory(parent)?;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FAIL_EXISTING_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn sync_existing(path: &StoreLocation) -> std::io::Result<()> {
    if path.durability() == hellas_private::Durability::Power {
        let file = hellas_private::open_nofollow(path)?;
        #[cfg(test)]
        if FAIL_EXISTING_SYNC.with(|failure| failure.replace(false)) {
            return Err(std::io::Error::other(
                "injected existing object sync failure",
            ));
        }
        path.durability().sync_file(&file)?;
    }
    Ok(())
}

impl ContentStore {
    /// Copy an object into owned storage with bounded payload buffering. The complete copy
    /// is verified before its content-addressed name is published.
    /// A mutable source is never linked into owned storage.
    pub fn put_reader(
        &self,
        root: &StoreLocation,
        expected: hellas_xet::XetHash,
        expected_len: u64,
        mut source: impl Read,
    ) -> Result<Indexed, Box<dyn std::error::Error + Send + Sync>> {
        let directory = root.join("objects");
        root.durability().create_dir_all(&directory)?;
        let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
        let mut hash = hellas_xet::XetFileHasher::new();
        let mut total = 0u64;
        let mut buffer = [0; 64 * 1024];
        loop {
            let remaining = expected_len - total;
            let limit = remaining.saturating_add(1).min(buffer.len() as u64) as usize;
            let n = match source.read(&mut buffer[..limit]) {
                Ok(n) => n,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            if n == 0 {
                break;
            }
            if n as u64 > remaining {
                return Err("object exceeds its declared length".into());
            }
            temporary.write_all(&buffer[..n])?;
            hash.update(&buffer[..n]);
            total += n as u64;
        }
        if total != expected_len || hash.finalize() != expected {
            return Err("object does not match its declared identity".into());
        }
        root.durability().sync_file(temporary.as_file())?;
        let path = root.child("objects").child(expected.to_string());
        match fs::hard_link(temporary.path(), &path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                sync_existing(&path)?;
            }
            Err(error) => return Err(error.into()),
        }
        // Drop the temporary link before indexing: unlink changes the inode's
        // ctime, which is part of the verified-file cache identity.
        drop(temporary);
        #[cfg(unix)]
        {
            root.durability().sync_directory(&directory)?;
            root.durability().sync_directory(root)?;
        }
        let indexed = self.index(&path)?;
        if indexed.id != expected || indexed.len != expected_len {
            return Err("corrupt existing object".into());
        }
        Ok(indexed)
    }

    /// Add bytes to the owned object directory and index their Xet identity.
    /// Existing objects must still verify; they are never overwritten.
    pub fn put(
        &self,
        root: &StoreLocation,
        bytes: &[u8],
    ) -> Result<Indexed, Box<dyn std::error::Error + Send + Sync>> {
        let id = hellas_xet::XetHash::hash(bytes);
        let path = root.child("objects").child(id.to_string());
        publish(&path, bytes, true)?;
        let indexed = self.index(&path)?;
        if indexed.id != id {
            return Err(format!("corrupt existing object {id}").into());
        }
        #[cfg(unix)]
        root.durability().sync_directory(root)?;
        Ok(indexed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_private::StoreLocation;

    #[test]
    fn power_republication_flushes_existing_objects() {
        let directory = tempfile::tempdir().unwrap();
        let crash = StoreLocation::for_test(directory.path());
        let power = crash
            .clone()
            .with_durability(hellas_private::Durability::Power);
        let store = ContentStore::new();
        let bytes = b"published without a power flush";
        let indexed = store.put(&crash, bytes).unwrap();
        for reader in [false, true] {
            let publish = || {
                if reader {
                    store.put_reader(&power, indexed.id, bytes.len() as u64, &bytes[..])
                } else {
                    store.put(&power, bytes)
                }
            };
            FAIL_EXISTING_SYNC.with(|failure| failure.set(true));
            let result = publish();
            FAIL_EXISTING_SYNC.with(|failure| failure.set(false));
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("existing object sync failure")
            );
            publish().unwrap();
        }
    }

    #[test]
    fn reader_import_is_bounded_and_verifies_before_publication() {
        struct Bounded<'a> {
            bytes: &'a [u8],
            read: usize,
            interrupted: bool,
        }
        impl Read for Bounded<'_> {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                assert!(output.len() <= 64 * 1024);
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                let n = self.bytes.read(output)?;
                self.read += n;
                Ok(n)
            }
        }
        let root = tempfile::tempdir().unwrap();
        let store = ContentStore::new();
        let bytes = vec![17; 200_000];
        let id = hellas_xet::XetHash::hash(&bytes);
        for length in [bytes.len() as u64 - 10, bytes.len() as u64 + 1] {
            let mut source = Bounded {
                bytes: &bytes,
                read: 0,
                interrupted: false,
            };
            let location = StoreLocation::for_test(root.path());
            assert!(
                store
                    .put_reader(&location, id, length, &mut source)
                    .is_err()
            );
            assert!(source.read as u64 <= length + 1);
            assert!(!root.path().join("objects").join(id.to_string()).exists());
        }
        let wrong = hellas_xet::XetHash::hash(b"wrong");
        let location = StoreLocation::for_test(root.path());
        assert!(
            store
                .put_reader(&location, wrong, bytes.len() as u64, bytes.as_slice())
                .is_err()
        );
        assert!(!root.path().join("objects").join(wrong.to_string()).exists());
        let source = Bounded {
            bytes: &bytes,
            read: 0,
            interrupted: false,
        };
        let indexed = store
            .put_reader(&location, id, bytes.len() as u64, source)
            .unwrap();
        assert_eq!(indexed.id, id);
        let mut file = store
            .open_verified(id, bytes.len() as u64)
            .unwrap()
            .unwrap()
            .into_file();
        let mut actual = Vec::new();
        file.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, bytes);
    }

    #[test]
    fn reader_import_owns_a_copy_and_refuses_corrupt_existing_objects() {
        let root = tempfile::tempdir().unwrap();
        let store = ContentStore::new();
        let source_path = root.path().join("source");
        fs::write(&source_path, b"original").unwrap();
        let id = hellas_xet::XetHash::hash(b"original");
        let location = StoreLocation::for_test(root.path());
        store
            .put_reader(&location, id, 8, fs::File::open(&source_path).unwrap())
            .unwrap();
        fs::write(&source_path, b"modified").unwrap();
        let destination = root.path().join("objects").join(id.to_string());
        assert_eq!(fs::read(&destination).unwrap(), b"original");
        fs::write(&destination, b"corrupt!").unwrap();
        assert!(
            store
                .put_reader(&location, id, 8, &b"original"[..])
                .is_err()
        );
        assert_eq!(fs::read(&destination).unwrap(), b"corrupt!");
    }
}
