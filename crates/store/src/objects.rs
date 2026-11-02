use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use crate::{ContentStore, Indexed};

/// Atomic publication shared by objects and their indexes. Callers serialize
/// index replacement; object publication uses a no-clobber hard link.
pub(crate) fn publish(path: &Path, bytes: &[u8], immutable: bool) -> std::io::Result<()> {
    let parent = path.parent().expect("store object has a parent");
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    if immutable {
        match fs::hard_link(temporary.path(), path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    } else {
        temporary.persist(path).map_err(|error| error.error)?;
    }
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

impl ContentStore {
    /// Copy an object into owned storage with bounded payload buffering. The complete copy
    /// is verified and synced before its content-addressed name is published.
    /// A mutable source is never linked into owned storage.
    pub fn put_reader(
        &self,
        root: &Path,
        expected: hellas_xet::XetHash,
        expected_len: u64,
        mut source: impl Read,
    ) -> Result<Indexed, Box<dyn std::error::Error + Send + Sync>> {
        let directory = root.join("objects");
        hellas_private::create_dir_all_durable(&directory)?;
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
        temporary.as_file().sync_all()?;
        let path = directory.join(expected.to_string());
        match fs::hard_link(temporary.path(), &path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        // Drop the temporary link before indexing: unlink changes the inode's
        // ctime, which is part of the verified-file cache identity.
        drop(temporary);
        #[cfg(unix)]
        {
            fs::File::open(&directory)?.sync_all()?;
            fs::File::open(root)?.sync_all()?;
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
        root: &Path,
        bytes: &[u8],
    ) -> Result<Indexed, Box<dyn std::error::Error + Send + Sync>> {
        let id = hellas_xet::XetHash::hash(bytes);
        let path = root.join("objects").join(id.to_string());
        publish(&path, bytes, true)?;
        let indexed = self.index(&path)?;
        if indexed.id != id {
            return Err(format!("corrupt existing object {id}").into());
        }
        #[cfg(unix)]
        fs::File::open(root)?.sync_all()?;
        Ok(indexed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            assert!(
                store
                    .put_reader(root.path(), id, length, &mut source)
                    .is_err()
            );
            assert!(source.read as u64 <= length + 1);
            assert!(!root.path().join("objects").join(id.to_string()).exists());
        }
        let wrong = hellas_xet::XetHash::hash(b"wrong");
        assert!(
            store
                .put_reader(root.path(), wrong, bytes.len() as u64, bytes.as_slice())
                .is_err()
        );
        assert!(!root.path().join("objects").join(wrong.to_string()).exists());
        let source = Bounded {
            bytes: &bytes,
            read: 0,
            interrupted: false,
        };
        let indexed = store
            .put_reader(root.path(), id, bytes.len() as u64, source)
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
        store
            .put_reader(root.path(), id, 8, fs::File::open(&source_path).unwrap())
            .unwrap();
        fs::write(&source_path, b"modified").unwrap();
        let destination = root.path().join("objects").join(id.to_string());
        assert_eq!(fs::read(&destination).unwrap(), b"original");
        fs::write(&destination, b"corrupt!").unwrap();
        assert!(
            store
                .put_reader(root.path(), id, 8, &b"original"[..])
                .is_err()
        );
        assert_eq!(fs::read(&destination).unwrap(), b"corrupt!");
    }
}
