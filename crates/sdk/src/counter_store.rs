use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use hellas_attestation::{AssertionCounterStore, AttestationError};

/// Filesystem-backed assertion-counter high-water marks for native clients.
/// Each producer key has one locked, atomically replaced counter file.
#[derive(Clone, Debug)]
pub struct FilesystemAssertionCounterStore {
    directory: PathBuf,
}

impl FilesystemAssertionCounterStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn path(&self, public_key: &[u8; 33], suffix: &str) -> PathBuf {
        self.directory
            .join(format!("{}{suffix}", hex::encode(public_key)))
    }
}

impl AssertionCounterStore for FilesystemAssertionCounterStore {
    fn advance(&self, public_key: &[u8; 33], counter: u32) -> Result<(), AttestationError> {
        hellas_private::create_dir_all_durable(&self.directory)
            .map_err(|_| AttestationError::State)?;
        hellas_private::restrict_directory(&self.directory).map_err(|_| AttestationError::State)?;
        let path = self.path(public_key, ".counter");
        let lock = hellas_private::open_lock_beside(&path).map_err(|_| AttestationError::State)?;
        fs::File::lock(&lock).map_err(|_| AttestationError::State)?;
        let previous = match hellas_private::read_bounded_regular_file(&path, 4) {
            Ok(stored) => match stored.as_slice() {
                [a, b, c, d] => u32::from_be_bytes([*a, *b, *c, *d]),
                _ => return Err(AttestationError::State),
            },
            Err(error) if error.kind() == ErrorKind::NotFound => 0,
            Err(_) => return Err(AttestationError::State),
        };
        if counter <= previous {
            return Err(AttestationError::Counter);
        }

        hellas_private::write_atomically(&path, ".writing", &counter.to_be_bytes())
            .map_err(|_| AttestationError::State)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_a_strict_counter_high_water_mark() {
        let directory = tempfile::tempdir().unwrap();
        let counters = FilesystemAssertionCounterStore::new(directory.path().join("counters"));
        let key = [7_u8; 33];

        counters.advance(&key, 1).unwrap();
        assert_eq!(counters.advance(&key, 1), Err(AttestationError::Counter));
        assert_eq!(counters.advance(&key, 0), Err(AttestationError::Counter));
        counters.advance(&key, 2).unwrap();

        let reopened = FilesystemAssertionCounterStore::new(directory.path().join("counters"));
        assert_eq!(reopened.advance(&key, 2), Err(AttestationError::Counter));
        reopened.advance(&key, 3).unwrap();
    }
    #[test]
    fn corruption_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let counters = FilesystemAssertionCounterStore::new(directory.path());
        let key = [8; 33];
        fs::write(counters.path(&key, ".counter"), [0, 1]).unwrap();
        assert_eq!(counters.advance(&key, 3), Err(AttestationError::State));
    }
}
