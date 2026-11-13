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

    /// The process's counters, at their one fixed place under `home`.
    pub fn in_home(home: &std::path::Path) -> Self {
        Self::new(home.join("apple-app-attest-open-counters"))
    }

    fn path(&self, public_key: &[u8; 33], suffix: &str) -> PathBuf {
        self.directory
            .join(format!("{}{suffix}", hex::encode(public_key)))
    }
    fn read(&self, public_key: &[u8; 33]) -> Result<u32, AttestationError> {
        match hellas_private::read_bounded_regular_file(&self.path(public_key, ".counter"), 4) {
            Ok(stored) => match stored.as_slice() {
                [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
                _ => Err(AttestationError::State),
            },
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(0),
            Err(_) => Err(AttestationError::State),
        }
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
        let previous = self.read(public_key)?;
        if counter <= previous {
            return Err(AttestationError::Counter);
        }

        hellas_private::write_atomically(&path, ".writing", &counter.to_be_bytes())
            .map_err(|_| AttestationError::State)
    }
}

/// Quote authentication checks durable high-water marks without changing them.
/// A committed candidate publishes its advances before exposing its backends.
pub(crate) struct PreparedCounters {
    store: FilesystemAssertionCounterStore,
    pending: std::sync::Mutex<Option<std::collections::BTreeMap<[u8; 33], u32>>>,
}
impl PreparedCounters {
    pub fn new(home: &std::path::Path) -> Self {
        Self {
            store: FilesystemAssertionCounterStore::in_home(home),
            pending: std::sync::Mutex::new(Some(Default::default())),
        }
    }
    pub fn activate(&self) -> Result<(), AttestationError> {
        let mut pending = self.pending.lock().map_err(|_| AttestationError::State)?;
        if let Some(advances) = pending.as_ref() {
            for (key, counter) in advances {
                self.store.advance(key, *counter)?;
            }
        }
        *pending = None;
        Ok(())
    }
}
impl AssertionCounterStore for PreparedCounters {
    fn advance(&self, key: &[u8; 33], counter: u32) -> Result<(), AttestationError> {
        let mut pending = self.pending.lock().map_err(|_| AttestationError::State)?;
        let Some(advances) = pending.as_mut() else {
            return self.store.advance(key, counter);
        };
        let previous = self
            .store
            .read(key)?
            .max(advances.get(key).copied().unwrap_or(0));
        if counter <= previous {
            return Err(AttestationError::Counter);
        }
        advances.insert(*key, counter);
        Ok(())
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
    fn prepared_counters_write_only_after_activation_and_keep_replay_checks() {
        let root = tempfile::tempdir().unwrap();
        let key = [9; 33];
        let staged = PreparedCounters::new(root.path());
        staged.advance(&key, 1).unwrap();
        assert!(std::fs::read_dir(root.path()).unwrap().next().is_none());
        drop(staged);
        let staged = PreparedCounters::new(root.path());
        staged.advance(&key, 1).unwrap();
        assert_eq!(staged.advance(&key, 1), Err(AttestationError::Counter));
        staged.activate().unwrap();
        let durable = FilesystemAssertionCounterStore::in_home(root.path());
        assert_eq!(durable.advance(&key, 1), Err(AttestationError::Counter));
        staged.advance(&key, 2).unwrap();
        assert_eq!(durable.advance(&key, 2), Err(AttestationError::Counter));
        let competing = PreparedCounters::new(root.path());
        competing.advance(&key, 3).unwrap();
        durable.advance(&key, 3).unwrap();
        assert_eq!(competing.activate(), Err(AttestationError::Counter));
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
