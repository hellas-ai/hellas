use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hellas_rpc::fetch::{
    FetchInput, FetchProtocolError, MAX_FETCH_OUTPUT_EVENTS, MAX_FETCH_OUTPUT_PAYLOAD_BYTES,
    MAX_FETCH_REQUEST_BODY_BYTES, verify_input_events, verify_output_events,
};
use hellas_rpc::{
    InputCommitment, InputEventEnvelope, OutputEventEnvelope, ProducerId, PublicKey,
    canonical_dag_cbor, decode_dag_cbor,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::{MAX_OUTSTANDING_QUOTES, QUOTE_TTL};

pub(crate) const MAX_FETCH_IN_MEMORY_TICKETS: usize = MAX_OUTSTANDING_QUOTES;
pub(crate) const MAX_FETCH_IN_MEMORY_INPUT_BYTES: usize = 32 * 1024 * 1024;
const FETCH_CAPACITY_LOCK_WAIT: Duration = Duration::from_millis(100);
const MAX_FETCH_CAPACITY_METADATA_BYTES: usize = 32;
/// Payload budgets plus one KiB of encoding/signature headroom per envelope.
const MAX_FETCH_TRANSCRIPT_BYTES: usize = MAX_FETCH_REQUEST_BODY_BYTES
    + MAX_FETCH_OUTPUT_PAYLOAD_BYTES
    + (MAX_FETCH_OUTPUT_EVENTS + 8) * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchTranscript {
    input_commitment: InputCommitment,
    input: Vec<InputEventEnvelope>,
    output: Vec<OutputEventEnvelope>,
}

/// A retained transcript whose input and output signatures, producer, and
/// caller policy have already been checked together.
#[derive(Debug)]
pub(crate) struct VerifiedFetchReplay {
    pub(crate) transcript: FetchTranscript,
    pub(crate) input: FetchInput,
}

impl FetchTranscript {
    pub fn new(
        input_commitment: InputCommitment,
        input: Vec<InputEventEnvelope>,
        output: Vec<OutputEventEnvelope>,
    ) -> Self {
        Self {
            input_commitment,
            input,
            output,
        }
    }

    pub const fn input_commitment(&self) -> InputCommitment {
        self.input_commitment
    }

    #[cfg(test)]
    pub fn output_events(&self) -> &[OutputEventEnvelope] {
        &self.output
    }

    pub fn into_output_events(self) -> Vec<OutputEventEnvelope> {
        self.output
    }

    /// The caller key claimed by persisted, not-yet-verified input bytes.
    ///
    /// This is safe only as a negative prefilter. Authorization still comes
    /// from [`Self::verify`], which proves that this key signed the complete
    /// fixed-shape input transcript.
    fn claimed_caller_key(&self) -> Option<&PublicKey> {
        self.input.first().map(|event| event.event().public_key())
    }

    pub fn from_quote(quote: &FetchQuote, output: Vec<OutputEventEnvelope>) -> Self {
        Self::new(quote.input_commitment, quote.input.clone(), output)
    }

    pub fn verify(&self, producer_key: &PublicKey) -> Result<FetchInput, FetchTranscriptError> {
        let input = verify_input_events(&self.input)?;
        if input.input_commitment != self.input_commitment {
            return Err(FetchTranscriptError::InputCommitmentMismatch);
        }
        let output = verify_output_events(input.input_commitment, input.assurance, &self.output)?;
        if output.producer_key != *producer_key {
            return Err(FetchTranscriptError::ProducerKeyMismatch);
        }
        Ok(input)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchQuote {
    pub input_commitment: InputCommitment,
    pub caller_key: PublicKey,
    pub assurance: hellas_rpc::Assurance,
    pub service: String,
    pub method: String,
    pub input: Vec<InputEventEnvelope>,
    pub retention: hellas_rpc::Retention,
}

impl FetchQuote {
    pub fn from_verified(verified: &FetchInput, input: Vec<InputEventEnvelope>) -> Self {
        Self {
            input_commitment: verified.input_commitment,
            caller_key: verified.caller_key,
            assurance: verified.assurance,
            service: verified.service.clone(),
            method: verified.method.clone(),
            input,
            retention: verified.retention,
        }
    }
}

/// An input transcript whose signatures and caller authorization were checked
/// by the state machine. Its fields are private so quote insertion cannot
/// accidentally accept a merely decoded `FetchInput` and skip either check.
pub(crate) struct VerifiedFetchQuoteInput {
    verified: FetchInput,
    input: Vec<InputEventEnvelope>,
}

impl VerifiedFetchQuoteInput {
    pub(crate) const fn input(&self) -> &FetchInput {
        &self.verified
    }
}

/// Operator-facing content of the running marker: enough to reconcile an
/// indeterminate run against the provider dashboard (route, caller, when,
/// and the idempotency key the provider saw) without external logs. The
/// input transcript is deliberately not included — it can be large, and the
/// idempotency key is the reconciliation handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchRunningRecord {
    pub service: String,
    pub method: String,
    /// Compressed secp256k1 caller public key, hex.
    pub caller_public_key: String,
    pub started_at_unix_ms: u64,
    /// hex(input transcript commitment); also the marker file name stem.
    pub idempotency_key: String,
}

impl FetchRunningRecord {
    fn from_quote(quote: &FetchQuote) -> Self {
        let started_at_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or_default();
        Self {
            service: quote.service.clone(),
            method: quote.method.clone(),
            caller_public_key: hex(quote.caller_key.bytes()),
            started_at_unix_ms,
            idempotency_key: quote.input_commitment.digest().to_string(),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FetchTicketEntry {
    quote: FetchQuote,
    expires_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FetchTicketState {
    Quoted(FetchTicketEntry),
    Queued(FetchTicketEntry),
    Running(FetchTicketEntry),
}

pub trait FetchTranscriptStore {
    fn put_completed(&self, transcript: &FetchTranscript) -> Result<(), FetchStoreError>;
    fn has_completed(&self, input: InputCommitment) -> Result<bool, FetchStoreError>;
    fn get_completed(
        &self,
        input: InputCommitment,
    ) -> Result<Option<FetchTranscript>, FetchStoreError>;
    #[cfg(test)]
    fn record_replay_verification(&self) {}
    /// Durably mark this input as having (possibly) reached the provider.
    /// Written before the provider call is issued; a marker without a
    /// completed transcript means the work is indeterminate after a crash
    /// and must not be re-run automatically.
    ///
    /// Acquisition is exclusive: if a marker already exists this fails with
    /// [`FetchStoreError::AlreadyExists`]. That makes the marker a mutual
    /// exclusion point for processes sharing a store — two nodes over the
    /// same filesystem root cannot both run the same ticket.
    fn put_running(
        &self,
        input: InputCommitment,
        record: &FetchRunningRecord,
    ) -> Result<(), FetchStoreError>;
    fn has_running(&self, input: InputCommitment) -> Result<bool, FetchStoreError>;
    fn remove_running(&self, input: InputCommitment) -> Result<(), FetchStoreError>;
}

#[derive(Debug)]
struct MemoryFetchTranscriptState {
    transcripts: HashMap<InputCommitment, FetchTranscript>,
    running: HashMap<InputCommitment, FetchRunningRecord>,
    max_retained_transcripts: usize,
}

impl MemoryFetchTranscriptState {
    fn retained_transcripts(&self) -> usize {
        self.transcripts.len().saturating_add(
            self.running
                .keys()
                .filter(|input| !self.transcripts.contains_key(input))
                .count(),
        )
    }
}

#[derive(Clone, Debug)]
pub struct MemoryFetchTranscriptStore {
    state: Arc<Mutex<MemoryFetchTranscriptState>>,
    #[cfg(test)]
    completed_loads: Arc<AtomicUsize>,
    #[cfg(test)]
    replay_verifications: Arc<AtomicUsize>,
    #[cfg(test)]
    running_removals: Arc<AtomicUsize>,
    #[cfg(test)]
    fail_running_put_after_write: Arc<AtomicBool>,
}

impl MemoryFetchTranscriptStore {
    pub fn with_capacity(max_retained_transcripts: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(MemoryFetchTranscriptState {
                transcripts: HashMap::new(),
                running: HashMap::new(),
                max_retained_transcripts,
            })),
            #[cfg(test)]
            completed_loads: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            replay_verifications: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            running_removals: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            fail_running_put_after_write: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(test)]
    pub(crate) fn completed_loads(&self) -> usize {
        self.completed_loads.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn replay_verifications(&self) -> usize {
        self.replay_verifications.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn running_removals(&self) -> usize {
        self.running_removals.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn fail_next_running_put_after_write(&self) {
        self.fail_running_put_after_write
            .store(true, Ordering::SeqCst);
    }
}

impl Default for MemoryFetchTranscriptStore {
    fn default() -> Self {
        Self::with_capacity(hellas_rpc::DEFAULT_FETCH_RETAINED_TRANSCRIPT_CAPACITY)
    }
}

impl FetchTranscriptStore for MemoryFetchTranscriptStore {
    fn put_completed(&self, transcript: &FetchTranscript) -> Result<(), FetchStoreError> {
        let mut state = self.state.lock().map_err(|_| FetchStoreError::Poisoned)?;
        match state.transcripts.get(&transcript.input_commitment()) {
            Some(existing) if existing == transcript => Ok(()),
            Some(_) => Err(FetchStoreError::Conflict {
                input: transcript.input_commitment(),
            }),
            None => {
                let input = transcript.input_commitment();
                if !state.running.contains_key(&input)
                    && state.retained_transcripts() >= state.max_retained_transcripts
                {
                    return Err(FetchStoreError::Capacity {
                        capacity: state.max_retained_transcripts,
                    });
                }
                state.transcripts.insert(input, transcript.clone());
                Ok(())
            }
        }
    }

    fn has_completed(&self, input: InputCommitment) -> Result<bool, FetchStoreError> {
        let state = self.state.lock().map_err(|_| FetchStoreError::Poisoned)?;
        Ok(state.transcripts.contains_key(&input))
    }

    fn get_completed(
        &self,
        input: InputCommitment,
    ) -> Result<Option<FetchTranscript>, FetchStoreError> {
        #[cfg(test)]
        self.completed_loads.fetch_add(1, Ordering::Relaxed);
        let state = self.state.lock().map_err(|_| FetchStoreError::Poisoned)?;
        Ok(state.transcripts.get(&input).cloned())
    }

    #[cfg(test)]
    fn record_replay_verification(&self) {
        self.replay_verifications.fetch_add(1, Ordering::Relaxed);
    }

    fn put_running(
        &self,
        input: InputCommitment,
        record: &FetchRunningRecord,
    ) -> Result<(), FetchStoreError> {
        let mut state = self.state.lock().map_err(|_| FetchStoreError::Poisoned)?;
        if state.transcripts.contains_key(&input) || state.running.contains_key(&input) {
            return Err(FetchStoreError::AlreadyExists);
        }
        if state.retained_transcripts() >= state.max_retained_transcripts {
            return Err(FetchStoreError::Capacity {
                capacity: state.max_retained_transcripts,
            });
        }
        state.running.insert(input, record.clone());
        #[cfg(test)]
        if self
            .fail_running_put_after_write
            .swap(false, Ordering::SeqCst)
        {
            return Err(FetchStoreError::Io(io::Error::other(
                "injected running-marker post-write failure",
            )));
        }
        Ok(())
    }

    fn has_running(&self, input: InputCommitment) -> Result<bool, FetchStoreError> {
        let state = self.state.lock().map_err(|_| FetchStoreError::Poisoned)?;
        Ok(state.running.contains_key(&input))
    }

    fn remove_running(&self, input: InputCommitment) -> Result<(), FetchStoreError> {
        let mut state = self.state.lock().map_err(|_| FetchStoreError::Poisoned)?;
        state.running.remove(&input);
        #[cfg(test)]
        self.running_removals.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum FetchTranscriptStoreBackend {
    Memory(MemoryFetchTranscriptStore),
    Fs(FsFetchTranscriptStore),
}

impl FetchTranscriptStoreBackend {
    pub fn memory() -> Self {
        Self::Memory(MemoryFetchTranscriptStore::default())
    }

    pub fn memory_with_capacity(max_retained_transcripts: usize) -> Self {
        Self::Memory(MemoryFetchTranscriptStore::with_capacity(
            max_retained_transcripts,
        ))
    }

    pub fn fs(root: impl Into<PathBuf>) -> Self {
        Self::Fs(FsFetchTranscriptStore::new(root))
    }

    pub fn fs_with_capacity(root: impl Into<PathBuf>, max_retained_transcripts: usize) -> Self {
        Self::Fs(FsFetchTranscriptStore::with_capacity(
            root,
            max_retained_transcripts,
        ))
    }

    pub fn init(&self) -> Result<(), FetchStoreError> {
        match self {
            Self::Memory(_) => Ok(()),
            Self::Fs(store) => {
                let store = store.clone();
                crate::private_fs::run_blocking_io(move || store.init())
                    .map_err(FetchStoreError::Io)?
            }
        }
    }
}

impl FetchTranscriptStore for FetchTranscriptStoreBackend {
    fn put_completed(&self, transcript: &FetchTranscript) -> Result<(), FetchStoreError> {
        match self {
            Self::Memory(store) => store.put_completed(transcript),
            Self::Fs(store) => {
                let store = store.clone();
                let transcript = transcript.clone();
                crate::private_fs::run_blocking_io(move || store.put_completed(&transcript))
                    .map_err(FetchStoreError::Io)?
            }
        }
    }

    fn has_completed(&self, input: InputCommitment) -> Result<bool, FetchStoreError> {
        match self {
            Self::Memory(store) => store.has_completed(input),
            Self::Fs(store) => {
                let store = store.clone();
                crate::private_fs::run_blocking_io(move || store.has_completed(input))
                    .map_err(FetchStoreError::Io)?
            }
        }
    }

    fn get_completed(
        &self,
        input: InputCommitment,
    ) -> Result<Option<FetchTranscript>, FetchStoreError> {
        match self {
            Self::Memory(store) => store.get_completed(input),
            Self::Fs(store) => {
                let store = store.clone();
                crate::private_fs::run_blocking_io(move || store.get_completed(input))
                    .map_err(FetchStoreError::Io)?
            }
        }
    }

    #[cfg(test)]
    fn record_replay_verification(&self) {
        match self {
            Self::Memory(store) => store.record_replay_verification(),
            Self::Fs(store) => store.record_replay_verification(),
        }
    }

    fn put_running(
        &self,
        input: InputCommitment,
        record: &FetchRunningRecord,
    ) -> Result<(), FetchStoreError> {
        match self {
            Self::Memory(store) => store.put_running(input, record),
            Self::Fs(store) => {
                let store = store.clone();
                let record = record.clone();
                crate::private_fs::run_blocking_io(move || store.put_running(input, &record))
                    .map_err(FetchStoreError::Io)?
            }
        }
    }

    fn has_running(&self, input: InputCommitment) -> Result<bool, FetchStoreError> {
        match self {
            Self::Memory(store) => store.has_running(input),
            Self::Fs(store) => {
                let store = store.clone();
                crate::private_fs::run_blocking_io(move || store.has_running(input))
                    .map_err(FetchStoreError::Io)?
            }
        }
    }

    fn remove_running(&self, input: InputCommitment) -> Result<(), FetchStoreError> {
        match self {
            Self::Memory(store) => store.remove_running(input),
            Self::Fs(store) => {
                let store = store.clone();
                crate::private_fs::run_blocking_io(move || store.remove_running(input))
                    .map_err(FetchStoreError::Io)?
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FetchCallerPolicy {
    trusted: HashMap<ProducerId, PublicKey>,
}

impl FetchCallerPolicy {
    pub fn new(trusted: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            trusted: trusted
                .into_iter()
                .map(|key| (ProducerId::from_public_key(&key), key))
                .collect(),
        }
    }

    pub fn is_authorized(&self, key: &PublicKey) -> bool {
        self.trusted
            .get(&ProducerId::from_public_key(key))
            .is_some_and(|trusted| trusted == key)
    }
}

#[derive(Debug, Clone)]
pub struct FsFetchTranscriptStore {
    root: PathBuf,
    max_retained_transcripts: usize,
}

impl FsFetchTranscriptStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_capacity(root, hellas_rpc::DEFAULT_FETCH_RETAINED_TRANSCRIPT_CAPACITY)
    }

    pub fn with_capacity(root: impl Into<PathBuf>, max_retained_transcripts: usize) -> Self {
        Self {
            root: root.into(),
            max_retained_transcripts,
        }
    }

    /// Create the store root and make its existence durable before any
    /// marker or transcript is written into it. Called once at executor
    /// startup so `put_running` only ever links into an already-durable
    /// directory.
    pub fn init(&self) -> Result<(), FetchStoreError> {
        crate::private_fs::create_private_dir_all(&self.root).map_err(FetchStoreError::Io)?;
        let _lock = self.capacity_lock()?;
        crate::private_fs::make_directory_private(&_lock).map_err(FetchStoreError::Io)?;
        self.ensure_capacity_metadata_locked()?;
        Ok(())
    }

    fn path(&self, input: InputCommitment) -> PathBuf {
        self.root.join(format!("{}.dagcbor", input.digest()))
    }

    fn running_path(&self, input: InputCommitment) -> PathBuf {
        self.root.join(format!("{}.running", input.digest()))
    }

    fn capacity_metadata_path(&self) -> PathBuf {
        self.root.join(".retained-transcript-capacity")
    }

    fn capacity_lock(&self) -> Result<fs::File, FetchStoreError> {
        // This advisory inode lock serializes cooperating stores that resolve
        // the same stable path. Later child access remains path-based, so the
        // root's ancestors must be trusted and must not be renamed or replaced;
        // same-user malicious code is outside this lock's protection.
        let directory =
            crate::private_fs::open_directory(&self.root).map_err(FetchStoreError::Io)?;
        let deadline = Instant::now() + FETCH_CAPACITY_LOCK_WAIT;
        loop {
            match directory.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(FetchStoreError::Io(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "timed out waiting for the fetch transcript capacity lock",
                    )));
                }
                Err(TryLockError::Error(error)) => return Err(FetchStoreError::Io(error)),
            }
        }
        Ok(directory)
    }

    fn ensure_capacity_metadata_locked(&self) -> Result<(), FetchStoreError> {
        // The limit is a property of the shared root, not of one process.
        // Persisting it makes a second process with a different CLI value fail
        // closed instead of racing the same evidence under another bound. An
        // operator may remove/change it only after stopping every sharer;
        // existing evidence is left untouched and may already exceed the new
        // value, in which case only new distinct retention is refused.
        let path = self.capacity_metadata_path();
        let expected = format!("{}\n", self.max_retained_transcripts);
        let bytes = match crate::private_fs::read_bounded_regular_file(
            &path,
            MAX_FETCH_CAPACITY_METADATA_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                match atomic_create_no_clobber(&path, expected.as_bytes()) {
                    Ok(()) => return Ok(()),
                    Err(FetchStoreError::AlreadyExists) => {
                        crate::private_fs::read_bounded_regular_file(
                            &path,
                            MAX_FETCH_CAPACITY_METADATA_BYTES,
                        )
                        .map_err(FetchStoreError::Io)?
                    }
                    Err(err) => return Err(err),
                }
            }
            Err(err) => return Err(FetchStoreError::Io(err)),
        };
        let persisted = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|value| value.strip_suffix('\n'))
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| {
                FetchStoreError::Decode(format!(
                    "invalid retained transcript capacity metadata at {}",
                    path.display()
                ))
            })?;
        if persisted == self.max_retained_transcripts {
            Ok(())
        } else {
            Err(FetchStoreError::CapacityConfiguration {
                configured: self.max_retained_transcripts,
                persisted,
                metadata_path: path,
                root: self.root.clone(),
            })
        }
    }

    fn retained_transcripts_locked(&self) -> Result<usize, FetchStoreError> {
        let mut commitments = HashSet::<OsString>::new();
        for entry in fs::read_dir(&self.root).map_err(FetchStoreError::Io)? {
            let path = entry.map_err(FetchStoreError::Io)?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "running" || extension == "dagcbor")
                && let Some(stem) = path.file_stem()
            {
                commitments.insert(stem.to_owned());
            }
        }
        Ok(commitments.len())
    }

    fn exists(path: &Path) -> Result<bool, FetchStoreError> {
        match fs::metadata(path) {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(FetchStoreError::Io(err)),
        }
    }

    fn check_capacity_locked(&self) -> Result<(), FetchStoreError> {
        if self.retained_transcripts_locked()? >= self.max_retained_transcripts {
            Err(FetchStoreError::Capacity {
                capacity: self.max_retained_transcripts,
            })
        } else {
            Ok(())
        }
    }
}

impl FetchTranscriptStore for FsFetchTranscriptStore {
    fn put_completed(&self, transcript: &FetchTranscript) -> Result<(), FetchStoreError> {
        let bytes = canonical_dag_cbor(transcript).map_err(|err| {
            FetchStoreError::Encode(format!("transcript DAG-CBOR encode failed: {err}"))
        })?;
        if bytes.len() > MAX_FETCH_TRANSCRIPT_BYTES {
            return Err(FetchStoreError::Encode(format!(
                "transcript DAG-CBOR is {} bytes, over the {MAX_FETCH_TRANSCRIPT_BYTES}-byte persistence limit",
                bytes.len()
            )));
        }
        let path = self.path(transcript.input_commitment());
        let _lock = self.capacity_lock()?;
        self.ensure_capacity_metadata_locked()?;
        if Self::exists(&path)? {
            let existing =
                crate::private_fs::read_bounded_regular_file(&path, MAX_FETCH_TRANSCRIPT_BYTES)
                    .map_err(FetchStoreError::Io)?;
            return if existing == bytes {
                Ok(())
            } else {
                Err(FetchStoreError::Conflict {
                    input: transcript.input_commitment(),
                })
            };
        }
        if !Self::exists(&self.running_path(transcript.input_commitment()))? {
            self.check_capacity_locked()?;
        }
        match atomic_create_no_clobber(&path, &bytes) {
            Ok(()) => Ok(()),
            Err(FetchStoreError::AlreadyExists) => {
                let existing =
                    crate::private_fs::read_bounded_regular_file(&path, MAX_FETCH_TRANSCRIPT_BYTES)
                        .map_err(FetchStoreError::Io)?;
                if existing == bytes {
                    Ok(())
                } else {
                    Err(FetchStoreError::Conflict {
                        input: transcript.input_commitment(),
                    })
                }
            }
            Err(err) => Err(err),
        }
    }

    fn has_completed(&self, input: InputCommitment) -> Result<bool, FetchStoreError> {
        Self::exists(&self.path(input))
    }

    fn get_completed(
        &self,
        input: InputCommitment,
    ) -> Result<Option<FetchTranscript>, FetchStoreError> {
        let path = self.path(input);
        let bytes =
            match crate::private_fs::read_bounded_regular_file(&path, MAX_FETCH_TRANSCRIPT_BYTES) {
                Ok(bytes) => bytes,
                Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(err) => return Err(FetchStoreError::Io(err)),
            };
        let transcript = decode_dag_cbor(&bytes).map_err(|err| {
            FetchStoreError::Decode(format!("transcript DAG-CBOR decode failed: {err}"))
        })?;
        Ok(Some(transcript))
    }

    fn put_running(
        &self,
        input: InputCommitment,
        record: &FetchRunningRecord,
    ) -> Result<(), FetchStoreError> {
        let bytes = serde_json::to_vec_pretty(record)
            .map_err(|err| FetchStoreError::Encode(format!("running record encode: {err}")))?;
        let _lock = self.capacity_lock()?;
        self.ensure_capacity_metadata_locked()?;
        if Self::exists(&self.running_path(input))? || Self::exists(&self.path(input))? {
            return Err(FetchStoreError::AlreadyExists);
        }
        self.check_capacity_locked()?;
        atomic_create_no_clobber(&self.running_path(input), &bytes)
    }

    fn has_running(&self, input: InputCommitment) -> Result<bool, FetchStoreError> {
        match fs::metadata(self.running_path(input)) {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(FetchStoreError::Io(err)),
        }
    }

    fn remove_running(&self, input: InputCommitment) -> Result<(), FetchStoreError> {
        let _lock = self.capacity_lock()?;
        self.ensure_capacity_metadata_locked()?;
        match fs::remove_file(self.running_path(input)) {
            Ok(()) => {
                #[cfg(unix)]
                hellas_private::sync_directory(&self.root).map_err(FetchStoreError::Io)?;
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                #[cfg(unix)]
                hellas_private::sync_directory(&self.root).map_err(FetchStoreError::Io)?;
                Ok(())
            }
            Err(err) => Err(FetchStoreError::Io(err)),
        }
    }
}

fn atomic_create_no_clobber(path: &Path, bytes: &[u8]) -> Result<(), FetchStoreError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("transcript");
    let tmp = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        Uuid::new_v4().simple()
    ));

    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(FetchStoreError::Io)?;
        file.write_all(bytes).map_err(FetchStoreError::Io)?;
        file.sync_all().map_err(FetchStoreError::Io)?;
        drop(file);

        match fs::hard_link(&tmp, path) {
            Ok(()) => {
                // The file contents are synced above; sync the directory so
                // the new link itself survives power loss, not just a
                // process crash. This matters for the running marker, which
                // is the only record that a paid provider call may exist.
                #[cfg(unix)]
                hellas_private::sync_directory(parent).map_err(FetchStoreError::Io)?;
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                Err(FetchStoreError::AlreadyExists)
            }
            Err(err) => Err(FetchStoreError::Io(err)),
        }
    })();

    let _ = fs::remove_file(&tmp);
    result
}

pub struct FetchStateMachine<S> {
    store: S,
    caller_policy: FetchCallerPolicy,
    tickets: HashMap<InputCommitment, FetchTicketState>,
    max_tickets: usize,
    max_input_bytes: usize,
}

impl<S> FetchStateMachine<S>
where
    S: FetchTranscriptStore,
{
    pub fn new(store: S, caller_policy: FetchCallerPolicy) -> Self {
        Self {
            store,
            caller_policy,
            tickets: HashMap::new(),
            max_tickets: MAX_FETCH_IN_MEMORY_TICKETS,
            max_input_bytes: MAX_FETCH_IN_MEMORY_INPUT_BYTES,
        }
    }

    #[cfg(test)]
    fn with_limits(
        store: S,
        caller_policy: FetchCallerPolicy,
        max_tickets: usize,
        max_input_bytes: usize,
    ) -> Self {
        Self {
            store,
            caller_policy,
            tickets: HashMap::new(),
            max_tickets,
            max_input_bytes,
        }
    }

    fn insert_quote(
        &mut self,
        quote: FetchQuote,
        expires_at: Instant,
    ) -> Result<(), FetchStateError> {
        let input = quote.input_commitment;
        if self.tickets.contains_key(&input) {
            return Err(FetchStateError::AlreadyExists);
        }
        if self.tickets.len() >= self.max_tickets {
            return Err(FetchStateError::TicketCapacity {
                capacity: self.max_tickets,
            });
        }
        let requested = self
            .in_memory_input_bytes()?
            .checked_add(accounted_input_bytes(&quote)?)
            .ok_or(FetchStateError::InputLengthOverflow)?;
        if requested > self.max_input_bytes {
            return Err(FetchStateError::InputCapacity {
                requested,
                capacity: self.max_input_bytes,
            });
        }
        self.tickets.insert(
            input,
            FetchTicketState::Quoted(FetchTicketEntry { quote, expires_at }),
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn quote_input(
        &mut self,
        input: Vec<InputEventEnvelope>,
    ) -> Result<(FetchQuote, FetchInput), FetchStateError> {
        self.quote_input_at(input, Instant::now())
    }

    #[cfg(test)]
    pub(crate) fn quote_input_at(
        &mut self,
        input: Vec<InputEventEnvelope>,
        now: Instant,
    ) -> Result<(FetchQuote, FetchInput), FetchStateError> {
        let authorized = self.verify_authorized_input(input)?;
        let verified = authorized.verified.clone();
        let quote = self.quote_verified_input_at(authorized, now)?;
        Ok((quote, verified))
    }

    pub(crate) fn verify_authorized_input(
        &self,
        input: Vec<InputEventEnvelope>,
    ) -> Result<VerifiedFetchQuoteInput, FetchStateError> {
        // Reject an unknown claimed key before spending eight signature
        // verifications. `verify_input_events` subsequently proves that this
        // key signed the exact fixed-shape transcript.
        if input
            .first()
            .is_some_and(|event| !self.caller_policy.is_authorized(event.event().public_key()))
        {
            return Err(FetchStateError::UnauthorizedCaller);
        }
        let verified = verify_input_events(&input)?;
        if !self.caller_policy.is_authorized(&verified.caller_key) {
            return Err(FetchStateError::UnauthorizedCaller);
        }
        Ok(VerifiedFetchQuoteInput { verified, input })
    }

    pub(crate) fn quote_verified_input_at(
        &mut self,
        authorized: VerifiedFetchQuoteInput,
        now: Instant,
    ) -> Result<FetchQuote, FetchStateError> {
        let VerifiedFetchQuoteInput { verified, input } = authorized;
        let quote = FetchQuote::from_verified(&verified, input);
        self.prune_expired_quotes(now);
        if quote.retention.should_retain() && self.store.has_completed(quote.input_commitment)? {
            return Ok(quote);
        }
        // A durable running marker without a completed transcript means a
        // previous process may have reached the paid provider before
        // crashing. Deny before quoting; an operator must resolve it.
        if quote.retention.should_retain() && self.store.has_running(quote.input_commitment)? {
            return Err(FetchStateError::Indeterminate);
        }
        self.insert_quote(quote.clone(), now + QUOTE_TTL)?;
        Ok(quote)
    }

    pub(crate) fn rollback_quote(&mut self, input: InputCommitment) -> bool {
        if matches!(self.tickets.get(&input), Some(FetchTicketState::Quoted(_))) {
            self.tickets.remove(&input);
            true
        } else {
            false
        }
    }

    fn prune_expired_quotes(&mut self, now: Instant) -> usize {
        let before = self.tickets.len();
        self.tickets.retain(
            |_, state| !matches!(state, FetchTicketState::Quoted(entry) if entry.expires_at <= now),
        );
        before - self.tickets.len()
    }

    fn in_memory_input_bytes(&self) -> Result<usize, FetchStateError> {
        self.tickets.values().try_fold(0_usize, |total, state| {
            let quote = match state {
                FetchTicketState::Quoted(entry)
                | FetchTicketState::Queued(entry)
                | FetchTicketState::Running(entry) => &entry.quote,
            };
            total
                .checked_add(accounted_input_bytes(quote)?)
                .ok_or(FetchStateError::InputLengthOverflow)
        })
    }

    pub fn queue(&mut self, input: InputCommitment) -> Result<FetchQuote, FetchStateError> {
        let retention = match self.tickets.get(&input) {
            Some(FetchTicketState::Quoted(entry))
            | Some(FetchTicketState::Queued(entry))
            | Some(FetchTicketState::Running(entry)) => entry.quote.retention,
            None => return Err(FetchStateError::NotFound),
        };
        if retention.should_retain() && self.store.has_completed(input)? {
            return Err(FetchStateError::AlreadyCompleted);
        }
        let state = self
            .tickets
            .get_mut(&input)
            .ok_or(FetchStateError::NotFound)?;
        match state {
            FetchTicketState::Quoted(entry) => {
                let entry = entry.clone();
                let quote = entry.quote.clone();
                *state = FetchTicketState::Queued(entry);
                Ok(quote)
            }
            FetchTicketState::Queued(_) => Err(FetchStateError::AlreadyQueued),
            FetchTicketState::Running(_) => Err(FetchStateError::AlreadyRunning),
        }
    }

    pub fn quoted(&self, input: InputCommitment) -> Result<FetchQuote, FetchStateError> {
        match self.tickets.get(&input) {
            Some(FetchTicketState::Quoted(entry)) => Ok(entry.quote.clone()),
            Some(FetchTicketState::Queued(_)) => Err(FetchStateError::AlreadyQueued),
            Some(FetchTicketState::Running(_)) => Err(FetchStateError::AlreadyRunning),
            None => Err(FetchStateError::NotFound),
        }
    }

    pub fn cancel_queued(&mut self, input: InputCommitment) -> Result<(), FetchStateError> {
        let state = self
            .tickets
            .get_mut(&input)
            .ok_or(FetchStateError::NotFound)?;
        match state {
            FetchTicketState::Queued(entry) => {
                *state = FetchTicketState::Quoted(entry.clone());
                Ok(())
            }
            FetchTicketState::Quoted(_) => Ok(()),
            FetchTicketState::Running(_) => Err(FetchStateError::AlreadyRunning),
        }
    }

    /// Drop a queued ticket after dispatch failed before any provider call.
    /// Unlike [`Self::cancel_queued`], this releases the in-memory ticket and
    /// its signed input because no caller remains attached to retry it.
    pub(crate) fn discard_queued(&mut self, input: InputCommitment) -> bool {
        if matches!(self.tickets.get(&input), Some(FetchTicketState::Queued(_))) {
            self.tickets.remove(&input);
            true
        } else {
            false
        }
    }

    pub fn start(&mut self, input: InputCommitment) -> Result<FetchQuote, FetchStateError> {
        let retention = match self.tickets.get(&input) {
            Some(FetchTicketState::Quoted(entry))
            | Some(FetchTicketState::Queued(entry))
            | Some(FetchTicketState::Running(entry)) => entry.quote.retention,
            None => return Err(FetchStateError::NotFound),
        };
        if retention.should_retain() && self.store.has_completed(input)? {
            return Err(FetchStateError::AlreadyCompleted);
        }
        let state = self
            .tickets
            .get_mut(&input)
            .ok_or(FetchStateError::NotFound)?;
        match state {
            FetchTicketState::Quoted(entry) | FetchTicketState::Queued(entry) => {
                let entry = entry.clone();
                let quote = entry.quote.clone();
                // Exclusive durable acquisition before the in-memory
                // transition: the provider can never be called without a
                // record that the call may have happened, and two processes
                // sharing a store cannot both win the same ticket.
                if quote.retention.should_retain() {
                    match self
                        .store
                        .put_running(input, &FetchRunningRecord::from_quote(&quote))
                    {
                        Ok(()) => {}
                        Err(FetchStoreError::AlreadyExists) => {
                            return Err(FetchStateError::Indeterminate);
                        }
                        Err(err) => {
                            if let Err(cleanup) = self.store.remove_running(input) {
                                return Err(FetchStateError::StartMarkerRollback {
                                    start: err.to_string(),
                                    cleanup: cleanup.to_string(),
                                });
                            }
                            return Err(err.into());
                        }
                    }
                }
                *state = FetchTicketState::Running(entry);
                Ok(quote)
            }
            FetchTicketState::Running(_) => Err(FetchStateError::AlreadyRunning),
        }
    }

    /// Roll back a successful [`Self::start`] before any provider task exists.
    ///
    /// Removing the durable marker comes first. If that fails, the Running
    /// ticket remains in memory and startup recovery can retry from the paired
    /// Pending quota entry; the caller must never invoke the provider.
    pub(crate) fn abort_before_dispatch(
        &mut self,
        input: InputCommitment,
    ) -> Result<(), FetchStateError> {
        let retention = match self.tickets.get(&input) {
            Some(FetchTicketState::Quoted(entry))
            | Some(FetchTicketState::Queued(entry))
            | Some(FetchTicketState::Running(entry)) => entry.quote.retention,
            None => {
                // The durable removal is idempotent. This lets a retry retire
                // an ambiguous acknowledgement without resurrecting a ticket.
                self.store.remove_running(input)?;
                return Ok(());
            }
        };
        if retention.should_retain() {
            self.store.remove_running(input)?;
        }
        self.tickets.remove(&input);
        Ok(())
    }

    pub fn complete_output(
        &mut self,
        input: InputCommitment,
        output: Vec<OutputEventEnvelope>,
        producer_key: &PublicKey,
    ) -> Result<FetchTranscript, FetchStateError> {
        let quote = match self.tickets.get(&input) {
            Some(FetchTicketState::Running(entry)) => entry.quote.clone(),
            Some(FetchTicketState::Quoted(_)) | Some(FetchTicketState::Queued(_)) => {
                return Err(FetchStateError::NotRunning);
            }
            None => return Err(FetchStateError::NotFound),
        };
        let transcript = FetchTranscript::from_quote(&quote, output);
        self.complete_transcript(transcript.clone(), producer_key)?;
        Ok(transcript)
    }

    fn complete_transcript(
        &mut self,
        transcript: FetchTranscript,
        producer_key: &PublicKey,
    ) -> Result<(), FetchStateError> {
        let input = transcript.input_commitment();
        let quote = match self.tickets.get(&input) {
            Some(FetchTicketState::Running(entry)) => &entry.quote,
            Some(FetchTicketState::Quoted(_)) | Some(FetchTicketState::Queued(_)) => {
                return Err(FetchStateError::NotRunning);
            }
            None => return Err(FetchStateError::NotFound),
        };
        if transcript.input != quote.input {
            return Err(FetchStateError::QuoteMismatch);
        }
        let verified = transcript.verify(producer_key)?;
        if verified.caller_key != quote.caller_key {
            return Err(FetchStateError::QuoteMismatch);
        }

        if quote.retention.should_retain() {
            self.store.put_completed(&transcript)?;
            // Hygiene only: every check consults the completed transcript
            // before the running marker, so a leftover marker cannot change
            // behavior.
            let _ = self.store.remove_running(input);
        }
        self.tickets.remove(&input);
        Ok(())
    }

    /// A retained running marker is deliberately kept on failure: the provider
    /// may have been reached and billed, so the only honest state for this
    /// input is indeterminate. Ephemeral work has no replay/crash barrier.
    pub fn fail(
        &mut self,
        input: InputCommitment,
        _reason: impl Into<String>,
    ) -> Result<(), FetchStateError> {
        if self.tickets.remove(&input).is_some() {
            Ok(())
        } else {
            Err(FetchStateError::NotFound)
        }
    }

    /// True when a durable running marker exists without a completed
    /// transcript: a previous process may have reached the provider before
    /// crashing, and the work must not be re-run automatically.
    pub fn is_indeterminate(&self, input: InputCommitment) -> Result<bool, FetchStateError> {
        if self.store.has_completed(input)? {
            return Ok(false);
        }
        Ok(self.store.has_running(input)?)
    }

    pub(crate) fn has_completed(&self, input: InputCommitment) -> Result<bool, FetchStateError> {
        Ok(self.store.has_completed(input)?)
    }

    pub fn replay_completed(
        &self,
        input: InputCommitment,
        producer_key: &PublicKey,
        runner_key: &PublicKey,
    ) -> Result<VerifiedFetchReplay, FetchStateError> {
        let transcript = match self.store.get_completed(input)? {
            Some(transcript) => transcript,
            None if self.tickets.contains_key(&input) => {
                return Err(FetchStateError::NotCompleted);
            }
            None => return Err(FetchStateError::NotFound),
        };
        if transcript.input_commitment() != input {
            return Err(FetchStateError::QuoteMismatch);
        }
        // Persisted transcript bytes are not trusted. Their claimed key can
        // cheaply reject the wrong run-ticket signer, but can never grant
        // access: a matching claim still pays for full signature verification
        // below before any replay is returned.
        if transcript
            .claimed_caller_key()
            .is_some_and(|claimed| claimed != runner_key)
        {
            return Err(FetchStateError::UnauthorizedRunner);
        }
        #[cfg(test)]
        self.store.record_replay_verification();
        let verified = transcript.verify(producer_key)?;
        if verified.caller_key != *runner_key {
            return Err(FetchStateError::UnauthorizedRunner);
        }
        if !self.caller_policy.is_authorized(&verified.caller_key) {
            return Err(FetchStateError::UnauthorizedCaller);
        }
        Ok(VerifiedFetchReplay {
            transcript,
            input: verified,
        })
    }
}

fn accounted_input_bytes(quote: &FetchQuote) -> Result<usize, FetchStateError> {
    let duplicated_route_bytes = quote
        .service
        .len()
        .checked_add(quote.method.len())
        .ok_or(FetchStateError::InputLengthOverflow)?;
    quote
        .input
        .iter()
        .try_fold(duplicated_route_bytes, |total, event| {
            total
                .checked_add(event.payload().len())
                .ok_or(FetchStateError::InputLengthOverflow)
        })
}

#[derive(Debug, thiserror::Error)]
pub enum FetchTranscriptError {
    #[error("stored input commitment does not match input transcript")]
    InputCommitmentMismatch,
    #[error("producer key does not match output transcript signer")]
    ProducerKeyMismatch,
    #[error("fetch protocol error: {0}")]
    Protocol(#[from] FetchProtocolError),
}

#[derive(Debug, thiserror::Error)]
pub enum FetchStateError {
    #[error("fetch ticket not found")]
    NotFound,
    #[error("fetch ticket already exists")]
    AlreadyExists,
    #[error("fetch ticket already queued")]
    AlreadyQueued,
    #[error("fetch ticket already running")]
    AlreadyRunning,
    #[error("fetch ticket is not running")]
    NotRunning,
    #[error(
        "fetch running-marker creation failed ({start}) and its pre-dispatch rollback also failed ({cleanup})"
    )]
    StartMarkerRollback { start: String, cleanup: String },
    #[error("fetch ticket is not completed")]
    NotCompleted,
    #[error("fetch ticket already completed")]
    AlreadyCompleted,
    #[error("fetch transcript does not match the stored quote")]
    QuoteMismatch,
    #[error(
        "fetch ticket is indeterminate: a previous run may have reached the provider before a crash; refusing to re-run automatically"
    )]
    Indeterminate,
    #[error("fetch in-memory ticket capacity of {capacity} is exhausted")]
    TicketCapacity { capacity: usize },
    #[error(
        "fetch in-memory signed-input payload would reach {requested} bytes, over the {capacity}-byte capacity"
    )]
    InputCapacity { requested: usize, capacity: usize },
    #[error("fetch signed-input payload length exceeds usize range")]
    InputLengthOverflow,
    #[error("fetch caller key is not authorized")]
    UnauthorizedCaller,
    #[error("run ticket signer is not authorized for this fetch transcript")]
    UnauthorizedRunner,
    #[error("fetch store error: {0}")]
    Store(#[from] FetchStoreError),
    #[error("fetch transcript verification failed: {0}")]
    Verify(#[from] FetchTranscriptError),
    #[error("fetch input verification failed: {0}")]
    Input(#[from] FetchProtocolError),
}

#[derive(Debug, thiserror::Error)]
pub enum FetchStoreError {
    #[error("fetch transcript already exists")]
    AlreadyExists,
    #[error("retained Fetch transcript capacity of {capacity} is exhausted")]
    Capacity { capacity: usize },
    #[error(
        "retained Fetch transcript capacity {configured} does not match persisted capacity {persisted} at {metadata_path}; stop every process sharing store root {root} before changing or removing that metadata (stored transcripts and running markers are never deleted)"
    )]
    CapacityConfiguration {
        configured: usize,
        persisted: usize,
        metadata_path: PathBuf,
        root: PathBuf,
    },
    #[error("conflicting completed transcript for input {input:?}")]
    Conflict { input: InputCommitment },
    #[error("I/O error: {0}")]
    Io(#[source] io::Error),
    #[error("encode error: {0}")]
    Encode(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("fetch transcript memory store lock is poisoned")]
    Poisoned,
}

#[cfg(test)]
mod tests;
