//! Append-only, fsynced journal with exclusive ownership and crash recovery.
//!
//! A torn final frame is truncated; a complete corrupt frame fails closed.
//! Rotation installs a checkpointed successor before retiring its predecessor.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use hellas_xet::XetFileHasher;

use hellas_rpc::observe::{LEVEL, TARGET, Timing};
use hellas_rpc::protocol::Digest;

use super::hex;

/// First bytes of every journal file.
const MAGIC: &[u8] = b"hellas.work-journal.v1";
/// Version 6 stores explicit work IDs and active/completed job collections.
/// Older versions omit required recovery markers, contest responses, journal
/// generations, or job IDs. They are rejected rather than migrated.
const FORMAT_VERSION: u8 = 6;
/// Domain of the header digest every frame is bound to.
const HEADER_DOMAIN: &[u8] = b"hellas.work.journal-header.v1";
/// Domain of one frame's digest.
const FRAME_DOMAIN: &[u8] = b"hellas.work.journal-frame.v1";

/// Bytes the fixed header occupies.
const HEADER_SIZE: usize = MAGIC.len() + 3 + 8 + 32;

/// Bytes a frame spends on its length prefix and trailing digest.
const FRAME_OVERHEAD: usize = 4 + Digest::LEN;

/// Largest record this journal will write or read back.
///
/// The widest record is one job proposal: an authorization, a
/// signature, and the whole prepared-input bundle the provider must
/// still be able to execute after a restart. The demonstration profile
/// bounds that bundle at a megabyte through
/// `max_encoded_quote_response`, and that bound is checked where the
/// profile is known. This is the coarser bound of the two: the length
/// past which a length field is more likely to be corruption than a
/// record.
pub const MAX_RECORD_BYTES: usize = 4 << 20;

/// Largest one active generation of a journal may grow.
///
/// Hard: [`Journal::append`] refuses past it rather than growing, and
/// the refusal is not a poisoning, because nothing was written.
pub const MAX_ACTIVE_JOURNAL_BYTES: u64 = 64 << 20;

/// Most frames one active generation of a journal may hold.
pub const MAX_ACTIVE_FRAMES: u64 = 4096;

/// Bytes of [`MAX_ACTIVE_JOURNAL_BYTES`] kept back for a duty already
/// under way.
///
/// The reserve is what an endpoint finishes an *already-exported* duty
/// into when a rotation cannot complete. It is not headroom for new
/// work: new work stops at the soft limit, and this is the room the
/// close, the answer, and the cursor advances that follow an exported
/// signature still have.
pub const DUTY_RESERVE_BYTES: u64 = 16 << 20;

/// Frames of [`MAX_ACTIVE_FRAMES`] kept back for the same reason.
pub const DUTY_RESERVE_FRAMES: u64 = 16;

/// Largest checkpoint a rotation may write.
///
/// The same number as [`MAX_RECORD_BYTES`], because a checkpoint is one
/// frame and a frame is bounded by that. It is spelled separately
/// because it bounds something else: the *state* an endpoint may reach,
/// which is why it is checked before a signature is exported rather than
/// only when a rotation is attempted.
pub const MAX_CHECKPOINT_BYTES: usize = MAX_RECORD_BYTES;

/// Which of the two journals a file is.
///
/// In the header, so a channel journal handed to the setup reader — or
/// to the counterparty ledger — fails to open rather than replaying as
/// an empty state of the wrong kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalKind {
    /// The two-Open handshake and its recovery state.
    Setup,
    /// One channel's job, credit, and certificate.
    Channel,
    /// Provider accounting whose request and response bodies never reach disk.
    /// A different kind prevents reopening a payload-bearing journal as ZDR.
    MetadataChannel,
}

impl JournalKind {
    const fn code(self) -> u8 {
        match self {
            Self::Setup => 1,
            Self::Channel => 2,
            Self::MetadataChannel => 3,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Setup),
            2 => Some(Self::Channel),
            3 => Some(Self::MetadataChannel),
            _ => None,
        }
    }
}

/// Which side of the channel this endpoint is.
///
/// The two endpoints share these transition rules and share nothing
/// else. It is in the header because the rules differ by role — only a
/// provider submits the opens, only a client consumes proposal nonces —
/// and a store replayed under the wrong role would apply the wrong ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The party that funds the payment edge and signs certificates.
    Client,
    /// The party that stakes the bond, executes, and is paid.
    Provider,
}

impl Role {
    const fn code(self) -> u8 {
        match self {
            Self::Client => 1,
            Self::Provider => 2,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Client),
            2 => Some(Self::Provider),
            _ => None,
        }
    }
}

/// What a journal file is about: its kind, its role, and the 32-byte key
/// of the thing it records.
///
/// The key is a commitment supplied by the caller — a channel id, or a
/// hash over the network and an edge or a counterparty key. Every frame
/// digest binds it, so a journal cannot be opened as, or grafted onto,
/// another one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalId {
    /// Which journal this is.
    pub kind: JournalKind,
    /// Which side of the channel wrote it.
    pub role: Role,
    /// What it is about.
    pub key: [u8; 32],
    /// Which file of the rotated sequence this is.
    ///
    /// In the header, and so in every frame digest, because rotation
    /// makes two files of one journal: without it a predecessor's frames
    /// verify unchanged at the same sequences of its successor, and a
    /// generation restored behind the writer's back opens as the live
    /// one. Generation zero is the file a journal starts at and the only
    /// one that holds no checkpoint.
    pub generation: u64,
}

impl JournalId {
    /// Returns the same journal at another generation.
    #[must_use]
    pub const fn at(self, generation: u64) -> Self {
        Self { generation, ..self }
    }

    fn header_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE);
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.push(self.kind.code());
        out.push(self.role.code());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.key);
        debug_assert_eq!(out.len(), HEADER_SIZE);
        out
    }

    fn digest(&self) -> Digest {
        let mut hasher = XetFileHasher::new();
        hasher.update(HEADER_DOMAIN);
        hasher.update(&self.header_bytes());
        hasher.finalize()
    }
}

/// Why a journal is not usable.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The file could not be created, read, written, or synced.
    #[error("journal i/o failed: {0}")]
    Io(#[from] std::io::Error),
    /// Another process holds this journal.
    #[error("another process holds the journal at {path}")]
    Locked {
        /// File that is already locked.
        path: PathBuf,
    },
    /// The file is a recognized journal envelope whose recovery contract has
    /// been retired.
    #[error("journal format {found} is retired; expected {expected}: {retirement}")]
    OldVersion {
        /// Version byte found after the journal magic.
        found: u8,
        /// Version this binary writes and reads.
        expected: u8,
        /// Operator-facing reason this version cannot be migrated safely.
        retirement: &'static str,
    },
    /// The file does not begin with a header this binary writes at all,
    /// so there is no kind, role or key in it to name.
    ///
    /// Distinct from [`Self::HeaderMismatch`], which is a journal that
    /// is somebody else's: this one is not a journal.
    #[error("the file at {path} does not begin with a journal header")]
    NotAJournal {
        /// File that was read.
        path: PathBuf,
    },
    /// The file exists and is not a journal of this kind, role, and key.
    #[error("the file at {path} is not this endpoint's {kind:?} journal")]
    HeaderMismatch {
        /// File that was opened.
        path: PathBuf,
        /// Kind that was expected.
        kind: JournalKind,
    },
    /// A complete frame did not verify. The file is not the file this
    /// endpoint wrote, and no earlier state is reconstructed from it.
    #[error("journal frame {seq} does not verify; the journal is corrupt")]
    Corrupt {
        /// Position of the first frame that failed.
        seq: u64,
    },
    /// A record was larger than [`MAX_RECORD_BYTES`].
    #[error("journal record of {len} bytes exceeds the {MAX_RECORD_BYTES}-byte maximum")]
    RecordTooLarge {
        /// Length the record claimed.
        len: usize,
    },
    /// An earlier append failed, so what this file holds is unknown to
    /// this handle. Reopening is the only way to find out.
    #[error("an earlier append failed; this journal must be reopened before it is written again")]
    Poisoned,
    /// The file's name carries one generation and its header another.
    ///
    /// A journal file is named by the generation it is, so the two are
    /// two copies of one fact and a disagreement between them is a file
    /// somebody moved. Refused rather than believed either way.
    #[error("the file at {path} is named generation {named} and its header says {header}")]
    GenerationMismatch {
        /// File that was opened.
        path: PathBuf,
        /// Generation the file name carries.
        named: u64,
        /// Generation the header carries.
        header: u64,
    },
    /// A generation after the first holds no checkpoint.
    ///
    /// Every successor's first frame is the state its predecessor
    /// reached. A successor without one is an install that did not
    /// finish, and nothing in it can be replayed from.
    #[error("the journal at {path} is a successor with no checkpoint frame")]
    MissingCheckpoint {
        /// File that was opened.
        path: PathBuf,
    },
    /// The state to be checkpointed is wider than one checkpoint frame.
    ///
    /// The endpoint cannot rotate, so it cannot bound the file it is
    /// writing. Reported before a signature is exported over such a
    /// state, and again if a rotation is attempted anyway.
    #[error("a checkpoint of {len} bytes exceeds the {MAX_CHECKPOINT_BYTES}-byte maximum")]
    CheckpointTooLarge {
        /// Bytes the checkpoint would occupy.
        len: usize,
    },
    /// The active generation is full, reserve included.
    ///
    /// Nothing was written, so the journal is not poisoned — but this
    /// generation takes no more, and only a rotation moves it on.
    #[error("the journal holds {frames} frames in {bytes} bytes and admits no more")]
    Full {
        /// Frames the active generation holds.
        frames: u64,
        /// Bytes it occupies.
        bytes: u64,
    },
}

/// What opening a journal found.
#[derive(Debug)]
pub struct Replay {
    /// The state the predecessor had reached, when this file is a
    /// successor.
    ///
    /// Present for every generation after the first and absent for the
    /// first, because it is that file's first frame. What is in it is
    /// this module's caller's business: the journal knows only that a
    /// successor begins with one and that replay starts from it rather
    /// than from any frame of a file that may already be gone.
    pub checkpoint: Option<Vec<u8>>,
    /// Every complete frame after the checkpoint, in the order it was
    /// appended.
    pub records: Vec<Vec<u8>>,
    /// Whether an interrupted write was removed to get here.
    ///
    /// True means the file ended inside an append — or inside the
    /// header — whose caller was never told it succeeded, and those
    /// bytes are gone. A clean shutdown does not produce it, which is
    /// why the stores carry it out to their callers rather than
    /// swallowing it.
    pub truncated_tail: bool,
}

/// One append-only fsynced file, exclusively held.
#[derive(Debug)]
pub struct Journal {
    file: File,
    path: PathBuf,
    directory: PathBuf,
    stem: String,
    id: JournalId,
    header: Digest,
    next_seq: u64,
    bytes: u64,
    poisoned: bool,
}

impl Journal {
    /// Opens or creates the journal at `path`, taking its exclusive
    /// lock and replaying it.
    ///
    /// The lock is taken before a single byte is interpreted, so two
    /// processes cannot both replay and then both act. It is
    /// non-blocking: a second opener is told the journal is held rather
    /// than waiting for a holder that may never let go.
    ///
    /// The path names one generation. [`Self::open_latest`] is what an
    /// endpoint that owns a journal calls: it finds which generation is
    /// live and finishes any install a crash interrupted, and this is
    /// the file underneath it.
    ///
    /// # Errors
    ///
    /// [`JournalError::Locked`] when another process holds it,
    /// [`JournalError::NotAJournal`] when the file name carries no
    /// generation, [`JournalError::GenerationMismatch`] when the name
    /// and the header disagree, [`JournalError::HeaderMismatch`] when
    /// the file is some other journal, [`JournalError::Corrupt`] when a
    /// complete frame does not verify,
    /// [`JournalError::MissingCheckpoint`] when a successor holds no
    /// first frame, and [`JournalError::Io`] for the filesystem.
    pub fn open(path: impl Into<PathBuf>, id: JournalId) -> Result<(Self, Replay), JournalError> {
        let path = path.into();
        let (directory, stem) = split_name(&path, id.generation)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(JournalError::Locked { path }),
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }

        let mut bytes = Vec::new();
        (&file).read_to_end(&mut bytes)?;
        let header = id.digest();
        let mut journal = Self {
            file,
            path,
            directory,
            stem,
            id,
            header,
            next_seq: 0,
            bytes: 0,
            poisoned: false,
        };

        if bytes.is_empty() {
            journal.write_header(&id)?;
            return journal.split_checkpoint(Vec::new(), false);
        }

        let expected = id.header_bytes();
        if !bytes.starts_with(&expected) {
            if bytes.starts_with(MAGIC)
                && bytes
                    .get(MAGIC.len())
                    .is_some_and(|found| *found < FORMAT_VERSION)
            {
                let found = bytes[MAGIC.len()];
                return Err(JournalError::OldVersion {
                    found,
                    expected: FORMAT_VERSION,
                    retirement: retirement(found),
                });
            }
            // A file that is a strict prefix of the header this journal
            // would write is the creation that was interrupted. No frame
            // can have been recorded under it — there is not even a
            // whole header yet — so it is written again rather than
            // refused as somebody else's file.
            if expected.starts_with(&bytes) {
                journal.file.set_len(0)?;
                journal.write_header(&id)?;
                return journal.split_checkpoint(Vec::new(), true);
            }
            return Err(JournalError::HeaderMismatch {
                path: journal.path,
                kind: id.kind,
            });
        }

        let (records, truncated_tail) = journal.replay(&bytes)?;
        journal.split_checkpoint(records, truncated_tail)
    }

    /// Takes the first frame of a successor as the state to replay from.
    ///
    /// One place, because "which frame is the checkpoint" is one fact:
    /// the first frame of every generation after the first, and no frame
    /// at all of the first. A successor that has none is an install that
    /// did not finish and is refused here rather than read as an empty
    /// journal — which is what it would look like to a reader that
    /// merely found no records.
    fn split_checkpoint(
        self,
        mut records: Vec<Vec<u8>>,
        truncated_tail: bool,
    ) -> Result<(Self, Replay), JournalError> {
        let checkpoint = if self.id.generation == 0 {
            None
        } else if records.is_empty() {
            return Err(JournalError::MissingCheckpoint { path: self.path });
        } else {
            Some(records.remove(0))
        };
        Ok((
            self,
            Replay {
                checkpoint,
                records,
                truncated_tail,
            },
        ))
    }

    /// Opens the live generation of the journal `stem` names under
    /// `directory`, and finishes any install a crash interrupted.
    ///
    /// Three rules, and they are the reading half of the install order.
    /// A candidate is ignored outright: it is a file whose writer was
    /// never told it existed. Of the installed generations the newest is
    /// the successor, and it is the one opened, because its first frame
    /// is everything the ones below it said. And every generation below
    /// the one opened is retired here, so the unlink a crash interrupted
    /// happens exactly once more rather than never.
    ///
    /// The one fallback is the newest successor that holds no checkpoint
    /// — an install that reached the rename with the frame not yet on
    /// the platter, which the `fsync` before that rename is what makes
    /// unreachable. It is a defence rather than an expectation: the
    /// predecessor is opened instead, and the incomplete successor is
    /// left for the next rotation to write over.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::open`] refuses about the generation it lands on,
    /// and [`JournalError::Io`] when the directory cannot be read.
    pub fn open_latest(
        directory: &Path,
        stem: &str,
        id: JournalId,
    ) -> Result<(Self, Replay), JournalError> {
        fs::create_dir_all(directory)?;
        let installed = installed_generations(directory, stem)?;
        let Some(&newest) = installed.last() else {
            return Self::open(generation_path(directory, stem, 0), id.at(0));
        };
        let (journal, replay) =
            match Self::open(generation_path(directory, stem, newest), id.at(newest)) {
                Err(JournalError::MissingCheckpoint { .. }) if newest > 0 => {
                    let below = *installed
                        .iter()
                        .rev()
                        .find(|generation| **generation < newest)
                        .unwrap_or(&0);
                    Self::open(generation_path(directory, stem, below), id.at(below))?
                }
                other => other?,
            };
        for generation in installed {
            if generation < journal.id.generation {
                retire(&generation_path(directory, stem, generation), directory)?;
            }
        }
        Ok((journal, replay))
    }

    fn write_header(&mut self, id: &JournalId) -> Result<(), JournalError> {
        self.file.write_all(&id.header_bytes())?;
        self.file.sync_all()?;
        self.bytes = HEADER_SIZE as u64;
        // The file's own bytes are durable above; this is what makes the
        // directory entry durable, so a crash cannot leave a channel
        // with a signature exported and no file to find it in.
        if let Some(parent) = self.path.parent() {
            hellas_private::sync_directory(parent)?;
        }
        Ok(())
    }

    /// Walks every frame, truncating one partial tail and refusing any
    /// complete frame that does not verify.
    fn replay(&mut self, bytes: &[u8]) -> Result<(Vec<Vec<u8>>, bool), JournalError> {
        let (records, truncated_tail, next_seq, offset) = walk(self.header, bytes)?;
        self.next_seq = next_seq;
        self.bytes = offset as u64;
        if truncated_tail {
            // The interrupted bytes are removed rather than left in
            // place: the next append must land where the next frame's
            // digest says it does, and a reader that skipped a partial
            // frame once would have to skip it identically forever.
            self.file.set_len(offset as u64)?;
            self.file.sync_all()?;
        }
        Ok((records, truncated_tail))
    }

    /// Reads what the file at `path` says it is, and what verifies in
    /// it, without taking it over.
    ///
    /// The header names the kind, the role and the key, so a reader that
    /// does not already know them can still be told. That is the whole
    /// reason this exists: [`Self::open`] can only be asked for a
    /// journal that is already named, and an endpoint enumerating the
    /// journals it owns has nobody to name them for it.
    ///
    /// Nothing is locked and nothing is written. A torn tail is left in
    /// the file and is merely absent from the records returned, because
    /// removing it is the writer's act and this is not the writer — the
    /// next [`Self::open`] does it, under the lock, exactly as it would
    /// have without this call.
    ///
    /// # Errors
    ///
    /// [`JournalError::NotAJournal`] when the file does not begin with a
    /// header this binary writes, [`JournalError::OldVersion`] for a
    /// retired one, [`JournalError::Corrupt`] when a complete frame does
    /// not verify, [`JournalError::RecordTooLarge`] for a frame longer
    /// than the ceiling, and [`JournalError::Io`] for the filesystem.
    pub fn inspect(path: &Path) -> Result<(JournalId, Replay), JournalError> {
        let bytes = fs::read(path)?;
        let id = read_id(path, &bytes)?;
        let (mut records, truncated_tail, _, _) = walk(id.digest(), &bytes)?;
        let checkpoint = if id.generation == 0 {
            None
        } else if records.is_empty() {
            return Err(JournalError::MissingCheckpoint {
                path: path.to_path_buf(),
            });
        } else {
            Some(records.remove(0))
        };
        Ok((
            id,
            Replay {
                checkpoint,
                records,
                truncated_tail,
            },
        ))
    }

    /// Returns which file of the rotated sequence this handle holds.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.id.generation
    }

    /// Returns how many bytes the active generation occupies.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Emits `restart_replay_ms_at_cap` for the open that produced this
    /// handle and the replay its caller then ran.
    ///
    /// The store calls it, not [`Self::open_latest`], because the
    /// quantity §4 divides by a block time is not the walk of a file: it
    /// is a process coming back and reaching the state it left, which is
    /// the walk plus the caller's own decode, signature checks and
    /// transitions. `timing` is therefore started before the open and
    /// finished after the last record has been applied.
    ///
    /// "At cap" is the probe's filter and not this seam's: a restart
    /// replays whatever the file happens to hold, so the sample carries
    /// the `frames` and `bytes` it actually walked and whoever is
    /// building a distribution decides which of them were full ones.
    pub fn observe_replay(&self, timing: Timing, records: usize) {
        if let Some(ms) = timing.ms() {
            tracing::event!(
                name: "restart_replay_ms_at_cap",
                target: TARGET,
                LEVEL,
                kind = ?self.id.kind,
                role = ?self.id.role,
                key = %hex(&self.id.key),
                generation = self.id.generation,
                frames = self.next_seq,
                bytes = self.bytes,
                records,
                ms,
            );
        }
    }

    /// Returns whether this generation has reached the point where the
    /// caller must rotate.
    ///
    /// The soft limit is the hard one less the duty reserve, in both
    /// frames and bytes. Past it the journal still takes records — that
    /// is what the reserve is — but a caller that keeps admitting new
    /// work past it is a caller that will run out of file in the middle
    /// of a duty.
    #[must_use]
    pub const fn at_soft_limit(&self) -> bool {
        self.next_seq >= MAX_ACTIVE_FRAMES.saturating_sub(DUTY_RESERVE_FRAMES)
            || self.bytes >= MAX_ACTIVE_JOURNAL_BYTES.saturating_sub(DUTY_RESERVE_BYTES)
    }

    /// Moves this journal on to its next generation, whose first frame
    /// is `checkpoint`.
    ///
    /// The three steps, in the one order that is recoverable at every
    /// point between them: the candidate is written and fsynced, then
    /// renamed with the directory fsynced after it, and only then is the
    /// predecessor unlinked and the directory fsynced again. A crash
    /// between any two of them leaves a journal [`Self::open_latest`]
    /// opens to the same state.
    ///
    /// This handle is the successor's on return, and it is unchanged on
    /// every failure before the rename: the caller may go on appending
    /// to the predecessor, which is what the duty reserve is for. A
    /// failure of the *last* step is reported and the successor is
    /// nonetheless installed and held — the predecessor it could not
    /// unlink is retired by the next open.
    ///
    /// # Errors
    ///
    /// [`JournalError::CheckpointTooLarge`] when the state does not fit
    /// one frame, [`JournalError::Poisoned`] when an earlier append
    /// failed, and [`JournalError::Io`] for any of the three steps.
    pub fn rotate(&mut self, checkpoint: &[u8]) -> Result<(), JournalError> {
        if self.poisoned {
            return Err(JournalError::Poisoned);
        }
        if checkpoint.len() > MAX_CHECKPOINT_BYTES {
            return Err(JournalError::CheckpointTooLarge {
                len: checkpoint.len(),
            });
        }
        let successor = self.id.at(self.id.generation.saturating_add(1));
        let candidate = candidate_path(&self.directory, &self.stem, successor.generation);
        let installed = generation_path(&self.directory, &self.stem, successor.generation);

        // `rotation_tail_ms`: the whole three-step install, candidate
        // fsync through the second directory fsync, because that is what
        // §4 puts in `Wresp` and `Wstart` — a duty that rotates waits for
        // all of it. A rotation that fails before the rename emits
        // nothing: no generation moved, so no rotation happened.
        let rotation = Timing::start();
        let retired_frames = self.next_seq;
        let retired_bytes = self.bytes;
        let (file, bytes) = write_candidate(&candidate, successor, checkpoint)?;
        install(&candidate, &installed, &self.directory)?;

        let retired = std::mem::replace(&mut self.path, installed);
        let predecessor = std::mem::replace(&mut self.file, file);
        self.id = successor;
        self.header = successor.digest();
        self.next_seq = 1;
        self.bytes = bytes;
        let outcome = retire(&retired, &self.directory);
        // Dropped after the unlink, not before: the lock this endpoint
        // holds on the predecessor is released when the descriptor
        // closes, and releasing it while the file still has a name is a
        // window in which a second process opens a journal this one has
        // already replaced.
        drop(predecessor);
        if let Some(ms) = rotation.ms() {
            tracing::event!(
                name: "rotation_tail_ms",
                target: TARGET,
                LEVEL,
                kind = ?self.id.kind,
                role = ?self.id.role,
                key = %hex(&self.id.key),
                generation = self.id.generation,
                frames = retired_frames,
                bytes = retired_bytes,
                checkpoint_bytes = checkpoint.len(),
                ms,
            );
        }
        outcome
    }

    /// Appends one record and returns only once it is on the disk.
    ///
    /// A write or a sync that fails poisons this handle: what the file
    /// holds afterwards is not something this process can describe, and
    /// a second append would be a guess about where the next frame
    /// starts and which sequence is free. Every later call is refused
    /// until the journal is reopened and the file is read again.
    ///
    /// A record refused for its *size* is not one of those. Nothing was
    /// written, so nothing is unknown, and the journal stays usable.
    ///
    /// # Errors
    ///
    /// [`JournalError::RecordTooLarge`] above [`MAX_RECORD_BYTES`],
    /// [`JournalError::Full`] when this generation has no room left even
    /// in the reserve, [`JournalError::Poisoned`] after any earlier
    /// append failed, and [`JournalError::Io`] when this write or its
    /// sync fails.
    pub fn append(&mut self, payload: &[u8]) -> Result<(), JournalError> {
        if self.poisoned {
            return Err(JournalError::Poisoned);
        }
        if payload.len() > MAX_RECORD_BYTES {
            return Err(JournalError::RecordTooLarge { len: payload.len() });
        }
        let Ok(len) = u32::try_from(payload.len()) else {
            return Err(JournalError::RecordTooLarge { len: payload.len() });
        };
        let frame_bytes = (FRAME_OVERHEAD + payload.len()) as u64;
        // Refused before the write, and not a poisoning: nothing was
        // written, so nothing about the file is unknown. What is over is
        // this *generation*, and only a rotation moves it on.
        if self.next_seq >= MAX_ACTIVE_FRAMES
            || self.bytes.saturating_add(frame_bytes) > MAX_ACTIVE_JOURNAL_BYTES
        {
            return Err(JournalError::Full {
                frames: self.next_seq,
                bytes: self.bytes,
            });
        }
        let digest = frame_digest(self.header, self.next_seq, payload);
        let mut frame = Vec::with_capacity(FRAME_OVERHEAD + payload.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(payload);
        frame.extend_from_slice(digest.as_bytes());
        // One `write_all` of the whole frame: the most an interrupted
        // *process* can leave behind is a short prefix of it, rather
        // than a length and a payload from two different calls.
        //
        // Poisoned before the failure is reported, so a caller cannot
        // answer an i/o error by offering the next record.
        self.write_frame(&frame).inspect_err(|_| {
            self.poisoned = true;
        })?;
        self.next_seq = self.next_seq.saturating_add(1);
        self.bytes = self.bytes.saturating_add(frame_bytes);
        Ok(())
    }

    fn write_frame(&mut self, frame: &[u8]) -> Result<(), JournalError> {
        self.file.write_all(frame)?;
        // `fsync_tail_ms`: the sync itself, and not the write before it.
        // It is the tail of one append — the part a caller waits on
        // before it may release the bytes the append records — and §4's
        // `Wresp` counts three of them. A sync that fails emits nothing:
        // the frame did not reach the disk, so there is no append here
        // to have taken any time at all.
        let fsync = Timing::start();
        self.file.sync_all()?;
        if let Some(ms) = fsync.ms() {
            tracing::event!(
                name: "fsync_tail_ms",
                target: TARGET,
                LEVEL,
                kind = ?self.id.kind,
                role = ?self.id.role,
                key = %hex(&self.id.key),
                generation = self.id.generation,
                seq = self.next_seq,
                bytes = frame.len(),
                ms,
            );
        }
        Ok(())
    }

    /// Returns how many records this journal holds.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.next_seq
    }

    /// Returns whether this journal holds no records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.next_seq == 0
    }
}

/// Reads the header a journal file opens with, without being told what
/// it should say.
///
/// The one place the header's bytes are read back rather than compared:
/// [`Journal::open`] knows the journal it wants and matches the whole
/// header at once, and everything below is for the reader that does not.
/// A code this binary does not write is not a journal it can describe,
/// so it is refused here rather than mapped to some nearby value.
fn read_id(path: &Path, bytes: &[u8]) -> Result<JournalId, JournalError> {
    let not_a_journal = || JournalError::NotAJournal {
        path: path.to_path_buf(),
    };
    if bytes.len() < HEADER_SIZE || !bytes.starts_with(MAGIC) {
        return Err(not_a_journal());
    }
    let version = bytes[MAGIC.len()];
    if version < FORMAT_VERSION {
        return Err(JournalError::OldVersion {
            found: version,
            expected: FORMAT_VERSION,
            retirement: retirement(version),
        });
    }
    if version > FORMAT_VERSION {
        return Err(not_a_journal());
    }
    let (Some(kind), Some(role)) = (
        JournalKind::from_code(bytes[MAGIC.len() + 1]),
        Role::from_code(bytes[MAGIC.len() + 2]),
    ) else {
        return Err(not_a_journal());
    };
    let mut generation = [0_u8; 8];
    generation.copy_from_slice(&bytes[MAGIC.len() + 3..MAGIC.len() + 11]);
    let mut key = [0_u8; 32];
    key.copy_from_slice(&bytes[MAGIC.len() + 11..HEADER_SIZE]);
    Ok(JournalId {
        kind,
        role,
        key,
        generation: u64::from_be_bytes(generation),
    })
}

/// Returns the file one generation of `stem` occupies.
///
/// The generation is in the name as well as in the header, because the
/// name is what a directory listing can be sorted by and the header is
/// what a frame digest binds. [`split_name`] is what refuses a file
/// where the two disagree.
#[must_use]
pub fn generation_path(directory: &Path, stem: &str, generation: u64) -> PathBuf {
    directory.join(format!("{stem}.{generation:016x}.journal"))
}

/// Returns the name a successor is written under before it is installed.
///
/// Deliberately not a journal name: [`installed_generations`] does not
/// see it, so a candidate is invisible to recovery until the rename that
/// installs it.
fn candidate_path(directory: &Path, stem: &str, generation: u64) -> PathBuf {
    directory.join(format!("{stem}.{generation:016x}.journal.candidate"))
}

/// Returns the stem and generation a journal file name carries.
///
/// Written back rather than trusted, for the reason a key is: the parse
/// below would accept a sign, mixed case, and a short field, and none of
/// them is a name this module ever wrote.
#[must_use]
pub fn journal_name_parts(name: &str) -> Option<(&str, u64)> {
    let (stem, digits) = name.strip_suffix(".journal")?.rsplit_once('.')?;
    if digits.len() != 16 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let generation = u64::from_str_radix(digits, 16).ok()?;
    (format!("{generation:016x}") == digits).then_some((stem, generation))
}

/// Returns the directory and stem a journal path names, refusing a name
/// that does not carry `generation`.
fn split_name(path: &Path, generation: u64) -> Result<(PathBuf, String), JournalError> {
    let not_a_journal = || JournalError::NotAJournal {
        path: path.to_path_buf(),
    };
    let name = path.file_name().and_then(|name| name.to_str());
    let Some((stem, named)) = name.and_then(journal_name_parts) else {
        return Err(not_a_journal());
    };
    if named != generation {
        return Err(JournalError::GenerationMismatch {
            path: path.to_path_buf(),
            named,
            header: generation,
        });
    }
    Ok((
        path.parent().unwrap_or(Path::new(".")).to_path_buf(),
        stem.to_owned(),
    ))
}

/// Returns every installed generation of `stem`, oldest first.
///
/// Installed is the whole of what this counts: a candidate does not end
/// in `.journal`, so a rotation that never reached its rename is a file
/// this function cannot see, which is what "recovery ignores an
/// uninstalled candidate" is.
fn installed_generations(directory: &Path, stem: &str) -> Result<Vec<u64>, JournalError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut generations = Vec::new();
    for entry in entries {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if let Some((found, generation)) = journal_name_parts(name)
            && found == stem
        {
            generations.push(generation);
        }
    }
    generations.sort_unstable();
    Ok(generations)
}

/// Step one of the install: the successor, whole, on the disk under a
/// name recovery does not look at.
///
/// The header and the checkpoint frame are one `write_all` and one
/// `sync_all`, so the file the rename installs is either the complete
/// successor or a file no reader will ever be shown.
fn write_candidate(
    candidate: &Path,
    id: JournalId,
    checkpoint: &[u8],
) -> Result<(File, u64), JournalError> {
    // A candidate left by an earlier interrupted rotation is bytes
    // nobody was told about, and this generation is about to say what
    // those bytes are. Removed rather than appended to.
    match fs::remove_file(candidate) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(true)
        .open(candidate)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            return Err(JournalError::Locked {
                path: candidate.to_path_buf(),
            });
        }
        Err(TryLockError::Error(error)) => return Err(error.into()),
    }
    let header = id.header_bytes();
    let digest = frame_digest(id.digest(), 0, checkpoint);
    let mut bytes = Vec::with_capacity(HEADER_SIZE + FRAME_OVERHEAD + checkpoint.len());
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(&(checkpoint.len() as u32).to_be_bytes());
    bytes.extend_from_slice(checkpoint);
    bytes.extend_from_slice(digest.as_bytes());
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok((file, bytes.len() as u64))
}

/// Step two: the rename that makes the successor the live generation,
/// and the directory `fsync` that makes the rename itself durable.
fn install(candidate: &Path, installed: &Path, directory: &Path) -> Result<(), JournalError> {
    fs::rename(candidate, installed)?;
    Ok(hellas_private::sync_directory(directory)?)
}

/// Step three: the predecessor's name goes, and the directory is fsynced
/// again so that going is durable.
///
/// A file already gone is not a failure. Recovery calls this for every
/// generation below the one it opened, so it is the same unlink the
/// rotation would have done, run once more.
fn retire(predecessor: &Path, directory: &Path) -> Result<(), JournalError> {
    match fs::remove_file(predecessor) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    Ok(hellas_private::sync_directory(directory)?)
}

/// Returns why one retired envelope version cannot be migrated.
const fn retirement(found: u8) -> &'static str {
    match found {
        0 | 1 => "pre-arming journals have no recoverable scan floor or close descriptor",
        2 => {
            "pre-terminal channel journals reuse tags 7-11 with other meanings and would mis-replay"
        }
        3 => {
            "pre-response channel journals cannot record an answered contest, so a fixed answer replays as one never given"
        }
        4 => {
            "pre-rotation journals bind no generation, so a predecessor's frames verify in its successor and a retired file opens as the live one"
        }
        5 => {
            "single-job journals do not identify follow-on records and cannot be replayed as concurrent-job journals"
        }
        _ => "unknown retired journal format",
    }
}

/// What one walk of a file found: the complete frames, whether a partial
/// tail was left, the sequence the next frame would occupy, and the
/// offset that tail begins at.
type Walked = (Vec<Vec<u8>>, bool, u64, usize);

/// Walks the frames after the header, stopping at the first partial one.
///
/// Returns what verified, the sequence the next frame would occupy, and
/// the offset a partial tail begins at — which is the length the file
/// would be truncated to. Reading and truncating are separated because
/// one caller is opening the journal to write it and the other is only
/// looking at it.
fn walk(header: Digest, bytes: &[u8]) -> Result<Walked, JournalError> {
    let mut offset = HEADER_SIZE;
    let mut seq = 0_u64;
    let mut records = Vec::new();
    let mut truncated_tail = false;
    while let Some(rest) = bytes.get(offset..).filter(|rest| !rest.is_empty()) {
        let Some(prefix) = rest.get(..4) else {
            truncated_tail = true;
            break;
        };
        let mut len_bytes = [0_u8; 4];
        len_bytes.copy_from_slice(prefix);
        let len = u32::from_be_bytes(len_bytes) as usize;
        // The extent first, and the length's plausibility second: a
        // frame that runs past the end of the file is an append the
        // file ends inside, whether its length field is a hundred
        // bytes too many or four gigabytes too many. Only a length
        // that fits inside the file could be a complete frame, and
        // only there is an oversized one evidence of corruption
        // rather than of a tear.
        let Some(frame) = FRAME_OVERHEAD
            .checked_add(len)
            .and_then(|end| rest.get(..end))
        else {
            truncated_tail = true;
            break;
        };
        if len > MAX_RECORD_BYTES {
            return Err(JournalError::RecordTooLarge { len });
        }
        let (Some(payload), Some(stored)) = (frame.get(4..4 + len), frame.get(4 + len..)) else {
            truncated_tail = true;
            break;
        };
        if stored != frame_digest(header, seq, payload).as_bytes() {
            // Every byte this frame claims is in the file, so it was
            // long enough to be a complete append — and a complete
            // append is one whose caller may have been given an
            // `Ok`. Nothing here can tell that from a machine that
            // died mid-flush, so the file is refused rather than
            // read back one record short of what a peer may hold.
            return Err(JournalError::Corrupt { seq });
        }
        records.push(payload.to_vec());
        seq = seq.saturating_add(1);
        offset += FRAME_OVERHEAD + len;
    }

    Ok((records, truncated_tail, seq, offset))
}

/// Returns the digest that binds one frame to its journal and position.
///
/// The header digest is in the preimage, so a frame lifted from another
/// channel's file does not verify here; the sequence is in it, so a
/// frame replayed at another position does not either; and the length
/// is, so a frame cannot be reinterpreted as a shorter one followed by
/// something else.
fn frame_digest(header: Digest, seq: u64, payload: &[u8]) -> Digest {
    let mut hasher = XetFileHasher::new();
    hasher.update(FRAME_DOMAIN);
    hasher.update(header.as_bytes());
    hasher.update(&seq.to_be_bytes());
    hasher.update(&(payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize()
}

#[cfg(test)]
mod tests;
