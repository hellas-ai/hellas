//! Durable, append-only endpoint state for setup and paid channels.
//!
//! Each transition is fsynced before its signature or result is released.
//! Replay validates transition order; journal ownership is exclusive.
//! The store does not prevent a caller from sending before committing, nor
//! protect against rollback of its backing storage.

pub mod channel;
pub mod journal;
pub mod setup;

mod cursor;

pub use channel::{
    Channel, ChannelRecord, ChannelStateError, ChannelStore, CloseSettlement, FinalizedHeight,
    Funding, JobBook, JobPhase, JobState, JobTerminal, OpenContest, PaidCertificate,
    PaymentFunding, RespondedContest, TerminalOutcome,
};
pub use journal::{JournalError, Role};
pub use setup::{
    DiscoveredSetup, ObservedSetup, SetupAbort, SetupDecision, SetupDiscovery, SetupDiscoveryError,
    SetupEnd, SetupFault, SetupHistoryBatch, SetupHistoryBlock, SetupOrigin, SetupRecord,
    SetupScan, SetupState, SetupStateError, SetupStore, UnidentifiedSetup, discover_setups,
};

/// Why a durable step could not be taken.
#[derive(Debug, thiserror::Error)]
pub enum WorkStoreError {
    /// The file could not be opened, replayed, or appended to.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The setup step is not one this handshake may take.
    #[error(transparent)]
    Setup(#[from] SetupStateError),
    /// The channel step is not one this state may take.
    #[error(transparent)]
    Channel(#[from] ChannelStateError),
}

/// Whether applying a record changed anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Applied {
    /// The state moved, so the record must be journaled.
    Changed,
    /// The state already held exactly this. Nothing is written, and the
    /// retry returns what the first call did.
    Redundant,
}

pub(crate) fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Writes one optional body behind a presence byte.
pub(crate) fn put_option<T>(
    out: &mut Vec<u8>,
    value: Option<&T>,
    body: impl FnOnce(&mut Vec<u8>, &T),
) {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            body(out, value);
        }
    }
}

/// Reads back exactly what [`put_option`] wrote.
pub(crate) fn take_option<T, E>(
    cursor: &mut cursor::Cursor<'_>,
    malformed: E,
    body: impl FnOnce(&mut cursor::Cursor<'_>) -> Result<T, E>,
) -> Result<Option<T>, E> {
    match cursor.byte() {
        Some(0) => Ok(None),
        Some(1) => body(cursor).map(Some),
        _ => Err(malformed),
    }
}

/// Writes a variable-width body behind its own length.
pub(crate) fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u64(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Reads back exactly what [`put_bytes`] wrote.
pub(crate) fn take_bytes<'a, E>(
    cursor: &mut cursor::Cursor<'a>,
    malformed: E,
) -> Result<&'a [u8], E> {
    let Some(len) = cursor.u64().and_then(|len| usize::try_from(len).ok()) else {
        return Err(malformed);
    };
    cursor.take(len).ok_or(malformed)
}

/// Reads one byte that may only be a boolean.
pub(crate) fn take_bool<E>(cursor: &mut cursor::Cursor<'_>, malformed: E) -> Result<bool, E> {
    match cursor.byte() {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(malformed),
    }
}

/// Renders a journal key as the lowercase hex a file is named with.
///
/// One spelling for both journals: a key rendered two ways is two
/// file names for one journal, and the second one is a store with no
/// history in it.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}
