//! The journal envelope, pinned as bytes.
//!
//! Every other test of these files writes with this code and reads with
//! this code, so all of them stay green when the magic, the version
//! byte, or either digest domain is changed — writer and reader move
//! together and agree with each other about a format nobody else would
//! recognise. What that hides is the only failure these constants have:
//! an endpoint that no longer opens the journal it wrote yesterday, and
//! reports its own file as somebody else's.
//!
//! So this is a file, from outside: fifty-seven header bytes and one
//! frame, written once and pinned as hex. It fails if the magic moves,
//! if the version moves, if the header domain moves — the header digest
//! is in every frame's preimage — or if the frame domain moves.

use hellas_rpc::observe::Samples;
use hellas_work::work_store::Role;
use hellas_work::work_store::journal::{Journal, JournalId, JournalKind};

/// Bytes before the first frame: magic, version, kind, role,
/// generation, key.
const HEADER_BYTES: usize = 65;

/// `hellas.work-journal.v1`, then `07` version, `02` channel, `02`
/// provider, the eight-byte generation, then the 32-byte key.
const GOLDEN_HEADER: &str = concat!(
    "68656c6c61732e776f726b2d6a6f75726e616c2e7631",
    "07",
    "02",
    "02",
    "0000000000000000",
    "1111111111111111111111111111111111111111111111111111111111111111",
);

/// A four-byte big-endian length, the record, and the frame digest over
/// the frame domain, the header digest, the sequence, and the length.
const GOLDEN_FRAME: &str = concat!(
    "0000000a",
    "6f6e65207265636f7264",
    "426b31f7176b3929136b6da7ca6d474e9b3d272c87efc95b96a1f69abe245889",
);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A mismatched format is rejected before records are read or the file is changed.
#[test]
fn mismatched_formats_are_refused_before_any_record_is_decoded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("format.0000000000000000.journal");
    let id = JournalId {
        kind: JournalKind::Channel,
        role: Role::Provider,
        key: [0x11; 32],
        generation: 0,
    };
    let (journal, _) = Journal::open(&path, id).unwrap();
    drop(journal);
    let header = std::fs::read(&path).unwrap();
    for found in (0..=u8::MAX).filter(|version| *version != 7) {
        let mut bytes = header.clone();
        bytes[b"hellas.work-journal.v1".len()] = found;
        bytes.extend_from_slice(b"intentionally invalid record");
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            Journal::open(&path, id),
            Err(hellas_work::work_store::JournalError::VersionMismatch {
                found: actual,
                expected: 7,
            }) if actual == found
        ));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(matches!(
            Journal::inspect(&path),
            Err(hellas_work::work_store::JournalError::VersionMismatch {
                found: actual,
                expected: 7,
            }) if actual == found
        ));
    }
}

/// One journal holding one record is these exact bytes.
#[test]
fn a_journal_of_one_record_is_these_bytes() {
    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let path = dir.path().join("golden.0000000000000000.journal");
    let id = JournalId {
        kind: JournalKind::Channel,
        role: Role::Provider,
        key: [0x11; 32],
        generation: 0,
    };
    {
        let (mut journal, replay) = match Journal::open(&path, id) {
            Ok(opened) => opened,
            Err(error) => panic!("the journal opens: {error}"),
        };
        assert!(replay.records.is_empty(), "a new file holds nothing");
        if let Err(error) = journal.append(b"one record") {
            panic!("the record appends: {error}");
        }
    }

    let Ok(bytes) = std::fs::read(&path) else {
        panic!("the journal reads");
    };
    assert!(
        bytes.len() > HEADER_BYTES,
        "a header and a frame, not {} bytes",
        bytes.len()
    );
    let (header, frame) = bytes.split_at(HEADER_BYTES);
    assert_eq!(hex(header), GOLDEN_HEADER, "the header this endpoint reads");
    assert_eq!(hex(frame), GOLDEN_FRAME, "the frame it binds");
}

// ── The measurement seams §4's budgets are made of ────────────────────

/// The records a measured fixture writes, and the state a rotation
/// carries forward.
const MEASURED: [&[u8]; 3] = [b"one", b"two", b"three"];
const MEASURED_CHECKPOINT: &[u8] = b"the state the predecessor reached";

/// Writes `MEASURED` into a fresh journal under `dir` and rotates it.
///
/// The one sequence both measurement tests below run, so "the same work
/// with an observer and without one" is the same call and not two
/// hand-copied ones.
fn measured_run(dir: &std::path::Path) {
    let (mut journal, _) = match Journal::open_latest(dir, "duty", measured_id()) {
        Ok(opened) => opened,
        Err(error) => panic!("the journal opens: {error}"),
    };
    for record in MEASURED {
        if let Err(error) = journal.append(record) {
            panic!("the record appends: {error}");
        }
    }
    if let Err(error) = journal.rotate(MEASURED_CHECKPOINT) {
        panic!("the rotation completes: {error}");
    }
    if let Err(error) = journal.append(b"after") {
        panic!("the successor takes a record: {error}");
    }
}

const fn measured_id() -> JournalId {
    JournalId {
        kind: JournalKind::Setup,
        role: Role::Provider,
        key: [0x5a; 32],
        generation: 0,
    }
}

/// Every append is one `fsync_tail_ms`, every rotation is one
/// `rotation_tail_ms`, and neither is ever a summary of the other.
///
/// §4 divides a lower tail by a block time, and a lower tail cannot be
/// recovered from a mean — so what this pins is not that a number was
/// emitted but that *each piece of work* emitted its own, distinguishable
/// from the others by the sequence it occupied. Four appends and one
/// rotation are four samples and one, never one of each carrying a count.
#[test]
fn each_append_and_each_rotation_is_its_own_sample() {
    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let samples = std::sync::Arc::new(Samples::new());
    tracing::subscriber::with_default(samples.clone(), || measured_run(dir.path()));

    let fsyncs = samples.of("fsync_tail_ms");
    assert_eq!(
        fsyncs.len(),
        4,
        "three predecessor appends and one successor append",
    );
    let seqs: Vec<Option<&str>> = fsyncs.iter().map(|sample| sample.field("seq")).collect();
    assert_eq!(
        seqs,
        vec![Some("0"), Some("1"), Some("2"), Some("1")],
        "each sample says which append it was, so none of them is a total",
    );
    assert_eq!(fsyncs[0].field("kind"), Some("Setup"));
    assert_eq!(fsyncs[0].field("role"), Some("Provider"));
    assert_eq!(fsyncs[0].field("key"), Some("5a".repeat(32).as_str()));
    assert_eq!(fsyncs[0].field("generation"), Some("0"));
    assert_eq!(
        fsyncs[3].field("generation"),
        Some("1"),
        "an append after a rotation is the successor's",
    );

    let rotations = samples.of("rotation_tail_ms");
    assert_eq!(rotations.len(), 1, "one rotation, one sample");
    assert_eq!(rotations[0].field("generation"), Some("1"));
    assert_eq!(
        rotations[0].field("frames"),
        Some("3"),
        "the predecessor's frames, which is what the successor no longer holds",
    );
    assert_eq!(
        rotations[0].field("checkpoint_bytes"),
        Some(MEASURED_CHECKPOINT.len().to_string().as_str()),
    );
    assert!(
        fsyncs
            .iter()
            .chain(&rotations)
            .all(|sample| sample.ms >= 0.0),
        "every sample carries the duration it is a sample of",
    );
}

/// Nothing that did not happen is sampled.
///
/// A journal that is opened and never written emits no `fsync_tail_ms`
/// — the header's own sync is not an append — and a rotation refused
/// before it writes anything emits no `rotation_tail_ms`, because no
/// generation moved.
#[test]
fn work_that_was_not_done_is_not_sampled() {
    use hellas_work::work_store::journal::MAX_CHECKPOINT_BYTES;

    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let samples = std::sync::Arc::new(Samples::new());
    tracing::subscriber::with_default(samples.clone(), || {
        let (mut journal, _) = match Journal::open_latest(dir.path(), "idle", measured_id()) {
            Ok(opened) => opened,
            Err(error) => panic!("the journal opens: {error}"),
        };
        assert!(
            samples.all().is_empty(),
            "opening an empty journal is not an append and not a rotation",
        );
        if journal
            .rotate(&vec![0_u8; MAX_CHECKPOINT_BYTES + 1])
            .is_ok()
        {
            panic!("a state wider than a frame cannot rotate");
        }
    });
    assert!(
        samples.of("fsync_tail_ms").is_empty(),
        "no record was appended",
    );
    assert!(
        samples.of("rotation_tail_ms").is_empty(),
        "a rotation that wrote nothing is not a rotation that happened",
    );
}

/// A journal nobody is measuring writes exactly the file a measured one
/// writes.
///
/// This is the hottest path in the tree, and the one place where an
/// observation that had become a decision would be invisible: the seam
/// sits around `sync_all` and around the three-step install, so a branch
/// taken on whether anyone is listening would change an order, a byte,
/// or a generation. Two runs of the identical sequence — one under a
/// collector, one under nothing at all — are compared as bytes.
#[test]
fn an_unobserved_journal_writes_the_same_file_as_an_observed_one() {
    let Ok(watched) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let Ok(unwatched) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };

    let samples = std::sync::Arc::new(Samples::new());
    tracing::subscriber::with_default(samples.clone(), || measured_run(watched.path()));
    measured_run(unwatched.path());

    assert!(
        !samples.all().is_empty(),
        "the observed run is observed, or this proves nothing",
    );

    let listing = |dir: &std::path::Path| {
        let Ok(entries) = std::fs::read_dir(dir) else {
            panic!("the journal directory reads");
        };
        let mut names: Vec<String> = entries
            .map(|entry| match entry {
                Ok(entry) => entry.file_name().to_string_lossy().into_owned(),
                Err(error) => panic!("the directory entry reads: {error}"),
            })
            .collect();
        names.sort();
        names
    };
    let names = listing(watched.path());
    assert_eq!(
        names,
        listing(unwatched.path()),
        "the same generation is live and the same predecessor is gone",
    );
    for name in names {
        let Ok(observed) = std::fs::read(watched.path().join(&name)) else {
            panic!("the observed journal reads");
        };
        let Ok(plain) = std::fs::read(unwatched.path().join(&name)) else {
            panic!("the unobserved journal reads");
        };
        assert_eq!(
            hex(&observed),
            hex(&plain),
            "{name} is byte-identical whether or not it was measured",
        );
    }
}
