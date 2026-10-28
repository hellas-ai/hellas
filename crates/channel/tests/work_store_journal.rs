//! The measurement seams §4's budgets are made of.

use hellas_channel::work_store::Role;
use hellas_channel::work_store::journal::{Journal, JournalId, JournalKind};
use hellas_rpc::observe::Samples;
use tracing::instrument::WithSubscriber;

/// The records a measured fixture writes, and the state a rotation
/// carries forward.
const MEASURED: [&[u8]; 3] = [b"one", b"two", b"three"];
const MEASURED_CHECKPOINT: &[u8] = b"the state the predecessor reached";

/// Writes `MEASURED` into a fresh journal under `dir` and rotates it.
///
/// The one sequence both measurement tests below run, so "the same work
/// with an observer and without one" is the same call and not two
/// hand-copied ones.
async fn measured_run(dir: &std::path::Path) {
    let (mut journal, _) = match Journal::open_latest(dir, "duty", measured_id()).await {
        Ok(opened) => opened,
        Err(error) => panic!("the journal opens: {error}"),
    };
    for record in MEASURED {
        if let Err(error) = journal.append(record).await {
            panic!("the record appends: {error}");
        }
    }
    if let Err(error) = journal.rotate(MEASURED_CHECKPOINT).await {
        panic!("the rotation completes: {error}");
    }
    if let Err(error) = journal.append(b"after").await {
        panic!("the successor takes a record: {error}");
    }
}

const fn measured_id() -> JournalId {
    JournalId {
        kind: JournalKind::Setup,
        role: Role::Provider,
        key: [0x5a; 32],
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
#[tokio::test]
async fn each_append_and_each_rotation_is_its_own_sample() {
    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let samples = std::sync::Arc::new(Samples::new());
    measured_run(dir.path())
        .with_subscriber(samples.clone())
        .await;

    let fsyncs = samples.of("fsync_tail_ms");
    assert_eq!(
        fsyncs.len(),
        4,
        "three predecessor appends and one successor append",
    );
    let seqs: Vec<Option<&str>> = fsyncs.iter().map(|sample| sample.field("seq")).collect();
    assert_eq!(
        seqs,
        vec![Some("0"), Some("1"), Some("2"), Some("0")],
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
        "the predecessor's records, which is what the successor no longer holds",
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
/// — creating it is not an append — and a rotation refused
/// before it writes anything emits no `rotation_tail_ms`, because no
/// generation moved.
#[tokio::test]
async fn work_that_was_not_done_is_not_sampled() {
    use hellas_channel::work_store::journal::MAX_CHECKPOINT_BYTES;

    let Ok(dir) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let samples = std::sync::Arc::new(Samples::new());
    async {
        let (mut journal, _) = match Journal::open_latest(dir.path(), "idle", measured_id()).await {
            Ok(opened) => opened,
            Err(error) => panic!("the journal opens: {error}"),
        };
        assert!(
            samples.all().is_empty(),
            "opening an empty journal is not an append and not a rotation",
        );
        if journal
            .rotate(&vec![0_u8; MAX_CHECKPOINT_BYTES + 1])
            .await
            .is_ok()
        {
            panic!("a state wider than a checkpoint cannot rotate");
        }
    }
    .with_subscriber(samples.clone())
    .await;
    assert!(
        samples.of("fsync_tail_ms").is_empty(),
        "no record was appended",
    );
    assert!(
        samples.of("rotation_tail_ms").is_empty(),
        "a rotation that wrote nothing is not a rotation that happened",
    );
}

/// A journal nobody is measuring holds exactly what a measured one holds.
///
/// This is the hottest path in the tree, and the one place where an
/// observation that had become a decision would be invisible: the seam
/// sits around the commit and around the rotation, so a branch taken on
/// whether anyone is listening would change an order, a record, or a
/// generation. Two runs of the identical sequence — one under a
/// collector, one under nothing at all — are compared as what they replay.
#[tokio::test]
async fn an_unobserved_journal_holds_the_same_records_as_an_observed_one() {
    let Ok(watched) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };
    let Ok(unwatched) = tempfile::tempdir() else {
        panic!("a temporary directory");
    };

    let samples = std::sync::Arc::new(Samples::new());
    measured_run(watched.path())
        .with_subscriber(samples.clone())
        .await;
    measured_run(unwatched.path()).await;

    assert!(
        !samples.all().is_empty(),
        "the observed run is observed, or this proves nothing",
    );

    let mut held = Vec::new();
    for root in [watched.path(), unwatched.path()] {
        let Ok((id, replay)) = Journal::inspect(root, "duty").await else {
            panic!("the journal reads");
        };
        held.push((id, replay.checkpoint, replay.records));
    }
    assert_eq!(
        held[0], held[1],
        "the same journal replays whether or not it was measured"
    );
    assert_eq!(
        held[0].1.as_deref(),
        Some(MEASURED_CHECKPOINT),
        "and it is the rotated one"
    );
}
