use super::*;
use crate::model::grant::budget::Usage;
use crate::test_support::{accept, dispatch, finish, principal, proposal, setup};
use hellas_auth::assert_err;
use hellas_private::StoreLocation;

impl NodeStore {
    pub(crate) async fn pause_next_statement(
        &mut self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        self.journal.pause_next_statement().await
    }

    pub(crate) async fn resume_statements(&mut self, release: std::sync::mpsc::Sender<()>) {
        self.journal.resume_statements(release).await;
    }

    pub(crate) const fn journal_len(&self) -> u64 {
        self.journal.len()
    }

    /// Makes every later journal write fail inside the database.
    pub(crate) async fn refuse_writes(&mut self) {
        self.journal.refuse("INSERT", "record").await;
        self.journal.refuse("UPDATE", "journal").await;
    }
}

#[tokio::test]
async fn a_poisoned_writer_refuses_new_acceptance_until_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let (mut store, caller) = setup(directory.path()).await;
    let before = store.state().clone();
    store.refuse_writes().await;
    let (first, signature, input) = proposal(&store, 1);
    assert_err!(
        accept(&mut store, &caller, (first, signature, &input), 1000).await,
        NodeStoreError::Journal(hellas_channel::work_store::journal::JournalError::Sqlx(_))
    );
    let (next, signature, input) = proposal(&store, 2);
    assert_err!(
        accept(&mut store, &caller, (next, signature, &input), 1000).await,
        NodeStoreError::Journal(hellas_channel::work_store::journal::JournalError::Poisoned)
    );
    assert_eq!(store.state(), &before);
    drop(store);
    let location = StoreLocation::for_test(directory.path());
    let mut store = NodeStore::open(
        &location,
        hellas_channel::test_support::network(),
        None,
        UnixMillis(1000),
    )
    .await
    .unwrap();
    assert_eq!(store.state(), &before);
    accept(&mut store, &caller, (next, signature, &input), 1000)
        .await
        .unwrap();
}

/// A rotated journal has no initialization frame to enforce the frame version.
/// Its snapshot must reject state produced under the old attribution rules too.
#[tokio::test]
async fn old_checkpoint_cannot_bypass_the_journal_format_boundary() {
    let directory = tempfile::tempdir().unwrap();
    let (mut store, _) = setup(directory.path()).await;
    let mut snapshot = serde_json::to_value(store.state.snapshot().unwrap()).unwrap();
    snapshot["namespace"] = serde_json::json!("hellas.node.checkpoint.v2");
    let snapshot: Snapshot = serde_json::from_value(snapshot).unwrap();
    store
        .journal
        .rotate(&encode(&snapshot).unwrap())
        .await
        .unwrap();
    drop(store);
    let location = StoreLocation::for_test(directory.path());
    assert!(matches!(
        NodeStore::open_initialized(&location, hellas_channel::test_support::network()).await,
        Err(NodeStoreError::Malformed)
    ));
}

/// Commits no longer serialize the whole state. The running bound that
/// replaces it must never under-count, and replay from any crash point between
/// appends or around a rotation must reach exactly the live state.
#[tokio::test]
async fn checkpoint_bound_covers_every_commit_and_replay_matches_live_state() {
    let directory = tempfile::tempdir().unwrap();
    let (mut store, caller) = setup(directory.path()).await;
    // Lift the fixture's quotas; concurrency stays bounded.
    let grant = store.state().grant(GrantId([1; 16])).unwrap();
    let mut budget = store.state().ledger().definition(grant.budget).unwrap();
    budget.revision = budget.revision.next().unwrap();
    budget.limits.clear();
    budget.max_in_flight = std::num::NonZeroU16::new(8).unwrap();
    let machine = Change::Machine {
        limits: vec![],
        concurrent: 8,
    };
    for change in [machine, Change::Budget(budget)] {
        store.commit(UnixMillis(1000), change, true).await.unwrap();
    }
    let (mut seed, mut now) = (0x9e37_79b9_7f4a_7c15_u64, 1000);
    let mut next = |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    // (channel, work, dispatched)
    let mut open: Vec<(ChannelId, Digest, bool)> = Vec::new();
    for nonce in 1..=400 {
        let step = next(8);
        match step {
            0 | 1 => {
                let (mut a, _, input) = proposal(&store, nonce);
                // Deadlines follow the clock so terminals are pruned as it advances.
                a.acceptance_deadline_ms = UnixMillis(now + 1000);
                a.terminal_deadline_ms = UnixMillis(now + 3000);
                a.delivery_deadline_ms = UnixMillis(now + 4000);
                let work = grant_work_id(store.state().network(), &a);
                let signature = principal(1).1.sign_digest(work).unwrap();
                match accept(&mut store, &caller, (a, signature, &input), now).await {
                    Ok(_) => open.push((a.channel_id, work, false)),
                    Err(NodeStoreError::Ledger(ledger::LedgerError::Concurrent(_))) => {}
                    Err(error) => panic!("{error:?}"),
                }
            }
            2 | 3 if !open.is_empty() => {
                let index = next(open.len() as u64) as usize;
                let job = &mut open[index];
                if !job.2 {
                    dispatch(&mut store, &caller, (job.0, job.1), now)
                        .await
                        .unwrap();
                    job.2 = true;
                }
            }
            4 | 5 if !open.is_empty() => {
                let index = next(open.len() as u64) as usize;
                let (channel, work, dispatched) = open.remove(index);
                if !dispatched {
                    store.release(channel, work, UnixMillis(now)).await.unwrap();
                } else {
                    let (outcome, usage) = if next(2) == 0 {
                        let usage = Usage::Observed(Charge([1, 0, 2, 0, 0]));
                        (GrantOutcome::Failed, usage)
                    } else {
                        (GrantOutcome::Indeterminate, Usage::Unknown)
                    };
                    let job = (channel, work);
                    finish(&mut store, job, outcome, usage, false, now)
                        .await
                        .unwrap();
                }
            }
            6 => {
                now += next(400);
                store.tick(UnixMillis(now)).await.unwrap();
            }
            7 => store.rotate().await.unwrap(),
            _ => {}
        }
        let cost = encode(&store.state.snapshot().unwrap()).unwrap().len()
            + store.state.ledger.clock_headroom();
        assert!(
            cost <= store.checkpoint_bound,
            "{cost} > {}",
            store.checkpoint_bound
        );
        if step == 7 || next(16) == 0 {
            let live = store.state.clone();
            store.close().await;
            drop(store);
            let network = hellas_channel::test_support::network();
            store =
                NodeStore::open_initialized(&StoreLocation::for_test(directory.path()), network)
                    .await
                    .unwrap();
            assert_eq!(store.state, live);
        }
    }
}
