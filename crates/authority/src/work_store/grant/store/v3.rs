//! One-way reader for `hellas.node.journal.v3`. Opening a v3 store replays it
//! into v4 state and rotates at once, rewriting it as a v4 checkpoint. Delete
//! this module once every node has opened under v4.
use super::super::NodeStoreError;
use super::super::state::{
    CHECKPOINT_NAMESPACE, Change, Frame, JOURNAL_NAMESPACE, Snapshot, State,
};
use crate::model::grant::budget::{BudgetDef, BudgetNode, Charge, Limit, Meter, Window};
use hellas_admission::{Counter, HoldId, Key, Spec};
use hellas_auth::Digest;
use hellas_auth::authority::{Revision, UnixMillis};
use hellas_channel::work_store::journal::MAX_RECORD_BYTES;
use hellas_rpc::protocol::value::decode_bounded;
use ipld_core::{
    ipld::Ipld,
    serde::{from_ipld, to_ipld},
};
use serde::{Deserialize, Serialize};

pub(super) const JOURNAL: &str = "hellas.node.journal.v3";
const CHECKPOINT: &str = "hellas.node.checkpoint.v3";

#[derive(Deserialize)]
struct Machine {
    limits: Vec<Limit>,
    concurrent: u16,
}
/// v3 machine configuration becomes the machine's budget definition; every
/// other change is encoded as it was.
pub(super) fn frame(bytes: &[u8], state: &State) -> Result<Frame, NodeStoreError> {
    let malformed = |_| NodeStoreError::Malformed;
    let Ipld::Map(mut fields) = decode_bounded::<Ipld>(bytes, MAX_RECORD_BYTES)? else {
        return Err(NodeStoreError::Malformed);
    };
    if fields.get("namespace") != Some(&Ipld::String(JOURNAL.into())) {
        return Err(NodeStoreError::Malformed);
    }
    let Some(Ipld::List(changes)) = fields.get_mut("changes") else {
        return Err(NodeStoreError::Malformed);
    };
    let mut revision = super::super::ledger::definition(state.ledger(), BudgetNode::Machine)
        .map_or(Revision(0), |d| d.revision);
    for change in changes.iter_mut() {
        let Ipld::Map(variant) = change else { continue };
        let Some(machine) = variant.remove("Machine") else {
            continue;
        };
        let Machine { limits, concurrent } = from_ipld(machine).map_err(malformed)?;
        revision = revision.next().ok_or(NodeStoreError::Malformed)?;
        let max_in_flight =
            std::num::NonZeroU16::new(concurrent).ok_or(NodeStoreError::Malformed)?;
        let budget = Change::Budget(BudgetDef {
            node: BudgetNode::Machine,
            parent: None,
            revision,
            limits,
            max_in_flight,
        });
        *change = to_ipld(budget).map_err(malformed)?;
    }
    fields.insert("namespace".into(), Ipld::String(JOURNAL_NAMESPACE.into()));
    from_ipld(Ipld::Map(fields)).map_err(malformed)
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
struct Ledger {
    nodes: Vec<(BudgetNode, Node)>,
    held: Vec<(Digest, Held)>,
    high_water: UnixMillis,
}
#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
struct Node {
    parent: Option<BudgetNode>,
    revision: Revision,
    limits: Vec<Limit>,
    concurrent: u16,
    counters: [[Counter; 4]; 5],
}
#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
struct Held {
    path: Vec<BudgetNode>,
    charge: Charge,
}
/// The v4 book's encoding; `State::restore` validates the result in full.
#[derive(Serialize)]
struct Book {
    nodes: Vec<(Key, BookNode)>,
    holds: Vec<(HoldId, BookHeld)>,
    high_water: u64,
}
#[derive(Serialize)]
struct BookNode {
    spec: Spec,
    counters: [[Counter; 4]; 5],
    buckets: [(); 0],
    block: Option<()>,
}
#[derive(Serialize)]
struct BookHeld {
    path: Vec<Key>,
    charge: Charge,
}
/// The v3 ledger and machine revision become the v4 book; every other field is unchanged.
pub(super) fn snapshot(bytes: &[u8]) -> Result<Snapshot, NodeStoreError> {
    let malformed = |_| NodeStoreError::Malformed;
    let Ipld::Map(mut fields) = decode_bounded::<Ipld>(bytes, usize::MAX)? else {
        return Err(NodeStoreError::Malformed);
    };
    if fields.get("namespace") != Some(&Ipld::String(CHECKPOINT.into())) {
        return Err(NodeStoreError::Malformed);
    }
    let take = |fields: &mut std::collections::BTreeMap<String, Ipld>, name| {
        fields.remove(name).ok_or(NodeStoreError::Malformed)
    };
    let machine: Revision = from_ipld(take(&mut fields, "machine_revision")?).map_err(malformed)?;
    let ledger: Ledger = from_ipld(take(&mut fields, "ledger")?).map_err(malformed)?;
    let book = Book {
        nodes: ledger
            .nodes
            .into_iter()
            .map(|(id, node)| {
                let mut limits = vec![Limit::new(
                    Meter::Requests,
                    Window::Held,
                    node.concurrent.into(),
                )];
                limits.extend(node.limits);
                let revision = if id == BudgetNode::Machine {
                    machine
                } else {
                    node.revision
                };
                let spec = Spec {
                    parent: node.parent.map(BudgetNode::key),
                    revision: revision.0,
                    limits,
                    queue: 0,
                    owner: false,
                };
                (
                    id.key(),
                    BookNode {
                        spec,
                        counters: node.counters,
                        buckets: [],
                        block: None,
                    },
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>()
            .into_iter()
            .collect(),
        holds: ledger
            .held
            .into_iter()
            .map(|(work, held)| {
                let path = held.path.into_iter().map(BudgetNode::key).collect();
                (
                    super::super::ledger::hold(work),
                    BookHeld {
                        path,
                        charge: held.charge,
                    },
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>()
            .into_iter()
            .collect(),
        high_water: ledger.high_water.0,
    };
    fields.insert("ledger".into(), to_ipld(book).map_err(malformed)?);
    fields.insert(
        "namespace".into(),
        Ipld::String(CHECKPOINT_NAMESPACE.into()),
    );
    from_ipld(Ipld::Map(fields)).map_err(malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{accept, proposal, setup};

    #[derive(Serialize)]
    struct V3Frame {
        namespace: String,
        now: UnixMillis,
        changes: Vec<V3Change>,
    }
    #[derive(Serialize)]
    enum V3Change {
        Machine {
            limits: Vec<Limit>,
            concurrent: u16,
        },
        #[serde(untagged)]
        Same(Box<Change>),
    }

    /// The state as v3 wrote it: the old ledger and a separate machine revision.
    fn encode_v3(state: &State) -> Vec<u8> {
        let book = state.ledger();
        let machine = book.node(Key::Machine).unwrap().spec().revision;
        let ledger = Ledger {
            nodes: book
                .nodes()
                .map(|(key, node)| {
                    let spec = node.spec();
                    let counters = Meter::ALL.map(|m| Window::CALENDAR.map(|w| node.counter(m, w)));
                    let v3 = Node {
                        parent: spec.parent.and_then(BudgetNode::from_key),
                        revision: Revision(if *key == Key::Machine {
                            0
                        } else {
                            spec.revision
                        }),
                        limits: super::super::super::ledger::limits(spec).to_vec(),
                        concurrent: super::super::super::ledger::concurrent(spec),
                        counters,
                    };
                    (BudgetNode::from_key(*key).unwrap(), v3)
                })
                .collect(),
            held: book
                .holds()
                .map(|(id, path, charge)| {
                    let path = path
                        .iter()
                        .map(|k| BudgetNode::from_key(*k).unwrap())
                        .collect();
                    (Digest::from_bytes(id.0), Held { path, charge })
                })
                .collect(),
            high_water: UnixMillis(book.high_water()),
        };
        let Ipld::Map(mut fields) = to_ipld(state.snapshot().unwrap()).unwrap() else {
            unreachable!()
        };
        fields.insert("ledger".into(), to_ipld(ledger).unwrap());
        fields.insert(
            "machine_revision".into(),
            to_ipld(Revision(machine)).unwrap(),
        );
        fields.insert("namespace".into(), Ipld::String(CHECKPOINT.into()));
        super::super::encode(&Ipld::Map(fields)).unwrap()
    }

    #[tokio::test]
    async fn a_v3_journal_is_rewritten_as_v4_when_opened() {
        let directory = tempfile::tempdir().unwrap();
        let (mut store, caller) = setup(directory.path()).await;
        let (a, signature, input) = proposal(&store, 1);
        accept(&mut store, &caller, (a, signature, &input), 1000)
            .await
            .unwrap();
        let mut expected = store.state().clone();
        let checkpoint = encode_v3(&expected);
        let work = crate::model::grant::grant_work_id(expected.network(), &a);
        let application = (&caller, crate::test_support::JOURNAL_AUTHORIZATION);
        let dispatched = Change::Dispatched {
            channel: a.channel_id,
            work,
            execution: super::super::super::ExecutionRecord::capture(
                &expected,
                application,
                a.grant_id,
                UnixMillis(1000),
            )
            .unwrap(),
        };
        let machine = V3Frame {
            namespace: JOURNAL.into(),
            now: UnixMillis(1000),
            changes: vec![
                V3Change::Same(Box::new(dispatched.clone())),
                V3Change::Machine {
                    limits: vec![],
                    concurrent: 8,
                },
            ],
        };
        store.journal.rotate(&checkpoint).await.unwrap();
        store
            .journal
            .append(&super::super::encode(&machine).unwrap())
            .await
            .unwrap();
        let mut definition =
            super::super::super::ledger::definition(expected.ledger(), BudgetNode::Machine)
                .unwrap();
        definition.revision.0 += 1;
        definition.limits.clear();
        definition.max_in_flight = std::num::NonZeroU16::new(8).unwrap();
        let v4 = Frame {
            namespace: JOURNAL_NAMESPACE.into(),
            now: UnixMillis(1000),
            changes: vec![dispatched, Change::Budget(definition)],
        };
        expected.apply(&v4, true).unwrap();
        store.close().await;
        drop(store);
        let network = hellas_channel::test_support::network();
        let mut store = super::super::NodeStore::open_initialized(
            &hellas_private::StoreLocation::for_test(directory.path()),
            network,
        )
        .await
        .unwrap();
        assert_eq!(store.state(), &expected);
        assert_eq!(
            store.journal_len(),
            0,
            "the v3 frames are rewritten into a v4 checkpoint"
        );
        store.close().await;
        drop(store);
        let store = super::super::NodeStore::open_initialized(
            &hellas_private::StoreLocation::for_test(directory.path()),
            network,
        )
        .await
        .unwrap();
        assert_eq!(store.state(), &expected);
    }
}
