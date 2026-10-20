//! Abstract state view canonicalization tests.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::expect_used)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

mod support;

use hellas_kernel::{
    Batch, BlockHash, BlockHeight, Context, Funding, Genesis, MAX_EDGE_OUTPUTS, Parties, PartyKeys,
    Payout, ProtocolCode, REGISTRY_CHUNK_DATA_CAPACITY, RegistryChunkId, RegistryNamespace,
    RegistryRecordTag, Snapshot, Store, Terms, Tx, View,
};
use support::{FAKE_VERIFIER, FixedStore, coin_id, key, list, open, state};

#[test]
fn view_compacts_sparse_coins_and_sorts_by_id() {
    let low = coin_id(1);
    let mid = coin_id(5);
    let high = coin_id(9);
    let owner = key(7);
    let state = state(
        FixedStore::empty([high, low, mid], []),
        [
            Genesis::coin(high, owner, 9),
            Genesis::coin(low, owner, 1),
            Genesis::coin(mid, owner, 5),
        ],
    );

    let view = state.view();
    let ids = view.coins().map(|(id, _)| id).collect::<Vec<_>>();

    assert_eq!(view.coin_len(), 3);
    assert_eq!(ids, vec![low, mid, high]);
    assert_eq!(view.coin(low).map(hellas_kernel::Coin::value), Some(1));
    assert_eq!(view.coin(mid).map(hellas_kernel::Coin::value), Some(5));
    assert_eq!(view.coin(high).map(hellas_kernel::Coin::value), Some(9));
}

#[test]
fn view_compacts_sparse_edges_and_sorts_by_id() {
    let maker = key(7);
    let taker = key(8);
    let maker_a = coin_id(1);
    let taker_a = coin_id(2);
    let maker_b = coin_id(3);
    let taker_b = coin_id(4);
    let funding_a = Funding::new(list(&[maker_a]), list(&[taker_a]));
    let funding_b = Funding::new(list(&[maker_b]), list(&[taker_b]));
    let terms_a = terms(maker, taker, 1);
    let terms_b = terms(maker, taker, 2);
    let edge_a = Tx::edge_id_of(&funding_a, &terms_a);
    let edge_b = Tx::edge_id_of(&funding_b, &terms_b);
    let open_a = open(
        funding_a,
        terms_a,
        (
            hellas_kernel::PartyKeys::sole(maker),
            hellas_kernel::Authority::Owner,
        ),
        (
            hellas_kernel::PartyKeys::sole(taker),
            hellas_kernel::Authority::Owner,
        ),
    );
    let open_b = open(
        funding_b,
        terms_b,
        (
            hellas_kernel::PartyKeys::sole(maker),
            hellas_kernel::Authority::Owner,
        ),
        (
            hellas_kernel::PartyKeys::sole(taker),
            hellas_kernel::Authority::Owner,
        ),
    );
    let mut expected = vec![edge_a, edge_b];
    expected.sort();
    let mut state = state(
        FixedStore::empty(
            [maker_a, taker_a, maker_b, taker_b],
            [expected[1], expected[0]],
        ),
        [
            Genesis::coin(maker_a, maker, 10),
            Genesis::coin(taker_a, taker, 5),
            Genesis::coin(maker_b, maker, 10),
            Genesis::coin(taker_b, taker, 5),
        ],
    );
    let context = Context::new(
        support::NETWORK,
        BlockHeight::new(1),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
    );

    state
        .apply(context, &FAKE_VERIFIER, &open_a)
        .expect("first edge opens");
    state
        .apply(context, &FAKE_VERIFIER, &open_b)
        .expect("second edge opens");
    let ids = state.view().edges().map(|(id, _)| id).collect::<Vec<_>>();

    assert_eq!(ids, expected);
}

fn terms(maker: hellas_kernel::Key, taker: hellas_kernel::Key, protocol: u8) -> Terms {
    let first = Payout::new(maker, 10);
    let mut outputs = [first; MAX_EDGE_OUTPUTS];
    outputs[1] = Payout::new(taker, 5);
    let outputs = hellas_kernel::List::new(outputs, 2).expect("two payouts fit");
    Terms::basic(
        ProtocolCode::new(protocol),
        Parties::new(PartyKeys::sole(maker), PartyKeys::sole(taker)),
        BlockHeight::new(9),
        outputs,
    )
}

// -- Registry -----------------------------------------------------------
//
// The view is what the invariant harnesses observe. If a registry chunk
// is invisible here, no conservation or shape test can see a registry
// bug either, so these pin both halves: that chunks reach the view at
// all, and that the view refuses to reassemble a value whose chunk set
// was corrupted.

const REGISTRY_KEY: [u8; 32] = [0x5b; 32];
const OTHER_KEY: [u8; 32] = [0x5c; 32];
const NAMESPACE: RegistryNamespace = RegistryNamespace::PaymentClose;
const RECORD: RegistryRecordTag = RegistryRecordTag::PaymentPending;

type RegistryStore = FixedStore<0, 0, 5>;

fn slot(key: [u8; 32], index: u8) -> RegistryChunkId {
    RegistryChunkId::derive(support::NETWORK, NAMESPACE, key, index)
}

/// A value distinct at every byte position, so a chunk that copies the
/// wrong window or lands in the wrong slot changes the reassembly.
fn body(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| {
            u8::try_from(index % 251)
                .expect("under 256")
                .wrapping_add(1)
        })
        .collect()
}

fn chunk_of(value: &[u8], index: u8) -> hellas_kernel::RegistryChunk {
    hellas_kernel::RegistryChunk::split(NAMESPACE, RECORD, value, index)
        .expect("value splits at this index")
}

/// Five declared slots: three for a three-chunk value, one for the
/// stale-tail case, and one keyed to a different logical value.
fn registry_store() -> RegistryStore {
    FixedStore::empty_with_registry(
        [],
        [],
        [
            slot(REGISTRY_KEY, 0),
            slot(REGISTRY_KEY, 1),
            slot(REGISTRY_KEY, 2),
            slot(REGISTRY_KEY, 3),
            slot(OTHER_KEY, 1),
        ],
    )
}

/// Writes `chunks` into their slots and returns the resulting view.
fn view_of(chunks: &[(RegistryChunkId, hellas_kernel::RegistryChunk)]) -> View<0, 0, 5> {
    let mut store = registry_store();
    {
        let mut batch = store.begin();
        for (id, chunk) in chunks {
            batch
                .insert_registry_chunk(*id, *chunk)
                .expect("declared slot accepts its chunk");
        }
        batch.commit();
    }
    store.view()
}

fn value_chunks(value: &[u8]) -> Vec<(RegistryChunkId, hellas_kernel::RegistryChunk)> {
    let count = hellas_kernel::RegistryChunk::chunk_count_for(value.len()).expect("splittable");
    (0..count)
        .map(|index| (slot(REGISTRY_KEY, index), chunk_of(value, index)))
        .collect()
}

#[test]
fn view_compacts_sparse_registry_chunks_and_sorts_by_id() {
    let value = body(2 * REGISTRY_CHUNK_DATA_CAPACITY + 3);
    let chunks = value_chunks(&value);
    let view = view_of(&chunks);

    let ids = view.registry_chunks().map(|(id, _)| id).collect::<Vec<_>>();
    let mut expected = chunks.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    expected.sort();

    assert_eq!(view.registry_len(), 3);
    assert_eq!(ids, expected, "chunks are canonically sorted by id");
    for (id, chunk) in &chunks {
        assert_eq!(view.registry_chunk(*id), Some(*chunk));
    }
}

#[test]
fn registry_value_reassembles_exactly_the_bytes_that_were_split() {
    for len in [
        1,
        REGISTRY_CHUNK_DATA_CAPACITY,
        2 * REGISTRY_CHUNK_DATA_CAPACITY + 3,
    ] {
        let value = body(len);
        let view = view_of(&value_chunks(&value));
        let mut buf = [0_u8; 3 * REGISTRY_CHUNK_DATA_CAPACITY];

        assert_eq!(
            view.registry_value(support::NETWORK, NAMESPACE, REGISTRY_KEY, &mut buf),
            Some((RECORD, value.as_slice())),
            "a {len}-byte value round trips through split and reassembly",
        );
    }
}

#[test]
fn registry_value_is_absent_when_no_chunk_was_ever_written() {
    let view = view_of(&[]);
    let mut buf = [0_u8; 3 * REGISTRY_CHUNK_DATA_CAPACITY];

    assert_eq!(
        view.registry_value(support::NETWORK, NAMESPACE, REGISTRY_KEY, &mut buf),
        None,
    );
}

/// Each of these is a chunk-set corruption a single chunk's decoder
/// cannot see, because every chunk involved is individually canonical.
/// Reassembly is the only place they can be caught, and each must read
/// as absent rather than as a shorter or spliced value.
#[test]
fn registry_value_refuses_every_corrupted_chunk_set() {
    let value = body(2 * REGISTRY_CHUNK_DATA_CAPACITY + 3);
    let chunks = value_chunks(&value);
    let mut buf = [0_u8; 3 * REGISTRY_CHUNK_DATA_CAPACITY];
    let read = |view: &View<0, 0, 5>, buf: &mut [u8]| {
        view.registry_value(support::NETWORK, NAMESPACE, REGISTRY_KEY, buf)
            .map(|(tag, bytes)| (tag, bytes.to_vec()))
    };

    // Sanity: the intact set does reassemble, so every `None` below is
    // the corruption talking and not the fixture.
    assert!(read(&view_of(&chunks), &mut buf).is_some());

    // A dropped middle chunk.
    let dropped = [chunks[0], chunks[2]];
    assert_eq!(read(&view_of(&dropped), &mut buf), None, "missing index 1");

    // A dropped last chunk: the head still claims three.
    let truncated = [chunks[0], chunks[1]];
    assert_eq!(
        read(&view_of(&truncated), &mut buf),
        None,
        "missing index 2"
    );

    // A chunk stored in a sibling's slot: index 1's body under index 2's
    // id. Both chunks are canonical; only the pairing is wrong.
    let misfiled = [chunks[0], chunks[1], (slot(REGISTRY_KEY, 2), chunks[1].1)];
    assert_eq!(read(&view_of(&misfiled), &mut buf), None, "index mismatch");

    // The same fault where the reassembled length still comes out
    // right: a two-chunk value whose head is stored in both slots. Every
    // field agrees and both halves are full, so the total is exactly the
    // declared length. Only the index a chunk carries can tell this
    // apart from the real value — dropping that one comparison leaves
    // the case above still passing, on the length check, which is
    // exactly how a check goes dead unnoticed.
    let even = body(2 * REGISTRY_CHUNK_DATA_CAPACITY);
    let even_chunks = value_chunks(&even);
    let duplicated = [even_chunks[0], (slot(REGISTRY_KEY, 1), even_chunks[0].1)];
    assert_eq!(
        read(&view_of(&duplicated), &mut buf),
        None,
        "duplicate index at the right total length",
    );

    // A chunk from a value of a different length: index 1 of a shorter
    // value declares a smaller count and length than the head.
    let shorter = body(REGISTRY_CHUNK_DATA_CAPACITY + 1);
    let foreign = hellas_kernel::RegistryChunk::split(NAMESPACE, RECORD, &shorter, 1)
        .expect("shorter value splits");
    let mixed = [chunks[0], (slot(REGISTRY_KEY, 1), foreign), chunks[2]];
    assert_eq!(
        read(&view_of(&mixed), &mut buf),
        None,
        "length disagreement"
    );

    // The same fault at a length the totals cannot see: 241 bytes and
    // 243 bytes both split into three chunks whose first two are full,
    // so a chunk borrowed from the 241-byte value agrees on count and
    // still sums to the declared total. Only the length each chunk
    // carries separates them.
    let near = body(2 * REGISTRY_CHUNK_DATA_CAPACITY + 1);
    let near_chunk = hellas_kernel::RegistryChunk::split(NAMESPACE, RECORD, &near, 1)
        .expect("near-length value splits");
    let near_mixed = [chunks[0], (slot(REGISTRY_KEY, 1), near_chunk), chunks[2]];
    assert_eq!(
        read(&view_of(&near_mixed), &mut buf),
        None,
        "value length disagreement at an identical chunk count and total",
    );

    // A chunk of another record kind in the middle of this record.
    let other_kind =
        hellas_kernel::RegistryChunk::split(NAMESPACE, RegistryRecordTag::BondLease, &value, 1)
            .expect("same value, other record kind");
    let hybrid = [chunks[0], (slot(REGISTRY_KEY, 1), other_kind), chunks[2]];
    assert_eq!(read(&view_of(&hybrid), &mut buf), None, "record tag drift");

    // A chunk whose own namespace is not the one its slot was derived
    // under: the id says `PaymentClose`, the body says `BondLease`.
    let other_namespace =
        hellas_kernel::RegistryChunk::split(RegistryNamespace::BondLease, RECORD, &value, 1)
            .expect("same value, other namespace");
    let crossed = [
        chunks[0],
        (slot(REGISTRY_KEY, 1), other_namespace),
        chunks[2],
    ];
    assert_eq!(read(&view_of(&crossed), &mut buf), None, "namespace drift");

    // A stale tail: a fourth chunk left behind by a longer earlier
    // value. Splicing it in would silently lengthen the record.
    let longer = body(3 * REGISTRY_CHUNK_DATA_CAPACITY + 1);
    let stale = hellas_kernel::RegistryChunk::split(NAMESPACE, RECORD, &longer, 3)
        .expect("longer value has a fourth chunk");
    let tailed = [
        chunks[0],
        chunks[1],
        chunks[2],
        (slot(REGISTRY_KEY, 3), stale),
    ];
    assert_eq!(read(&view_of(&tailed), &mut buf), None, "stale tail chunk");

    // A buffer that cannot hold the value is not a short read.
    let mut small = [0_u8; REGISTRY_CHUNK_DATA_CAPACITY];
    assert_eq!(
        read(&view_of(&chunks), &mut small),
        None,
        "buffer too small"
    );
}

/// The blind spot, pinned so it stays deliberate: a chunk body carries
/// its namespace, record kind, index, count, and length, but not the
/// logical key its id was derived from. Two values of identical shape
/// in one namespace can therefore swap a chunk without reassembly
/// noticing. Only the record's own contents can bind that, and the
/// stored chunk is not the place to fix it — the chunk body is a pinned
/// consensus encoding. A record whose body does not name what it is
/// about is trusting the store to have filed it correctly.
#[test]
fn registry_value_cannot_detect_a_chunk_swapped_between_two_values_of_one_shape() {
    let mine = body(2 * REGISTRY_CHUNK_DATA_CAPACITY + 3);
    let theirs = body(2 * REGISTRY_CHUNK_DATA_CAPACITY + 3)
        .iter()
        .map(|byte| byte.wrapping_add(0x40))
        .collect::<Vec<_>>();
    let chunks = value_chunks(&mine);
    let swapped = [
        chunks[0],
        (slot(REGISTRY_KEY, 1), chunk_of(&theirs, 1)),
        chunks[2],
    ];
    let view = view_of(&swapped);
    let mut buf = [0_u8; 3 * REGISTRY_CHUNK_DATA_CAPACITY];

    let (tag, bytes) = view
        .registry_value(support::NETWORK, NAMESPACE, REGISTRY_KEY, &mut buf)
        .expect("the spliced set is structurally consistent");

    assert_eq!(tag, RECORD);
    assert_ne!(
        bytes,
        mine.as_slice(),
        "the value is not the one that was stored"
    );
    assert_eq!(
        &bytes[REGISTRY_CHUNK_DATA_CAPACITY..2 * REGISTRY_CHUNK_DATA_CAPACITY],
        &theirs[REGISTRY_CHUNK_DATA_CAPACITY..2 * REGISTRY_CHUNK_DATA_CAPACITY],
        "the foreign chunk is spliced in undetected",
    );
}
