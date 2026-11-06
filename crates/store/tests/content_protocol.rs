use hellas_rpc::{ContentId, ContentRef, pb::content as pb};
use hellas_store::content::{
    Cursor, MAX_NAME_BYTES, MAX_PATH_BYTES, MAX_TREE_BYTES, MAX_TREE_ENTRIES, PinName, Target,
    Tree, UploadSession, body_limit, chunk_page,
};
use hellas_wire::canonical::Encode;
use hellas_xet::{Chunk, XetHash, chunk, chunk_hash, file_hash};
use prost::Message;

#[test]
fn tree_has_the_exact_canonical_bytes_and_rejects_noncanonical_input() {
    let empty = ContentRef::new(ContentId::from_bytes([0; 32]), 0);
    let tree = Tree::new(vec![("a".into(), Target::Object(empty))]).unwrap();
    let mut expected = vec![0, 0, 0, 1, 0, 0, 0, 1, b'a', 0];
    expected.extend_from_slice(&[0; 40]);
    assert_eq!(tree.bytes(), expected);
    assert_eq!(tree.encoded_size(), 50);
    let mut trailing = expected.clone();
    trailing.push(0);
    assert!(Tree::decode(&trailing).is_err());
    expected[9] = 2;
    assert!(Tree::decode(&expected).is_err());
    assert!(Tree::decode(&[0, 0, 0, 1]).is_err());
    assert!(
        Tree::new(vec![
            ("a".into(), Target::Object(empty)),
            ("a".into(), Target::Tree(empty))
        ])
        .is_err()
    );
    let ordered = Tree::new(vec![
        ("a".into(), Target::Object(empty)),
        ("b".into(), Target::Object(empty)),
    ])
    .unwrap();
    let mut reversed = ordered.bytes();
    reversed.swap(8, 54);
    assert!(Tree::decode(&reversed).is_err());
}

#[test]
fn tree_and_pin_limits_are_checked_in_bytes() {
    let object = ContentRef::for_bytes(b"leaf");
    for name in ["", ".", "..", "a/b", "a\0b"] {
        assert!(Tree::new(vec![(name.into(), Target::Object(object))]).is_err());
    }
    assert!(
        Tree::new(vec![(
            "x".repeat(MAX_NAME_BYTES + 1),
            Target::Object(object)
        )])
        .is_err()
    );
    let entries = (0..MAX_TREE_ENTRIES)
        .map(|i| {
            (
                format!("{i:05}{}", "x".repeat(MAX_NAME_BYTES - 5)),
                Target::Object(object),
            )
        })
        .collect();
    let tree = Tree::new(entries).unwrap();
    assert_eq!(tree.bytes().len(), MAX_TREE_BYTES);
    assert_eq!(
        Tree::decode(&tree.bytes()).unwrap().entries().len(),
        MAX_TREE_ENTRIES
    );
    let mut entries = tree.entries().to_vec();
    entries.push(("extra".into(), Target::Object(object)));
    assert!(Tree::new(entries).is_err());
    for name in ["", "/a", "a/", "a//b", "a/../b", "a/./b"] {
        assert!(PinName::new(name.into()).is_err());
    }
    assert!(PinName::new("weights/模型".into()).is_ok());
    let path = std::iter::repeat_n("x".repeat(255), 16)
        .collect::<Vec<_>>()
        .join("/");
    assert_eq!(path.len(), MAX_PATH_BYTES - 1);
    assert!(PinName::new(path.clone()).is_ok());
    assert!(PinName::new(format!("{path}/x")).is_err());
}

#[test]
fn upload_requires_a_complete_manifest_and_rejects_noncanonical_boundaries() {
    let data = vec![b'x'; 150_000];
    let descriptors = chunk(&data);
    let mut session = UploadSession::new(ContentRef::for_bytes(&data));
    assert!(!session.complete());
    session.declare(&descriptors, true).unwrap();
    let mut start = 0;
    for descriptor in &descriptors {
        let end = start + descriptor.data_len as usize;
        session.accept_chunk(&data[start..end]).unwrap();
        start = end;
    }
    assert!(session.complete());
    assert!(session.accept_chunk(b"extra").is_err());
    assert!(!session.complete());
    let mut early = UploadSession::new(ContentRef::for_bytes(b"x"));
    assert!(early.accept_chunk(b"x").is_err());
    assert!(early.declare(&chunk(b"x"), true).is_err());

    // Both declared hashes are valid, but an early arbitrary cut changes identity.
    let split = 16_384;
    let wrong = vec![
        Chunk::new(chunk_hash(&data[..split]), split as u64),
        Chunk::new(chunk_hash(&data[split..2 * split]), split as u64),
    ];
    let object = ContentRef::new(
        ContentId::from_bytes(file_hash(&wrong).into_bytes()),
        (2 * split) as u64,
    );
    assert_ne!(object.id(), ContentId::hash(&data[..2 * split]));
    let mut bad = UploadSession::new(object);
    bad.declare(&wrong, true).unwrap();
    let first = bad.accept_chunk(&data[..split]);
    assert!(first.is_err() || bad.accept_chunk(&data[split..2 * split]).is_err());
    assert!(!bad.complete());
}

#[test]
fn empty_object_is_complete_on_declaration_and_bad_lists_poison_sessions() {
    let mut empty = UploadSession::new(ContentRef::new(ContentId::from_bytes([0; 32]), 0));
    empty.declare(&[], true).unwrap();
    assert!(empty.complete());
    let mut wrong = UploadSession::new(ContentRef::for_bytes(b"hello"));
    assert!(wrong.declare(&chunk(b"other"), true).is_err());
    assert!(wrong.declare(&chunk(b"hello"), true).is_err());
    let mut over = UploadSession::new(ContentRef::for_bytes(b"x"));
    assert!(
        over.declare(&[Chunk::new(XetHash::ZERO, u64::MAX)], true)
            .is_err()
    );
}

#[test]
fn chunk_pages_fit_real_protobuf_envelopes_and_bind_the_object() {
    let descriptors = vec![Chunk::new(XetHash::ZERO, 131_072); 40_000];
    let object = ContentRef::new(
        ContentId::from_bytes(file_hash(&descriptors).into_bytes()),
        131_072 * 40_000,
    );
    let page = chunk_page(object, &descriptors, Cursor::default()).unwrap();
    assert!(!page.chunks.is_empty() && page.chunks.len() < descriptors.len());
    let next = page.next.unwrap();
    let encoded = pb::ChunksResponse {
        object: Some(pb::ContentRef {
            id: object.id().as_bytes().to_vec(),
            bytes: object.bytes(),
        }),
        chunks: page
            .chunks
            .iter()
            .map(|c| pb::Chunk {
                hash: c.hash.as_bytes().to_vec(),
                bytes: c.data_len,
            })
            .collect(),
        next: Some(pb::Cursor {
            offset: next.offset,
            generation: next.generation,
            object: Some(pb::ContentRef {
                id: object.id().as_bytes().to_vec(),
                bytes: object.bytes(),
            }),
        }),
    };
    assert!(encoded.encoded_len() <= hellas_wire::mux::DEFAULT_STREAM_WINDOW as usize);
    assert!(encoded.encoded_len() <= body_limit());
    assert!(chunk_page(ContentRef::for_bytes(b"moved"), &descriptors, next).is_err());
    let rest = chunk_page(object, &descriptors, next).unwrap();
    assert_eq!(page.chunks.len() + rest.chunks.len(), descriptors.len());
    assert!(rest.next.is_none());
    let mut upload = UploadSession::new(object);
    assert!(upload.declare(&descriptors, true).is_err());
}
