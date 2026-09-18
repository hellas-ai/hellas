use super::*;
use hellas_rpc::cache::CacheKind;

#[test]
fn absent_read_only_index_is_an_empty_cache_without_creating_files() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("absent");
    let store = FsCacheStore::open(&root, false).unwrap();
    assert!(store.list().unwrap().is_empty());
    assert!(
        store
            .get(&CacheKey::hash(CacheKind::Proxy, &[b"miss"]))
            .unwrap()
            .is_none()
    );
    assert!(!root.exists());
}

fn key(value: &[u8]) -> CacheKey {
    CacheKey::hash(CacheKind::Proxy, &[value])
}

#[test]
fn storage_errors_preserve_their_source_type() {
    let directory = tempfile::tempdir().unwrap();
    let not_a_directory = directory.path().join("file");
    fs::write(&not_a_directory, b"file").unwrap();
    let error = FsCacheStore::open(&not_a_directory, false).err().unwrap();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotADirectory
    );
}

#[test]
fn empty_index_is_a_valid_read_only_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    drop(FsCacheStore::open(directory.path(), true).unwrap());
    let reader = FsCacheStore::open(directory.path(), false).unwrap();
    assert!(reader.list().unwrap().is_empty());
    assert!(reader.get(&key(b"miss")).unwrap().is_none());
}

#[test]
fn objects_are_deduplicated_and_input_mappings_survive_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let store = FsCacheStore::open(directory.path(), true).unwrap();
    assert!(FsCacheStore::open(directory.path(), true).is_err());
    store.insert(&key(b"one"), b"answer", 42).unwrap();
    store.insert(&key(b"two"), b"answer", 43).unwrap();
    store.insert(&key(b"one"), b"replacement", 44).unwrap();
    assert_eq!(store.get(&key(b"one")).unwrap().unwrap(), b"answer");
    let entries = store.list().unwrap();
    assert_eq!(entries[0].output, entries[1].output);
    assert_eq!(
        fs::read_dir(directory.path().join("objects"))
            .unwrap()
            .count(),
        1
    );
    assert!(store.remove(&key(b"one")).unwrap());
    assert_eq!(store.get(&key(b"two")).unwrap().unwrap(), b"answer");
    drop(store);
    let reader = FsCacheStore::open(directory.path(), false).unwrap();
    assert_eq!(reader.list().unwrap().len(), 1);
    assert_eq!(reader.get(&key(b"two")).unwrap().unwrap(), b"answer");
    assert!(reader.remove(&key(b"two")).is_err());
    assert!(reader.insert(&key(b"one"), b"answer", 42).is_err());
}

#[test]
fn index_queries_do_not_read_objects_but_replay_verifies_them() {
    let directory = tempfile::tempdir().unwrap();
    let store = FsCacheStore::open(directory.path(), true).unwrap();
    store.insert(&key(b"one"), b"answer", 42).unwrap();
    let entry = store.list().unwrap().remove(0);
    fs::write(
        directory
            .path()
            .join("objects")
            .join(entry.output.to_string()),
        b"broken",
    )
    .unwrap();
    assert_eq!(store.list().unwrap().len(), 1);
    assert!(store.get(&key(b"one")).is_err());
    assert!(store.remove(&key(b"one")).unwrap());
}

#[test]
fn unsupported_index_is_not_silently_replaced() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join(INDEX),
        serde_ipld_dagcbor::to_vec(&Index {
            version: 2,
            entries: Vec::new(),
            generation: 0,
        })
        .unwrap(),
    )
    .unwrap();
    assert!(FsCacheStore::open(directory.path(), true).is_err());
}

#[test]
fn clear_is_atomic_preserves_objects_and_prevents_late_publication() {
    use hellas_rpc::cache::CacheRecording;
    use std::sync::Arc;
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(FsCacheStore::open(directory.path(), true).unwrap());
    store.insert(&key(b"one"), b"shared object", 42).unwrap();
    let old = CacheRecording::new(store.clone()).unwrap();
    let generation = store.generation().unwrap();
    let preview = store
        .evict(&Eviction {
            dry_run: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(preview, [key(b"one")]);
    assert_eq!(store.generation().unwrap(), generation);
    assert_eq!(store.evict(&Eviction::default()).unwrap(), preview);
    old.insert(&key(b"late"), b"late result", 43).unwrap();
    assert!(store.list().unwrap().is_empty());
    assert_eq!(
        fs::read_dir(directory.path().join("objects"))
            .unwrap()
            .count(),
        1
    );
    let reader = FsCacheStore::open(directory.path(), false).unwrap();
    assert!(reader.list().unwrap().is_empty());
    assert!(reader.evict(&Eviction::default()).is_err());
    store.insert(&key(b"fresh"), b"fresh result", 44).unwrap();
    assert_eq!(store.list().unwrap().len(), 1);
}
