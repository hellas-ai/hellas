//! Application-owned retained-job trees. The store only sees canonical trees.
use hellas_rpc::{ContentId, ContentRef};
use hellas_store::content::{MAX_TREE_ENTRIES, Target, Tree};
use std::collections::BTreeMap;

pub(crate) struct JobTree {
    pub root: ContentRef,
    pub objects: Vec<(ContentRef, Vec<u8>)>,
}
impl JobTree {
    pub fn bytes(&self) -> Option<u64> {
        self.objects.iter().try_fold(0u64, |total, (_, bytes)| {
            total.checked_add(bytes.len() as u64)
        })
    }
}

pub(crate) fn job_tree(
    closure: &[ContentRef],
    transcript: Option<ContentRef>,
) -> hellas_store::content::Result<JobTree> {
    use hellas_store::content::Error;
    let mut unique = BTreeMap::new();
    for object in closure {
        if unique
            .insert(object.id(), *object)
            .is_some_and(|old| old != *object)
        {
            return Err(Error::Invalid("job closure has conflicting lengths"));
        }
    }
    let mut entries = unique
        .into_values()
        .map(|object| (object.id().to_string(), Target::Object(object)))
        .collect::<Vec<_>>();
    let mut objects = Vec::new();
    // Leave one root entry for the transcript. Subtrees use the full node limit;
    // their first declared id supplies a deterministic, collision-free label.
    while entries.len() >= MAX_TREE_ENTRIES {
        let mut parents = Vec::new();
        for chunk in entries.chunks(MAX_TREE_ENTRIES) {
            let bytes = Tree::new(chunk.to_vec())?.bytes();
            let object = ContentRef::for_bytes(&bytes);
            parents.push((chunk[0].0.clone(), Target::Tree(object)));
            objects.push((object, bytes));
        }
        entries = parents;
    }
    if let Some(transcript) = transcript {
        entries.push(("transcript".into(), Target::Object(transcript)));
    }
    let bytes = Tree::new(entries)?.bytes();
    let root = ContentRef::for_bytes(&bytes);
    objects.push((root, bytes));
    Ok(JobTree { root, objects })
}

pub(crate) fn tree_reservation(
    closure: &[ContentRef],
    max_spool_bytes: u64,
) -> hellas_store::content::Result<u64> {
    use hellas_store::content::Error;
    let initial = job_tree(closure, None)?;
    let replacement = job_tree(
        closure,
        Some(ContentRef::new(
            ContentId::from_bytes([0; 32]),
            max_spool_bytes,
        )),
    )?;
    // Child nodes are identical. Only the old and new root overlap at transcript
    // publication; all object-reference lengths have fixed canonical encoding.
    initial
        .bytes()
        .and_then(|bytes| bytes.checked_add(replacement.objects.last()?.1.len() as u64))
        .ok_or(Error::Capacity)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grouping_starts_at_the_first_node_that_cannot_leave_a_transcript_slot() {
        let closure = (0..MAX_TREE_ENTRIES)
            .map(|index| ContentRef::for_bytes(&(index as u64).to_be_bytes()))
            .collect::<Vec<_>>();
        assert_eq!(
            job_tree(&closure[..MAX_TREE_ENTRIES - 1], None)
                .unwrap()
                .objects
                .len(),
            1
        );
        let grouped = job_tree(&closure, None).unwrap();
        assert_eq!(grouped.objects.len(), 2);
        let root = Tree::decode(&grouped.objects.last().unwrap().1).unwrap();
        assert!(matches!(root.entries()[0].1, Target::Tree(_)));
    }
    #[test]
    fn large_closure_is_bounded_deterministic_and_leaves_room_for_transcript() {
        let closure = (0..=MAX_TREE_ENTRIES)
            .map(|index| ContentRef::for_bytes(&(index as u64).to_be_bytes()))
            .collect::<Vec<_>>();
        let tree = job_tree(&closure, None).unwrap();
        assert!(tree.objects.len() > 1);
        let mut reversed = closure.clone();
        reversed.reverse();
        assert_eq!(job_tree(&reversed, None).unwrap().root, tree.root);
        let transcript = ContentRef::for_bytes(b"transcript");
        let finished = job_tree(&closure, Some(transcript)).unwrap();
        assert_ne!(tree.root, finished.root);
        assert_eq!(
            &tree.objects[..tree.objects.len() - 1],
            &finished.objects[..finished.objects.len() - 1]
        );
        let mut leaves = BTreeMap::new();
        for (_, bytes) in &finished.objects {
            let node = Tree::decode(bytes).unwrap();
            assert!(node.entries().len() <= MAX_TREE_ENTRIES);
            for (name, target) in node.entries() {
                if let Target::Object(object) = target {
                    leaves.insert(name.clone(), *object);
                }
            }
        }
        assert_eq!(leaves.len(), closure.len() + 1);
        assert_eq!(leaves["transcript"], transcript);
        for object in closure {
            assert_eq!(leaves[&object.id().to_string()], object);
        }
    }
}

#[cfg(test)]
async fn stage(
    store: &hellas_store::content::DiskStore,
    scope: &hellas_store::content::Scope,
    bytes: &[u8],
) {
    let mut upload = store
        .stage_output(scope, ContentRef::for_bytes(bytes))
        .await
        .unwrap();
    if !upload.complete() {
        let chunks = hellas_xet::chunk(bytes);
        upload.declare(&chunks, true).await.unwrap();
        let mut offset = 0;
        for chunk in chunks {
            let end = offset + chunk.data_len as usize;
            upload.accept_chunk(&bytes[offset..end]).await.unwrap();
            offset = end;
        }
    }
    assert!(upload.complete());
}
#[tokio::test]
async fn metadata_reservation_fits_real_input_and_transcript_publications_at_exact_capacity() {
    use hellas_auth::Digest;
    use hellas_store::content::*;
    let root = tempfile::tempdir().unwrap();
    let input = b"declared job input";
    let object = ContentRef::for_bytes(input);
    let closure = vec![object];
    let output = b"retained transcript";
    let transcript = ContentRef::for_bytes(output);
    let capacity = object.bytes()
        + transcript.bytes()
        + tree_reservation(&closure, transcript.bytes()).unwrap();
    let store = DiskStore::open(
        root.path().into(),
        vec![],
        IndexMode::Resume,
        Some(capacity),
        Reservations::ram(1 << 20),
    )
    .await
    .unwrap();
    store.finish_recovery().await.unwrap();
    let job = JobId {
        channel: Digest::from_bytes([1; 32]),
        id: Digest::from_bytes([2; 32]),
    };
    let scope = store
        .open_work(job, closure.clone(), object.bytes())
        .await
        .unwrap();
    store
        .reserve_output(
            &scope,
            transcript.bytes() + tree_reservation(&closure, transcript.bytes()).unwrap(),
        )
        .await
        .unwrap();
    let mut upload = store.upload(&scope, object, None).await.unwrap();
    upload
        .declare(&hellas_xet::chunk(input), true)
        .await
        .unwrap();
    upload.accept_chunk(input).await.unwrap();
    let initial = job_tree(&closure, None).unwrap();
    for (_, bytes) in &initial.objects {
        stage(&store, &scope, bytes).await;
    }
    let pin = PinTarget {
        name: PinName::new("channel/job".into()).unwrap(),
        policy: PinPolicy::Channel(job.channel),
    };
    store
        .promote_work(&scope, Target::Tree(initial.root), pin.clone())
        .await
        .unwrap();
    stage(&store, &scope, output).await;
    let finished = job_tree(&closure, Some(transcript)).unwrap();
    for (_, bytes) in &finished.objects {
        stage(&store, &scope, bytes).await;
    }
    store
        .promote_work(&scope, Target::Tree(finished.root), pin)
        .await
        .unwrap();
    assert_eq!(store.stats().unwrap().used, capacity);
    assert_eq!(store.stats().unwrap().outstanding, 0);
    assert!(matches!(
        store
            .stage_output(&scope, ContentRef::for_bytes(b"one more byte"))
            .await,
        Err(Error::Capacity)
    ));
    store.end_work(&scope).await.unwrap();
    store.close().await;
}
