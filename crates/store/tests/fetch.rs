//! Parsing a real reconstruction response, and fetching a real file.
//!
//! The parsing tests use a response captured from HuggingFace and need
//! no network. The end-to-end fetch does, so it is `#[ignore]`d — run it
//! with `cargo test -p hellas-store -- --ignored`. Its value is that it
//! is the only test proving the three requests compose: token,
//! reconstruction, xorb ranges, reassembly, and the file-hash check.

use std::sync::Arc;

use hellas_store::hf::{HfCas, Reconstruction, Repo, RepoKind};
use hellas_store::{ContentStore, Fetcher};
use hellas_xet::XetHash;

/// Captured from `/v2/reconstructions/118a5332…` for the Xet spec's
/// reference dataset.
const RECONSTRUCTION: &str = include_str!("vectors/reference-reconstruction.json");

const FILE_ID: &str = "118a53328412787fee04011dcf82fdc4acf3a4a1eddec341c910d30a306aaf97";
const XORB: &str = "eea25d6ee393ccae385820daed127b96ef0ea034dfb7cf6da3a950ce334b7632";

fn reference_repo() -> Repo {
    Repo {
        kind: RepoKind::Dataset,
        id: "xet-team/xet-spec-reference-files".to_string(),
        revision: "main".to_string(),
    }
}

#[test]
fn a_real_reconstruction_response_parses() {
    let plan = Reconstruction::parse(RECONSTRUCTION).expect("parse");

    assert_eq!(plan.offset_into_first_range, 0);
    assert_eq!(plan.terms.len(), 1);

    let term = &plan.terms[0];
    assert_eq!(term.xorb.to_string(), XORB);
    // Chunk indices, half-open: two chunks, 0 and 1.
    assert_eq!(term.chunks, 0..2);
    assert_eq!(term.unpacked_length, 237_171);
}

/// The two range conventions in one object are the easiest thing to get
/// wrong, so assert both shapes explicitly rather than trusting that
/// the parse "looked right".
#[test]
fn chunk_ranges_are_half_open_and_byte_ranges_are_inclusive() {
    let plan = Reconstruction::parse(RECONSTRUCTION).expect("parse");
    let ranges = plan.ranges_for(&plan.terms[0]);
    assert_eq!(ranges.len(), 1);

    let range = ranges[0];
    assert_eq!(range.chunks, 0..2, "chunks are half-open");
    assert_eq!(*range.bytes.start(), 0);
    assert_eq!(*range.bytes.end(), 50_468, "bytes are inclusive");
    // 0..=50_468 is 50_469 bytes, which is exactly what the CDN served.
    assert_eq!(range.bytes.end() - range.bytes.start() + 1, 50_469);
    // The URL is CloudFront-signed. Observed params on this response:
    // user_id, repo_id, Expires, Policy, Signature, Key-Pair-Id — and
    // notably NOT X-Xet-Signed-Range, which the docs describe but this
    // single-range response does not carry.
    assert!(range.url.contains("Signature="));
    assert!(range.url.contains("Expires="));
}

#[test]
fn a_malformed_response_is_refused_rather_than_half_read() {
    assert!(Reconstruction::parse("{}").is_err());
    assert!(Reconstruction::parse("not json").is_err());
    assert!(Reconstruction::parse(r#"{"terms":[],"xorbs":{}}"#).is_ok());
    // A term whose hash is not a hash must not parse into a zero hash.
    assert!(
        Reconstruction::parse(
            r#"{"terms":[{"hash":"nope","unpacked_length":1,"range":{"start":0,"end":1}}],"xorbs":{}}"#
        )
        .is_err()
    );
}

/// End to end against production. Ignored by default: needs network.
#[test]
#[ignore = "requires network access to huggingface.co"]
fn fetches_the_reference_file_and_verifies_it() {
    let id = FILE_ID.parse::<XetHash>().expect("file id");
    let dir = std::env::temp_dir().join(format!("hellas-fetch-{}", std::process::id()));
    let dest = dir.join("reference.csv");
    let _ = std::fs::remove_dir_all(&dir);

    let store = ContentStore::new();
    let source = HfCas::new(reference_repo());
    let indexed = store
        .materialize(id, &dest, &source)
        .expect("materialize the reference file");

    assert_eq!(indexed.id, id, "content must hash to what we asked for");
    assert_eq!(indexed.len, 63_527_244, "x-linked-size for this file");
    assert_eq!(indexed.chunks.len(), 796, "the published chunk count");
    assert!(store.have(id));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A fetcher that writes the wrong bytes must not leave them in the
/// store under a name they do not own.
#[test]
fn content_that_does_not_hash_to_its_id_is_not_kept() {
    struct Liar;
    impl Fetcher for Liar {
        fn name(&self) -> &str {
            "liar"
        }
        fn fetch(
            &self,
            _id: XetHash,
            dest: &std::path::Path,
            _expected: Option<&[hellas_xet::Chunk]>,
        ) -> Result<u64, hellas_store::hf::FetchError> {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).expect("parent");
            }
            std::fs::write(dest, b"not the content you asked for").expect("write");
            Ok(29)
        }
    }

    let dir = std::env::temp_dir().join(format!("hellas-liar-{}", std::process::id()));
    let dest = dir.join("lie.bin");
    let _ = std::fs::remove_dir_all(&dir);

    let wanted = XetHash::hash(b"the real content");
    let store = ContentStore::new();
    let outcome = store.materialize(wanted, &dest, &Liar);

    assert!(outcome.is_err(), "a wrong-content fetch must fail");
    assert!(!dest.exists(), "and must not leave the bytes behind");
    assert!(!store.have(wanted));
    let _ = std::fs::remove_dir_all(&dir);

    // Silence the unused-import warning for Arc in builds where the
    // ignored test is not compiled in.
    let _ = Arc::new(0_u8);
}

/// Publishing verified bytes must not follow, truncate, or half-write a
/// destination.
///
/// `std::fs::write` did all three. The bytes are verified before this
/// point and cannot change; the *destination* can, and a symlink at
/// `dest` sent the whole download somewhere else entirely.
#[cfg(unix)]
#[test]
fn verified_bytes_are_published_atomically_and_follow_nothing() {
    use hellas_store::hf::publish;

    let dir = std::env::temp_dir().join(format!("hellas-publish-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");

    // Ordinary case: the bytes land, and nothing is left beside them.
    let dest = dir.join("weights").join("model.safetensors");
    publish(&dest, b"the verified bytes").expect("publish");
    assert_eq!(
        std::fs::read(&dest).expect("read back"),
        b"the verified bytes",
    );
    assert_eq!(
        std::fs::read_dir(dest.parent().expect("parent"))
            .expect("list")
            .count(),
        1,
        "a temporary file was left behind",
    );

    // Replacing: the old content is gone, in one step.
    publish(&dest, b"newer verified bytes").expect("publish again");
    assert_eq!(
        std::fs::read(&dest).expect("read back"),
        b"newer verified bytes",
    );

    // A symlink at the destination is replaced, not followed. Without
    // this the download lands wherever the link points — which, in a
    // HuggingFace cache, is a blob some other model is using.
    let elsewhere = dir.join("someone-elses-file");
    std::fs::write(&elsewhere, b"not to be touched").expect("write");
    let link = dir.join("linked-dest");
    std::os::unix::fs::symlink(&elsewhere, &link).expect("symlink");
    publish(&link, b"the verified bytes").expect("publish through a symlink");
    assert_eq!(
        std::fs::read(&elsewhere).expect("read back"),
        b"not to be touched",
        "publishing followed the symlink and overwrote another file",
    );
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("stat")
            .file_type()
            .is_file(),
        "the destination must be the file itself, not a link to one",
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The check inside `HfCas::fetch` that a happy-path test can never
/// exercise: assembled bytes that are not the content we asked for.
#[test]
fn assembled_bytes_are_refused_unless_they_hash_to_the_requested_id() {
    use hellas_store::hf::verified;

    let content = b"the content that was asked for".to_vec();
    let id = XetHash::hash(&content);

    assert_eq!(
        verified(id, &content, 0).expect("matching content"),
        &content[..]
    );

    // Right length, wrong bytes.
    let mut tampered = content.clone();
    tampered[0] ^= 0xff;
    assert!(
        verified(id, &tampered, 0).is_err(),
        "tampered bytes must be refused"
    );

    // Correct bytes, wrong id.
    assert!(verified(XetHash::hash(b"something else"), &content, 0).is_err());

    // The offset applies before hashing, so a response with a leading
    // partial chunk still verifies once trimmed.
    let mut padded = vec![0_u8; 5];
    padded.extend_from_slice(&content);
    assert_eq!(verified(id, &padded, 5).expect("trimmed"), &content[..]);
    assert!(
        verified(id, &padded, 4).is_err(),
        "a wrong offset must not verify"
    );
    assert!(
        verified(id, &padded, 999).is_err(),
        "an absurd offset is refused"
    );
}
