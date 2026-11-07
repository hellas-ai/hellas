//! Parsing a real reconstruction response, and fetching a real file.
//!
//! The parsing tests use a response captured from HuggingFace and need
//! no network. The end-to-end fetch does, so it is `#[ignore]`d — run it
//! with `cargo test -p hellas-store -- --ignored`. Its value is that it
//! is the only test proving the three requests compose: token,
//! reconstruction, xorb ranges, reassembly, and the file-hash check.

use futures::StreamExt as _;
use hellas_store::content::*;
use hellas_store::hf::{FetchError, Reconstruction, Repo, RepoKind};

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

#[test]
fn a_range_that_ends_before_it_starts_does_not_parse() {
    let backwards_chunks = format!(
        r#"{{"terms":[{{"hash":"{XORB}","unpacked_length":1,"range":{{"start":9,"end":2}}}}],
            "xorbs":{{}}}}"#
    );
    assert!(matches!(
        Reconstruction::parse(&backwards_chunks),
        Err(FetchError::Malformed(_)),
    ));

    let backwards_bytes = format!(
        r#"{{"terms":[],
            "xorbs":{{"{XORB}":[{{"url":"http://example.invalid",
              "ranges":[{{"chunks":{{"start":0,"end":1}},
                          "bytes":{{"start":100,"end":0}}}}]}}]}}}}"#
    );
    assert!(matches!(
        Reconstruction::parse(&backwards_bytes),
        Err(FetchError::Malformed(_)),
    ));

    // The control: the same shapes, the right way round.
    let forwards = format!(
        r#"{{"terms":[{{"hash":"{XORB}","unpacked_length":1,"range":{{"start":2,"end":9}}}}],
            "xorbs":{{"{XORB}":[{{"url":"http://example.invalid",
              "ranges":[{{"chunks":{{"start":0,"end":1}},
                          "bytes":{{"start":0,"end":100}}}}]}}]}}}}"#
    );
    assert!(Reconstruction::parse(&forwards).is_ok());
}

/// Exercises actual Owner Resolve, immutable acquisition and disk publication.
#[tokio::test]
#[ignore = "requires network access to huggingface.co"]
async fn fetches_the_reference_file_and_verifies_it() {
    let directory = tempfile::tempdir().unwrap();
    let store = DiskStore::open(
        directory.path().into(),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(32 << 20),
        false,
        Default::default(),
    )
    .await
    .unwrap();
    store.finish_recovery().await.unwrap();
    let repo = reference_repo();
    let (sha, root) = store.resolve_hf(&Scope::Owner, repo.clone()).await.unwrap();
    eprintln!("resolved reference dataset at {sha}");
    let pin = PinName::new(format!("hf/{}@{sha}", repo.id)).unwrap();
    let mut pending = vec![(String::new(), root)];
    let mut found = None;
    while let Some((directory, object)) = pending.pop() {
        let at = Path::new(pin.clone(), directory.clone()).unwrap();
        let mut read = store
            .read(&Scope::Owner, &at, 0..object.bytes())
            .await
            .unwrap();
        let mut bytes = Vec::new();
        while let Some(chunk) = read.bytes.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        for (name, target) in Tree::decode(&bytes).unwrap().entries() {
            let name = if directory.is_empty() {
                name.clone()
            } else {
                format!("{directory}/{name}")
            };
            match target {
                Target::Tree(child) => pending.push((name, *child)),
                Target::Object(child) if child.id().to_string() == FILE_ID => {
                    found = Some((name, *child))
                }
                Target::Object(_) => {}
            }
        }
    }
    let (path, expected) = found.expect("reference file in the resolved dataset");
    assert_eq!(expected.bytes(), 63_527_244);
    let name = PinName::new("reference".into()).unwrap();
    let got = store
        .acquire(
            &Scope::Owner,
            Source::HfXet {
                repo: Repo {
                    revision: sha.clone(),
                    ..repo
                },
                commit: sha,
                path: Some(path),
            },
            Some(expected),
            PinTarget {
                name: name.clone(),
                policy: PinPolicy::Owner,
            },
        )
        .await
        .unwrap();
    assert_eq!(got.object, expected);
    let mut read = store
        .read(
            &Scope::Owner,
            &Path::new(name, String::new()).unwrap(),
            0..expected.bytes(),
        )
        .await
        .unwrap();
    let mut hasher = hellas_xet::XetFileHasher::new();
    while let Some(chunk) = read.bytes.next().await {
        hasher.update(&chunk.unwrap());
    }
    let chunks = hasher.finalize_chunks();
    assert_eq!(chunks.len(), 796);
    assert_eq!(
        hellas_xet::file_hash(&chunks).as_bytes(),
        expected.id().as_bytes()
    );
    drop(read);
    store.close().await;
}
