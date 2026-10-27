//! The machinery this slice deleted has no reachable caller.
//!
//! The current per-channel job archive replaces an earlier reusable-slot
//! design: identity-wide counterparty-loss accounting and its second
//! journal, the interrupted two-file terminal, the loss-of-a-job cause
//! rule, and the paid-twice error that design alone could construct.
//! None of it is behind a feature or a
//! `cfg` — it is gone — and the proof that it is gone rather than merely
//! unused is that its names appear nowhere in this crate's production
//! source. A caller that could reach it would have to name it, and
//! nothing does.

use std::fs;
use std::path::Path;

/// The identifiers the deleted machinery was reached through. Each named
/// exactly one deleted thing, so a single occurrence anywhere in `src`
/// would be a reachable caller.
const DELETED: &[&str] = &[
    "CounterpartyLoss",
    "paid_work_ids",
    "finish_interrupted_ending",
    "next_proposal_nonce",
    "LossTotals",
    "loss_of",
    // `PaidWorkError::Duplicate` — its only constructor left with
    // `paid_work_ids`, so the variant went with it. The brace keeps
    // this from matching the unrelated `DuplicateFunding` and wire
    // `Duplicate` status.
    "Duplicate {",
];

#[test]
fn the_deleted_machinery_is_named_nowhere_in_production_source() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let rpc_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rpc/src");
    let mut offenders = Vec::new();
    scan(&src, &mut offenders);
    scan(&rpc_src, &mut offenders);
    assert!(
        offenders.is_empty(),
        "deleted machinery is still named in production source: {offenders:?}",
    );
}

/// Nothing reachable from outside this module returns the endpoint, or
/// a borrow of one.
///
/// This is about the shape of the surface rather than one spelling of
/// it. Every `pub` and `pub(crate)` signature in the work source is
/// read and its *return type* examined, so a renamed accessor, a
/// reformatted signature, a `pub(crate)` one, or a second method with
/// another name entirely are all offenders — which the earlier scan for
/// the exact text `pub fn endpoint(` was not able to say.
///
/// A handout is not a style violation, it is the whole of the
/// authority: with a borrow in hand a caller reads on past a close
/// duty, copies a duty another driver already took, and holds the
/// request path's lock across a chain wait. `ChannelDriver` is what the
/// surface offers in its place, and there is one of it at a time.
///
/// The parameter side is deliberately not examined: `WorkService::new`
/// consumes a `ProviderEndpoint`, and taking one is the opposite of
/// handing one out.
///
/// What this is, exactly: a textual tripwire over return types, not a
/// complete constraint on the surface. It reads the source of one file
/// and matches the two spellings below, so a type alias for the
/// endpoint, a `pub` field holding one, a trait method that hands one
/// back, or a callback parameter such as `FnOnce(&mut ProviderEndpoint)`
/// would all pass it. It catches the accessor that gets added back,
/// which is the regression that actually happens; it does not prove the
/// surface cannot leak.
#[test]
fn no_public_signature_returns_the_endpoint_or_a_borrow_of_it() {
    let work = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/work.rs");
    let source = match fs::read_to_string(&work) {
        Ok(source) => source,
        Err(error) => panic!("{} is readable: {error}", work.display()),
    };
    let returns = public_returns(&source);
    assert!(
        returns.len() > 20,
        "the scan read {} public signatures, which is too few to be reading this file",
        returns.len(),
    );
    let handouts: Vec<&String> = returns
        .iter()
        .filter(|returned| returned.contains("ProviderEndpoint") || returned.contains("MutexGuard"))
        .collect();
    assert!(
        handouts.is_empty(),
        "the endpoint is handed out again, and with it the raw cursor path: {handouts:?}",
    );
}

/// The return type of every `pub`/`pub(crate)` function in `source`,
/// as written.
///
/// A signature runs from the line its visibility is on to the brace that
/// opens its body, so a return type broken across lines or trailed by a
/// `where` clause is read whole.
fn public_returns(source: &str) -> Vec<String> {
    let mut returns = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    for (start, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("pub") || !trimmed.contains(" fn ") {
            continue;
        }
        let mut signature = String::new();
        for tail in &lines[start..] {
            signature.push(' ');
            signature.push_str(tail.trim());
            if tail.contains('{') || tail.trim_end().ends_with(';') {
                break;
            }
        }
        let Some((_, returned)) = signature.split_once("->") else {
            continue;
        };
        returns.push(
            returned
                .trim()
                .trim_end_matches(['{', ';'])
                .trim()
                .to_owned(),
        );
    }
    returns
}

fn scan(dir: &Path, offenders: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => panic!("the source tree is readable at {}: {error}", dir.display()),
    };
    for entry in entries {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(error) => panic!("a source entry is readable: {error}"),
        };
        if path.is_dir() {
            scan(&path, offenders);
            continue;
        }
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => panic!("{} is readable: {error}", path.display()),
        };
        for name in DELETED {
            if text.contains(name) {
                offenders.push(format!("{} names `{name}`", path.display()));
            }
        }
    }
}
