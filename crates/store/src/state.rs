//! Where the store keeps its fast-resume record.
//!
//! `fastresume.bin` records what has already been hashed
//! ([`crate::fastresume`]). It lives in Hellas state and never inside the
//! HuggingFace cache. That cache belongs to somebody else's tool, and
//! writing our bookkeeping into it is how programs end up blamed for
//! each other's bugs — and how a `huggingface-cli delete-cache` takes
//! the record with it.
//!
use std::path::{Path, PathBuf};

#[must_use]
pub fn records_path_at(root: &Path) -> PathBuf {
    root.join(RECORDS_FILE)
}

#[must_use]
pub fn records_path_in(home: &Path) -> PathBuf {
    records_path_at(&home.join("store"))
}

const RECORDS_FILE: &str = "fastresume.bin";
