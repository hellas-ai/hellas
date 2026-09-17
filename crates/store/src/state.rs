//! Where the store keeps its fast-resume record.
//!
//! `fastresume.bin` records what has already been hashed
//! ([`crate::fastresume`]). It lives in Hellas state and never inside the
//! HuggingFace cache. That cache belongs to somebody else's tool, and
//! writing our bookkeeping into it is how programs end up blamed for
//! each other's bugs — and how a `huggingface-cli delete-cache` takes
//! the record with it.
//!
//! `HELLAS_STORE_DIR` moves the directory, for a node whose state does
//! not live under `$HOME` and for tests, which must never read or write
//! the developer's own.

use std::path::{Path, PathBuf};

/// Where this node keeps store state, if it can be determined.
///
/// `HELLAS_STORE_DIR`, else `$HOME/.hellas/store`. `None` rather than a
/// guess when neither is set: writing to a path we invented is worse
/// than telling the operator to name one.
#[must_use]
pub fn dir() -> Option<PathBuf> {
    resolve_dir(
        std::env::var_os("HELLAS_STORE_DIR"),
        std::env::var_os("HOME"),
    )
}

/// Where the fastresume record lives by default.
#[must_use]
pub fn records_path() -> Option<PathBuf> {
    dir().map(|dir| records_path_at(&dir))
}

#[must_use]
pub fn records_path_at(root: &Path) -> PathBuf {
    root.join(RECORDS_FILE)
}

const RECORDS_FILE: &str = "fastresume.bin";

fn resolve_dir(
    override_dir: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    if let Some(dir) = override_dir {
        return Some(PathBuf::from(dir));
    }
    home.map(|home| PathBuf::from(home).join(".hellas/store"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_hellas_state_and_never_a_huggingface_cache() {
        let dir = resolve_dir(None, Some("/home/someone".into())).expect("a home is enough");
        assert_eq!(dir, PathBuf::from("/home/someone/.hellas/store"));
        assert_eq!(
            resolve_dir(Some("/var/lib/hellas".into()), Some("/home/someone".into())),
            Some(PathBuf::from("/var/lib/hellas")),
            "the override must win over $HOME",
        );
        assert_eq!(
            resolve_dir(None, None),
            None,
            "with nowhere to put it, say so rather than invent a path",
        );
    }
}
