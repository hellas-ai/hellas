use std::fs;
use std::io::Write;
use std::path::Path;

use crate::{ContentStore, Indexed};

/// Atomic publication shared by objects and their indexes. Callers serialize
/// index replacement; object publication uses a no-clobber hard link.
pub(crate) fn publish(path: &Path, bytes: &[u8], immutable: bool) -> std::io::Result<()> {
    let parent = path.parent().expect("store object has a parent");
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    if immutable {
        match fs::hard_link(temporary.path(), path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    } else {
        temporary.persist(path).map_err(|error| error.error)?;
    }
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

impl ContentStore {
    /// Add bytes to the owned object directory and index their Xet identity.
    /// Existing objects must still verify; they are never overwritten.
    pub fn put(
        &self,
        root: &Path,
        bytes: &[u8],
    ) -> Result<Indexed, Box<dyn std::error::Error + Send + Sync>> {
        let id = hellas_xet::XetHash::hash(bytes);
        let path = root.join("objects").join(id.to_string());
        publish(&path, bytes, true)?;
        let indexed = self.index(&path)?;
        if indexed.id != id {
            return Err(format!("corrupt existing object {id}").into());
        }
        #[cfg(unix)]
        fs::File::open(root)?.sync_all()?;
        Ok(indexed)
    }
}
