use std::path::{Path, PathBuf};
const IDENTITY_DIR: &str = ".hellas";

pub(crate) fn resolve_home(explicit: Option<&Path>) -> anyhow::Result<PathBuf> {
    let selected = explicit
        .map(Path::to_owned)
        .or_else(|| std::env::var_os("HELLAS_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(IDENTITY_DIR)))
        .ok_or_else(|| anyhow::anyhow!("set --home or HELLAS_HOME"))?;
    std::path::absolute(selected).map_err(Into::into)
}
