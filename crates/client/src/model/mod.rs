//! Client-side model assets.
#[cfg(feature = "models")]
pub mod flux;
pub mod gguf;
#[cfg(feature = "models")]
mod package;
#[cfg(feature = "models")]
mod program;
#[cfg(feature = "models")]
pub use package::{ComputeJob, ModelPackage, ModelRequest, ModelResponse};
#[cfg(feature = "models")]
mod qwen3;
#[cfg(feature = "models")]
pub mod whisper;

#[cfg(feature = "models")]
pub mod wav;

#[cfg(feature = "models")]
fn file_content(path: &std::path::Path) -> anyhow::Result<hellas_rpc::ContentRef> {
    use std::io::Read;
    let mut file = hellas_private::open_regular_file(path)?;
    let before = file.metadata()?;
    let mut hasher = hellas_xet::XetFileHasher::new();
    let mut buffer = vec![0; hellas_xet::MAX_CHUNK_SIZE];
    let mut remaining = before.len();
    while remaining != 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let read = file.read(&mut buffer[..wanted])?;
        anyhow::ensure!(read != 0, "model file was truncated while hashing");
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    anyhow::ensure!(file.read(&mut [0])? == 0, "model file grew while hashing");
    #[cfg(unix)]
    let identity = |metadata: &std::fs::Metadata| {
        use std::os::unix::fs::MetadataExt;
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    #[cfg(not(unix))]
    let identity = |metadata: &std::fs::Metadata| {
        (
            metadata.len(),
            metadata.modified().ok(),
            metadata.created().ok(),
        )
    };
    anyhow::ensure!(
        identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&std::fs::metadata(path)?),
        "model file changed while hashing"
    );
    Ok(hellas_rpc::ContentRef::new(
        hellas_rpc::ContentId::from_bytes(hasher.finalize().into_bytes()),
        before.len(),
    ))
}
