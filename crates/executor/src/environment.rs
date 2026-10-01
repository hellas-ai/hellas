//! Locally bound content for one Catena causal-LM program.
//!
//! This boundary only admits canonical protocol objects and content already
//! available through a local [`ContentStore`]. It neither acquires nor compiles
//! anything. The manifest root is itself reopened as bounded, verified content,
//! so an accepted paid job can reconstruct the same environment after a
//! restart without depending on a prior in-memory state. The parsed environment
//! is immutable. A paid worker reopens
//! verified descriptors while constructing its persistent safe runtime, so
//! replacing a cache path cannot retarget an already-open descriptor. This is
//! not an inode write seal: provider deployments must keep indexed backing
//! files immutable to untrusted same-UID writers while descriptors or Catena
//! mappings are live. Static objects can then remain resident across
//! invocations without per-execution copies or rehashes.

use std::io::{self, Read as _};
use std::sync::Arc;

use hellas_rpc::{
    CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR, CausalLmEnvironment, ContentId, ContentRef,
    MAX_CAUSAL_LM_ENVIRONMENT_BYTES, ProgramManifest,
};
use hellas_store::{ContentStore, VerifiedFile};

/// A strictly decoded causal-LM environment bound to locally available content.
///
/// Paths and file descriptors remain inside the content store. This value keeps
/// only immutable protocol metadata and a cheap clone of the store handle. The
/// store's read-only descriptors protect against path replacement, not
/// same-inode writes through another descriptor; the backing store is an
/// operational trust boundary.
#[derive(Clone, Debug)]
pub struct CausalLmEnvironmentSource {
    store: ContentStore,
    manifest_id: ContentId,
    environment: Arc<CausalLmEnvironment>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ParsedCausalLmManifest {
    manifest_id: ContentId,
    root: ContentId,
}

impl ParsedCausalLmManifest {
    pub(crate) const fn id(self) -> ContentId {
        self.manifest_id
    }
}

impl CausalLmEnvironmentSource {
    /// Validates and locally binds one canonical Catena causal-LM environment.
    ///
    /// `manifest_bytes` must be the one strict DAG-CBOR spelling. The manifest
    /// must name exactly
    /// `(hellas/catena-gpu-0.0.1, causal-lm-0.0.1)`, and its root must be the
    /// locally indexed Xet content identifier of a strict causal-LM environment.
    /// Every program and static object is opened with its declared identifier
    /// and length before this returns. No fetcher or compiler is consulted.
    pub fn from_manifest_bytes(
        store: &ContentStore,
        manifest_bytes: &[u8],
    ) -> Result<Self, CausalLmEnvironmentSourceError> {
        let manifest = Self::parse_manifest(manifest_bytes)?;
        Self::bind_manifest(store, manifest)
    }

    /// Parses the strict outer manifest without touching its local content.
    ///
    /// Keeping this separate lets the executor identify an already-bound
    /// environment without reopening its root, program, or static objects.
    pub(crate) fn parse_manifest(
        manifest_bytes: &[u8],
    ) -> Result<ParsedCausalLmManifest, CausalLmEnvironmentSourceError> {
        let manifest = ProgramManifest::from_canonical_bytes(manifest_bytes)
            .map_err(|error| CausalLmEnvironmentSourceError::InvalidManifest(error.to_string()))?;

        if (
            manifest.application().evaluator(),
            manifest.application().adaptor(),
        ) != (CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR)
        {
            return Err(CausalLmEnvironmentSourceError::UnsupportedApplication {
                evaluator: manifest.application().evaluator().to_string(),
                adaptor: manifest.application().adaptor().to_string(),
            });
        }

        Ok(ParsedCausalLmManifest {
            manifest_id: manifest.content_id(),
            root: manifest.root(),
        })
    }

    /// Binds one parsed manifest to content that is available and verified now.
    pub(crate) fn bind_manifest(
        store: &ContentStore,
        manifest: ParsedCausalLmManifest,
    ) -> Result<Self, CausalLmEnvironmentSourceError> {
        let environment_file = store
            .open_verified_bounded(
                manifest.root.digest(),
                MAX_CAUSAL_LM_ENVIRONMENT_BYTES as u64,
            )
            .map_err(|_| CausalLmEnvironmentSourceError::InvalidLocalContent { id: manifest.root })?
            .ok_or(CausalLmEnvironmentSourceError::MissingContent { id: manifest.root })?;
        let environment_bytes = read_verified_bytes(environment_file).map_err(|_| {
            CausalLmEnvironmentSourceError::InvalidLocalContent { id: manifest.root }
        })?;
        let environment =
            CausalLmEnvironment::from_canonical_bytes(&environment_bytes).map_err(|error| {
                CausalLmEnvironmentSourceError::InvalidEnvironment(error.to_string())
            })?;

        let bound = Self {
            store: store.clone(),
            manifest_id: manifest.manifest_id,
            environment: Arc::new(environment),
        };
        bound.open_verified_files()?;
        Ok(bound)
    }

    /// The content identifier of the exact canonical manifest admitted here.
    #[must_use]
    pub const fn manifest_id(&self) -> ContentId {
        self.manifest_id
    }

    /// Immutable application-owned metadata below the manifest root.
    #[must_use]
    pub fn environment(&self) -> &CausalLmEnvironment {
        self.environment.as_ref()
    }

    /// Reopens the exact program and ordered static objects for one paid worker.
    ///
    /// The vector follows [`CausalLmEnvironment::static_objects`] order. Each
    /// handle is checked against its indexed file identity and declared length
    /// when opened, so a stale or replaced local path becomes an error. The
    /// returned read-only handle does not make its backing inode immutable.
    pub(crate) fn open_verified_files(
        &self,
    ) -> Result<(VerifiedFile, Vec<VerifiedFile>), CausalLmEnvironmentSourceError> {
        let program = self.open_verified_program()?;
        let static_objects = self
            .environment
            .static_objects()
            .iter()
            .enumerate()
            .map(|(index, _)| self.open_verified_static_object(index))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((program, static_objects))
    }

    /// Reopens only the exact program descriptor. A worker skips this once the
    /// same content ID and declared length are resident in its current session.
    pub(crate) fn open_verified_program(
        &self,
    ) -> Result<VerifiedFile, CausalLmEnvironmentSourceError> {
        open_content(&self.store, self.environment.program())
    }

    /// Reopens one exact static object by its validated environment index.
    pub(crate) fn open_verified_static_object(
        &self,
        index: usize,
    ) -> Result<VerifiedFile, CausalLmEnvironmentSourceError> {
        let content = self
            .environment
            .static_objects()
            .get(index)
            .copied()
            .ok_or(CausalLmEnvironmentSourceError::InvalidEnvironment(
                "static object index is out of bounds".to_string(),
            ))?;
        open_content(&self.store, content)
    }
}

fn open_content(
    store: &ContentStore,
    content: ContentRef,
) -> Result<VerifiedFile, CausalLmEnvironmentSourceError> {
    match store.open_verified(content.id().digest(), content.bytes()) {
        Ok(Some(file)) => Ok(file),
        Ok(None) => Err(CausalLmEnvironmentSourceError::MissingContent { id: content.id() }),
        Err(_) => Err(CausalLmEnvironmentSourceError::InvalidLocalContent { id: content.id() }),
    }
}

/// Consume exactly the length verified by the content store without allowing a
/// concurrently grown inode to turn a bounded metadata read into an unbounded
/// allocation. Reading one sentinel byte also distinguishes growth from an
/// exact read; a short read is rejected as truncation. This is a length guard,
/// not a write seal: a same-length in-place overwrite is outside what this read
/// can detect without rehashing.
pub(crate) fn read_verified_bytes(file: VerifiedFile) -> io::Result<Vec<u8>> {
    let expected_len = file.len();
    let capacity = usize::try_from(expected_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "verified content length does not fit address space",
        )
    })?;
    let read_limit = expected_len.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "verified content length cannot be bounded with a sentinel byte",
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.into_file().take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() != capacity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "verified content length changed: expected {expected_len} bytes, read {}",
                bytes.len()
            ),
        ));
    }
    Ok(bytes)
}

/// Why canonical evaluator metadata could not be bound to local content.
///
/// Store errors are deliberately reduced to content identifiers: local cache
/// paths are operational details and do not cross this executor boundary.
#[derive(Debug, thiserror::Error)]
pub enum CausalLmEnvironmentSourceError {
    /// The outer manifest was not its bounded canonical representation.
    #[error("invalid canonical program manifest: {0}")]
    InvalidManifest(String),
    /// The exact application pair was not the Catena causal-LM contract.
    #[error("unsupported application ({evaluator:?}, {adaptor:?})")]
    UnsupportedApplication { evaluator: String, adaptor: String },
    /// The application-owned environment was not its bounded canonical form.
    #[error("invalid canonical causal-LM environment: {0}")]
    InvalidEnvironment(String),
    /// Declared content was absent from all local store sources.
    #[error("content {id} is not locally available")]
    MissingContent { id: ContentId },
    /// A local source could not prove the declared identifier and length.
    #[error("local content {id} failed verification")]
    InvalidLocalContent { id: ContentId },
}

#[cfg(test)]
mod tests;
