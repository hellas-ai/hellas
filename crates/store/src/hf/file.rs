//! Metadata and exact byte ranges of an immutable Hub file.
use super::*;
use hellas_rpc::ContentRef;
use std::ops::Range;

#[derive(Clone)]
pub struct PinnedFile {
    pub repo: Repo,
    pub path: String,
    pub object: ContentRef,
}

/// File metadata at one immutable revision. A single listing covers sharded checkpoints.
pub struct PinnedRepo {
    pub repo: Repo,
    files: Vec<RepoFile>,
    _charges: Vec<std::sync::Arc<crate::content::reservation::Reservation>>,
}

impl PinnedRepo {
    pub fn open(uri: &str, pool: &crate::content::Reservations) -> Result<(Self, Option<String>)> {
        let (id, tail) = uri
            .split_once('@')
            .ok_or_else(|| FetchError::Malformed("expected hf://org/repo@SHA[/file]".into()))?;
        let (revision, selector) = tail
            .split_once('/')
            .map_or((tail, None), |(rev, file)| (rev, Some(file.to_owned())));
        if !immutable_sha(revision) {
            return Err(FetchError::Malformed(
                "model reference requires a 40-hex commit".into(),
            ));
        }
        let repo = Repo::from_uri(&format!("{id}@{revision}"))?;
        let (files, _charges) = HfCas::new(repo.clone()).files(pool)?;
        Ok((
            Self {
                repo,
                files,
                _charges,
            },
            selector,
        ))
    }

    pub fn contains(&self, path: &str) -> bool {
        self.files.iter().any(|f| f.path == path)
    }

    fn entry(&self, path: &str) -> Result<&RepoFile> {
        self.files
            .iter()
            .find(|f| f.path == path)
            .ok_or_else(|| FetchError::Malformed(format!("missing file {path} at pinned revision")))
    }

    /// A weight file whose verified bytes the provider acquires.
    pub fn file(&self, path: &str) -> Result<PinnedFile> {
        let file = self.entry(path)?;
        let id = file
            .xet_hash
            .as_deref()
            .and_then(|id| id.parse().ok())
            .ok_or_else(|| {
                FetchError::Malformed(format!("{path} has no published Xet identity"))
            })?;
        Ok(PinnedFile {
            repo: self.repo.clone(),
            path: file.path.clone(),
            object: ContentRef::new(id, file.size),
        })
    }

    /// Bounded metadata, including ordinary Git objects without a Xet identity.
    pub fn metadata(&self, path: &str, limit: u64) -> Result<Vec<u8>> {
        let size = self.entry(path)?.size;
        if size > limit {
            return Err(FetchError::Malformed(format!(
                "{path} exceeds metadata limit"
            )));
        }
        let mut bytes = Vec::new();
        HfCas::new(self.repo.clone())
            .small_file(path)?
            .take(size + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| FetchError::Io {
                context: path.into(),
                source,
            })?;
        if bytes.len() as u64 != size {
            return Err(FetchError::Malformed(format!(
                "incorrect metadata length for {path}"
            )));
        }
        Ok(bytes)
    }

    pub fn select(&self, extension: &str, selector: Option<&str>) -> Result<PinnedFile> {
        let mut matching = self.files.iter().filter(|file| {
            std::path::Path::new(&file.path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case(extension))
                && selector.is_none_or(|path| file.path == path)
        });
        let file = matching
            .next()
            .ok_or_else(|| FetchError::Malformed("no matching file at pinned revision".into()))?;
        if matching.next().is_some() {
            return Err(FetchError::Malformed(
                "multiple matching files; specify the repository path after the commit".into(),
            ));
        }
        self.file(&file.path)
    }
}

impl PinnedFile {
    pub fn resolve(
        uri: &str,
        extension: &str,
        pool: &crate::content::Reservations,
    ) -> Result<Self> {
        let (repo, selector) = PinnedRepo::open(uri, pool)?;
        repo.select(extension, selector.as_deref())
    }

    pub fn read_range(&self, range: Range<u64>, out: &mut impl std::io::Write) -> Result<()> {
        if range.is_empty() || range.end > self.object.bytes() {
            return Err(FetchError::Malformed("invalid Hub file range".into()));
        }
        let mut url =
            HfCas::new(self.repo.clone()).hub_url(false, &["resolve", &self.repo.revision])?;
        url.path_segments_mut()
            .map_err(|_| FetchError::Malformed("Hub path".into()))?
            .extend(self.path.split('/'));
        let bounds = format!("{}-{}", range.start, range.end - 1);
        let mut response = authenticated_get(url.as_str(), node_token().as_deref())
            .header("Range", &format!("bytes={bounds}"))
            .header("Accept-Encoding", "identity")
            .call()
            .map_err(|source| FetchError::Http {
                context: "Hub file range".into(),
                source: Box::new(source),
            })?;
        if response.status() != 206
            || response
                .headers()
                .get("content-range")
                .and_then(|v| v.to_str().ok())
                != Some(&format!("bytes {bounds}/{}", self.object.bytes()))
        {
            return Err(FetchError::Malformed("incorrect Hub Content-Range".into()));
        }
        let size = range.end - range.start;
        let bytes = std::io::copy(&mut response.body_mut().as_reader().take(size), out).map_err(
            |source| FetchError::Io {
                context: "Hub file range".into(),
                source,
            },
        )?;
        let mut sentinel = [0];
        if bytes != size
            || response
                .body_mut()
                .as_reader()
                .read(&mut sentinel)
                .map_err(|source| FetchError::Io {
                    context: "Hub file range".into(),
                    source,
                })?
                != 0
        {
            return Err(FetchError::Malformed(
                "incorrect Hub file range length".into(),
            ));
        }
        Ok(())
    }
}

impl PinnedFile {
    /// Make this verified object available to local execution jobs.
    pub async fn acquire(&self, store: &crate::content::DiskStore) -> crate::content::Result<()> {
        use crate::content::{
            ContentStore, PinName, PinPolicy, PinTarget, Scope, Source, Target, owner_pin,
        };
        let name = PinName::new(format!("models/{}", self.object.id()))?;
        if owner_pin(store, &name).await?.is_some_and(|value| {
            value.target == Target::Object(self.object)
                && value.policy == PinPolicy::Jobs
                && value.expires.is_none()
        }) {
            return Ok(());
        }
        store
            .acquire(
                &Scope::Owner,
                Source::HfXet {
                    repo: self.repo.clone(),
                    commit: self.repo.revision.clone(),
                    path: Some(self.path.clone()),
                },
                Some(self.object),
                PinTarget {
                    name,
                    policy: PinPolicy::Jobs,
                },
            )
            .await?;
        Ok(())
    }
}
