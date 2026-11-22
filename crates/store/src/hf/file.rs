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

impl PinnedFile {
    /// Select the named file, or the only file with the requested extension.
    pub fn resolve(
        uri: &str,
        extension: &str,
        pool: &crate::content::Reservations,
    ) -> Result<Self> {
        let (id, tail) = uri
            .split_once('@')
            .ok_or_else(|| FetchError::Malformed("expected hf://org/repo@SHA[/file]".into()))?;
        let (revision, selector) = tail
            .split_once('/')
            .map_or((tail, None), |(rev, file)| (rev, Some(file)));
        if !immutable_sha(revision) {
            return Err(FetchError::Malformed(
                "model reference requires a 40-hex commit".into(),
            ));
        }
        let repo = Repo::from_uri(&format!("{id}@{revision}"))?;
        let (files, _charges) = HfCas::new(repo.clone()).files(pool)?;
        let mut matching = files.into_iter().filter(|file| {
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
        let id = file
            .xet_hash
            .and_then(|id| id.parse().ok())
            .ok_or_else(|| FetchError::Malformed("file has no published Xet identity".into()))?;
        Ok(Self {
            repo,
            path: file.path,
            object: ContentRef::new(id, file.size),
        })
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
