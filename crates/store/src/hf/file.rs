//! Metadata and exact byte ranges of an immutable Hub file.
use super::*;
use hellas_rpc::ContentRef;
use std::ops::Range;

#[derive(Clone)]
pub struct PinnedFile {
    pub repo: Repo,
    pub path: String,
    pub object: ContentRef,
    downloaded: Option<std::sync::Arc<tempfile::NamedTempFile>>,
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
        PinnedFile::from_entry(&HfCas::new(self.repo.clone()), self.entry(path)?)
    }

    /// Bounded metadata, including ordinary Git objects without a Xet identity.
    pub fn metadata(&self, path: &str, limit: u64) -> Result<Vec<u8>> {
        let file = self.entry(path)?;
        let size = file.size;
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
        use sha2::Digest as _;
        if file
            .advertised()?
            .is_some_and(|expected| ContentRef::for_bytes(&bytes) != expected)
            || file
                .lfs_sha256()?
                .is_some_and(|expected| <[u8; 32]>::from(sha2::Sha256::digest(&bytes)) != expected)
        {
            return Err(FetchError::Malformed(format!(
                "incorrect metadata digest for {path}"
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
    pub fn new(repo: Repo, path: String, object: ContentRef) -> Self {
        Self {
            repo,
            path,
            object,
            downloaded: None,
        }
    }

    fn from_entry(cas: &HfCas, file: &RepoFile) -> Result<Self> {
        if let Some(object) = file.advertised()? {
            return Ok(Self::new(cas.repo.clone(), file.path.clone(), object));
        }
        use sha2::Digest as _;
        use std::io::Write as _;
        let io_error = |source| FetchError::Io {
            context: file.path.clone(),
            source,
        };
        let expected = file.lfs_sha256()?;
        let mut sha = expected.map(|_| sha2::Sha256::new());
        let mut saved = tempfile::NamedTempFile::new().map_err(io_error)?;
        let mut input = cas.small_file(&file.path)?;
        let indexed = crate::index_stream(&mut input, file.size, |bytes| {
            if let Some(digest) = &mut sha {
                digest.update(bytes);
            }
            saved.write_all(bytes)
        })
        .map_err(io_error)?
        .ok_or_else(|| FetchError::Malformed(format!("incorrect file length for {}", file.path)))?;
        if let Some((digest, hash)) = sha.zip(expected)
            && <[u8; 32]>::from(digest.finalize()) != hash
        {
            return Err(FetchError::Malformed(format!(
                "incorrect LFS SHA-256 for {}",
                file.path
            )));
        }
        Ok(Self {
            repo: cas.repo.clone(),
            path: file.path.clone(),
            object: ContentRef::new(
                hellas_rpc::ContentId::from_bytes(indexed.id.into_bytes()),
                indexed.len,
            ),
            downloaded: Some(std::sync::Arc::new(saved)),
        })
    }
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
        if let Some(saved) = &self.downloaded {
            use std::io::{Seek as _, SeekFrom};
            return (|| {
                let mut input = saved.reopen()?;
                input.seek(SeekFrom::Start(range.start))?;
                let len = range.end - range.start;
                if std::io::copy(&mut input.take(len), out)? != len {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                Ok(())
            })()
            .map_err(|source| FetchError::Io {
                context: self.path.clone(),
                source,
            });
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
        if store
            .core
            .hub_files(self.object)
            .await?
            .iter()
            .any(|(repo, commit, path)| {
                repo == &self.repo.id && commit == &self.repo.revision && path == &self.path
            })
            && owner_pin(store, &name).await?.is_some_and(|value| {
                value.target == Target::Object(self.object)
                    && value.policy == PinPolicy::Jobs
                    && value.expires.is_none()
            })
        {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::testing::hub;
    #[test]
    fn pinned_git_weights_use_verified_download_for_header_ranges() {
        let metadata = br#"{"tensor":{"dtype":"U8","shape":[4],"data_offsets":[0,4]}}"#;
        let header_size = metadata.len().next_multiple_of(8);
        let mut bytes = (header_size as u64).to_le_bytes().to_vec();
        bytes.extend(metadata);
        bytes.resize(8 + header_size, b' ');
        bytes.extend([1, 2, 3, 4]);
        let path = "shard.safetensors";
        let sha = "a".repeat(40);
        let repo = Repo::from_uri(&format!("hf://org/model@{sha}")).unwrap();
        let oid = "60ef6645a381c2305e5bd66b09ae8a7e82374faaa89c756bf5c54e043e4d05d5";
        for lfs in [
            None,
            Some(serde_json::json!({"oid":oid})),
            Some(serde_json::json!({"oid":"0".repeat(64)})),
        ] {
            let valid = lfs.as_ref().is_none_or(|lfs| lfs["oid"] == oid);
            let (url, serving) = hub(|_| {
                vec![(
                    format!("/org/model/resolve/{sha}/{path}"),
                    200,
                    bytes.to_vec(),
                )]
            });
            let cas = HfCas::new(repo.clone()).with_hub(url);
            let entry = RepoFile {
                path: path.into(),
                size: bytes.len() as u64,
                xet_hash: None,
                lfs,
            };
            let got = PinnedFile::from_entry(&cas, &entry);
            serving.join().unwrap();
            if valid {
                let got = got.unwrap();
                assert_eq!(got.object, ContentRef::for_bytes(&bytes));
                let mut header = Vec::new();
                got.read_range(8..8 + header_size as u64, &mut header)
                    .unwrap();
                assert_eq!(&header[..metadata.len()], metadata);
            } else {
                assert!(got.is_err());
            }
        }
        let entry = RepoFile {
            path: path.into(),
            size: bytes.len() as u64,
            xet_hash: Some("malformed".into()),
            lfs: None,
        };
        assert!(PinnedFile::from_entry(&HfCas::new(repo), &entry).is_err());
    }
}
