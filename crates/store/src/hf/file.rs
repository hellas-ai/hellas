//! Metadata and exact byte ranges of an immutable Hub file.
use super::*;
use hellas_rpc::ContentRef;
use std::{
    io::{Read, Seek, SeekFrom},
    ops::Range,
    sync::Arc,
};

#[derive(Clone)]
pub struct PinnedFile {
    pub repo: Repo,
    pub path: String,
    pub object: ContentRef,
    downloaded: Option<Arc<tempfile::NamedTempFile>>,
}

/// A model repository, optional ref name and optional file within the repository.
#[derive(Clone, Debug)]
pub struct ModelReference {
    pub repo: Repo,
    pub selector: Option<String>,
}

impl ModelReference {
    pub fn parse(uri: &str) -> Result<Self> {
        if let Some(value) = uri.strip_prefix("hf://") {
            let (org, rest) = value
                .split_once('/')
                .ok_or(FetchError::Locator("missing repository"))?;
            if org.eq_ignore_ascii_case("huggingface.co") {
                return Err(FetchError::Locator("omit huggingface.co/ after hf://"));
            }
            let (name, path) = rest
                .split_once('/')
                .map_or((rest, None), |(name, path)| (name, Some(path)));
            let (repository, revision) = name
                .split_once('@')
                .map_or((name, None), |(name, revision)| (name, Some(revision)));
            return Self::from_parts(org, repository, revision, path);
        }
        let url = url::Url::parse(uri).map_err(|_| FetchError::Locator("invalid Hub URL"))?;
        Self::from_url(&url)
    }

    pub fn from_url(url: &url::Url) -> Result<Self> {
        if url.scheme() != "https"
            || url.host_str() != Some("huggingface.co")
            || url.port().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(FetchError::Locator("expected an HTTPS huggingface.co URL"));
        }
        let mut parts = url
            .path()
            .strip_prefix('/')
            .unwrap_or(url.path())
            .splitn(5, '/');
        let org = parts
            .next()
            .ok_or(FetchError::Locator("missing repository"))?;
        let repository = parts
            .next()
            .ok_or(FetchError::Locator("missing repository"))?;
        let (revision, path) = match parts.next() {
            None => (None, None),
            Some("") if parts.next().is_none() => (None, None),
            Some("tree") => (
                Some(
                    parts
                        .next()
                        .ok_or(FetchError::Locator("missing tree revision"))?,
                ),
                parts.next().filter(|path| !path.is_empty()),
            ),
            Some("resolve" | "blob") => (
                Some(
                    parts
                        .next()
                        .ok_or(FetchError::Locator("missing file revision"))?,
                ),
                Some(
                    parts
                        .next()
                        .ok_or(FetchError::Locator("missing file path"))?,
                ),
            ),
            Some(_) => {
                return Err(FetchError::Locator(
                    "expected /tree/REF, /resolve/REF or /blob/REF",
                ));
            }
        };
        Self::from_parts(org, repository, revision, path)
    }

    fn from_parts(
        org: &str,
        repository: &str,
        revision: Option<&str>,
        path: Option<&str>,
    ) -> Result<Self> {
        let repo = Repo::new(&format!("{org}/{repository}"), revision)?;
        let selector = path
            .map(|path| -> Result<String> {
                let path = percent_encoding::percent_decode_str(path)
                    .decode_utf8()
                    .map_err(|_| FetchError::Locator("invalid UTF-8 in file path"))?;
                crate::content::tree::validate_path(&path, false)
                    .map_err(|_| FetchError::Locator("invalid file path"))?;
                Ok(path.into_owned())
            })
            .transpose()?;
        Ok(Self { repo, selector })
    }
}

/// Whether a gateway selection still needs to interpret its first `@` as a Hub revision.
pub fn is_bare_repo(uri: &str) -> bool {
    ModelReference::parse(uri)
        .is_ok_and(|reference| reference.repo.default_branch && reference.selector.is_none())
}

/// Revisions observed while resolving the inputs of one command or gateway.
pub struct Revisions {
    commits: std::collections::BTreeMap<(String, Option<String>), String>,
    hub: String,
}

impl Default for Revisions {
    fn default() -> Self {
        Self {
            commits: Default::default(),
            hub: HUB.into(),
        }
    }
}

impl Revisions {
    /// Return a pinned URI for a mutable ref. Exact refs do no I/O and keep their spelling.
    pub fn pin(
        &mut self,
        uri: &str,
        pool: &crate::content::Reservations,
        resolved: impl FnOnce(&str, &str),
    ) -> Result<Option<String>> {
        let ModelReference { repo, selector } = ModelReference::parse(uri)?;
        let default_branch = repo.default_branch;
        if immutable_sha(&repo.revision) {
            return Ok(None);
        }
        let key = (
            repo.id.clone(),
            (!default_branch).then(|| repo.revision.clone()),
        );
        let entry = self.commits.entry(key);
        let sha = match entry {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let sha = HfCas::new(repo.clone())
                    .with_hub(&self.hub)
                    .resolve_revision(default_branch, pool)?;
                resolved(&repo.id, &sha);
                entry.insert(sha)
            }
        };
        let mut uri = format!("hf://{}@{sha}", repo.id);
        if let Some(file) = selector {
            const FILE_PATH: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
                .add(b'%')
                .add(b'?')
                .add(b'#')
                .add(b' ');
            uri.push('/');
            uri.push_str(&percent_encoding::utf8_percent_encode(&file, FILE_PATH).to_string());
        }
        Ok(Some(uri))
    }
}

/// File metadata at one immutable revision. A single listing covers sharded checkpoints.
pub struct PinnedRepo {
    pub repo: Repo,
    files: Vec<RepoFile>,
    _charges: Vec<Arc<crate::content::reservation::Reservation>>,
}

impl PinnedRepo {
    pub fn open(uri: &str, pool: &crate::content::Reservations) -> Result<(Self, Option<String>)> {
        let reference = ModelReference::parse(uri)?;
        let repo = reference.repo;
        if !immutable_sha(&repo.revision) {
            return Err(FetchError::Malformed(
                "model reference requires a 40-hex commit".into(),
            ));
        }
        let selector = reference.selector;
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
        file.download(&HfCas::new(self.repo.clone()), &mut bytes)?;
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
        let mut saved = tempfile::NamedTempFile::new()?;
        let object = file.download(cas, &mut saved)?;
        let mut pinned = Self::new(cas.repo.clone(), file.path.clone(), object);
        pinned.downloaded = Some(Arc::new(saved));
        Ok(pinned)
    }

    pub fn read_range(&self, range: Range<u64>, out: &mut impl std::io::Write) -> Result<()> {
        if range.is_empty() || range.end > self.object.bytes() {
            return Err(FetchError::Malformed("invalid Hub file range".into()));
        }
        let size = range.end - range.start;
        if let Some(saved) = &self.downloaded {
            let mut input = saved.reopen()?;
            input.seek(SeekFrom::Start(range.start))?;
            if std::io::copy(&mut input.take(size), out)? != size {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
            return Ok(());
        }
        let url = HfCas::new(self.repo.clone()).file_url(&self.path)?;
        let bounds = format!("{}-{}", range.start, range.end - 1);
        let mut response = authenticated_get(url.as_str(), None)
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
        let mut body = response.body_mut().as_reader();
        if std::io::copy(&mut body.by_ref().take(size), out)? != size || body.read(&mut [0])? != 0 {
            return Err(FetchError::Malformed(
                "incorrect Hub file range length".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn source(&self) -> crate::content::Source {
        crate::content::Source::HfXet {
            repo: self.repo.clone(),
            path: Some(self.path.clone()),
        }
    }

    /// Make this verified object available to local execution jobs.
    pub async fn acquire(&self, store: &crate::content::DiskStore) -> crate::content::Result<()> {
        use crate::content::{ContentStore, LocalStore, PinTarget, Scope, Target};
        let pin = PinTarget::model_object(self.object)?;
        if pin.holds(store, Target::Object(self.object)).await?
            && LocalStore::Disk(store.clone())
                .verified_hub_files(self.object)
                .await?
                .iter()
                .any(|(repo, commit, path)| {
                    repo == &self.repo.id && commit == &self.repo.revision && path == &self.path
                })
        {
            return Ok(());
        }
        store
            .acquire(&Scope::Owner, self.source(), Some(self.object), pin)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::testing::hub;
    #[test]
    fn mutable_selectors_share_one_lookup_and_exact_refs_do_no_io() {
        const A: &str = "1234567890abcdef1234567890abcdef12345678";
        const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let (hub, server) = hub(|_| {
            [
                ("/api/models/org/repo", A),
                ("/api/models/org/repo/revision/releases%2Fv1", B),
                ("/api/models/org/repo", B),
            ]
            .map(|(path, sha)| {
                (
                    path.into(),
                    200,
                    serde_json::to_vec(&serde_json::json!({"sha":sha})).unwrap(),
                )
            })
            .into()
        });
        let mut revisions = Revisions {
            hub: hub.clone(),
            ..Default::default()
        };
        let pool = crate::content::Reservations::ram(RECONSTRUCTION_BODY_LIMIT);
        let mut observed = Vec::new();
        for (uri, sha, file) in [
            ("hf://org/repo/a", A, "a"),
            ("hf://org/repo/b", A, "b"),
            ("hf://org/repo@releases%2Fv1/nested/c", B, "nested/c"),
        ] {
            let pinned = revisions
                .pin(uri, &pool, |repo, sha| {
                    observed.push((repo.to_owned(), sha.to_owned()))
                })
                .unwrap();
            assert_eq!(pinned.unwrap(), format!("hf://org/repo@{sha}/{file}"));
            assert!(PinnedRepo::open(uri, &pool).is_err());
        }
        assert_eq!(
            observed,
            [("org/repo".into(), A.into()), ("org/repo".into(), B.into())]
        );
        let upper = format!("hf://org/repo@{}", A.to_ascii_uppercase());
        assert!(
            revisions
                .pin(
                    &upper,
                    &crate::content::Reservations::ram(0),
                    |_, _| panic!("exact ref resolved")
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(ModelReference::parse(&upper).unwrap().repo.revision, A);
        let mut next = Revisions {
            hub,
            ..Default::default()
        };
        assert_eq!(
            next.pin("hf://org/repo", &pool, |_, _| {})
                .unwrap()
                .unwrap(),
            format!("hf://org/repo@{B}")
        );
        server.join().unwrap();
    }

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
        let repo: Repo = format!("hf://org/model@{sha}").parse().unwrap();
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
