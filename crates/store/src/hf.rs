//! Fetching content from HuggingFace's Xet CAS.
//!
//! Three requests, in order:
//!
//! 1. `GET huggingface.co/api/{type}s/{repo}/xet-read-token/{rev}` for a
//!    short-lived CAS token and the CAS URL. The node's HF credential is
//!    used only for HF HTTPS origins; anonymous public reads also work.
//! 2. `GET {cas}/v2/reconstructions/{file_id}` for the file's terms.
//! 3. `GET` each signed CDN URL for the xorb bytes those terms name.
//!
//! # Two conventions that differ inside one JSON object
//!
//! A term's `range` is over **chunk indices, half-open** `[start, end)`.
//! A fetch entry's `bytes` is a **byte range, inclusive** `[start, end]`.
//! Getting these the same way round produces off-by-one downloads that
//! decode as truncated xorbs rather than as anything obviously wrong.
//!
//! # The URL is signed, so ask for exactly what you were offered
//!
//! Fetch URLs are CloudFront-signed (`Expires`, `Policy`, `Signature`,
//! `Key-Pair-Id`). The protocol docs describe an `X-Xet-Signed-Range`
//! parameter pinning the URL to specific byte ranges; the
//! single-range responses observed here do not carry one, so that has
//! NOT been confirmed against production and multi-range behaviour is
//! untested. Either way the rule is the same: request the ranges the
//! response listed, unmodified. Widening a request to save a round trip
//! is how you get an authorisation failure instead of a 416.
//!
//! # Verification
//!
//! Whole-file: the reassembled bytes are re-chunked and their file hash
//! compared with the id that was asked for, so a wrong or tampered
//! response cannot be written into the store under a name it does not
//! own. Per-chunk: [`crate::xorb::decode_range`] additionally checks
//! every chunk against our own chunk list when we have one, which is
//! what makes a *partial* fetch verifiable at all — HuggingFace returns
//! no chunk hashes.

use std::io::Read as _;

use hellas_xet::{Chunk, XetHash};

/// Which kind of repository a model lives in. The API path pluralises
/// it, which is why this is not just a string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepoKind {
    Model,
    Dataset,
}

impl RepoKind {
    const fn path_segment(self) -> &'static str {
        match self {
            Self::Model => "models",
            Self::Dataset => "datasets",
        }
    }
}

/// The repository a token is minted for.
///
/// HuggingFace's CAS is content-addressed for *reads* but not for
/// *authorisation*: a token is scoped to one repository and one
/// revision, so fetching by content id alone is not possible against
/// this source. A peer source would not need this.
#[derive(Clone, Debug)]
pub struct Repo {
    pub kind: RepoKind,
    /// `org/name`.
    pub id: String,
    /// Branch, tag or commit sha.
    pub revision: String,
}

/// The most a token response may be.
///
/// It is a small JSON object with a token and a URL in it. Everything
/// here is read into memory before anything about it is checked, so
/// every body needs a number — a response is a stranger's choice of
/// length until it has been read.
const TOKEN_BODY_LIMIT: u64 = 64 * 1024;

/// The most a reconstruction response may be.
///
/// It lists every term and signed URL for one file: a 14 GB model runs
/// to a few hundred terms of a few hundred bytes each. Two orders of
/// magnitude of headroom, and still a bound.
const RECONSTRUCTION_BODY_LIMIT: u64 = 8 * 1024 * 1024;

/// Why a fetch failed.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("source scratch reservation exhausted")]
    Capacity,
    #[error("{context}: {source}")]
    Http {
        context: String,
        #[source]
        source: Box<ureq::Error>,
    },
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error("malformed reconstruction response: {0}")]
    Malformed(String),
    #[error("decoding a xorb: {0}")]
    Xorb(#[from] crate::xorb::XorbError),
    #[error("{context}: response is longer than the {limit} bytes allowed")]
    TooLarge { context: String, limit: u64 },
}

pub(crate) const LEGACY_CHUNKING: &str =
    "HF file uses legacy (pre-2026) Xet chunking; not supported";

type Result<T> = std::result::Result<T, FetchError>;

/// A CAS read token and where to spend it.
#[derive(Clone)]
pub struct XetToken {
    pub access_token: String,
    /// Where the CAS lives. Dynamic — do not hardcode it.
    pub cas_url: String,
}

/// One contiguous run of chunks inside one xorb.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Term {
    pub xorb: XetHash,
    /// Chunk indices, half-open.
    pub chunks: core::ops::Range<u64>,
    pub unpacked_length: u64,
}

/// Where to get some of a xorb's bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchRange {
    pub url: String,
    /// Chunk indices, half-open.
    pub chunks: core::ops::Range<u64>,
    /// Byte range, INCLUSIVE — unlike `chunks`.
    pub bytes: core::ops::RangeInclusive<u64>,
}

/// A file's layout across xorbs.
#[derive(Clone, Debug)]
pub struct Reconstruction {
    /// Bytes to drop from the front of the first term's output.
    pub offset_into_first_range: u64,
    pub terms: Vec<Term>,
    /// Fetch entries per xorb hash.
    pub fetches: Vec<(XetHash, Vec<FetchRange>)>,
}

impl Reconstruction {
    /// Parses a `/v2/reconstructions` response.
    pub fn parse(json: &str) -> Result<Self> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|err| FetchError::Malformed(err.to_string()))?;
        let bad = |what: &str| FetchError::Malformed(what.to_string());

        let terms = value
            .get("terms")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| bad("terms missing"))?
            .iter()
            .map(|term| {
                let range = term.get("range").ok_or_else(|| bad("term range missing"))?;
                Ok(Term {
                    xorb: hash_field(term, "hash")?,
                    chunks: half_open(range)?,
                    unpacked_length: u64_field(term, "unpacked_length")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let fetches = value
            .get("xorbs")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| bad("xorbs missing"))?
            .iter()
            .map(|(hash, entries)| {
                let hash = hash
                    .parse::<XetHash>()
                    .map_err(|_| bad("xorb key is not a hash"))?;
                let entries = entries
                    .as_array()
                    .ok_or_else(|| bad("xorb entries are not an array"))?
                    .iter()
                    .map(|entry| {
                        let url = entry
                            .get("url")
                            .and_then(serde_json::Value::as_str)
                            .ok_or_else(|| bad("fetch url missing"))?
                            .to_string();
                        entry
                            .get("ranges")
                            .and_then(serde_json::Value::as_array)
                            .ok_or_else(|| bad("fetch ranges missing"))?
                            .iter()
                            .map(|range| {
                                let chunks =
                                    range.get("chunks").ok_or_else(|| bad("chunks missing"))?;
                                let bytes =
                                    range.get("bytes").ok_or_else(|| bad("bytes missing"))?;
                                Ok(FetchRange {
                                    url: url.clone(),
                                    // Half-open.
                                    chunks: half_open(chunks)?,
                                    // Inclusive. Deliberately not the same shape.
                                    bytes: inclusive(bytes)?,
                                })
                            })
                            .collect::<Result<Vec<_>>>()
                    })
                    .collect::<Result<Vec<_>>>()?
                    .concat();
                Ok((hash, entries))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            offset_into_first_range: value
                .get("offset_into_first_range")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            terms,
            fetches,
        })
    }

    /// Fetch entries covering `term`, in chunk order.
    #[must_use]
    pub fn ranges_for(&self, term: &Term) -> Vec<&FetchRange> {
        let mut ranges: Vec<&FetchRange> = self
            .fetches
            .iter()
            .filter(|(hash, _)| *hash == term.xorb)
            .flat_map(|(_, entries)| entries)
            .filter(|range| {
                range.chunks.start < term.chunks.end && term.chunks.start < range.chunks.end
            })
            .collect();
        ranges.sort_by_key(|range| range.chunks.start);
        ranges
    }
}

/// A `{start, end}` object read as a half-open chunk range.
///
/// A range that ends before it starts is refused here rather than
/// underflowing at `end - start` several layers down, where the number
/// it produces is enormous and the failure is a panic or an absurd
/// allocation instead of a parse error.
fn half_open(value: &serde_json::Value) -> Result<core::ops::Range<u64>> {
    let start = u64_field(value, "start")?;
    let end = u64_field(value, "end")?;
    if end < start {
        return Err(FetchError::Malformed(format!(
            "range {start}..{end} ends before it starts"
        )));
    }
    Ok(start..end)
}

/// The same, for the byte ranges — which are inclusive, so `start == end`
/// is one byte and not zero.
fn inclusive(value: &serde_json::Value) -> Result<core::ops::RangeInclusive<u64>> {
    let start = u64_field(value, "start")?;
    let end = u64_field(value, "end")?;
    if end < start {
        return Err(FetchError::Malformed(format!(
            "byte range {start}..={end} ends before it starts"
        )));
    }
    Ok(start..=end)
}

fn u64_field(value: &serde_json::Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| FetchError::Malformed(format!("{field} missing or not a number")))
}

fn hash_field(value: &serde_json::Value, field: &str) -> Result<XetHash> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .and_then(|hash| hash.parse::<XetHash>().ok())
        .ok_or_else(|| FetchError::Malformed(format!("{field} missing or not a hash")))
}

/// A HuggingFace-backed source for one repository.
#[derive(Clone, Debug)]
pub struct HfCas {
    repo: Repo,
    /// Hub base, overridable for testing against another endpoint.
    hub: String,
}

impl HfCas {
    /// A source reading `repo` from huggingface.co.
    #[must_use]
    pub fn new(repo: Repo) -> Self {
        Self {
            repo,
            hub: "https://huggingface.co".to_string(),
        }
    }

    /// Points this source at another hub.
    ///
    /// The field was always here and its comment always said "overridable
    /// for testing"; without a way to set it, that was an aspiration.
    /// Every bound in this module is about what a *response* may do, and
    /// a response is the one thing production cannot be asked for on
    /// demand.
    #[must_use]
    pub fn with_hub(mut self, hub: impl Into<String>) -> Self {
        self.hub = hub.into();
        self
    }

    /// Obtains a CAS read token.
    ///
    /// Uses the node user's HF credential only for authenticated HF origins.
    pub fn token(&self) -> Result<XetToken> {
        self.repo.validate()?;
        let url = self.hub_url(true, &["xet-read-token", &self.repo.revision])?;
        let node_token = hf_origin(url.as_str()).then(node_token).flatten();
        let body = get(url.as_str(), node_token.as_deref(), TOKEN_BODY_LIMIT)?;
        let value: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|err| FetchError::Malformed(format!("token response: {err}")))?;
        let field = |name: &str| {
            value
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| FetchError::Malformed(format!("token response has no {name}")))
        };
        Ok(XetToken {
            access_token: field("accessToken")?,
            cas_url: field("casUrl")?,
        })
    }

    /// Reads the file's layout across xorbs.
    pub fn reconstruction(&self, token: &XetToken, id: XetHash) -> Result<Reconstruction> {
        let url = format!("{}/v2/reconstructions/{id}", token.cas_url);
        let body = get(&url, Some(&token.access_token), RECONSTRUCTION_BODY_LIMIT)?;
        let json = String::from_utf8(body)
            .map_err(|_| FetchError::Malformed("reconstruction is not UTF-8".to_string()))?;
        Reconstruction::parse(&json)
    }
}

fn get(url: &str, bearer: Option<&str>, limit: u64) -> Result<Vec<u8>> {
    let (_, body) = read_body(authenticated_get(url, bearer), url, limit)?;
    Ok(body)
}

/// Reads at most `limit` bytes of a response, and refuses one more.
///
/// `read_to_end` on a response body is an allocation whose size the
/// other end chooses. Reading `limit + 1` and refusing the overflow is
/// the difference between a bounded read and a promise.
fn read_body(
    request: ureq::RequestBuilder<ureq::typestate::WithoutBody>,
    url: &str,
    limit: u64,
) -> Result<(u16, Vec<u8>)> {
    let context = || format!("GET {url}");
    let mut response = request.call().map_err(|source| FetchError::Http {
        context: context(),
        source: Box::new(source),
    })?;
    let status = response.status().as_u16();
    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(limit.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|source| FetchError::Io {
            context: context(),
            source,
        })?;
    if body.len() as u64 > limit {
        return Err(FetchError::TooLarge {
            context: context(),
            limit,
        });
    }
    Ok((status, body))
}

impl std::fmt::Debug for XetToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("XetToken").finish_non_exhaustive()
    }
}
fn hf_origin(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.host_str().is_some_and(|host| {
            host == "huggingface.co"
                || host.ends_with(".huggingface.co")
                || host == "hf.co"
                || host.ends_with(".hf.co")
        })
}
fn node_token() -> Option<String> {
    token_from(|name| std::env::var_os(name))
}
fn token_from(env: impl Fn(&str) -> Option<std::ffi::OsString>) -> Option<String> {
    if let Some(token) = env("HF_TOKEN").and_then(|value| value.into_string().ok())
        && !token.trim().is_empty()
    {
        return Some(token.trim().to_owned());
    }
    let home = env("HF_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            env("XDG_CACHE_HOME").map(|path| std::path::PathBuf::from(path).join("huggingface"))
        })
        .or_else(|| {
            env("HOME").map(|path| std::path::PathBuf::from(path).join(".cache/huggingface"))
        })?;
    let bytes = hellas_private::read_bounded_regular_file(
        &home.join("token"),
        hellas_private::MAX_SECRET_BYTES,
    )
    .ok()?;
    let token = String::from_utf8(bytes).ok()?;
    (!token.trim().is_empty()).then(|| token.trim().to_owned())
}
fn authenticated_get(
    url: &str,
    bearer: Option<&str>,
) -> ureq::RequestBuilder<ureq::typestate::WithoutBody> {
    let request = ureq::get(url);
    if let Some(token) = bearer.filter(|_| hf_origin(url)) {
        request.header("Authorization", &format!("Bearer {token}"))
    } else {
        request
    }
}

#[derive(Clone, Debug, serde::Deserialize)]
pub(crate) struct RepoFile {
    pub path: String,
    pub size: u64,
    #[serde(rename = "xetHash", default)]
    pub xet_hash: Option<String>,
    #[serde(default)]
    pub lfs: Option<serde_json::Value>,
}
impl Repo {
    pub fn from_uri(uri: &str) -> Result<Self> {
        let value = uri
            .strip_prefix("hf://")
            .ok_or_else(|| FetchError::Malformed("expected hf://org/repo[@revision]".into()))?;
        let (id, revision) = value.split_once('@').unwrap_or((value, "main"));
        let repo = Self {
            kind: RepoKind::Model,
            id: id.into(),
            revision: revision.into(),
        };
        repo.validate()?;
        Ok(repo)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let parts: Vec<_> = self.id.split('/').collect();
        if parts.len() != 2
            || parts.iter().any(|part| !safe_component(part))
            || self.revision.is_empty()
            || self.revision.contains('\0')
        {
            return Err(FetchError::Malformed(
                "invalid HF repository or revision".into(),
            ));
        }
        Ok(())
    }
}
fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}
impl HfCas {
    fn hub_url(&self, api: bool, tail: &[&str]) -> Result<url::Url> {
        let mut url =
            url::Url::parse(&self.hub).map_err(|_| FetchError::Malformed("Hub origin".into()))?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| FetchError::Malformed("Hub origin".into()))?;
            segments.pop_if_empty();
            if api {
                segments.push("api").push(self.repo.kind.path_segment());
            } else if self.repo.kind == RepoKind::Dataset {
                segments.push("datasets");
            }
            segments
                .extend(self.repo.id.split('/'))
                .extend(tail.iter().copied());
        }
        Ok(url)
    }
    pub(crate) fn resolve_revision(&self, pool: &crate::content::Reservations) -> Result<String> {
        self.repo.validate()?;
        let _metadata = pool
            .reserve(RECONSTRUCTION_BODY_LIMIT)
            .map_err(|_| FetchError::Capacity)?;
        let url = self.hub_url(true, &["revision", &self.repo.revision])?;
        let token = hf_origin(url.as_str()).then(node_token).flatten();
        let value: serde_json::Value = serde_json::from_slice(&get(
            url.as_str(),
            token.as_deref(),
            RECONSTRUCTION_BODY_LIMIT,
        )?)
        .map_err(|_| FetchError::Malformed("repository revision response".into()))?;
        value
            .get("sha")
            .and_then(serde_json::Value::as_str)
            .filter(|sha| immutable_sha(sha))
            .map(str::to_owned)
            .ok_or_else(|| FetchError::Malformed("repository has no immutable SHA".into()))
    }
    pub(crate) fn files(
        &self,
        pool: &crate::content::Reservations,
    ) -> Result<(
        Vec<RepoFile>,
        Vec<std::sync::Arc<crate::content::reservation::Reservation>>,
    )> {
        self.repo.validate()?;
        let mut initial = self.hub_url(true, &["tree", &self.repo.revision])?;
        initial.set_query(Some("recursive=true"));
        let mut url = initial.to_string();
        let mut seen = std::collections::BTreeSet::new();
        let mut files = Vec::new();
        let mut charges = Vec::new();
        loop {
            if !seen.insert(url.clone()) {
                return Err(FetchError::Malformed("cyclic Hub pagination".into()));
            }
            let charge = pool
                .reserve(RECONSTRUCTION_BODY_LIMIT)
                .map_err(|_| FetchError::Capacity)?;
            let token = hf_origin(&url).then(node_token).flatten();
            let mut response = authenticated_get(&url, token.as_deref())
                .call()
                .map_err(|_| FetchError::Malformed("Hub listing failed".into()))?;
            let next = response
                .headers()
                .get("link")
                .and_then(|header| header.to_str().ok())
                .and_then(|links| links.split(',').find(|link| link.contains("rel=\"next\"")))
                .and_then(|link| link.trim().strip_prefix('<'))
                .and_then(|link| link.split_once('>'))
                .map(|(url, _)| url.to_owned());
            let mut body = Vec::new();
            response
                .body_mut()
                .as_reader()
                .take(RECONSTRUCTION_BODY_LIMIT + 1)
                .read_to_end(&mut body)
                .map_err(|_| FetchError::Malformed("Hub listing body".into()))?;
            if body.len() as u64 > RECONSTRUCTION_BODY_LIMIT {
                return Err(FetchError::Capacity);
            }
            let values: Vec<serde_json::Value> = serde_json::from_slice(&body)
                .map_err(|_| FetchError::Malformed("Hub listing encoding".into()))?;
            for value in values.into_iter().filter(|value| {
                value.get("type").and_then(serde_json::Value::as_str) == Some("file")
            }) {
                let file: RepoFile = serde_json::from_value(value)
                    .map_err(|_| FetchError::Malformed("Hub file metadata".into()))?;
                crate::content::Path::new(
                    crate::content::PinName::new("hf".into())
                        .map_err(|_| FetchError::Malformed("pin".into()))?,
                    file.path.clone(),
                )
                .map_err(|_| FetchError::Malformed("Hub file path".into()))?;
                files.push(file);
            }
            charges.push(charge);
            match next {
                Some(next) => {
                    let origin = url::Url::parse(&self.hub)
                        .map_err(|_| FetchError::Malformed("Hub URL".into()))?;
                    let parsed = url::Url::parse(&next)
                        .map_err(|_| FetchError::Malformed("Hub next URL".into()))?;
                    if parsed.origin() != origin.origin() {
                        return Err(FetchError::Malformed("cross-origin Hub pagination".into()));
                    }
                    url = next;
                }
                None => return Ok((files, charges)),
            }
        }
    }
    pub(crate) fn small_file(&self, path: &str) -> Result<impl std::io::Read + use<>> {
        let mut url = self.hub_url(false, &["resolve", &self.repo.revision])?;
        url.path_segments_mut()
            .map_err(|_| FetchError::Malformed("Hub path".into()))?
            .extend(path.split('/'));
        let url = url.to_string();
        let token = hf_origin(&url).then(node_token).flatten();
        let response = authenticated_get(&url, token.as_deref())
            .call()
            .map_err(|_| FetchError::Malformed("Hub file request failed".into()))?;
        if response.status() != 200 {
            return Err(FetchError::Malformed("Hub file status".into()));
        }
        Ok(response.into_body().into_reader())
    }
    /// Reconstruction streams framed chunks; no whole xorb or file assembly.
    pub(crate) fn write_xet(
        &self,
        id: XetHash,
        len: u64,
        expected: Option<&[Chunk]>,
        writer: &mut impl std::io::Write,
        pool: &crate::content::Reservations,
    ) -> Result<()> {
        if let Some(chunks) = expected {
            let total = chunks
                .iter()
                .try_fold(0u64, |total, chunk| total.checked_add(chunk.data_len));
            if total != Some(len)
                || hellas_xet::file_hash(chunks) != id
                || chunks.iter().any(|chunk| {
                    chunk.data_len == 0 || chunk.data_len > hellas_xet::MAX_CHUNK_SIZE as u64
                })
                || chunks
                    .iter()
                    .rev()
                    .skip(1)
                    .any(|chunk| chunk.data_len < hellas_xet::MIN_CHUNK_SIZE as u64)
            {
                return Err(FetchError::Malformed(
                    "expected descriptor commitment".into(),
                ));
            }
        }
        let _metadata = pool
            .reserve(TOKEN_BODY_LIMIT + RECONSTRUCTION_BODY_LIMIT)
            .map_err(|_| FetchError::Capacity)?;
        let token = self.token()?;
        let plan = self.reconstruction(&token, id)?;
        let declared = plan
            .terms
            .iter()
            .try_fold(0u64, |sum, term| sum.checked_add(term.unpacked_length))
            .ok_or_else(|| FetchError::Malformed("reconstruction length overflow".into()))?;
        if declared.checked_sub(plan.offset_into_first_range) != Some(len) {
            return Err(FetchError::Malformed(
                "reconstruction length contract".into(),
            ));
        }
        let mut skip = plan.offset_into_first_range;
        let mut descriptor = 0usize;
        let mut written = 0u64;
        for term in &plan.terms {
            if term.chunks.end - term.chunks.start
                > term.unpacked_length / hellas_xet::MIN_CHUNK_SIZE as u64 + 1
            {
                return Err(FetchError::Malformed("reconstruction chunk count".into()));
            }
            let mut next = term.chunks.start;
            let mut unpacked = 0u64;
            for range in plan.ranges_for(term) {
                let length = range
                    .bytes
                    .end()
                    .checked_sub(*range.bytes.start())
                    .and_then(|length| length.checked_add(1))
                    .ok_or_else(|| FetchError::Malformed("reconstruction byte range".into()))?;
                let count = range.chunks.end - range.chunks.start;
                if count > length / crate::xorb::HEADER as u64 {
                    return Err(FetchError::Malformed("reconstruction framing count".into()));
                }
                let mut response = ureq::get(&range.url)
                    .header(
                        "Range",
                        &format!("bytes={}-{}", range.bytes.start(), range.bytes.end()),
                    )
                    .call()
                    .map_err(|_| FetchError::Malformed("CAS range request failed".into()))?;
                if response.status() != 206 {
                    return Err(FetchError::Malformed("CAS range status".into()));
                }
                let mut reader = response
                    .body_mut()
                    .as_reader()
                    .take(length.saturating_add(1));
                let mut consumed = 0u64;
                for index in range.chunks.clone() {
                    let mut header = [0u8; crate::xorb::HEADER];
                    reader
                        .read_exact(&mut header)
                        .map_err(|_| FetchError::Malformed("truncated xorb header".into()))?;
                    let compressed =
                        u32::from_le_bytes([header[1], header[2], header[3], 0]) as usize;
                    consumed = consumed
                        .checked_add((header.len() + compressed) as u64)
                        .filter(|bytes| *bytes <= length)
                        .ok_or_else(|| FetchError::Malformed("xorb frame exceeds range".into()))?;
                    let _scratch = pool
                        .reserve(
                            (header.len()
                                + compressed
                                + 2 * (hellas_xet::MAX_CHUNK_SIZE + 1)
                                + if header[4] == 0 {
                                    0
                                } else {
                                    crate::xorb::LZ4_SCRATCH_BYTES
                                }) as u64,
                        )
                        .map_err(|_| FetchError::Capacity)?;
                    let mut frame = Vec::with_capacity(header.len() + compressed);
                    frame.extend_from_slice(&header);
                    frame.resize(header.len() + compressed, 0);
                    reader
                        .read_exact(&mut frame[header.len()..])
                        .map_err(|_| FetchError::Malformed("truncated xorb payload".into()))?;
                    let in_term = term.chunks.contains(&index);
                    let chunk = if in_term {
                        expected
                            .map(|expected| {
                                expected.get(descriptor).ok_or_else(|| {
                                    FetchError::Malformed(
                                        "reconstruction exceeded descriptors".into(),
                                    )
                                })
                            })
                            .transpose()?
                    } else {
                        None
                    };
                    let decoded = crate::xorb::decode_chunk_bounded(&frame, chunk)?;
                    if !in_term {
                        continue;
                    }
                    if index != next {
                        return Err(FetchError::Malformed(
                            "overlapping or missing reconstruction chunks".into(),
                        ));
                    }
                    next += 1;
                    unpacked = unpacked
                        .checked_add(decoded.data.len() as u64)
                        .ok_or_else(|| FetchError::Malformed("term length overflow".into()))?;
                    let trim = skip.min(decoded.data.len() as u64) as usize;
                    skip -= trim as u64;
                    let bytes = &decoded.data[trim..];
                    written = written
                        .checked_add(bytes.len() as u64)
                        .filter(|written| *written <= len)
                        .ok_or_else(|| {
                            FetchError::Malformed("reconstruction exceeds reservation".into())
                        })?;
                    if written < len && decoded.data.len() < hellas_xet::MIN_CHUNK_SIZE {
                        return Err(FetchError::Malformed(LEGACY_CHUNKING.into()));
                    }
                    writer
                        .write_all(bytes)
                        .map_err(|_| FetchError::Malformed("staging reconstructed bytes".into()))?;
                    descriptor += 1;
                }
                let mut sentinel = [0];
                if consumed != length
                    || reader
                        .read(&mut sentinel)
                        .map_err(|_| FetchError::Malformed("CAS range sentinel".into()))?
                        != 0
                {
                    return Err(FetchError::Malformed("CAS range length".into()));
                }
            }
            if next != term.chunks.end || unpacked != term.unpacked_length {
                return Err(FetchError::Malformed("reconstruction term length".into()));
            }
        }
        if written != len
            || skip != 0
            || expected.is_some_and(|expected| descriptor != expected.len())
        {
            return Err(FetchError::Malformed("short reconstruction".into()));
        }
        Ok(())
    }
}
pub fn immutable_sha(sha: &str) -> bool {
    sha.len() == 40 && sha.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod credentials_tests {
    use super::*;
    #[test]
    fn credential_sources_and_origin_filtering_use_the_supplied_node_secret() {
        use std::collections::BTreeMap;
        let home = tempfile::tempdir().unwrap();
        for directory in [
            home.path().join("hf"),
            home.path().join("xdg/huggingface"),
            home.path().join(".cache/huggingface"),
        ] {
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(
                directory.join("token"),
                directory.file_name().unwrap().to_str().unwrap(),
            )
            .unwrap();
        }
        let mut env = BTreeMap::<&str, std::ffi::OsString>::from([
            ("HF_TOKEN", " sentinel-private-token ".into()),
            ("HF_HOME", home.path().join("hf").into()),
            ("XDG_CACHE_HOME", home.path().join("xdg").into()),
            ("HOME", home.path().into()),
        ]);
        let secret = token_from(|name| env.get(name).cloned()).unwrap();
        assert_eq!(secret, "sentinel-private-token");
        for origin in [
            "https://huggingface.co/private/file",
            "https://cas-server.xethub.hf.co/file",
        ] {
            let request = authenticated_get(origin, Some(&secret));
            assert_eq!(
                request.headers_ref().unwrap()["authorization"],
                "Bearer sentinel-private-token"
            );
        }
        for origin in [
            "http://huggingface.co/file",
            "https://huggingface.co.evil.invalid/file",
            "https://evil.invalid/file",
        ] {
            assert!(
                !authenticated_get(origin, Some(&secret))
                    .headers_ref()
                    .unwrap()
                    .contains_key("authorization")
            );
        }
        env.remove("HF_TOKEN");
        assert_eq!(
            token_from(|name| env.get(name).cloned()).as_deref(),
            Some("hf")
        );
        env.remove("HF_HOME");
        assert_eq!(
            token_from(|name| env.get(name).cloned()).as_deref(),
            Some("huggingface")
        );
        std::fs::write(home.path().join(".cache/huggingface/token"), " home-token ").unwrap();
        env.remove("XDG_CACHE_HOME");
        assert_eq!(
            token_from(|name| env.get(name).cloned()).as_deref(),
            Some("home-token")
        );
    }
    #[test]
    fn revision_metadata_requires_a_reservation_before_any_request() {
        let cas = HfCas::new(Repo {
            kind: RepoKind::Model,
            id: "org/repo".into(),
            revision: "main".into(),
        });
        assert!(matches!(
            cas.resolve_revision(&crate::content::Reservations::ram(0)),
            Err(FetchError::Capacity)
        ));
    }
    #[test]
    fn redirects_strip_the_authorization_header() {
        use std::io::{BufRead, Write};
        use std::net::TcpListener;
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", first.local_addr().unwrap());
        let target = format!("http://{}", second.local_addr().unwrap());
        let serving = std::thread::spawn(move || {
            for (listener, auth, redirect) in [(first, true, Some(target)), (second, false, None)] {
                let (mut socket, _) = listener.accept().unwrap();
                let mut input = std::io::BufReader::new(socket.try_clone().unwrap());
                let mut authorization = None;
                loop {
                    let mut line = String::new();
                    input.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if line.to_ascii_lowercase().starts_with("authorization:") {
                        authorization = Some(line);
                    }
                }
                assert_eq!(authorization.is_some(), auth);
                if auth {
                    assert!(authorization.unwrap().contains("sentinel-private-token"));
                }
                if let Some(target) = redirect {
                    write!(socket, "HTTP/1.1 302 Found\r\nLocation: {target}/file\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                } else {
                    write!(
                        socket,
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    )
                    .unwrap();
                }
            }
        });
        let (_, body) = read_body(
            ureq::get(&url).header("Authorization", "Bearer sentinel-private-token"),
            &url,
            2,
        )
        .unwrap();
        assert_eq!(body, b"ok");
        serving.join().unwrap();
    }
}
