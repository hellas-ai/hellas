//! Fetching content from HuggingFace's Xet CAS.
//!
//! Three requests, in order:
//!
//! 1. `GET huggingface.co/api/{type}s/{repo}/xet-read-token/{rev}` for a
//!    short-lived CAS token and the CAS URL. **No `Authorization`
//!    header for public repositories** — anonymous read works, and the
//!    token that comes back says `userId: "public"`.
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
use std::path::Path;

use hellas_xet::{Chunk, XetFileHasher, XetHash};

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
    #[error("reconstructed content hashed to {actual}, asked for {expected}")]
    WrongContent { expected: XetHash, actual: XetHash },
    #[error("{context}: response is longer than the {limit} bytes allowed")]
    TooLarge { context: String, limit: u64 },
    #[error("{context}: asked for {expected} bytes, got {actual} with status {status}")]
    BadRange {
        context: String,
        status: u16,
        expected: u64,
        actual: u64,
    },
}

type Result<T> = std::result::Result<T, FetchError>;

/// A CAS read token and where to spend it.
#[derive(Clone, Debug)]
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
    /// Deliberately sends no `Authorization` header: public repositories
    /// need none, and this crate holds no credentials. Private
    /// repositories will fail here, loudly, which is the honest
    /// behaviour for a component that was not given a secret.
    pub fn token(&self) -> Result<XetToken> {
        let url = format!(
            "{}/api/{}/{}/xet-read-token/{}",
            self.hub,
            self.repo.kind.path_segment(),
            self.repo.id,
            self.repo.revision,
        );
        let body = get(&url, None, TOKEN_BODY_LIMIT)?;
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

    /// Materialises content `id` at `dest`, refusing to write anything
    /// that does not hash to `id`.
    ///
    /// The file is assembled in memory before being written, so the
    /// store never contains a partially-fetched file under a real name.
    /// That costs one file's worth of memory and buys the guarantee that
    /// a path in the store always holds the content its id claims.
    pub fn fetch(&self, id: XetHash, dest: &Path, expected: Option<&[Chunk]>) -> Result<u64> {
        let token = self.token()?;
        let plan = self.reconstruction(&token, id)?;

        let mut assembled: Vec<u8> = Vec::new();
        let mut chunk_index = 0_usize;
        for term in &plan.terms {
            for range in plan.ranges_for(term) {
                let bytes = get_range(&range.url, *range.bytes.start(), *range.bytes.end())?;
                let count = range
                    .chunks
                    .end
                    .checked_sub(range.chunks.start)
                    .and_then(|count| usize::try_from(count).ok())
                    .ok_or_else(|| FetchError::Malformed("absurd chunk count".to_string()))?;
                // Verify per-chunk when we already know what to expect.
                // Without a chunk list this is impossible: the response
                // carries no chunk hashes.
                let slice = expected
                    .map(|chunks| {
                        chunks
                            .get(chunk_index..chunk_index + count)
                            .ok_or_else(|| FetchError::Malformed("chunk list too short".into()))
                    })
                    .transpose()?;
                let decoded = crate::xorb::decode_chunks(&bytes, count, slice)?;
                for data in decoded {
                    assembled.extend_from_slice(&data);
                }
                chunk_index += count;
            }
        }

        let content = verified(id, &assembled, plan.offset_into_first_range)?;
        publish(dest, content)?;
        Ok(content.len() as u64)
    }
}

/// Puts verified bytes at `dest`, atomically, without following anything.
///
/// Public for the same reason [`verified`] is: it is only ever called
/// after a network fetch, and a step that can only run against
/// production is a step nobody can regression-test.
///
/// The bytes cannot change once verified, but the destination can.
/// `std::fs::write` opens `dest` by name, which follows a symlink to
/// wherever it points, truncates whatever it finds, and — if the write
/// fails halfway — leaves a short file under a name that now claims to be
/// a whole one. Two materializations of different content to the same
/// path could interleave into a mixture of both.
///
/// So: a uniquely named sibling opened with `create_new`, which cannot
/// follow anything because it refuses to open something that exists;
/// `sync_all`, so a crash cannot leave the rename pointing at a file the
/// page cache never wrote; then `rename`, which is atomic. A reader at
/// `dest` sees the old file or the whole new one, never a prefix.
pub fn publish(dest: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write as _;

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|source| FetchError::Io {
            context: format!("creating {}", parent.display()),
            source,
        })?;
    }

    let name = dest
        .file_name()
        .ok_or_else(|| FetchError::Malformed(format!("{} is not a file name", dest.display())))?;
    let parent = dest
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let io = |context: String| move |source| FetchError::Io { context, source };
    let mut incoming = tempfile::Builder::new()
        .prefix(name)
        .suffix(".incoming")
        .make_in(parent, |path| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
        })
        .map_err(io(format!(
            "creating temporary file beside {}",
            dest.display()
        )))?;
    incoming
        .write_all(content)
        .map_err(io(format!("writing {}", incoming.path().display())))?;
    incoming
        .as_file()
        .sync_all()
        .map_err(io(format!("syncing {}", incoming.path().display())))?;
    let incoming = incoming.into_temp_path();
    std::fs::rename(&incoming, dest).map_err(io(format!("publishing {}", dest.display())))?;
    let _published = incoming.keep();
    Ok(())
}

/// Trims the leading offset and checks the result is the content that
/// was asked for.
///
/// Separated from [`HfCas::fetch`] so it is reachable without a network:
/// this is the check that stops a wrong or tampered response being
/// written into the store under a name it does not own, and a check
/// that only runs against production is a check nobody can regression-
/// test.
pub fn verified(id: XetHash, assembled: &[u8], offset: u64) -> Result<&[u8]> {
    let start =
        usize::try_from(offset).map_err(|_| FetchError::Malformed("absurd offset".into()))?;
    let content = assembled
        .get(start..)
        .ok_or_else(|| FetchError::Malformed("offset past the assembled content".into()))?;

    let mut hasher = XetFileHasher::new();
    hasher.update(content);
    let actual = hasher.finalize();
    if actual != id {
        return Err(FetchError::WrongContent {
            expected: id,
            actual,
        });
    }
    Ok(content)
}

fn get(url: &str, bearer: Option<&str>, limit: u64) -> Result<Vec<u8>> {
    let mut request = ureq::get(url);
    if let Some(token) = bearer {
        request = request.header("Authorization", &format!("Bearer {token}"));
    }
    let (_, body) = read_body(request, url, limit)?;
    Ok(body)
}

/// Exactly the bytes that were asked for, or an error.
///
/// A range request is the one case where the length is known in advance,
/// so it is the one case where "however much you send" is inexcusable.
/// A 200 here would be the whole xorb — potentially gigabytes — in
/// answer to a request for a few hundred kilobytes.
fn get_range(url: &str, start: u64, end: u64) -> Result<Vec<u8>> {
    // Inclusive, matching the reconstruction response's own convention
    // and the signed range on the URL.
    let expected = end
        .checked_sub(start)
        .and_then(|span| span.checked_add(1))
        .ok_or_else(|| FetchError::Malformed(format!("byte range {start}..={end}")))?;
    let request = ureq::get(url).header("Range", &format!("bytes={start}-{end}"));
    let (status, body) = read_body(request, url, expected)?;
    if status != 206 || body.len() as u64 != expected {
        return Err(FetchError::BadRange {
            context: format!("GET {url}"),
            status,
            expected,
            actual: body.len() as u64,
        });
    }
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

impl crate::Fetcher for HfCas {
    fn name(&self) -> &str {
        "huggingface"
    }

    fn fetch(&self, id: XetHash, dest: &Path, expected: Option<&[Chunk]>) -> Result<u64> {
        Self::fetch(self, id, dest, expected)
    }
}
