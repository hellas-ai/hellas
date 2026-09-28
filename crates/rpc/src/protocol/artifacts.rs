//! Content-addressed evaluate artifact schema.
//!
//! These are the canonical bodies an execution is addressed by: the
//! prompt tokens, the generation policy, the execution that binds them to
//! a source, and the identity or output artifact that source resolves to.
//! Their bytes are content ids, so there is exactly one encoder and one
//! decoder for them in the workspace.
//!
//! They live in the neutral RPC protocol crate rather than in the
//! executor because both endpoints need them: the provider builds these
//! bodies while executing, and the client must rebuild them to check a
//! paid result rather than accepting a returned digest. A second
//! implementation on the client side would be a second opinion about what
//! a content id means.
//!
//! The decoder is strict in the way a content-addressed schema has to be:
//! [`CanonicalDecode::from_canonical_bytes`] re-encodes what it decoded
//! and rejects any input whose bytes it does not reproduce, so a
//! noncanonical integer, a reordered field, or a trailing byte cannot
//! produce a value that would hash to a different id than it arrived
//! under.

use crate::protocol::value::{CanonicalDecodeError, CanonicalDecoder};
use crate::{DagCborEncoder, Digest};
use std::{format, marker::PhantomData, str, vec::Vec};

const SOURCE_INPUT_SCHEMA: &str = "hellas.evaluate.source.input.v1";
const SOURCE_OUTPUT_SCHEMA: &str = "hellas.evaluate.source.output.v1";
const TOKEN_IDS_SCHEMA: &str = "hellas.evaluate.token_ids.v1";
const TEXT_POLICY_SCHEMA: &str = "hellas.evaluate.text.policy.v1";
const TEXT_EXECUTION_SCHEMA: &str = "hellas.evaluate.text.execution.v1";
const TEXT_STATE_SCHEMA: &str = "hellas.evaluate.text.state.v1";
const TEXT_ARTIFACT_IDENTITY_SCHEMA: &str = "hellas.evaluate.text.artifact.identity.v3";
const TEXT_ARTIFACT_OUTPUT_SCHEMA: &str = "hellas.evaluate.text.artifact.output.v1";

/// Conservative maximum number of token IDs in one retained token artifact.
///
/// Every possible artifact at this bound, including the five-byte DAG-CBOR
/// encoding of `u32::MAX`, fits in one 4 MiB Courtesy response frame. Providers
/// may choose a lower generation limit, but must not admit a retained execution
/// whose prompt-plus-output artifact can no longer be retrieved.
pub const MAX_RETRIEVABLE_TOKEN_IDS: u64 = 524_288;

pub trait Canonical {
    fn encode(&self, encoder: &mut DagCborEncoder);

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = DagCborEncoder::new();
        self.encode(&mut encoder);
        encoder.into_bytes()
    }
}

pub trait CanonicalDecode: Canonical + Sized {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalDecodeError>;
}

pub trait InputAddressed: Canonical {
    type Artifact: OutputAddressed;

    fn input_id(&self) -> InputId<Self>
    where
        Self: Sized,
    {
        InputId::from_digest(Digest::hash(&self.canonical_bytes()))
    }
}

pub trait OutputAddressed: Canonical {
    fn output_id(&self) -> OutputId<Self>
    where
        Self: Sized,
    {
        OutputId::from_digest(Digest::hash(&self.canonical_bytes()))
    }
}

pub struct InputId<I> {
    digest: Digest,
    _ty: PhantomData<I>,
}

impl<I> InputId<I> {
    pub const fn from_digest(digest: Digest) -> Self {
        Self {
            digest,
            _ty: PhantomData,
        }
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self::from_digest(Digest::from_bytes(bytes))
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.digest.as_bytes()
    }
}

impl<I> Clone for InputId<I> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<I> Copy for InputId<I> {}

impl<I> PartialEq for InputId<I> {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

impl<I> Eq for InputId<I> {}

impl<I> core::hash::Hash for InputId<I> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
    }
}

impl<I> core::fmt::Display for InputId<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.digest.fmt(f)
    }
}

impl<I> core::fmt::Debug for InputId<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "InputId({})", self.digest)
    }
}

pub struct OutputId<O> {
    digest: Digest,
    _ty: PhantomData<O>,
}

impl<O> OutputId<O> {
    pub const fn from_digest(digest: Digest) -> Self {
        Self {
            digest,
            _ty: PhantomData,
        }
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self::from_digest(Digest::from_bytes(bytes))
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.digest.as_bytes()
    }
}

impl<O> Clone for OutputId<O> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<O> Copy for OutputId<O> {}

impl<O> PartialEq for OutputId<O> {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

impl<O> Eq for OutputId<O> {}

impl<O> core::hash::Hash for OutputId<O> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
    }
}

impl<O> core::fmt::Display for OutputId<O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.digest.fmt(f)
    }
}

impl<O> core::fmt::Debug for OutputId<O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "OutputId({})", self.digest)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SourceRef<I: InputAddressed> {
    Input(InputId<I>),
    Output(OutputId<I::Artifact>),
}

impl<I: InputAddressed> SourceRef<I> {
    pub const fn input(id: InputId<I>) -> Self {
        Self::Input(id)
    }

    pub const fn output(id: OutputId<I::Artifact>) -> Self {
        Self::Output(id)
    }

    fn encode(&self, encoder: &mut DagCborEncoder) {
        match self {
            Self::Input(id) => {
                encoder.array(2);
                encoder.str(SOURCE_INPUT_SCHEMA);
                encoder.bytes(id.as_bytes());
            }
            Self::Output(id) => {
                encoder.array(2);
                encoder.str(SOURCE_OUTPUT_SCHEMA);
                encoder.bytes(id.as_bytes());
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoundTerm;

pub type BoundTermId = OutputId<BoundTerm>;
pub type TokenIdsId = OutputId<TokenIds>;
pub type TextPolicyId = OutputId<TextPolicy>;
pub type TextExecutionId = InputId<TextExecution>;
pub type TextArtifactId = OutputId<TextArtifact>;
pub type TextStateId = OutputId<TextState>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenId(u32);

impl TokenId {
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<u32> for TokenId {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl core::fmt::Display for TokenId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<i32> for TokenId {
    type Error = TokenIdError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match u32::try_from(value) {
            Ok(value) => Ok(Self(value)),
            Err(_) => Err(TokenIdError { value }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenIdError {
    value: i32,
}

impl TokenIdError {
    #[cfg(test)]
    fn value(self) -> i32 {
        self.value
    }
}

impl core::fmt::Display for TokenIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "token id {} is negative", self.value)
    }
}

impl core::error::Error for TokenIdError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenIds {
    tokens: Vec<TokenId>,
}

impl TokenIds {
    pub fn new(tokens: impl Into<Vec<TokenId>>) -> Self {
        Self {
            tokens: tokens.into(),
        }
    }

    pub fn from_u32s(tokens: impl IntoIterator<Item = u32>) -> Self {
        Self {
            tokens: tokens.into_iter().map(TokenId::new).collect(),
        }
    }

    pub fn as_slice(&self) -> &[TokenId] {
        &self.tokens
    }

    /// Requested heap capacity retained by this token buffer.
    #[must_use]
    pub fn retained_heap_bytes(&self) -> Option<usize> {
        self.tokens
            .capacity()
            .checked_mul(std::mem::size_of::<TokenId>())
    }
}

impl<const N: usize> From<[u32; N]> for TokenIds {
    fn from(value: [u32; N]) -> Self {
        Self::from_u32s(value)
    }
}

impl From<Vec<u32>> for TokenIds {
    fn from(value: Vec<u32>) -> Self {
        Self::from_u32s(value)
    }
}

impl FromIterator<TokenId> for TokenIds {
    fn from_iter<T: IntoIterator<Item = TokenId>>(iter: T) -> Self {
        Self::new(iter.into_iter().collect::<Vec<_>>())
    }
}

impl FromIterator<u32> for TokenIds {
    fn from_iter<T: IntoIterator<Item = u32>>(iter: T) -> Self {
        Self::from_u32s(iter)
    }
}

impl Canonical for TokenIds {
    fn encode(&self, encoder: &mut DagCborEncoder) {
        encoder.array(2);
        encoder.str(TOKEN_IDS_SCHEMA);
        encoder.array(self.tokens.len() as u64);
        for token in &self.tokens {
            encoder.u64(token.as_u32() as u64);
        }
    }
}

impl OutputAddressed for TokenIds {}

impl CanonicalDecode for TokenIds {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalDecodeError> {
        parse_canonical(bytes, decode_token_ids)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextPolicy {
    max_new_tokens: u32,
    stop_token_ids: Vec<TokenId>,
}

impl TextPolicy {
    pub fn new(max_new_tokens: u32, stop_token_ids: impl IntoIterator<Item = TokenId>) -> Self {
        let mut stop_token_ids: Vec<_> = stop_token_ids.into_iter().collect();
        stop_token_ids.sort_unstable();
        stop_token_ids.dedup();
        Self {
            max_new_tokens,
            stop_token_ids,
        }
    }

    pub fn from_u32_stop_tokens(
        max_new_tokens: u32,
        stop_token_ids: impl IntoIterator<Item = u32>,
    ) -> Self {
        Self::new(max_new_tokens, stop_token_ids.into_iter().map(TokenId::new))
    }

    pub const fn max_new_tokens(&self) -> u32 {
        self.max_new_tokens
    }

    pub fn stop_token_ids(&self) -> &[TokenId] {
        &self.stop_token_ids
    }

    /// Requested heap capacity retained by the stop-token buffer.
    #[must_use]
    pub fn retained_heap_bytes(&self) -> Option<usize> {
        self.stop_token_ids
            .capacity()
            .checked_mul(std::mem::size_of::<TokenId>())
    }
}

impl Canonical for TextPolicy {
    fn encode(&self, encoder: &mut DagCborEncoder) {
        encoder.array(3);
        encoder.str(TEXT_POLICY_SCHEMA);
        encoder.u64(self.max_new_tokens as u64);
        encoder.array(self.stop_token_ids.len() as u64);
        for token in &self.stop_token_ids {
            encoder.u64(token.as_u32() as u64);
        }
    }
}

impl OutputAddressed for TextPolicy {}

impl CanonicalDecode for TextPolicy {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalDecodeError> {
        parse_canonical(bytes, decode_text_policy)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TextState {
    tokens: TokenIdsId,
}

impl TextState {
    pub const fn new(tokens: TokenIdsId) -> Self {
        Self { tokens }
    }

    pub const fn tokens(&self) -> TokenIdsId {
        self.tokens
    }
}

impl Canonical for TextState {
    fn encode(&self, encoder: &mut DagCborEncoder) {
        encoder.array(2);
        encoder.str(TEXT_STATE_SCHEMA);
        encoder.bytes(self.tokens.as_bytes());
    }
}

impl OutputAddressed for TextState {}

impl CanonicalDecode for TextState {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalDecodeError> {
        parse_canonical(bytes, decode_text_state)
    }
}

pub type TextSource = SourceRef<TextExecution>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextExecution {
    from: TextSource,
    prompt_tokens: TokenIdsId,
    policy: TextPolicyId,
}

impl TextExecution {
    pub const fn new(from: TextSource, prompt_tokens: TokenIdsId, policy: TextPolicyId) -> Self {
        Self {
            from,
            prompt_tokens,
            policy,
        }
    }

    pub const fn from(&self) -> &TextSource {
        &self.from
    }

    pub const fn prompt_tokens(&self) -> TokenIdsId {
        self.prompt_tokens
    }

    pub const fn policy(&self) -> TextPolicyId {
        self.policy
    }
}

impl Canonical for TextExecution {
    fn encode(&self, encoder: &mut DagCborEncoder) {
        encoder.array(4);
        encoder.str(TEXT_EXECUTION_SCHEMA);
        self.from.encode(encoder);
        encoder.bytes(self.prompt_tokens.as_bytes());
        encoder.bytes(self.policy.as_bytes());
    }
}

impl InputAddressed for TextExecution {
    type Artifact = TextArtifact;
}

impl CanonicalDecode for TextExecution {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalDecodeError> {
        parse_canonical(bytes, decode_text_execution)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextOutput {
    execution: TextExecutionId,
    position: u64,
    state: TextStateId,
    generated_tokens: TokenIdsId,
}

impl TextOutput {
    pub const fn new(
        execution: TextExecutionId,
        position: u64,
        state: TextStateId,
        generated_tokens: TokenIdsId,
    ) -> Self {
        Self {
            execution,
            position,
            state,
            generated_tokens,
        }
    }

    pub const fn execution(&self) -> TextExecutionId {
        self.execution
    }

    pub const fn position(&self) -> u64 {
        self.position
    }

    pub const fn state(&self) -> TextStateId {
        self.state
    }

    pub const fn generated_tokens(&self) -> TokenIdsId {
        self.generated_tokens
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextArtifact {
    /// The genesis artifact for one bound execution environment.
    ///
    /// `bound_term` is the content id of the complete [`crate::ProgramManifest`],
    /// so it already commits to the exact evaluator, adaptor, and application
    /// root. Repeating one application-specific content id here would add no
    /// security binding and could disagree with the manifest it purported to
    /// identify.
    Identity {
        bound_term: BoundTermId,
    },
    Output(TextOutput),
}

impl TextArtifact {
    pub const fn identity(bound_term: BoundTermId) -> Self {
        Self::Identity { bound_term }
    }

    pub const fn output(
        execution: TextExecutionId,
        position: u64,
        state: TextStateId,
        generated_tokens: TokenIdsId,
    ) -> Self {
        Self::Output(TextOutput::new(
            execution,
            position,
            state,
            generated_tokens,
        ))
    }
}

impl Canonical for TextArtifact {
    fn encode(&self, encoder: &mut DagCborEncoder) {
        match self {
            Self::Identity { bound_term } => {
                encoder.array(2);
                encoder.str(TEXT_ARTIFACT_IDENTITY_SCHEMA);
                encoder.bytes(bound_term.as_bytes());
            }
            Self::Output(output) => {
                encoder.array(5);
                encoder.str(TEXT_ARTIFACT_OUTPUT_SCHEMA);
                encoder.bytes(output.execution.as_bytes());
                encoder.u64(output.position);
                encoder.bytes(output.state.as_bytes());
                encoder.bytes(output.generated_tokens.as_bytes());
            }
        }
    }
}

impl OutputAddressed for TextArtifact {}

impl CanonicalDecode for TextArtifact {
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalDecodeError> {
        parse_canonical(bytes, decode_text_artifact)
    }
}

// ── What one finished text execution produced ─────────────────────────

/// The four content-addressed bodies one finished text execution
/// produces, derived from its inputs and its output tokens alone.
///
/// They are returned together because they are one derivation: the
/// artifact names the state, the state names the state tokens, and the
/// artifact names the generated tokens. A caller that needed only the
/// artifact would still have to compute the other three to get it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedText {
    /// The tokens this execution generated.
    pub generated_tokens: TokenIds,
    /// Its input tokens followed by the generated ones.
    pub state_tokens: TokenIds,
    /// The state those tokens make.
    pub state: TextState,
    /// The output artifact naming all of it.
    pub artifact: TextArtifact,
}

/// Derives what a finished text execution produced.
///
/// This is the one definition, and it has two consumers who must not
/// disagree: the provider, which records these bodies in its artifact
/// store and signs the resulting artifact id inside a terminal event,
/// and an independent re-execution, which has neither that store nor
/// those events and must arrive at the same id from the same inputs. Two
/// spellings of it would be two answers to "was this the right output",
/// agreeing until one of them changed.
///
/// `input_ids` is the whole prompt as the execution was actually
/// invoked with it — for a job that starts from an identity artifact
/// that is exactly the execution's prompt tokens, because an identity
/// source carries no prior state.
#[must_use]
pub fn completed_text(
    execution: TextExecutionId,
    input_ids: &[u32],
    output_tokens: &[u32],
) -> CompletedText {
    let generated_tokens = TokenIds::from_u32s(output_tokens.iter().copied());
    let state_tokens = TokenIds::from_u32s(input_ids.iter().chain(output_tokens).copied());
    let state = TextState::new(state_tokens.output_id());
    let artifact = TextArtifact::output(
        execution,
        output_tokens.len() as u64,
        state.output_id(),
        generated_tokens.output_id(),
    );
    CompletedText {
        generated_tokens,
        state_tokens,
        state,
        artifact,
    }
}

// ── The prepared paid-work input bundle ───────────────────────────────

/// The six canonical bodies a paid job is prepared from, in one
/// length-delimited byte string.
///
/// Every field above is content-addressed, and an id is not a body: an
/// endpoint holding only ids cannot check what it is about to pay for.
/// This is the bundle that travels with a quote so both endpoints hold
/// the same six bodies, hash them the same way, and can rebuild every
/// commitment in the authorization from bytes they possess.
///
/// It carries bytes rather than parsed values on purpose. The bytes *are*
/// the content ids, so a bundle that stored values and re-encoded them
/// would be asserting that this crate's encoder agrees with whatever
/// produced the ids. [`Self::parts`] parses them, strictly, when meaning
/// is needed.
///
/// Unlike the fixed paid-work records this bundle carries no envelope:
/// it is never signed on its own, and the digest that commits to it
/// supplies its domain separation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedPaidInputV1 {
    evaluate_request: Vec<u8>,
    manifest: Vec<u8>,
    text_execution: Vec<u8>,
    prompt_tokens: Vec<u8>,
    text_policy: Vec<u8>,
    identity_artifact: Vec<u8>,
}

/// Bytes each nested body's length prefix occupies: unsigned big-endian
/// `u32`, six of them.
const LENGTH_PREFIX: usize = 4;

/// The six bodies of a [`PreparedPaidInputV1`], parsed.
///
/// The manifest is retained as its parsed value. Parsing proves the carried
/// bytes were canonical; re-encoding it therefore recovers those exact bytes
/// for a backend after the journal is reopened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedPaidInputParts {
    /// The request whose commitment the authorization names.
    pub evaluate_request: crate::EvaluateRequest,
    /// The strictly decoded environment manifest carried by the bundle.
    pub manifest: crate::ProgramManifest,
    /// The execution the request is addressed by.
    pub text_execution: TextExecution,
    /// Prompt tokens the execution names.
    pub prompt_tokens: TokenIds,
    /// Generation policy the execution names.
    pub text_policy: TextPolicy,
    /// Identity artifact the execution starts from.
    pub identity_artifact: TextArtifact,
}

impl PreparedPaidInputV1 {
    /// Builds a bundle from the six values, encoding each body once.
    pub fn new(
        evaluate_request: &crate::EvaluateRequest,
        manifest: &crate::ProgramManifest,
        text_execution: &TextExecution,
        prompt_tokens: &TokenIds,
        text_policy: &TextPolicy,
        identity_artifact: &TextArtifact,
    ) -> Self {
        Self {
            evaluate_request: crate::protocol::schemes::evaluate::evaluate_request_bytes(
                evaluate_request,
            ),
            manifest: manifest.canonical_bytes(),
            text_execution: text_execution.canonical_bytes(),
            prompt_tokens: prompt_tokens.canonical_bytes(),
            text_policy: text_policy.canonical_bytes(),
            identity_artifact: identity_artifact.canonical_bytes(),
        }
    }

    /// Returns the canonical encoding: six unsigned big-endian `u32`
    /// lengths, each immediately followed by that many body bytes.
    ///
    /// Fallible for one reason: a body whose length does not fit its
    /// `u32` prefix has no encoding here. Truncating the prefix would
    /// give that body a second, shorter spelling whose digest is a
    /// different bundle's, so it is refused instead. No bounded decoder
    /// can produce such a body — [`Self::decode`] reads each length as a
    /// `u32` — but [`Self::new`] takes whatever it is handed.
    pub fn encode(&self) -> Result<Vec<u8>, CanonicalDecodeError> {
        let mut bytes = Vec::new();
        for body in self.bodies() {
            let len = u32::try_from(body.len()).map_err(|_| {
                CanonicalDecodeError::new(format!(
                    "prepared input body is {} bytes, over the u32 length prefix",
                    body.len()
                ))
            })?;
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.extend_from_slice(body);
        }
        Ok(bytes)
    }

    /// Decodes a bundle, refusing anything that does not fit `budget`.
    ///
    /// `budget` is the profile's complete-bundle limit. It is checked
    /// against the input before the first length is read and against the
    /// running total after each one, so six individually representable
    /// lengths cannot add up to a bundle this endpoint never agreed to
    /// hold. No length is trusted far enough to reserve memory for: each
    /// body is taken from the input that already exists.
    pub fn decode(bytes: &[u8], budget: usize) -> Result<Self, CanonicalDecodeError> {
        if bytes.len() > budget {
            return Err(CanonicalDecodeError::new(format!(
                "prepared input is {} bytes, over the {budget}-byte budget",
                bytes.len()
            )));
        }
        let mut reader = BundleReader::new(bytes, budget);
        let bundle = Self {
            evaluate_request: reader.body("evaluate_request")?,
            manifest: reader.body("manifest")?,
            text_execution: reader.body("text_execution")?,
            prompt_tokens: reader.body("prompt_tokens")?,
            text_policy: reader.body("text_policy")?,
            identity_artifact: reader.body("identity_artifact")?,
        };
        if reader.offset != bytes.len() {
            return Err(CanonicalDecodeError::new(format!(
                "trailing bytes after prepared input: {}",
                bytes.len() - reader.offset
            )));
        }
        Ok(bundle)
    }

    /// Parses all six bodies, rejecting any that is not canonical.
    pub fn parts(&self) -> Result<PreparedPaidInputParts, CanonicalDecodeError> {
        Ok(PreparedPaidInputParts {
            evaluate_request: crate::protocol::schemes::evaluate::decode_evaluate_request(
                &self.evaluate_request,
            )?,
            manifest: crate::ProgramManifest::from_canonical_bytes(&self.manifest)?,
            text_execution: TextExecution::from_canonical_bytes(&self.text_execution)?,
            prompt_tokens: TokenIds::from_canonical_bytes(&self.prompt_tokens)?,
            text_policy: TextPolicy::from_canonical_bytes(&self.text_policy)?,
            identity_artifact: TextArtifact::from_canonical_bytes(&self.identity_artifact)?,
        })
    }

    fn bodies(&self) -> [&[u8]; 6] {
        [
            &self.evaluate_request,
            &self.manifest,
            &self.text_execution,
            &self.prompt_tokens,
            &self.text_policy,
            &self.identity_artifact,
        ]
    }
}

/// Cursor over a length-prefixed bundle's bodies.
///
/// Shared with the fetch profile's two-body bundle
/// ([`super::work_fetch::PreparedPaidFetchInputV1`]) so the two rules that
/// keep a declared length honest — never past the input, never past the
/// budget — exist once. The error messages name "prepared input"; the
/// fetch bundle is one.
pub(crate) struct BundleReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    budget: usize,
}

impl<'a> BundleReader<'a> {
    pub(crate) const fn new(bytes: &'a [u8], budget: usize) -> Self {
        Self {
            bytes,
            offset: 0,
            budget,
        }
    }

    /// Bytes consumed so far; the caller compares it against the input
    /// length to refuse trailing bytes.
    ///
    /// Used by the fetch profile's bundle; the evaluate bundle reads the
    /// field directly, one module over.
    #[cfg(feature = "work")]
    pub(crate) const fn offset(&self) -> usize {
        self.offset
    }

    pub(crate) fn body(&mut self, field: &'static str) -> Result<Vec<u8>, CanonicalDecodeError> {
        let start = self
            .offset
            .checked_add(LENGTH_PREFIX)
            .ok_or_else(|| CanonicalDecodeError::new("prepared input offset overflow"))?;
        let prefix = self
            .bytes
            .get(self.offset..start)
            .ok_or_else(|| CanonicalDecodeError::new(format!("{field} length is truncated")))?;
        let mut length = [0_u8; LENGTH_PREFIX];
        length.copy_from_slice(prefix);
        let length = u32::from_be_bytes(length) as usize;

        let end = start
            .checked_add(length)
            .ok_or_else(|| CanonicalDecodeError::new("prepared input offset overflow"))?;
        if end > self.budget {
            return Err(CanonicalDecodeError::new(format!(
                "{field} of {length} bytes exceeds the {}-byte budget",
                self.budget
            )));
        }
        let body = self.bytes.get(start..end).ok_or_else(|| {
            CanonicalDecodeError::new(format!(
                "{field} declares {length} bytes but {} remain",
                self.bytes.len().saturating_sub(start)
            ))
        })?;
        self.offset = end;
        Ok(body.to_vec())
    }
}

fn parse_canonical<T: Canonical>(
    bytes: &[u8],
    decode: fn(&mut CanonicalDecoder<'_>) -> Result<T, CanonicalDecodeError>,
) -> Result<T, CanonicalDecodeError> {
    let mut decoder = CanonicalDecoder::new(bytes);
    let value = decode(&mut decoder)?;
    decoder.finish()?;
    if value.canonical_bytes() != bytes {
        return Err(CanonicalDecodeError::new(
            "value is not in canonical artifact form",
        ));
    }
    Ok(value)
}

fn decode_token_ids(decoder: &mut CanonicalDecoder<'_>) -> Result<TokenIds, CanonicalDecodeError> {
    decoder.array_exact(2)?;
    decoder.expect_str(TOKEN_IDS_SCHEMA)?;
    let len = decoder.array_len()?;
    let mut tokens = Vec::with_capacity(len);
    for _ in 0..len {
        tokens.push(TokenId::new(decoder.u32()?));
    }
    Ok(TokenIds::new(tokens))
}

fn decode_text_policy(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<TextPolicy, CanonicalDecodeError> {
    decoder.array_exact(3)?;
    decoder.expect_str(TEXT_POLICY_SCHEMA)?;
    let max_new_tokens = decoder.u32()?;
    let len = decoder.array_len()?;
    let mut stop_token_ids = Vec::with_capacity(len);
    for _ in 0..len {
        stop_token_ids.push(TokenId::new(decoder.u32()?));
    }
    Ok(TextPolicy::new(max_new_tokens, stop_token_ids))
}

fn decode_text_state(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<TextState, CanonicalDecodeError> {
    decoder.array_exact(2)?;
    decoder.expect_str(TEXT_STATE_SCHEMA)?;
    Ok(TextState::new(TokenIdsId::from_bytes(decoder.bytes_32()?)))
}

fn decode_text_source(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<TextSource, CanonicalDecodeError> {
    decoder.array_exact(2)?;
    match decoder.str()? {
        SOURCE_INPUT_SCHEMA => Ok(SourceRef::input(TextExecutionId::from_bytes(
            decoder.bytes_32()?,
        ))),
        SOURCE_OUTPUT_SCHEMA => Ok(SourceRef::output(TextArtifactId::from_bytes(
            decoder.bytes_32()?,
        ))),
        other => Err(CanonicalDecodeError::new(format!(
            "unexpected text source schema tag {other:?}"
        ))),
    }
}

fn decode_text_execution(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<TextExecution, CanonicalDecodeError> {
    decoder.array_exact(4)?;
    decoder.expect_str(TEXT_EXECUTION_SCHEMA)?;
    let from = decode_text_source(decoder)?;
    let prompt_tokens = TokenIdsId::from_bytes(decoder.bytes_32()?);
    let policy = TextPolicyId::from_bytes(decoder.bytes_32()?);
    Ok(TextExecution::new(from, prompt_tokens, policy))
}

fn decode_text_artifact(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<TextArtifact, CanonicalDecodeError> {
    let len = decoder.array_len()?;
    match decoder.str()? {
        TEXT_ARTIFACT_IDENTITY_SCHEMA => {
            if len != 2 {
                return Err(CanonicalDecodeError::new(format!(
                    "{TEXT_ARTIFACT_IDENTITY_SCHEMA} expected array length 2, got {len}"
                )));
            }
            Ok(TextArtifact::identity(BoundTermId::from_bytes(
                decoder.bytes_32()?,
            )))
        }
        TEXT_ARTIFACT_OUTPUT_SCHEMA => {
            if len != 5 {
                return Err(CanonicalDecodeError::new(format!(
                    "{TEXT_ARTIFACT_OUTPUT_SCHEMA} expected array length 5, got {len}"
                )));
            }
            Ok(TextArtifact::output(
                TextExecutionId::from_bytes(decoder.bytes_32()?),
                decoder.u64()?,
                TextStateId::from_bytes(decoder.bytes_32()?),
                TokenIdsId::from_bytes(decoder.bytes_32()?),
            ))
        }
        other => Err(CanonicalDecodeError::new(format!(
            "unexpected text artifact schema tag {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests;
