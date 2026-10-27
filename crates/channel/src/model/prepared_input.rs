//! Prepared paid-work input bundles.

use hellas_rpc::protocol::artifacts::{
    BundleReader, Canonical, CanonicalDecode, TextArtifact, TextExecution, TextPolicy, TokenIds,
};
use hellas_rpc::protocol::value::CanonicalDecodeError;

/// The six canonical bodies a paid job is prepared from, in one
/// length-delimited byte string.
///
/// Every field is content-addressed, and an id is not a body: an
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

/// The six bodies of a [`PreparedPaidInputV1`], parsed.
///
/// The manifest is retained as its parsed value. Parsing proves the carried
/// bytes were canonical; re-encoding it therefore recovers those exact bytes
/// for a backend after the journal is reopened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedPaidInputParts {
    /// The request whose commitment the authorization names.
    pub evaluate_request: hellas_rpc::EvaluateRequest,
    /// The strictly decoded environment manifest carried by the bundle.
    pub manifest: hellas_rpc::ProgramManifest,
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
        evaluate_request: &hellas_rpc::EvaluateRequest,
        manifest: &hellas_rpc::ProgramManifest,
        text_execution: &TextExecution,
        prompt_tokens: &TokenIds,
        text_policy: &TextPolicy,
        identity_artifact: &TextArtifact,
    ) -> Self {
        Self {
            evaluate_request: hellas_rpc::protocol::schemes::evaluate::evaluate_request_bytes(
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
        if reader.offset() != bytes.len() {
            return Err(CanonicalDecodeError::new(format!(
                "trailing bytes after prepared input: {}",
                bytes.len() - reader.offset()
            )));
        }
        Ok(bundle)
    }

    /// Parses all six bodies, rejecting any that is not canonical.
    pub fn parts(&self) -> Result<PreparedPaidInputParts, CanonicalDecodeError> {
        Ok(PreparedPaidInputParts {
            evaluate_request: hellas_rpc::protocol::schemes::evaluate::decode_evaluate_request(
                &self.evaluate_request,
            )?,
            manifest: hellas_rpc::ProgramManifest::from_canonical_bytes(&self.manifest)?,
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
