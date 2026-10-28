//! Application-neutral inputs and results for paid execution.
//!
//! The application named by a ProgramManifest owns the meaning of parameters
//! and typed artifacts. This layer binds their exact bytes, without interpreting
//! an audio sample, image pixel, or token as a common billing unit.

use hellas_auth::{Digest, PublicKey};
use serde::{Deserialize, Serialize};

use super::value::{CanonicalDecodeError, decode_canonical_dag_cbor};
use crate::{
    Assurance, ContentId, InputCommitment, JsonBytes, ProgramManifest, RequestCommitment,
    canonical_dag_cbor,
};

mod admission;
pub use admission::{AdmissionFacts, VerifiedOutput};
pub mod compute;
pub mod fetch;
pub mod policy;
pub use policy::{Admission, CapacityDomain, InvocationPolicy, Limits};
pub mod output;

const REQUEST_DOMAIN: &str = "hellas.invocation.request.v1";
const INPUT_DOMAIN: &str = "hellas.invocation.input.v1";
const PREPARED_DOMAIN: &str = "hellas.work.prepared-invocation.v1";
const ARTIFACT_DOMAIN: &str = "hellas.invocation.artifact.v1";
const MAX_LABEL_BYTES: usize = 256;
pub const MAX_ARTIFACTS: usize = 64;
/// Hard per-invocation encoded input or signed-transcript ceiling. Transport
/// frames and application/channel limits are independently smaller bounds.
pub const MAX_INVOCATION_BYTES: usize = 64 * 1024 * 1024;

/// Named numeric or other application-defined content. `format` is an exact
/// application-owned codec identity, not a display MIME type inferred by a host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub name: String,
    pub format: String,
    pub bytes: JsonBytes,
}

impl Artifact {
    pub fn new(name: impl Into<String>, format: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            format: format.into(),
            bytes: JsonBytes(bytes),
        }
    }

    /// Binds both the bytes and how the application interprets them.
    pub fn content_id(&self) -> Result<ContentId, CanonicalDecodeError> {
        self.validate()?;
        Ok(ContentId::hash(&encode(&(ARTIFACT_DOMAIN, self))?))
    }

    pub fn validate(&self) -> Result<(), CanonicalDecodeError> {
        label(&self.name)?;
        label(&self.format)
    }
}

/// Parameters and inputs in lexicographic artifact-name order. A name occurs
/// exactly once; adapters never get ambiguous duplicate input roles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationInput {
    pub parameters: JsonBytes,
    pub artifacts: Vec<Artifact>,
}

impl InvocationInput {
    pub fn validate(&self) -> Result<(), CanonicalDecodeError> {
        validate_artifacts(&self.artifacts)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalDecodeError> {
        self.validate()?;
        encode(&(INPUT_DOMAIN, self))
    }

    pub fn content_id(&self) -> Result<ContentId, CanonicalDecodeError> {
        Ok(ContentId::hash(&self.canonical_bytes()?))
    }

    pub fn from_canonical_bytes(bytes: &[u8], budget: usize) -> Result<Self, CanonicalDecodeError> {
        bound(bytes, budget)?;
        let (domain, input): (String, Self) = decode_canonical_dag_cbor(bytes)?;
        domain_is(&domain, INPUT_DOMAIN)?;
        input.validate()?;
        Ok(input)
    }
}

/// The common request. Its environment pins the exact application and root;
/// its input pins parameters, seed, reference media, and other application data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationRequest {
    pub execution_environment: ContentId,
    pub input: ContentId,
    pub runner_public_key: PublicKey,
    pub nonce: [u8; 32],
    pub assurance: Assurance,
    pub retain: bool,
}

impl InvocationRequest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalDecodeError> {
        encode(&(REQUEST_DOMAIN, self))
    }

    pub fn commitment(&self) -> Result<RequestCommitment, CanonicalDecodeError> {
        Ok(RequestCommitment::from_canonical_bytes(
            &self.canonical_bytes()?,
        ))
    }

    pub fn input_commitment(&self) -> Result<InputCommitment, CanonicalDecodeError> {
        Ok(InputCommitment::from_digest(self.commitment()?.digest()))
    }
}

/// Exact request and manifest bytes, the input, and the application admission
/// policy body. Model objects remain below the content-addressed manifest root.
/// No path, tokenizer default, or provider-local option can change this input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedInvocation {
    pub request: InvocationRequest,
    manifest: JsonBytes,
    pub input: InvocationInput,
    pub application_policy: JsonBytes,
}

impl PreparedInvocation {
    /// Conservative directly owned heap size, including spare collection capacity.
    /// Provider admission can bound retained prepared requests before dispatch.
    pub fn retained_heap_bytes(&self) -> Option<usize> {
        let mut bytes = self
            .manifest
            .0
            .capacity()
            .checked_add(self.input.parameters.0.capacity())?
            .checked_add(self.application_policy.0.capacity())?
            .checked_add(
                self.input
                    .artifacts
                    .capacity()
                    .checked_mul(std::mem::size_of::<Artifact>())?,
            )?;
        for artifact in &self.input.artifacts {
            bytes = bytes
                .checked_add(artifact.name.capacity())?
                .checked_add(artifact.format.capacity())?
                .checked_add(artifact.bytes.0.capacity())?;
        }
        Some(bytes)
    }
    pub fn new(
        request: InvocationRequest,
        manifest: &ProgramManifest,
        input: InvocationInput,
        application_policy: Vec<u8>,
    ) -> Result<Self, CanonicalDecodeError> {
        let prepared = Self {
            request,
            manifest: JsonBytes(manifest.canonical_bytes()),
            input,
            application_policy: JsonBytes(application_policy),
        };
        prepared.validate()?;
        Ok(prepared)
    }

    pub fn manifest(&self) -> Result<ProgramManifest, CanonicalDecodeError> {
        ProgramManifest::from_canonical_bytes(self.manifest.as_bytes())
    }

    pub fn policy_digest(&self) -> Digest {
        hellas_auth::hash_tuple(
            "hellas.work.application-policy.v1",
            &[self.application_policy.as_bytes()],
        )
    }

    pub fn validate(&self) -> Result<(), CanonicalDecodeError> {
        if self.manifest()?.content_id() != self.request.execution_environment {
            return Err(error("invocation manifest does not match the request"));
        }
        if self.input.content_id()? != self.request.input {
            return Err(error("invocation input does not match the request"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalDecodeError> {
        self.validate()?;
        encode(&(PREPARED_DOMAIN, self))
    }

    pub fn from_canonical_bytes(bytes: &[u8], budget: usize) -> Result<Self, CanonicalDecodeError> {
        bound(bytes, budget)?;
        let (domain, prepared): (String, Self) = decode_canonical_dag_cbor(bytes)?;
        domain_is(&domain, PREPARED_DOMAIN)?;
        prepared.validate()?;
        Ok(prepared)
    }
}

pub(crate) fn validate_artifacts(artifacts: &[Artifact]) -> Result<(), CanonicalDecodeError> {
    if artifacts.len() > MAX_ARTIFACTS {
        return Err(error("too many invocation artifacts"));
    }
    let mut previous: Option<&str> = None;
    for artifact in artifacts {
        artifact.validate()?;
        if previous.is_some_and(|name| name >= artifact.name.as_str()) {
            return Err(error("artifact names must be unique and sorted"));
        }
        previous = Some(&artifact.name);
    }
    Ok(())
}

pub(crate) fn label(value: &str) -> Result<(), CanonicalDecodeError> {
    if value.is_empty() || value.len() > MAX_LABEL_BYTES || value.chars().any(char::is_control) {
        return Err(error(
            "artifact names and formats must be bounded nonempty labels",
        ));
    }
    Ok(())
}

pub(crate) fn bound(bytes: &[u8], budget: usize) -> Result<(), CanonicalDecodeError> {
    if bytes.len() > budget {
        return Err(error("invocation exceeds its byte budget"));
    }
    Ok(())
}

pub(crate) fn domain_is(actual: &str, expected: &str) -> Result<(), CanonicalDecodeError> {
    if actual != expected {
        return Err(error("wrong invocation schema"));
    }
    Ok(())
}

pub(crate) fn encode(value: &impl Serialize) -> Result<Vec<u8>, CanonicalDecodeError> {
    canonical_dag_cbor(value).map_err(|e| error(e.to_string()))
}

pub(crate) fn error(message: impl Into<String>) -> CanonicalDecodeError {
    CanonicalDecodeError::new(message)
}

#[cfg(all(test, feature = "fetch"))]
mod tests;
