use crate::{ContentId, DagCborEncoder};

use super::value::{CanonicalDecodeError, CanonicalDecoder};

const PROGRAM_MANIFEST_DOMAIN: &str = "hellas.program.manifest.v4";
const MAX_PROGRAM_MANIFEST_BYTES: usize = 4 * 1024;
/// Maximum UTF-8 byte length of each opaque application identity component.
pub const MAX_APPLICATION_ID_BYTES: usize = 1024;

/// The exact evaluator and adaptor that interpret a program root.
///
/// Both identifiers are opaque. Identity compares the complete pair exactly as
/// supplied: this layer performs no parsing, normalization, version
/// negotiation, or compatibility inference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Application {
    evaluator: String,
    adaptor: String,
}

impl Application {
    /// Builds one exact application identity without parsing or normalization.
    pub fn new(
        evaluator: impl Into<String>,
        adaptor: impl Into<String>,
    ) -> Result<Self, ApplicationError> {
        let evaluator = evaluator.into();
        let adaptor = adaptor.into();
        if evaluator.is_empty() {
            return Err(ApplicationError::EmptyEvaluator);
        }
        if evaluator.len() > MAX_APPLICATION_ID_BYTES {
            return Err(ApplicationError::EvaluatorTooLong {
                bytes: evaluator.len(),
                limit: MAX_APPLICATION_ID_BYTES,
            });
        }
        if adaptor.is_empty() {
            return Err(ApplicationError::EmptyAdaptor);
        }
        if adaptor.len() > MAX_APPLICATION_ID_BYTES {
            return Err(ApplicationError::AdaptorTooLong {
                bytes: adaptor.len(),
                limit: MAX_APPLICATION_ID_BYTES,
            });
        }
        Ok(Self { evaluator, adaptor })
    }

    /// Returns the exact opaque evaluator identity.
    #[must_use]
    pub fn evaluator(&self) -> &str {
        &self.evaluator
    }

    /// Returns the exact opaque adaptor identity.
    #[must_use]
    pub fn adaptor(&self) -> &str {
        &self.adaptor
    }
}

/// A malformed opaque component of an [`Application`] identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ApplicationError {
    /// The evaluator identity was empty.
    #[error("application evaluator must not be empty")]
    EmptyEvaluator,
    /// The adaptor identity was empty.
    #[error("application adaptor must not be empty")]
    EmptyAdaptor,
    /// The evaluator identity exceeded [`MAX_APPLICATION_ID_BYTES`].
    #[error("application evaluator is {bytes} UTF-8 bytes, over the {limit}-byte limit")]
    EvaluatorTooLong {
        /// Observed UTF-8 byte length.
        bytes: usize,
        /// Maximum accepted UTF-8 byte length.
        limit: usize,
    },
    /// The adaptor identity exceeded [`MAX_APPLICATION_ID_BYTES`].
    #[error("application adaptor is {bytes} UTF-8 bytes, over the {limit}-byte limit")]
    AdaptorTooLong {
        /// Observed UTF-8 byte length.
        bytes: usize,
        /// Maximum accepted UTF-8 byte length.
        limit: usize,
    },
}

/// One application-owned, content-addressed execution environment.
///
/// The application defines the meaning of `root`. For example, Catena causal
/// LM roots exclude tokenizers, chat templates, decoding, and other
/// presentation policy. An attested Fetch application instead includes its
/// exact request structuring and response destructuring because those steps are
/// trusted computation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramManifest {
    application: Application,
    root: ContentId,
}

// The prepared invocation carries the manifest as its strict canonical byte string.
impl serde::Serialize for ProgramManifest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.canonical_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for ProgramManifest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        Self::from_canonical_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl ProgramManifest {
    pub(super) fn retained_heap_bytes(&self) -> Option<usize> {
        self.application
            .evaluator
            .capacity()
            .checked_add(self.application.adaptor.capacity())
    }

    /// Binds an exact application identity to its application-owned root.
    #[must_use]
    pub const fn new(application: Application, root: ContentId) -> Self {
        Self { application, root }
    }

    /// Returns the complete, exact interpreter identity.
    #[must_use]
    pub const fn application(&self) -> &Application {
        &self.application
    }

    /// Returns the content identifier whose structure the application owns.
    #[must_use]
    pub const fn root(&self) -> ContentId {
        self.root
    }

    /// Strict DAG-CBOR `[domain, [evaluator, adaptor], root]` encoding.
    ///
    /// Definite arrays and the minimal encoder give every manifest exactly one
    /// wire representation, independent of which application interprets it.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = DagCborEncoder::new();
        encoder.array(3);
        encoder.str(PROGRAM_MANIFEST_DOMAIN);
        encoder.array(2);
        encoder.str(&self.application.evaluator);
        encoder.str(&self.application.adaptor);
        encoder.bytes(self.root.as_bytes());
        encoder.into_bytes()
    }

    /// Decodes the single strict, bounded DAG-CBOR manifest representation.
    ///
    /// Evaluator and adaptor identifiers remain exact opaque strings; decoding
    /// does not normalize, parse, or negotiate either one.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalDecodeError> {
        if bytes.len() > MAX_PROGRAM_MANIFEST_BYTES {
            return Err(CanonicalDecodeError::new(format!(
                "program manifest is {} bytes, over the {MAX_PROGRAM_MANIFEST_BYTES}-byte limit",
                bytes.len()
            )));
        }

        let mut decoder = CanonicalDecoder::new(bytes);
        decoder.array_exact(3)?;
        decoder.expect_str(PROGRAM_MANIFEST_DOMAIN)?;
        decoder.array_exact(2)?;
        let evaluator = decoder.str()?.to_string();
        let adaptor = decoder.str()?.to_string();
        let root = ContentId::from_bytes(decoder.bytes_32()?);
        decoder.finish()?;

        let application = Application::new(evaluator, adaptor)
            .map_err(|error| CanonicalDecodeError::new(error.to_string()))?;
        let manifest = Self::new(application, root);
        if manifest.canonical_bytes() != bytes {
            return Err(CanonicalDecodeError::new(
                "program manifest is not in canonical DAG-CBOR form",
            ));
        }
        Ok(manifest)
    }

    /// Returns the Xet content identifier of the canonical manifest bytes.
    pub fn content_id(&self) -> ContentId {
        ContentId::hash(&self.canonical_bytes())
    }
}

#[cfg(test)]
mod tests;
