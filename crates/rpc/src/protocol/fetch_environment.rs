//! Canonical environment interpreted by the attested Fetch application.
//!
//! Unlike the causal-LM evaluator, Fetch includes exact request structuring
//! and response destructuring in its trusted, attested path. A value of this
//! type therefore names a built-in transformation contract; it is not an
//! operator-supplied claim about an external program or build.
//!
//! A platform-backed assurance authenticates the running application that
//! implements the contract. `ProducerSigned` authenticates only the producer
//! key and transcript; it makes no claim about the running binary. Route names,
//! upstream credentials, and access policy remain provider-local and are
//! deliberately absent from this root.
//! Selecting the upstream destination is trusted execution semantics, so every
//! built-in root commits a driver contract. Sealed roots fix the endpoint; the
//! HTTP root interprets the URL and TLS policy in the caller-signed request.
//! The upstream service and every response claim remain adversarial input.

use crate::{Application, ContentId, DagCborEncoder, ProgramManifest};

use super::value::{CanonicalDecodeError, CanonicalDecoder};

/// Exact evaluator identity for attested Fetch transformations.
pub const FETCH_EVALUATOR: &str = "hellas/fetch-0.0.1";
/// Exact adaptor identity of the built-in Codex Responses transformation.
pub const CODEX_RESPONSES_ADAPTOR: &str = "codex-responses-0.0.1";
/// Exact adaptor identity of the built-in OpenAI Responses transformation.
pub const OPENAI_RESPONSES_ADAPTOR: &str = "openai-responses-0.0.1";

/// The only egress destination of [`FetchEnvironment::CodexResponses`].
pub const CODEX_RESPONSES_ENDPOINT: &str = "https://chatgpt.com/backend-api/codex/responses";
/// The only egress destination of [`FetchEnvironment::OpenAiResponses`].
pub const OPENAI_RESPONSES_ENDPOINT: &str = "https://api.openai.com/v1/responses";

// These are opaque protocol identities, not capability strings. Each one
// names the complete built-in request builder, authentication/header driver,
// no-redirect rule, and SSE response projector. Changing any of those
// semantics requires a new identity and therefore a new manifest ID.
const CODEX_RESPONSES_DRIVER: &str = "codex-responses-driver-0.0.1";
const OPENAI_RESPONSES_DRIVER: &str = "openai-responses-driver-0.0.1";

const FETCH_ENVIRONMENT_DOMAIN: &str = "hellas.fetch.environment.v1";

/// An exact built-in request/response transformation and its trusted config.
///
/// Each variant fixes the interpreter compiled into the attested application.
/// The HTTP interpreter binds request-selected destinations and TLS settings
/// through the signed input; it does not enumerate upstream vendors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchEnvironment {
    /// HTTPS to the signed URL with selected trust roots and optional SPKI pins.
    Http,
    /// Build an official Codex Responses request, send it only to the fixed
    /// ChatGPT Codex endpoint, and project its SSE response.
    CodexResponses,
    /// Build an official OpenAI Responses request, send it only to the fixed
    /// official endpoint, and project its SSE response into the canonical
    /// Hellas output event stream.
    OpenAiResponses,
}

impl FetchEnvironment {
    /// Returns the exact opaque adaptor identity owned by this built-in
    /// transformation.
    #[must_use]
    pub const fn adaptor(self) -> &'static str {
        match self {
            Self::Http => "http-0.0.1",
            Self::CodexResponses => CODEX_RESPONSES_ADAPTOR,
            Self::OpenAiResponses => OPENAI_RESPONSES_ADAPTOR,
        }
    }

    /// The exact built-in HTTP driver contract committed by this root.
    #[must_use]
    pub const fn driver(self) -> &'static str {
        match self {
            Self::Http => "https-request-roots-and-spki-no-redirect-0.0.1",
            Self::CodexResponses => CODEX_RESPONSES_DRIVER,
            Self::OpenAiResponses => OPENAI_RESPONSES_DRIVER,
        }
    }

    /// The exact HTTPS endpoint committed by this root.
    #[must_use]
    pub const fn endpoint(self) -> &'static str {
        match self {
            Self::Http => "caller-signed:https-url",
            Self::CodexResponses => CODEX_RESPONSES_ENDPOINT,
            Self::OpenAiResponses => OPENAI_RESPONSES_ENDPOINT,
        }
    }

    /// Strict DAG-CBOR `[domain, adaptor, driver, endpoint]` encoding.
    ///
    /// Repeating the adaptor below the generic manifest root makes the root a
    /// self-describing commitment to the trusted transformation contract. It
    /// does not assert an independently unverifiable build identity.
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut encoder = DagCborEncoder::new();
        encoder.array(4);
        encoder.str(FETCH_ENVIRONMENT_DOMAIN);
        encoder.str(self.adaptor());
        encoder.str(self.driver());
        encoder.str(self.endpoint());
        encoder.into_bytes()
    }

    /// Decodes exactly one of the built-in transformation roots.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalDecodeError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        decoder.array_exact(4)?;
        decoder.expect_str(FETCH_ENVIRONMENT_DOMAIN)?;
        let adaptor = decoder.str()?;
        let driver = decoder.str()?;
        let endpoint = decoder.str()?;
        decoder.finish()?;

        let environment = match (adaptor, driver, endpoint) {
            (
                "http-0.0.1",
                "https-request-roots-and-spki-no-redirect-0.0.1",
                "caller-signed:https-url",
            ) => Self::Http,
            (CODEX_RESPONSES_ADAPTOR, CODEX_RESPONSES_DRIVER, CODEX_RESPONSES_ENDPOINT) => {
                Self::CodexResponses
            }
            (OPENAI_RESPONSES_ADAPTOR, OPENAI_RESPONSES_DRIVER, OPENAI_RESPONSES_ENDPOINT) => {
                Self::OpenAiResponses
            }
            _ => {
                return Err(CanonicalDecodeError::new(
                    "unknown Fetch adaptor, driver, or endpoint combination",
                ));
            }
        };
        if environment.canonical_bytes() != bytes {
            return Err(CanonicalDecodeError::new(
                "Fetch environment is not in canonical DAG-CBOR form",
            ));
        }
        Ok(environment)
    }

    /// Returns the Xet content identifier used as [`ProgramManifest::root`].
    #[must_use]
    pub fn content_id(self) -> ContentId {
        ContentId::hash(&self.canonical_bytes())
    }

    /// Wraps this trusted root in the exact application identity implemented
    /// by the built-in adaptor and driver.
    #[must_use]
    pub fn manifest(self) -> ProgramManifest {
        let application = Application::new(FETCH_EVALUATOR, self.adaptor())
            .expect("built-in Fetch application IDs are valid");
        ProgramManifest::new(application, self.content_id())
    }

    /// Returns the complete execution-environment commitment quoted for this
    /// built-in transformation.
    #[must_use]
    pub fn manifest_id(self) -> ContentId {
        self.manifest().content_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_roots_are_fixed_distinct_and_round_trip() {
        for environment in [
            FetchEnvironment::CodexResponses,
            FetchEnvironment::OpenAiResponses,
        ] {
            let bytes = environment.canonical_bytes();
            assert_eq!(
                FetchEnvironment::from_canonical_bytes(&bytes),
                Ok(environment)
            );
            assert_eq!(environment.content_id(), ContentId::hash(&bytes));

            let manifest = environment.manifest();
            assert_eq!(manifest.application().evaluator(), FETCH_EVALUATOR);
            assert_eq!(manifest.application().adaptor(), environment.adaptor());
            assert_eq!(manifest.root(), environment.content_id());
            assert_eq!(manifest.content_id(), environment.manifest_id());
        }

        assert_ne!(
            FetchEnvironment::CodexResponses.content_id(),
            FetchEnvironment::OpenAiResponses.content_id()
        );
        assert_ne!(
            FetchEnvironment::CodexResponses.manifest_id(),
            FetchEnvironment::OpenAiResponses.manifest_id()
        );
        assert_eq!(
            FetchEnvironment::CodexResponses.manifest_id().to_string(),
            "82ebed7724b614bfcca6082924710098821cafc95789f136f770667e16ef9785"
        );
        assert_eq!(
            FetchEnvironment::OpenAiResponses.manifest_id().to_string(),
            "a4ff1dbe22fe5d6888258bd95d21a288855c11d40b59c86ad834ab747033e8e8"
        );
    }

    #[test]
    fn decoder_rejects_mixed_contracts_and_noncanonical_shapes() {
        let canonical = FetchEnvironment::OpenAiResponses.canonical_bytes();

        let mut mixed = DagCborEncoder::new();
        mixed.array(4);
        mixed.str(FETCH_ENVIRONMENT_DOMAIN);
        mixed.str(CODEX_RESPONSES_ADAPTOR);
        mixed.str(OPENAI_RESPONSES_DRIVER);
        mixed.str(CODEX_RESPONSES_ENDPOINT);
        assert!(FetchEnvironment::from_canonical_bytes(&mixed.into_bytes()).is_err());

        let mut wrong_shape = canonical.clone();
        wrong_shape[0] = 0x85;
        assert!(FetchEnvironment::from_canonical_bytes(&wrong_shape).is_err());

        let mut trailing = canonical;
        trailing.push(0);
        assert!(FetchEnvironment::from_canonical_bytes(&trailing).is_err());
    }
}
