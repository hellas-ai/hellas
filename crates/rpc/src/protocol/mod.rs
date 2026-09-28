//! Protocol primitives for Hellas commitments and signed streams.

pub mod artifacts;
pub mod causal_lm;
pub mod commitment;
pub mod digest;
pub mod fetch_environment;
pub mod identity;
pub mod job;
pub mod manifest;
pub mod open;
pub mod retention;
pub mod schemes;
pub mod signature;
pub mod stream;
pub mod tags;
pub mod value;
#[cfg(feature = "work")]
pub mod work;
#[cfg(feature = "work")]
pub mod work_bundle;
#[cfg(feature = "work")]
pub mod work_fetch;
#[cfg(feature = "work")]
pub mod work_profile;
#[cfg(feature = "work")]
pub mod work_setup;

pub use causal_lm::{
    CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR, CausalLmEnvironment, CausalLmEnvironmentError,
    CausalLmGenerationSchedule, ContentRef, MAX_CAUSAL_LM_ENVIRONMENT_BYTES,
    MAX_CAUSAL_LM_STATIC_BYTES, StaticSlice,
};
pub use commitment::{Assurance, Operation, RequestCommitment, SchemeId, scheme_id};
pub use digest::{ContentId, Digest, hash_tuple};
pub use fetch_environment::{
    CODEX_RESPONSES_ADAPTOR, CODEX_RESPONSES_ENDPOINT, FETCH_EVALUATOR, FetchEnvironment,
    OPENAI_RESPONSES_ADAPTOR, OPENAI_RESPONSES_ENDPOINT,
};
pub use identity::{
    AppleAppAttestEnrollment, Decoder as DagCborDecoder, PlatformCredential, PlatformEnrollment,
    ProviderEnrollmentBundle, ProviderGenesisDecodeError, ProviderGenesisStatement,
    ProviderIdentityV1, RootKind, RootProof, SignedProviderGenesis,
};
pub use job::{APPLE_APP_ATTEST, JobTerms};
pub use manifest::{Application, ApplicationError, MAX_APPLICATION_ID_BYTES, ProgramManifest};
pub use open::{
    OPEN_EXPORTER_LEN, OPEN_NONCE_LEN, OPEN_PROOF_DOMAIN, OPEN_PROVIDER_ROLE, open_proof_binding,
};
pub use retention::Retention;
pub use schemes::evaluate::{Evaluate, EvaluateRequest};
pub use signature::{
    ProducerId, ProducerSigningKey, PublicKey, Signature, SignatureError, SignatureKind,
};
pub use stream::{
    CanonicalizationId, EventCommitment, InputCommitment, InputEventBody, InputEventBodyParts,
    InputEventEnvelope, InputTranscriptBuilder, OutputEventBody, OutputEventBodyParts,
    OutputEventEnvelope, OutputTranscriptBuilder, SignedInputEvent, SignedOutputEvent, StreamId,
    StreamVerifyError, input_genesis, output_genesis, verify_input_event_envelopes,
    verify_input_transcript, verify_output_event_continuation, verify_output_event_envelopes,
    verify_output_transcript,
};
pub use value::{
    DagCborDecodeError, DagCborEncodeError, DagCborEncoder, JsonBytes, canonical_dag_cbor,
    decode_dag_cbor,
};
