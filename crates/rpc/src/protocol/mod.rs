//! Protocol primitives for Hellas commitments and signed streams.

pub mod artifacts;
pub mod causal_lm;
pub mod commitment;
pub mod digest;
pub mod fetch_contract;
pub use fetch_contract::{FETCH_EVALUATOR, FetchContract, FetchEgress, FetchSchema};
pub mod identity;
pub mod job;
pub mod manifest;
pub mod open;
pub mod retention;
pub mod schemes;
pub mod stream;
pub mod tags;
pub mod value;

pub use causal_lm::{
    CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR, CausalLmEnvironment, CausalLmEnvironmentError,
    CausalLmGenerationSchedule, ContentRef, MAX_CAUSAL_LM_ENVIRONMENT_BYTES,
    MAX_CAUSAL_LM_STATIC_BYTES, StaticSlice,
};
pub use commitment::{Assurance, Operation, RequestCommitment, SchemeId, scheme_id};
pub use digest::ContentId;
pub use identity::{
    AppleAppAttestEnrollment, Decoder as DagCborDecoder, PlatformCredential, PlatformEnrollment,
    ProviderEnrollmentBundle, ProviderGenesisDecodeError, ProviderGenesisStatement, RootKind,
    RootProof, SignedProviderGenesis,
};
pub use job::APPLE_APP_ATTEST;
pub use manifest::{Application, ApplicationError, MAX_APPLICATION_ID_BYTES, ProgramManifest};
pub use open::{
    OPEN_EXPORTER_LEN, OPEN_NONCE_LEN, OPEN_PROOF_DOMAIN, OPEN_PROVIDER_ROLE, open_proof_binding,
};
pub use retention::Retention;
pub use schemes::evaluate::{Evaluate, EvaluateRequest};
pub use stream::{
    CanonicalizationId, EventCommitment, InputCommitment, InputEventBody, InputEventBodyParts,
    InputEventEnvelope, InputTranscriptBuilder, OutputEventBody, OutputEventBodyParts,
    OutputEventEnvelope, OutputTranscriptBuilder, SignedInputEvent, SignedOutputEvent, StreamId,
    StreamVerifyError, input_genesis, output_genesis, verify_input_event_envelopes,
    verify_output_event_continuation, verify_output_event_envelopes,
};
pub use value::{
    DagCborDecodeError, DagCborEncodeError, DagCborEncoder, JsonBytes, canonical_dag_cbor,
    decode_dag_cbor,
};
