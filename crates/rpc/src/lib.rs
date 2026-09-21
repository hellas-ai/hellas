pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GIT_REV: &str = match option_env!("GIT_REV") {
    Some(rev) => rev,
    None => "unknown",
};

/// Maximum canonical size of one submitted transaction.
pub const MAX_CANONICAL_TRANSACTION_BYTES: usize = 65_536;
/// Exact protobuf envelope size of a maximum-size `SubmitTx` kernel payload.
pub const MAX_SUBMIT_TX_PROTO_BYTES: usize = 65_540;
/// Raw protobuf request-body ceiling for `SubmitWorkResponse`.
pub const MAX_SUBMIT_WORK_RESPONSE_PROTO_BYTES: usize = 65_536;

/// What happened when a transaction was submitted to a node.
///
/// This type deliberately has no unspecified variant. The protobuf zero value
/// is a wire error, not an outcome an in-process caller can mistake for
/// acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitTxOutcome {
    /// The transaction is resident locally, pending consensus inclusion.
    Enqueued,
    /// The same transaction digest is already resident locally.
    Duplicate,
    /// The bounded mempool had no room for the transaction.
    Full,
    /// Snapshot-local admission validation rejected the transaction.
    ValidationRejected,
}

impl core::fmt::Display for SubmitTxOutcome {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Enqueued => "enqueued, pending inclusion",
            Self::Duplicate => "duplicate, pending inclusion",
            Self::Full => "mempool full, not enqueued",
            Self::ValidationRejected => "validation rejected, not enqueued",
        })
    }
}

pub mod cache;
pub mod call;
#[cfg(feature = "chain")]
pub mod edge_index;
#[cfg(feature = "evaluate")]
pub mod evaluate;
#[cfg(feature = "fetch")]
pub mod fetch;
pub mod observe;
#[cfg(feature = "execute")]
pub mod open;
#[cfg(feature = "fetch")]
pub mod output;
/// Peer registry, admission, and connection directory module.
pub mod peers;
/// Execution authorization policy module.
#[cfg(feature = "execute")]
pub mod policy;
pub mod protocol;
#[cfg(feature = "execute")]
pub mod run_ticket;
pub mod serve;
#[cfg(feature = "execute")]
pub mod stream;

pub mod provenance;

#[cfg(feature = "execute")]
mod tokens;
#[cfg(feature = "execute")]
pub use tokens::{
    DEFAULT_MAX_NEW_TOKENS, MAX_STOP_TOKEN_IDS, TokenBytesError, decode_token_ids,
    encode_token_ids, normalize_stop_token_ids,
};

pub use protocol::{
    APPLE_APP_ATTEST, AppleAppAttestEnrollment, Application, ApplicationError, Assurance,
    CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR, CODEX_RESPONSES_ADAPTOR, CODEX_RESPONSES_ENDPOINT,
    CanonicalizationId, CausalLmEnvironment, CausalLmEnvironmentError, ContentId, ContentRef,
    DagCborDecodeError, DagCborDecoder, DagCborEncodeError, DagCborEncoder, Digest, Evaluate,
    EvaluateRequest, EventCommitment, FETCH_EVALUATOR, FetchEnvironment, InputCommitment,
    InputEventBody, InputEventBodyParts, InputEventEnvelope, InputTranscriptBuilder, JobTerms,
    JsonBytes, MAX_APPLICATION_ID_BYTES, MAX_CAUSAL_LM_ENVIRONMENT_BYTES,
    MAX_CAUSAL_LM_STATIC_BYTES, OPEN_EXPORTER_LEN, OPEN_NONCE_LEN, OPEN_PROOF_DOMAIN,
    OPEN_PROVIDER_ROLE, OPENAI_RESPONSES_ADAPTOR, OPENAI_RESPONSES_ENDPOINT, Operation,
    OutputEventBody, OutputEventBodyParts, OutputEventEnvelope, OutputTranscriptBuilder,
    PlatformCredential, PlatformEnrollment, ProducerId, ProducerSigningKey, ProgramManifest,
    ProviderEnrollmentBundle, ProviderGenesisDecodeError, ProviderGenesisStatement,
    ProviderIdentityV1, PublicKey, RequestCommitment, Retention, RootKind, RootProof, SchemeId,
    Signature, SignatureError, SignatureKind, SignedInputEvent, SignedOutputEvent,
    SignedProviderGenesis, StaticSlice, StreamId, StreamVerifyError, canonical_dag_cbor,
    decode_dag_cbor, hash_tuple, input_genesis, open_proof_binding, output_genesis, scheme_id,
    verify_input_event_envelopes, verify_input_transcript, verify_output_event_continuation,
    verify_output_event_envelopes, verify_output_transcript,
};
pub use protocol::{commitment, digest, retention, signature, tags, value};

/// Protobuf-generated message types plus per-service typed client traits,
/// method markers, and server dispatchers. The bare `pb` module is
/// doc-hidden; use the per-service re-exports under
/// `pb::{courtesy, swarm, execute, fetch, evaluate}` or the marker and
/// handler modules under `pb::services::*`.
#[doc(hidden)]
pub mod pb;

/// Service marker and handler modules.
pub use crate::pb::services;

/// ALPN/FQN service aliases derived from this crate's generated service
/// catalogue, for injecting into [`peers::PeerDirectoryConfig`]. p2p is
/// protocol-agnostic and ships an empty alias table; this is where the
/// concrete services get wired in.
pub fn peer_service_aliases() -> Vec<peers::ServiceAlias> {
    crate::services::KNOWN_SERVICES
        .iter()
        .filter(|entry| !entry.name.starts_with("hellas.host."))
        .flat_map(|entry| {
            [
                peers::ServiceAlias::new(entry.alpn, entry.name),
                peers::ServiceAlias::new(entry.name, entry.name),
            ]
        })
        .collect()
}

/// Administrative services are not automatically advertised as peer services.
/// Remote access requires an explicit mount and administrative grant.
#[cfg(all(test, feature = "host-control"))]
mod local_service_tests {
    #[test]
    fn host_control_is_not_a_peer_alias() {
        assert!(super::peer_service_aliases().iter().all(|alias| {
            !alias.query.starts_with("hellas.host.") && !alias.service.starts_with("hellas.host.")
        }));
    }
}

/// A [`peers::PeerDirectoryConfig`] preseeded with [`peer_service_aliases`].
pub fn peer_directory_config() -> peers::PeerDirectoryConfig {
    peers::PeerDirectoryConfig {
        service_aliases: peer_service_aliases(),
        ..Default::default()
    }
}

/// Default bound on the in-memory execution queue carried by `hellas_executor::Executor`.
#[cfg(feature = "execute")]
pub const DEFAULT_EXECUTION_QUEUE_CAPACITY: usize = 8;

/// Default maximum number of Fetch provider streams running at once.
#[cfg(feature = "execute")]
pub const DEFAULT_FETCH_MAX_IN_FLIGHT: usize = 16;

/// Default bound on Fetch executions waiting behind active provider streams.
#[cfg(feature = "execute")]
pub const DEFAULT_FETCH_QUEUE_CAPACITY: usize = 64;

/// Default maximum number of distinct retained Fetch transcripts, including
/// both completed transcripts and indeterminate running markers.
#[cfg(feature = "execute")]
pub const DEFAULT_FETCH_RETAINED_TRANSCRIPT_CAPACITY: usize = 1024;

/// Default maximum number of retained Fetch transcripts being replayed to
/// consumers at once.
#[cfg(feature = "execute")]
pub const DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT: usize = 16;
