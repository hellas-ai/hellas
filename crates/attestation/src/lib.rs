#[cfg(feature = "apple-app-attest")]
mod apple;
use std::future::Future;

use hellas_auth::Digest;
use hellas_rpc::pb::execute::AssuranceEvidence;
use hellas_rpc::{DagCborEncoder, EventCommitment};

#[cfg(feature = "apple-app-attest")]
pub use apple::{
    AppleClaims, AppleCredential, AppleCredentialIdentity, ApplePolicy, AppleVerdict,
    AssertionCounterStore, RegisteredAppleCredential, apple_app_attest_root_ca, apple_app_id_hash,
    apple_client_data_hash, apple_credential_identity, appraise_apple, register_apple,
    verify_apple, verify_apple_assertion, verify_apple_provider_genesis,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding(Digest);

impl Binding {
    pub fn new(statement_tag: &str, terminal: EventCommitment) -> Self {
        let mut e = DagCborEncoder::new();
        e.array(2);
        e.str(statement_tag);
        e.bytes(terminal.as_bytes());
        Self(Digest::hash(&e.into_bytes()))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorTime(pub u64);

pub trait Attester {
    fn attest(
        &self,
        binding: Binding,
    ) -> impl Future<Output = Result<AssuranceEvidence, AttestationError>> + Send;
}

/// Produces the root proofs that bind a provider identity to its enrollment
/// statement and to a live confidential transport.
///
/// The two inputs are deliberately separate. A software root signs Hellas's
/// digest of a statement, while Apple App Attest signs SHA-256(statement).
/// A confidential-open binding is already a protocol digest and must not be
/// hashed a second time by this interface.
pub type RootProofFuture<'a> = std::pin::Pin<
    Box<dyn Future<Output = Result<hellas_rpc::RootProof, AttestationError>> + Send + 'a>,
>;

pub trait RootProver: Send + Sync {
    fn prove_statement<'a>(&'a self, statement: &'a [u8]) -> RootProofFuture<'a>;
    fn prove_open_binding(&self, binding: hellas_auth::Digest) -> RootProofFuture<'_>;
}

impl RootProver for hellas_auth::ProducerSigningKey {
    fn prove_statement<'a>(&'a self, statement: &'a [u8]) -> RootProofFuture<'a> {
        Box::pin(async move { self.prove_open_binding(Digest::hash(statement)).await })
    }
    fn prove_open_binding<'a>(&'a self, binding: Digest) -> RootProofFuture<'a> {
        Box::pin(async move {
            self.sign_digest(binding)
                .map(hellas_rpc::RootProof::Software)
                .map_err(|_| AttestationError::Signature)
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestationError {
    #[error("wrong evidence codec")]
    Codec,
    #[error("invalid evidence credential")]
    Credential,
    #[error("malformed {0}")]
    Malformed(&'static str),
    #[error("evidence does not bind the terminal event")]
    Binding,
    #[error("evidence signature is invalid")]
    Signature,
    #[cfg(feature = "apple-app-attest")]
    #[error("assertion counter did not increase")]
    Counter,
    #[cfg(feature = "apple-app-attest")]
    #[error("Apple attestation state is unavailable")]
    State,
    #[cfg(feature = "apple-app-attest")]
    #[error("Apple App Attest omitted required CDHash evidence")]
    AppleCdHashMissing,
    #[error("platform attestation failed: {0}")]
    Platform(String),
}
