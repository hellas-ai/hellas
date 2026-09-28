use std::path::PathBuf;

/// Errors retain the admission/payment stage and the original typed cause.
#[derive(Debug, thiserror::Error)]
pub enum PaidClientError {
    #[error("invalid paid-work options: {0}")]
    InvalidOptions(&'static str),
    #[error("paid input does not match {0}")]
    InputMismatch(&'static str),
    #[error("paid-work state is missing: {0}")]
    MissingState(&'static str),
    #[error("multiple active jobs match this prepared input")]
    AmbiguousRecovery,
    #[error("payment deadline elapsed during result delivery")]
    PaymentExpired,
    #[error("{stage} deadline overflow")]
    DeadlineOverflow { stage: &'static str },
    #[error("{stage} timed out; journals retain payment state")]
    Timeout { stage: &'static str },
    #[error("no configured validator answered ({0:?})")]
    ValidatorsUnavailable(Vec<(String, hellas_chain::QueryError)>),
    #[error("authenticated provider key differs from the payment channel")]
    ProviderIdentityChanged,
    #[error("provider identity lock poisoned")]
    ProviderIdentityPoisoned,
    #[error("validator genesis differs from the configured genesis")]
    GenesisMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error("paid-work setup ended: {0:?}")]
    SetupEnded(hellas_work::work_open::SetupProgress),
    #[error("cannot create journal directory {}: {source}", path.display())]
    JournalDirectory {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot connect to provider {provider}: {source}")]
    Connect {
        provider: iroh::EndpointId,
        source: iroh::endpoint::ConnectError,
    },
    #[error(transparent)]
    Bind(#[from] iroh::endpoint::BindError),
    #[error(transparent)]
    Client(#[from] hellas_client::ClientError),
    #[error(transparent)]
    Canonical(#[from] hellas_rpc::protocol::value::CanonicalDecodeError),
    #[error(transparent)]
    Work(#[from] hellas_rpc::protocol::work::PaidWorkError),
    #[error(transparent)]
    WorkSetup(#[from] hellas_rpc::protocol::work_setup::WorkSetupError),
    #[error(transparent)]
    Store(#[from] hellas_work::work_store::WorkStoreError),
    #[error(transparent)]
    Endpoint(#[from] hellas_work::work::EndpointError),
    #[error(transparent)]
    Propose(#[from] hellas_work::work::ProposeError),
    #[error(transparent)]
    Deliver(#[from] hellas_work::work::DeliverError),
    #[error(transparent)]
    Payment(#[from] hellas_work::work::PaymentError),
    #[error(transparent)]
    Collect(#[from] hellas_client::work::CollectResultError),
    #[error(transparent)]
    Close(#[from] hellas_work::work_close::CloseError),
    #[error(transparent)]
    CatchUp(#[from] hellas_work::work_close::CatchUpError),
    #[error(transparent)]
    Setup(#[from] hellas_work::work_handshake::SetupExchangeError),
    #[error(transparent)]
    SetupDrive(#[from] hellas_work::work_open::SetupDriveError),
    #[error(transparent)]
    BlockSource(#[from] hellas_work::work_close::BlockSourceError),
    #[error(transparent)]
    Consensus(#[from] hellas_chain::ConsensusVerificationError),
    #[error(transparent)]
    Query(#[from] hellas_chain::QueryError),
    #[error(transparent)]
    Fetch(#[from] hellas_rpc::fetch::FetchProtocolError),
}
