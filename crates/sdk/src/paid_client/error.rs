use std::path::PathBuf;

/// Errors retain the admission/payment stage and the original typed cause.
#[derive(Debug, thiserror::Error)]
pub enum PaidClientError {
    #[error(transparent)]
    Purchase(#[from] crate::transact::PurchaseError),
    #[error(transparent)]
    Owner(#[from] crate::client_owner::ClientOwnerError),
    #[error("no retained open channel with this provider")]
    NoRetainedChannel,
    #[error(transparent)]
    Job(#[from] crate::job::JobError),
    #[error(
        "provider charges {quoted} per job; this job says {requested}. Nothing was signed or paid."
    )]
    PriceMismatch { quoted: u64, requested: u64 },
    #[error("provider refused offer request ({0}). Nothing was paid.")]
    OfferRefused(i32),
    #[error(transparent)]
    Offer(#[from] hellas_channel::model::offer::PaidOfferError),
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
    #[error("authenticated provider key differs from the payment channel")]
    ProviderIdentityChanged,
    #[error("provider identity lock poisoned")]
    ProviderIdentityPoisoned,
    #[error("paid-work setup ended: {0:?}")]
    SetupEnded(hellas_channel::work_open::SetupProgress),
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
    Work(#[from] hellas_channel::model::work::PaidWorkError),
    #[error(transparent)]
    WorkSetup(#[from] hellas_channel::model::setup::WorkSetupError),
    #[error(transparent)]
    Store(#[from] hellas_channel::work_store::WorkStoreError),
    #[error(transparent)]
    Endpoint(#[from] hellas_channel::work::EndpointError),
    #[error(transparent)]
    Propose(#[from] hellas_channel::work::ProposeError),
    #[error(transparent)]
    Deliver(#[from] hellas_channel::work::DeliverError),
    #[error(transparent)]
    Payment(#[from] hellas_channel::work::PaymentError),
    #[error(transparent)]
    Collect(#[from] hellas_client::work::CollectResultError),
    #[error(transparent)]
    Close(#[from] hellas_channel::work_close::CloseError),
    #[error(transparent)]
    CatchUp(#[from] hellas_channel::work_close::CatchUpError),
    #[error(transparent)]
    Setup(#[from] hellas_channel::work_handshake::SetupExchangeError),
    #[error(transparent)]
    SetupDrive(#[from] hellas_channel::work_open::SetupDriveError),
    #[error(transparent)]
    BlockSource(#[from] hellas_channel::work_close::BlockSourceError),
    #[error(transparent)]
    Config(#[from] crate::work_config::WorkConfigError),
    #[error(transparent)]
    Query(#[from] hellas_chain::QueryError),
    #[error(transparent)]
    Fetch(#[from] hellas_rpc::fetch::FetchProtocolError),
}
