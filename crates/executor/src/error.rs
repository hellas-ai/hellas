use hellas_rpc::TokenBytesError;
use hellas_wire::{WireCode, WireStatus};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error(transparent)]
    Backend(#[from] hellas_work::work::BackendFault),
    #[error("worker exited without acknowledging completion")]
    Completion(#[source] tokio::sync::oneshot::error::RecvError),
    #[error("executor channel closed")]
    ChannelClosed,
    #[error("{0}")]
    ResourceExhausted(String),
    #[error("invalid execution input: {0}")]
    InvalidInput(String),
    #[error("execution failed: {0}")]
    Execution(String),
    #[error("content not found: {0}")]
    ContentNotFound(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("invalid token payload: {0}")]
    InvalidTokenPayload(String),
    #[error(transparent)]
    TokenBytes(#[from] TokenBytesError),
}
impl From<ExecutorError> for WireStatus {
    fn from(err: ExecutorError) -> Self {
        let code = match &err {
            ExecutorError::ResourceExhausted(_) => WireCode::ResourceExhausted,
            ExecutorError::InvalidInput(_)
            | ExecutorError::InvalidTokenPayload(_)
            | ExecutorError::TokenBytes(_) => WireCode::InvalidArgument,
            ExecutorError::PolicyDenied(_) => WireCode::PermissionDenied,
            ExecutorError::ContentNotFound(_) => WireCode::NotFound,
            ExecutorError::Completion(_)
            | ExecutorError::Backend(_)
            | ExecutorError::ChannelClosed
            | ExecutorError::Execution(_) => WireCode::Internal,
        };
        WireStatus::new(code, err.to_string())
    }
}
