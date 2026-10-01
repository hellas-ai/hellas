use thiserror::Error;

use crate::fetch_provider::{FetchCall, FetchProviderResponseHead, PreparedFetchRequest};
use hellas_rpc::ContentId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectedFetch {
    Event(Vec<u8>),
    Terminal(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequestView {
    pub service: String,
    pub method: String,
    pub model: Option<String>,
    pub max_output_units: Option<u64>,
}

impl FetchRequestView {
    pub fn from_call(request: &FetchCall) -> Self {
        Self {
            service: request.service.clone(),
            method: request.method.clone(),
            model: None,
            max_output_units: None,
        }
    }
}

pub struct FetchAdaptorSession {
    pub request_view: FetchRequestView,
    /// Provider-only request constructed inside the trusted Fetch app.
    pub provider_request: PreparedFetchRequest,
    pub projector: Box<dyn FetchProjector>,
}

pub trait FetchProjector: Send + Sync + 'static {
    /// Receive the closed semantic HTTP response head before body projection.
    /// Adaptors that do not define a head contract reject populated claims so
    /// adversarial upstream claims can never disappear silently.
    fn begin(
        &mut self,
        head: FetchProviderResponseHead,
    ) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        if head.is_empty() {
            Ok(Vec::new())
        } else {
            Err(FetchAdaptorError::failed(
                "fetch projector does not accept response-head claims",
            ))
        }
    }

    fn project(&mut self, bytes: &[u8]) -> Result<Vec<ProjectedFetch>, FetchAdaptorError>;
    fn finish(&mut self) -> Result<Vec<ProjectedFetch>, FetchAdaptorError>;
}

pub trait FetchAdaptorFactory: Send + Sync + 'static {
    /// The complete manifest commitment for the exact structuring,
    /// destructuring, and trusted config implemented by this factory.
    ///
    /// A route derives its execution environment from this method; an
    /// operator cannot pair this adaptor with a separately claimed
    /// environment identity.
    fn execution_environment(&self) -> ContentId;

    fn create(&self, request: &FetchCall) -> Result<FetchAdaptorSession, FetchAdaptorError>;
}

/// Request construction or response projection failed inside the selected
/// trusted adaptor. Routing happens before the adaptor is created, so there is
/// no "not my route" rejection variant.
#[derive(Debug, Error)]
#[error("fetch adaptor failed: {0}")]
pub struct FetchAdaptorError(String);

impl FetchAdaptorError {
    pub fn failed(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}
