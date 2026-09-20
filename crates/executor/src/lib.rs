#[macro_use]
extern crate tracing;

mod error;
pub use error::{ExecutorError, StateError};

#[cfg(feature = "evaluate")]
mod artifact_store;
#[cfg(feature = "evaluate")]
mod artifacts;

mod chain;
#[cfg(feature = "evaluate")]
mod environment;
#[cfg(feature = "evaluate")]
mod evaluate;
mod executor;
mod fetch;
mod fetch_policy;
mod fetch_projection;
mod fetch_provider;
mod fetch_registry;
mod metrics;
mod private_fs;
mod state;
mod work;
#[cfg(feature = "evaluate")]
mod worker;

#[cfg(feature = "evaluate")]
pub use artifact_store::{ArtifactStoreConfig, DEFAULT_EVALUATE_RETAINED_EXECUTION_CAPACITY};
#[cfg(feature = "evaluate")]
pub use catena_lang::safe_gpu::Backend as GpuBackend;
pub use chain::{ChainView, kernel_signer};
#[cfg(feature = "evaluate")]
pub use environment::{CausalLmEnvironmentSource, CausalLmEnvironmentSourceError};
pub use executor::{Executor, ExecutorHandle, ExecutorSpawnConfig};
pub use fetch::FetchTranscriptStoreBackend;
pub use fetch_policy::{
    CallerAccess, FetchAccessError, FetchAccessPolicy, FetchAdmission, FetchQuotaReservation,
    FetchQuotaStoreBackend, FetchRoute, FetchRouteGrant, FetchRoutePolicy, RequestRateLimit,
    RouteSet, SpendLimit,
};
pub use fetch_projection::{
    FetchAdaptorError, FetchAdaptorFactory, FetchAdaptorSession, FetchProjector, FetchRequestView,
    ProjectedFetch,
};
pub use fetch_provider::{
    FetchCall, FetchProvider, FetchProviderError, FetchProviderFuture, FetchProviderResponse,
    FetchProviderResponseHead, FetchProviderStream, MockFetchProvider, PreparedFetchRequest,
};
pub use fetch_registry::{
    DuplicateFetchRoute, FetchRouteBindingError, FetchRouteEntry, FetchRouteRegistry,
};
pub use hellas_rpc::services::courtesy::CourtesyServer;
pub use hellas_rpc::services::evaluate::EvaluateServer;
pub use hellas_rpc::services::execute::ExecuteServer;
pub use hellas_rpc::services::fetch::FetchServer;
pub use metrics::ExecutorMetrics;
#[cfg(feature = "evaluate")]
pub use worker::{
    DEFAULT_GPU_COMPILE_TIMEOUT_SECS, DEFAULT_GPU_EXECUTION_TIMEOUT_SECS,
    DEFAULT_GPU_MAX_GENERATION_CAPACITY, DEFAULT_GPU_MAX_GENERATION_DEVICE_BYTES,
    DEFAULT_GPU_SESSION_ASSET_BYTES, DEFAULT_GPU_SESSION_PROGRAMS, GpuConfig,
    MAX_GPU_GENERATION_CAPACITY,
};
#[cfg(feature = "evaluate")]
mod inference_cache;
