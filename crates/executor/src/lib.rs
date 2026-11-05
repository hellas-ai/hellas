mod error;
pub use error::ExecutorError;
#[cfg(feature = "compute")]
pub mod catena;
mod executor;
mod fetch_execution;
mod fetch_policy;
mod fetch_projection;
mod fetch_provider;
mod fetch_registry;
#[cfg(feature = "otel")]
mod metrics;

#[cfg(feature = "compute")]
pub use catena::child_main;
#[cfg(feature = "compute")]
pub use catena_lang::codegen::GpuDialect;
#[cfg(feature = "compute")]
pub use executor::{DEFAULT_GPU_SESSION_ASSET_BYTES, DEFAULT_GPU_SESSION_PROGRAMS, GpuConfig};
pub use executor::{Executor, ExecutorHandle, ExecutorSpawnConfig};
pub use fetch_policy::{FetchAccessError, FetchRoute, FetchRoutePolicy};
pub use fetch_projection::{
    FetchAdaptorError, FetchAdaptorFactory, FetchAdaptorSession, FetchProjector, FetchRequestView,
    ProjectedFetch,
};
pub use fetch_provider::{
    FetchCall, FetchProvider, FetchProviderError, FetchProviderErrorKind, FetchProviderFuture,
    FetchProviderResponse, FetchProviderResponseHead, FetchProviderStream, HttpResponseHead,
    MockFetchProvider, PreparedFetchRequest,
};
pub use fetch_registry::{
    DuplicateFetchRoute, FetchRouteBindingError, FetchRouteEntry, FetchRouteRegistry,
};
#[cfg(feature = "otel")]
pub use metrics::ExecutorMetrics;
