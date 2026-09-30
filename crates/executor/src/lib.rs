#[cfg(feature = "evaluate")]
#[macro_use]
extern crate tracing;

mod error;
pub use error::ExecutorError;

#[cfg(feature = "evaluate")]
mod artifacts;

mod chain;
#[cfg(feature = "evaluate")]
mod environment;
#[cfg(feature = "evaluate")]
mod evaluate;
mod executor;
mod fetch_policy;
mod fetch_projection;
mod fetch_provider;
mod fetch_registry;
mod metrics;
#[cfg(feature = "evaluate")]
mod state;
mod work;
#[cfg(feature = "evaluate")]
mod worker;

#[cfg(feature = "evaluate")]
pub use catena_lang::safe_gpu::Backend as GpuBackend;
pub use chain::kernel_signer;
#[cfg(feature = "evaluate")]
pub use environment::{CausalLmEnvironmentSource, CausalLmEnvironmentSourceError};
pub use executor::{Executor, ExecutorHandle, ExecutorSpawnConfig};
pub use fetch_policy::{FetchAccessError, FetchRoute, FetchRoutePolicy};
pub use fetch_projection::{
    FetchAdaptorError, FetchAdaptorFactory, FetchAdaptorSession, FetchProjector, FetchRequestView,
    ProjectedFetch,
};
pub use fetch_provider::{
    FetchCall, FetchProvider, FetchProviderError, FetchProviderFuture, FetchProviderResponse,
    FetchProviderResponseHead, FetchProviderStream, HttpResponseHead, MockFetchProvider,
    PreparedFetchRequest,
};
pub use fetch_registry::{
    DuplicateFetchRoute, FetchRouteBindingError, FetchRouteEntry, FetchRouteRegistry,
};
pub use metrics::ExecutorMetrics;
#[cfg(feature = "evaluate")]
pub use worker::{
    DEFAULT_GPU_COMPILE_TIMEOUT_SECS, DEFAULT_GPU_EXECUTION_TIMEOUT_SECS,
    DEFAULT_GPU_MAX_GENERATION_CAPACITY, DEFAULT_GPU_MAX_GENERATION_DEVICE_BYTES,
    DEFAULT_GPU_SESSION_ASSET_BYTES, DEFAULT_GPU_SESSION_PROGRAMS, GpuConfig,
    MAX_GPU_GENERATION_CAPACITY,
};
