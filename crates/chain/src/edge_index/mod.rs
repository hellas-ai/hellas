//! Bounded native discovery and public state projection. Responses are deliberately
//! separate from the authenticated light-client object API.
pub mod projection;
pub mod query;
pub mod types;
pub use types::*;
#[cfg(feature = "indexer-api")]
mod native;
#[cfg(feature = "indexer-api")]
mod store;
#[cfg(feature = "indexer-api")]
pub use native::{EdgeIndex, EdgeIndexError};

#[cfg(feature = "indexer-api")]
mod replay;
#[cfg(feature = "indexer-api")]
pub(crate) use replay::Replay;

#[cfg(feature = "indexer-api")]
pub(crate) mod http;
#[cfg(feature = "indexer-api")]
pub(crate) mod rpc;

#[cfg(all(test, feature = "indexer-api"))]
pub(crate) use replay::tests::{Harness as ReplayHarness, basic as replay_basic};

#[cfg(feature = "indexer-api")]
mod execution;
