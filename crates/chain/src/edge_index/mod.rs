//! Bounded native discovery and public state projection. Responses are deliberately
//! separate from the authenticated light-client object API.
pub mod projection;
pub mod query;
pub mod types;
pub use types::*;
#[cfg(feature = "explorer-origin")]
mod native;
#[cfg(feature = "explorer-origin")]
mod store;
#[cfg(feature = "explorer-origin")]
pub use native::{EdgeIndex, EdgeIndexError};

#[cfg(feature = "explorer-origin")]
mod replay;
#[cfg(feature = "explorer-origin")]
pub(crate) use replay::Replay;

#[cfg(feature = "explorer-origin")]
pub(crate) mod http;
#[cfg(feature = "explorer-origin")]
pub(crate) mod rpc;

#[cfg(all(test, feature = "explorer-origin"))]
pub(crate) use replay::tests::{Harness as ReplayHarness, basic as replay_basic};
