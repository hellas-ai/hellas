//! Client-side model assets.
pub mod gguf;
#[cfg(feature = "models")]
mod package;
#[cfg(feature = "models")]
pub use package::{ComputeJob, ModelPackage};
