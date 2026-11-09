//! Client-side model assets.
#[cfg(feature = "models")]
pub mod flux;
pub mod gguf;
#[cfg(feature = "models")]
mod package;
#[cfg(feature = "models")]
mod program;
#[cfg(feature = "models")]
pub use package::{ComputeJob, ModelPackage, ModelRequest, ModelResponse};
#[cfg(feature = "models")]
mod qwen3;
#[cfg(feature = "models")]
pub mod whisper;

#[cfg(feature = "models")]
pub mod wav;
