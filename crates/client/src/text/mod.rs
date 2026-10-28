//! Client-side text model assets.
pub mod gguf;
#[cfg(feature = "text")]
mod package;
#[cfg(feature = "text")]
pub use package::{TextJob, TextPackage};
