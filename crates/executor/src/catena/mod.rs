//! Process-contained upstream Catena execution.
pub mod assets;
pub mod compile;
pub mod driver;
pub mod pool;
pub(crate) mod process;
pub mod program;
pub use process::{Cancellation, isolate_child};
mod memory;
pub mod validate;

pub fn child_main() -> Result<bool, Box<dyn std::error::Error>> {
    compile::child_main()
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "inventory class A/B/C: test timing fixtures pending their rollout"
)]
mod tests;
