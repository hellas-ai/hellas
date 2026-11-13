//! Process-contained upstream Catena execution.
pub mod assets;
pub mod compile;
pub mod driver;
pub mod pool;
pub(crate) mod process;
pub mod program;
pub use process::{Cancellation, isolate_child};

/// The evaluator id a GPU runtime registers: the programs it compiles. The
/// executor runs only programs whose evaluator its runtime registered.
pub fn evaluator(dialect: catena_lang::codegen::GpuDialect) -> String {
    let name = compile::name(dialect);
    format!(
        "{}-{name}",
        hellas_rpc::protocol::invocation::compute::EVALUATOR
    )
}
/// Resolve an opaque evaluator id registered by this executor build.
pub fn registered_evaluator(id: &str) -> Result<catena_lang::codegen::GpuDialect, String> {
    use catena_lang::codegen::GpuDialect;
    [GpuDialect::Hip, GpuDialect::Cuda]
        .into_iter()
        .find(|dialect| evaluator(*dialect) == id)
        .ok_or_else(|| format!("unregistered evaluator: {id}"))
}

/// Select the native executor once, at its boundary with the host platform.
pub fn default_gpu() -> catena_lang::codegen::GpuDialect {
    use catena_lang::codegen::GpuDialect;
    if std::path::Path::new("/dev/nvidiactl").exists() {
        GpuDialect::Cuda
    } else {
        GpuDialect::Hip
    }
}

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
