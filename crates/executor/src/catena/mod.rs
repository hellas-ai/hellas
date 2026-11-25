//! Process-contained upstream Catena execution.
pub mod assets;
pub mod compile;
pub mod driver;
pub mod pool;
pub(crate) mod process;
pub mod program;
pub use process::{Cancellation, isolate_child};

/// A GPU runtime on the device it opened. It registers one evaluator id, and
/// the executor runs only programs that name it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gpu {
    pub dialect: catena_lang::codegen::GpuDialect,
    pub arch: String,
}
impl Gpu {
    /// The runtime on this host that registers `evaluator`; without one, the
    /// native runtime: CUDA with an NVIDIA driver, otherwise HIP.
    pub fn select(evaluator: Option<&str>) -> Result<Self, String> {
        use catena_lang::codegen::GpuDialect;
        let Some(evaluator) = evaluator else {
            return Self::open(if std::path::Path::new("/dev/nvidiactl").exists() {
                GpuDialect::Cuda
            } else {
                GpuDialect::Hip
            });
        };
        let opened = [GpuDialect::Hip, GpuDialect::Cuda].map(Self::open);
        if let Some(gpu) = opened
            .iter()
            .flatten()
            .find(|gpu| gpu.evaluator() == evaluator)
        {
            return Ok(gpu.clone());
        }
        let registered: Vec<_> = opened
            .into_iter()
            .map(|gpu| gpu.map_or_else(|error| error, |gpu| gpu.evaluator()))
            .collect();
        Err(format!(
            "unregistered evaluator {evaluator}; this host has {}",
            registered.join(", ")
        ))
    }

    /// Open `dialect`'s runtime on its current device.
    fn open(dialect: catena_lang::codegen::GpuDialect) -> Result<Self, String> {
        let arch = memory::architecture(dialect).map_err(|error| error.to_string())?;
        Ok(Self { dialect, arch })
    }

    pub fn evaluator(&self) -> String {
        hellas_rpc::protocol::invocation::compute::evaluator(
            compile::name(self.dialect),
            &self.arch,
        )
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
