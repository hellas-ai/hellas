//! Ship the complete program catena-models compiles for a model source.
use anyhow::Result;
use catena_models::catena::{program_sources, runtime_sources};

pub(super) fn render(model: &str, dialect: super::GpuDialect) -> Result<String> {
    Ok(program_sources(runtime_sources(model), dialect)?.to_hexpr_text())
}
