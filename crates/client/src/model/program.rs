//! Ship the complete program catena-models compiles for a model source.
use anyhow::Result;
use catena_models::catena::{program_sources, runtime_sources};
use hellas_channel::content::{DEFAULT_MAX_STAGING_BYTES, upload_object};
use hellas_rpc::protocol::invocation::compute::{Environment, NamedAsset};
use hellas_store::content::{LocalStore, MemoryStore, Reservations, Scope};

pub(super) fn render(model: &str, dialect: super::GpuDialect) -> Result<String> {
    Ok(program_sources(runtime_sources(model), dialect)?.to_hexpr_text())
}

/// The environment of one rendered program over `assets`, and the content
/// every job of it carries: the program and the environment.
pub(super) async fn environment(
    source: &str,
    assets: Vec<NamedAsset>,
) -> Result<(Environment, (LocalStore, Scope))> {
    let content = (
        LocalStore::Memory(MemoryStore::new(Reservations::ram(
            DEFAULT_MAX_STAGING_BYTES,
        ))),
        Scope::Owner,
    );
    let source = upload_object(&content.0, source.as_bytes()).await?;
    let environment = Environment {
        sources: vec![source],
        assets,
    };
    upload_object(&content.0, &environment.canonical_bytes()?).await?;
    Ok((environment, content))
}
