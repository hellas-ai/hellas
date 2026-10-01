use crate::commands::CliResult;
use hellas_client::execution::CausalLmExecutionEnvironment;
use hellas_rpc::ContentId;
use std::path::Path;
/// Canonical evaluator metadata loaded from an operator-selected root file.
///
/// The caller-selected or locally derived manifest is the only evaluator
/// identity bound into a Work input. The environment body stays local and
/// supplies the bounded causal-LM metadata used to validate the token request.
pub(crate) struct LoadedCausalLmEnvironment {
    execution: CausalLmExecutionEnvironment,
}

impl LoadedCausalLmEnvironment {
    pub(crate) fn execution(&self) -> &CausalLmExecutionEnvironment {
        &self.execution
    }

    pub(crate) fn into_execution(self) -> CausalLmExecutionEnvironment {
        self.execution
    }
}

/// Strictly load one canonical causal-LM root and enforce any caller-selected
/// manifest identity before constructing a local or remote route.
pub(crate) fn load_environment(
    path: &Path,
    manifest_id: Option<ContentId>,
) -> CliResult<LoadedCausalLmEnvironment> {
    let bytes = super::read_bounded_regular_file(
        path,
        "environment",
        hellas_rpc::MAX_CAUSAL_LM_ENVIRONMENT_BYTES,
    )?;
    let environment =
        hellas_rpc::CausalLmEnvironment::from_canonical_bytes(&bytes).map_err(|error| {
            anyhow::anyhow!("invalid canonical environment {}: {error}", path.display())
        })?;
    let manifest = environment.manifest();
    let manifest_bytes = manifest.canonical_bytes();
    let derived_manifest_id = manifest.content_id();
    let expected_manifest_id = manifest_id.unwrap_or(derived_manifest_id);
    anyhow::ensure!(
        derived_manifest_id == expected_manifest_id,
        "environment {} derives manifest {derived_manifest_id}, not caller-pinned {expected_manifest_id}",
        path.display()
    );
    let execution = CausalLmExecutionEnvironment::from_canonical_bytes(
        expected_manifest_id,
        manifest_bytes,
        bytes,
    )
    .map_err(|error| anyhow::anyhow!("invalid causal-LM execution environment: {error}"))?;
    Ok(LoadedCausalLmEnvironment { execution })
}
