//! Bounded Compute evaluation without transport authorization or a signing key.
use super::{assets::Assets, compile, driver, pool::Pool, validate};
use crate::GpuConfig;
use hellas_channel::content::InvocationContent;
use hellas_rpc::{
    ContentRef,
    protocol::invocation::{
        Artifact, Limits,
        compute::{Environment, Plan},
        output::InvocationOutput,
    },
};
use std::{collections::BTreeMap, time::Duration};

pub fn execute(
    environment: &Environment,
    plan: &Plan,
    inputs: &[Artifact],
    content: &InvocationContent,
    limits: &Limits,
    gpu: GpuConfig,
    cancel: super::Cancellation,
) -> Result<InvocationOutput, Box<dyn std::error::Error>> {
    let descriptors = inputs
        .iter()
        .map(|a| (a.name.clone(), ContentRef::for_bytes(a.bytes.as_bytes())))
        .collect();
    validate::preflight(environment, &descriptors, plan, limits, content)?;
    let sources = environment
        .sources
        .iter()
        .map(|object| Ok(String::from_utf8(content.read(*object)?.to_vec())?))
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let module =
        compile::compile_cancellable(&sources, &std::env::current_exe()?, &cancel, gpu.backend)?;
    validate::validate(&module, environment, &descriptors, plan, limits, content)?;
    let pool = Pool::new(1, gpu.session_programs)?;
    let mut worker = pool.lease_cancellable(
        &module,
        Duration::from_millis(limits.execution_timeout_ms),
        cancel,
    )?;
    let inputs: BTreeMap<_, _> = inputs
        .iter()
        .map(|a| (a.name.clone(), a.bytes.0.clone()))
        .collect();
    let completed = driver::execute(
        &mut worker,
        &module,
        environment,
        &inputs,
        plan,
        limits,
        &Assets::new(gpu.session_asset_bytes, gpu.backend),
        content,
        |_| Ok(()),
    )?;
    let output = completed.output(plan)?;
    let bytes = output
        .artifacts
        .iter()
        .try_fold(output.metadata.0.len() as u64, |sum, artifact| {
            sum.checked_add(artifact.bytes.0.len() as u64)
        })
        .ok_or("output size overflow")?;
    if bytes > limits.max_output_bytes {
        return Err("local output exceeds max_output_bytes".into());
    }
    Ok(output)
}
