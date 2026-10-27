use super::{compile, validate};
use catena_lang::{codegen::GpuDialect, runtime::RuntimeModule};
use hellas_channel::content::InvocationContent;
use hellas_rpc::{
    ContentId, ContentRef,
    protocol::invocation::{Limits, PreparedInvocation, compute::*},
};
use std::{collections::BTreeMap, path::Path};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct BoundProgram {
    environment: Environment,
    module: RuntimeModule,
    manifest: ContentId,
}
impl BoundProgram {
    pub fn compile(
        content: &InvocationContent,
        prepared: &PreparedInvocation,
        limits: &Limits,
        executable: &Path,
        dialect: GpuDialect,
    ) -> Result<Self> {
        Self::compile_cancellable(
            content,
            prepared,
            limits,
            executable,
            &super::Cancellation::default(),
            dialect,
        )
    }
    pub fn compile_cancellable(
        content: &InvocationContent,
        prepared: &PreparedInvocation,
        limits: &Limits,
        executable: &Path,
        cancel: &super::Cancellation,
        dialect: GpuDialect,
    ) -> Result<Self> {
        prepared.validate()?;
        if prepared.request.retain != (content.retention() == hellas_rpc::Retention::Retain) {
            return Err("compute content retention differs from the signed request".into());
        }
        let manifest = prepared.manifest()?;
        if manifest.application().evaluator() != EVALUATOR
            || manifest.application().adaptor() != ADAPTOR
        {
            return Err("unsupported compute evaluator".into());
        }
        let root = content.read_bounded(manifest.root(), MAX_ENVIRONMENT_BYTES as u64)?;
        let environment = Environment::from_canonical_bytes(&root)?;
        if environment.manifest()?.content_id() != manifest.content_id() {
            return Err("compute environment identity mismatch".into());
        }
        let plan = Plan::from_canonical_bytes(prepared.input.parameters.as_bytes())?;
        let inputs = prepared
            .input
            .artifacts
            .iter()
            .map(|a| (a.name.clone(), ContentRef::for_bytes(a.bytes.as_bytes())))
            .collect();
        validate::preflight(&environment, &inputs, &plan, limits, content)?;
        let sources = environment
            .sources
            .iter()
            .map(|object| {
                let bytes = content.read(*object)?;
                Ok(std::str::from_utf8(&bytes)?.to_owned())
            })
            .collect::<Result<Vec<_>>>()?;
        let module = compile::compile_cancellable(
            &sources,
            executable,
            cancel,
            content.retention(),
            dialect,
        )?;
        validate::validate(&module, &environment, &inputs, &plan, limits, content)?;
        Ok(Self {
            environment,
            module,
            manifest: manifest.content_id(),
        })
    }
    pub fn module(&self) -> &RuntimeModule {
        &self.module
    }
    pub fn environment(&self) -> &Environment {
        &self.environment
    }
    pub(crate) fn input(
        &self,
        prepared: &PreparedInvocation,
    ) -> Result<(Plan, BTreeMap<String, Vec<u8>>)> {
        prepared.validate()?;
        if prepared.manifest()?.content_id() != self.manifest {
            return Err("prepared environment differs from compiled program".into());
        }
        let plan = Plan::from_canonical_bytes(prepared.input.parameters.as_bytes())?;
        let inputs = prepared
            .input
            .artifacts
            .iter()
            .map(|a| (a.name.clone(), a.bytes.0.clone()))
            .collect();
        Ok((plan, inputs))
    }
}
