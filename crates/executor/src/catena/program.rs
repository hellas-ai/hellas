use super::{compile, validate};
use catena_lang::{codegen::GpuDialect, runtime::RuntimeModule};
use hellas_rpc::{
    ContentId, ContentRef,
    protocol::invocation::{Limits, PreparedInvocation, compute::*},
};
use hellas_store::content::{LocalStore, Scope, VerifiedReader};
use std::{collections::BTreeMap, path::Path};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct BoundProgram {
    environment: Environment,
    module: RuntimeModule,
    manifest: ContentId,
}
impl BoundProgram {
    /// Open every asset through current pin policy before entering synchronous GPU code.
    /// These owned readers also authorize GPU cache hits.
    pub async fn open(
        content: &(LocalStore, Scope),
        prepared: &PreparedInvocation,
        limits: &Limits,
    ) -> Result<(
        Environment,
        Vec<String>,
        BTreeMap<ContentId, VerifiedReader>,
    )> {
        prepared.validate()?;
        if prepared.request.retain != (content.0.retention() == hellas_rpc::Retention::Retain) {
            return Err("compute content retention differs from the signed request".into());
        }
        let manifest = prepared.manifest()?;
        if manifest.application().evaluator() != EVALUATOR
            || manifest.application().adaptor() != ADAPTOR
        {
            return Err("unsupported compute evaluator".into());
        }
        let root = hellas_channel::content::root(&content.0, &content.1, manifest.root()).await?;
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
        validate::preflight(&environment, &inputs, &plan, limits)?;
        let mut sources = Vec::new();
        for object in &environment.sources {
            let bytes =
                hellas_channel::content::read(&content.0, &content.1, *object, MAX_SOURCE_BYTES)
                    .await?;
            sources.push(std::str::from_utf8(&bytes)?.to_owned());
        }
        let mut readers = BTreeMap::new();
        for asset in &environment.assets {
            let reader = content
                .0
                .open_verified(&content.1, asset.object, None)
                .await?
                .ok_or("missing compute asset")?;
            readers.insert(asset.object.id(), reader);
        }
        Ok((environment, sources, readers))
    }
    pub fn compile_cancellable(
        environment: Environment,
        sources: Vec<String>,
        prepared: &PreparedInvocation,
        limits: &Limits,
        executable: &Path,
        cancel: &super::Cancellation,
        dialect: GpuDialect,
    ) -> Result<Self> {
        let manifest = prepared.manifest()?;
        let plan = Plan::from_canonical_bytes(prepared.input.parameters.as_bytes())?;
        let inputs = prepared
            .input
            .artifacts
            .iter()
            .map(|a| (a.name.clone(), ContentRef::for_bytes(a.bytes.as_bytes())))
            .collect();
        let module = compile::compile_cancellable(&sources, executable, cancel, dialect)?;
        validate::validate(&module, &environment, &inputs, &plan, limits)?;
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
