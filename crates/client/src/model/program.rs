//! Ship the client's reachable stdlib with the model as one Hex source.
use anyhow::Result;
use metacat::theory::RawTheorySet;

pub(super) fn render(model: &str) -> Result<String> {
    let raw = RawTheorySet::from_texts(catena_models::catena::runtime_sources(model))?;
    Ok(catena_models::catena::prepare_sources(raw)?.to_hexpr_text())
}

#[cfg(test)]
pub(super) async fn assert_shipped_module(job: &super::ComputeJob, model: &str) {
    use catena_lang::{codegen::CodegenKind, report::CompileReport, runtime::GpuDialect};

    let [source] = job.environment.sources[..] else {
        panic!("one self-contained program")
    };
    let bytes =
        hellas_channel::content::read(&job.content.0, &job.content.1, source, source.bytes())
            .await
            .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let shipped = RawTheorySet::from_text(text).unwrap();
    let unpruned = RawTheorySet::from_texts(catena_models::catena::runtime_sources(model)).unwrap();
    let expanded = unpruned.clone().with_extensions().unwrap();
    let program = "program".parse().unwrap();
    for dialect in [GpuDialect::Hip, GpuDialect::Cuda] {
        // The reference invokes upstream's pruning pass; the actual
        // compile receives only the bytes the client sends to the provider.
        let actual = catena_lang::compile::compile(
            &mut CompileReport::new(shipped.clone()),
            CodegenKind::Default,
            dialect,
        )
        .unwrap();
        let reference = catena_models::catena::compile(unpruned.clone(), dialect).unwrap();
        assert!(
            reference == actual,
            "{dialect:?}: generated source or ABI differs"
        );
    }
    assert!(shipped.extensions.is_empty());
    assert_eq!(shipped.to_hexpr_text(), text);
    assert!(shipped.theories[&program].arrows.len() < expanded.theories[&program].arrows.len());
    assert_eq!(shipped.theories.len(), expanded.theories.len());
}
