//! Ship the client's reachable stdlib with the model as one Hex source.
use anyhow::{Context, Result};
use metacat::theory::RawTheorySet;
use std::collections::BTreeSet;

pub(super) fn render(model: &str) -> Result<String> {
    let mut raw = RawTheorySet::from_texts(catena_models::catena::runtime_sources(model))?
        .with_extensions()?;
    let program = raw
        .theories
        .get_mut(&"program".parse().unwrap())
        .context("missing program theory")?;
    // Match catena-models' prepare_sources policy. Module-equivalence tests
    // guard this private upstream policy when either dependency changes.
    let available: BTreeSet<_> = program
        .arrows
        .keys()
        .map(|name| name.as_str().to_owned())
        .collect();
    let mut pending: Vec<_> = program
        .arrows
        .iter()
        .filter(|(name, arrow)| {
            !name.as_str().starts_with("meta.")
                && (arrow.definition.is_none() || !name.as_str().starts_with("stdlib."))
        })
        .map(|(name, _)| name.as_str().to_owned())
        .collect();
    let mut used = BTreeSet::new();
    while let Some(name) = pending.pop() {
        if !used.insert(name.clone()) {
            continue;
        }
        let Some(arrow) = program.arrows.get(&name.parse().unwrap()) else {
            continue;
        };
        for expr in [&arrow.type_maps.0, &arrow.type_maps.1]
            .into_iter()
            .chain(arrow.definition.iter())
        {
            for token in expr
                .to_string()
                .split(|c: char| c.is_whitespace() || "(){}[]^".contains(c))
            {
                let token = token.strip_prefix("name.").unwrap_or(token);
                let token = token
                    .strip_prefix("partial.")
                    .and_then(|s| s.rsplit_once('.'))
                    .filter(|(_, n)| n.parse::<usize>().is_ok())
                    .map_or(token, |(s, _)| s);
                if available.contains(token) {
                    pending.push(token.to_owned());
                }
            }
        }
    }
    program
        .arrows
        .retain(|name, _| used.contains(name.as_str()));
    Ok(raw.to_hexpr_text())
}

#[cfg(test)]
pub(super) fn assert_shipped_module(job: &super::ComputeJob, model: &str) {
    use catena_lang::{codegen::CodegenKind, report::CompileReport, runtime::GpuDialect};

    let [source] = job.environment.sources[..] else {
        panic!("one self-contained program")
    };
    let bytes = job.content.read(source).unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let shipped = RawTheorySet::from_text(text).unwrap();
    let unpruned = RawTheorySet::from_texts(catena_models::catena::runtime_sources(model)).unwrap();
    let expanded = unpruned.clone().with_extensions().unwrap();
    let program = "program".parse().unwrap();
    for dialect in [GpuDialect::Hip, GpuDialect::Cuda] {
        // The reference invokes upstream's private pruning pass; the actual
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
