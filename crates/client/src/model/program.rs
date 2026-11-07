//! Ship the client's reachable stdlib with the model as one Hex source.
use anyhow::Result;
use metacat::theory::RawTheorySet;

pub(super) fn render(model: &str) -> Result<String> {
    let raw = RawTheorySet::from_texts(catena_models::catena::runtime_sources(model))?;
    Ok(catena_models::catena::prepare_sources(raw)?.to_hexpr_text())
}
