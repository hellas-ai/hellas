use anyhow::Context;
use hellas_client::{ApplePolicy, DEFAULT_APP_ID};
use std::collections::BTreeSet;

/// Resolve consumer requirements from CLI flags, job folders or gateway configuration.
pub fn from_requirements(
    app_ids: Option<&[String]>,
    cd_hashes: Option<&[String]>,
) -> anyhow::Result<ApplePolicy> {
    let app_ids = match app_ids {
        Some(ids) => ids.iter().cloned().collect(),
        None => BTreeSet::from([DEFAULT_APP_ID.to_owned()]),
    };
    let cd_hashes = cd_hashes
        .map(|hashes| {
            hashes
                .iter()
                .map(|hash| {
                    let mut bytes = [0; 32];
                    hex::decode_to_slice(hash, &mut bytes)
                        .context("Apple CDHash must be 64 hexadecimal digits")?;
                    Ok::<_, anyhow::Error>(bytes)
                })
                .collect::<anyhow::Result<BTreeSet<_>>>()
        })
        .transpose()?;
    Ok(ApplePolicy::new(app_ids, cd_hashes)?)
}

// Human-readable configuration uses names. The protocol encodes assurance as a byte.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(remote = "hellas_rpc::Assurance", rename_all = "kebab-case")]
pub(crate) enum AssuranceName {
    ProducerSigned,
    AppleAppAttest,
}
