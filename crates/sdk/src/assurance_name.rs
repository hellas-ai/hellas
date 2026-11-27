// Human-readable configuration uses names. The protocol encodes assurance as a byte.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(remote = "hellas_rpc::Assurance", rename_all = "kebab-case")]
pub(crate) enum AssuranceName {
    ProducerSigned,
    AppleAppAttest,
}
