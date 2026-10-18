//! Argument parsers for the CLI's clap definitions.

pub(crate) fn parse_content_id_hex(s: &str) -> Result<hellas_rpc::ContentId, String> {
    s.parse()
        .map_err(|error| format!("invalid ContentId: {error}"))
}

pub(crate) fn parse_positive_usize(s: &str) -> Result<usize, String> {
    usize::try_from(parse_positive_u64(s)?)
        .map_err(|_| "invalid positive integer: number too large to fit in target type".to_string())
}

pub(crate) fn parse_positive_u64(s: &str) -> Result<u64, String> {
    let value = s
        .parse::<u64>()
        .map_err(|error| format!("invalid positive integer: {error}"))?;
    (value > 0)
        .then_some(value)
        .ok_or_else(|| "value must be greater than zero".to_string())
}

pub(crate) fn parse_assurance(s: &str) -> Result<hellas_rpc::Assurance, String> {
    match s {
        "producer-signed" => Ok(hellas_rpc::Assurance::ProducerSigned),
        "apple-app-attest" => Ok(hellas_rpc::Assurance::AppleAppAttest),
        _ => Err("assurance must be producer-signed or apple-app-attest".to_string()),
    }
}

pub(crate) fn parse_json_object(
    s: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    match serde_json::from_str::<serde_json::Value>(s) {
        Ok(serde_json::Value::Object(object)) => Ok(object),
        Ok(_) => Err("expected a JSON object".to_string()),
        Err(err) => Err(format!("invalid JSON object: {err}")),
    }
}
