//! Argument parsers for the CLI's clap definitions.

#[cfg(feature = "node")]
pub(crate) fn parse_public_key_hex(s: &str) -> Result<hellas_rpc::PublicKey, String> {
    let bytes = parse_hex_array::<33>(s)?;
    Ok(hellas_rpc::PublicKey::Secp256k1(bytes))
}

pub(crate) fn parse_hex_array<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, s.len()));
    }
    let mut out = [0u8; N];
    for (idx, byte) in out.iter_mut().enumerate() {
        let start = idx * 2;
        *byte = u8::from_str_radix(&s[start..start + 2], 16)
            .map_err(|err| format!("invalid hex at byte {idx}: {err}"))?;
    }
    Ok(out)
}

pub(crate) fn parse_content_id_hex(s: &str) -> Result<hellas_rpc::ContentId, String> {
    s.parse()
        .map_err(|error| format!("invalid ContentId: {error}"))
}

pub(crate) fn parse_fetch_environment(s: &str) -> Result<hellas_rpc::ContentId, String> {
    match s {
        "codex-responses" => Ok(hellas_rpc::FetchEnvironment::CodexResponses.manifest_id()),
        "openai-responses" => Ok(hellas_rpc::FetchEnvironment::OpenAiResponses.manifest_id()),
        "http" => Ok(hellas_rpc::FetchEnvironment::Http.manifest_id()),
        content_id => parse_content_id_hex(content_id),
    }
}

#[cfg(feature = "node")]
pub(crate) fn parse_positive_usize(s: &str) -> Result<usize, String> {
    usize::try_from(parse_positive_u64(s)?)
        .map_err(|_| "invalid positive integer: number too large to fit in target type".to_string())
}

#[cfg(feature = "node")]
pub(crate) fn parse_positive_u64(s: &str) -> Result<u64, String> {
    let value = s
        .parse::<u64>()
        .map_err(|error| format!("invalid positive integer: {error}"))?;
    (value > 0)
        .then_some(value)
        .ok_or_else(|| "value must be greater than zero".to_string())
}

#[cfg(feature = "evaluate")]
pub(crate) fn parse_gpu_generation_capacity(s: &str) -> Result<u64, String> {
    let value = parse_positive_u64(s)?;
    (value <= hellas_executor::MAX_GPU_GENERATION_CAPACITY)
        .then_some(value)
        .ok_or_else(|| {
            format!(
                "value must not exceed {}",
                hellas_executor::MAX_GPU_GENERATION_CAPACITY
            )
        })
}

pub(crate) fn parse_assurance(s: &str) -> Result<hellas_rpc::Assurance, String> {
    match s {
        "producer-signed" => Ok(hellas_rpc::Assurance::ProducerSigned),
        "apple-app-attest" => Ok(hellas_rpc::Assurance::AppleAppAttest),
        _ => Err("assurance must be producer-signed or apple-app-attest".to_string()),
    }
}

#[cfg(feature = "gateway")]
pub(crate) fn parse_json_object(
    s: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    match serde_json::from_str::<serde_json::Value>(s) {
        Ok(serde_json::Value::Object(object)) => Ok(object),
        Ok(_) => Err("expected a JSON object".to_string()),
        Err(err) => Err(format!("invalid JSON object: {err}")),
    }
}
