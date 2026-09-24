//! Read routing hints without changing the bytes forwarded upstream.
use axum::http::HeaderMap;
use serde_json::Value;
use std::io::Read;

#[derive(Default)]
pub(super) struct Hints {
    pub model: Option<String>,
    pub session: Option<(String, String)>,
    pub previous: Option<String>,
    pub conversation: Option<String>,
}

impl Hints {
    pub fn read(headers: &HeaderMap, body: &[u8]) -> Result<Self, &'static str> {
        let decoded;
        let decode = |reader: &mut dyn Read| -> Result<Vec<u8>, &'static str> {
            let mut output = Vec::new();
            reader
                .take(8 * 1024 * 1024 + 1)
                .read_to_end(&mut output)
                .map_err(|_| "invalid compressed routing request")?;
            if output.len() > 8 * 1024 * 1024 {
                return Err("decoded routing request exceeds limit");
            }
            Ok(output)
        };
        let encoding = headers
            .get("content-encoding")
            .map(|v| v.to_str().map(|s| s.trim().to_ascii_lowercase()))
            .transpose()
            .map_err(|_| "invalid request encoding")?;
        let bytes = match encoding.as_deref() {
            None | Some("") | Some("identity") => body,
            Some("gzip") => {
                decoded = decode(&mut flate2::read::MultiGzDecoder::new(body))?;
                &decoded
            }
            Some("zstd") => {
                let mut decoder = zstd::stream::read::Decoder::new(body)
                    .map_err(|_| "invalid compressed routing request")?;
                decoder
                    .window_log_max(23)
                    .map_err(|_| "invalid compressed routing request")?;
                decoded = decode(&mut decoder)?;
                &decoded
            }
            _ => return Err("unsupported request encoding for model routing"),
        };
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice::<Value>(bytes)
                .map_err(|_| "model routing requires a JSON request")?
        };
        fn field(value: Option<&Value>) -> Result<Option<String>, &'static str> {
            match value {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) if !s.is_empty() && s.len() <= 1024 => Ok(Some(s.clone())),
                _ => Err("invalid model or session identifier"),
            }
        }
        let mut session = None;
        for name in [
            "x-hellas-session-id",
            "x-claude-code-session-id",
            "session-id",
            "thread-id",
        ] {
            if let Some(value) = headers.get(name) {
                if headers.get_all(name).iter().count() != 1 {
                    return Err("ambiguous session header");
                }
                let value = value.to_str().map_err(|_| "invalid session header")?;
                if value.is_empty() || value.len() > 1024 {
                    return Err("invalid session header");
                }
                if session.is_none() {
                    session = Some((name.into(), value.into()));
                }
            }
        }
        if session.is_none()
            && let Some(user) = value.pointer("/metadata/user_id").and_then(Value::as_str)
        {
            let id = serde_json::from_str::<Value>(user)
                .ok()
                .and_then(|v| {
                    v.get("session_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .or_else(|| user.rsplit_once("_session_").map(|(_, id)| id.to_owned()));
            if let Some(id) = id.filter(|s| !s.is_empty() && s.len() <= 1024) {
                session = Some(("claude-session".into(), id));
            }
        }
        if session.is_none() {
            session = field(value.get("prompt_cache_key"))?.map(|v| ("prompt-cache".into(), v));
        }
        let conversation = value.get("conversation");
        Ok(Self {
            model: field(value.get("model"))?,
            session,
            previous: field(value.get("previous_response_id"))?,
            conversation: field(
                conversation.and_then(|v| if v.is_object() { v.get("id") } else { Some(v) }),
            )?,
        })
    }
}

pub(super) fn family(path: &str) -> &str {
    path.strip_suffix("/compact")
        .or_else(|| path.strip_suffix("/count_tokens"))
        .unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::io::Write;

    #[test]
    fn native_client_hints_and_compressed_json_are_read_without_rewriting() {
        let body = br#"{"model":"k3","prompt_cache_key":"kimi-session"}"#;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(body).unwrap();
        let wire = encoder.finish().unwrap();
        let headers = HeaderMap::from_iter([(
            "content-encoding".parse().unwrap(),
            HeaderValue::from_static("gzip"),
        )]);
        let hints = Hints::read(&headers, &wire).unwrap();
        assert_eq!(hints.model.as_deref(), Some("k3"));
        assert_eq!(hints.session.unwrap().1, "kimi-session");
        let compressed = zstd::stream::encode_all(body.as_slice(), 1).unwrap();
        let headers = HeaderMap::from_iter([(
            "content-encoding".parse().unwrap(),
            HeaderValue::from_static("zstd"),
        )]);
        assert_eq!(
            Hints::read(&headers, &compressed).unwrap().model.as_deref(),
            Some("k3")
        );
        let mut headers = HeaderMap::new();
        headers.insert("session-id", HeaderValue::from_static("codex-session"));
        assert_eq!(
            Hints::read(&headers, body).unwrap().session.unwrap().1,
            "codex-session"
        );
        let body=serde_json::to_vec(&serde_json::json!({"model":"claude", "metadata":{"user_id":"{\"device_id\":\"not-a-session\",\"session_id\":\"claude-session\"}"}})).unwrap();
        assert_eq!(
            Hints::read(&HeaderMap::new(), &body)
                .unwrap()
                .session
                .unwrap()
                .1,
            "claude-session"
        );
        headers.append("session-id", HeaderValue::from_static("ambiguous"));
        assert!(Hints::read(&headers, &body).is_err());
        assert!(Hints::read(&HeaderMap::new(), br#"{"model":4}"#).is_err());
        assert!(
            Hints::read(
                &HeaderMap::new(),
                br#"{"model":"k3","previous_response_id":{}}"#
            )
            .is_err()
        );
    }
}
