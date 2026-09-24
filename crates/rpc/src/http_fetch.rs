//! Caller-signed HTTPS request vocabulary. Provider-owned credentials are selected
//! by alias; their secret values stay with the provider.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

pub const MAX_HTTP_RESPONSE_BYTES: u32 = 8 * 1024 * 1024;
pub const MAX_HTTP_HEADERS_BYTES: usize = 16 * 1024;
pub const MAX_HTTP_HEADERS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpFetchRequest {
    pub url: String,
    pub method: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body_base64: String,
    pub tls: HttpTls,
    #[serde(default)]
    pub credential: Option<String>,
    pub max_response_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpTls {
    pub roots: HttpTrustRoots,
    /// Additional SHA-256 pins over the leaf certificate's DER SPKI.
    #[serde(default)]
    pub spki_sha256: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum HttpTrustRoots {
    WebPki,
    /// Exact base64 DER trust anchors, without implicit system roots.
    Certificates {
        der_base64: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid HTTPS Fetch request: {0}")]
pub struct HttpRequestError(pub &'static str);

impl HttpFetchRequest {
    pub fn decode(bytes: &[u8]) -> Result<Self, HttpRequestError> {
        if bytes.len() > crate::fetch::MAX_FETCH_REQUEST_BODY_BYTES {
            return Err(HttpRequestError("request exceeds byte limit"));
        }
        let request: Self =
            serde_json::from_slice(bytes).map_err(|_| HttpRequestError("request schema"))?;
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), HttpRequestError> {
        self.parsed_url()?;
        if !matches!(
            self.method.as_str(),
            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
        ) {
            return Err(HttpRequestError("HTTP method"));
        }
        check_headers(&self.headers, true)?;
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_HTTP_RESPONSE_BYTES {
            return Err(HttpRequestError("response byte limit"));
        }
        self.body()?;
        if self.credential.as_ref().is_some_and(|alias| {
            alias.is_empty()
                || alias.len() > 128
                || !alias
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        }) {
            return Err(HttpRequestError("credential alias"));
        }
        self.tls.validate()
    }

    pub fn parsed_url(&self) -> Result<url::Url, HttpRequestError> {
        if self.url.len() > 8192 {
            return Err(HttpRequestError("URL length"));
        }
        let url = url::Url::parse(&self.url).map_err(|_| HttpRequestError("URL"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(HttpRequestError(
                "URL must be HTTPS without userinfo or fragment",
            ));
        }
        Ok(url)
    }

    pub fn body(&self) -> Result<Vec<u8>, HttpRequestError> {
        if self.body_base64.len() > crate::fetch::MAX_FETCH_REQUEST_BODY_BYTES {
            return Err(HttpRequestError("body length"));
        }
        decode_base64(&self.body_base64)
    }
}

impl HttpTls {
    pub fn validate(&self) -> Result<(), HttpRequestError> {
        if let HttpTrustRoots::Certificates { der_base64 } = &self.roots {
            if der_base64.is_empty() || der_base64.len() > 16 {
                return Err(HttpRequestError("trust anchor count"));
            }
            for der in der_base64 {
                if der.is_empty() || der.len() > 32768 {
                    return Err(HttpRequestError("trust anchor size"));
                }
                decode_base64(der)?;
            }
        }
        if self.spki_sha256.len() > 16 {
            return Err(HttpRequestError("SPKI pin count"));
        }
        for pin in &self.spki_sha256 {
            decode_pin(pin)?;
        }
        Ok(())
    }
}

pub fn decode_pin(pin: &str) -> Result<[u8; 32], HttpRequestError> {
    if pin.len() != 64 {
        return Err(HttpRequestError("SPKI pin must be 64 lowercase hex digits"));
    }
    let mut out = [0; 32];
    for (i, pair) in pin.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(HttpRequestError("SPKI pin encoding")),
        };
        out[i] = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(out)
}

pub fn decode_base64(encoded: &str) -> Result<Vec<u8>, HttpRequestError> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| HttpRequestError("base64 encoding"))?;
    if STANDARD.encode(&bytes) != encoded {
        return Err(HttpRequestError("noncanonical base64"));
    }
    Ok(bytes)
}

pub fn check_headers(headers: &[(String, String)], request: bool) -> Result<(), HttpRequestError> {
    if headers.len() > MAX_HTTP_HEADERS
        || headers
            .iter()
            .map(|(k, v)| k.len().saturating_add(v.len()))
            .sum::<usize>()
            > MAX_HTTP_HEADERS_BYTES
    {
        return Err(HttpRequestError("header limit"));
    }
    for (name, value) in headers {
        if name.is_empty()
            || !name.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == 0x60
                    || b"!#$%&'*+-.^_|~".contains(&b)
            })
            || !value
                .bytes()
                .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
        {
            return Err(HttpRequestError("header encoding"));
        }
        if request
            && matches!(
                name.as_str(),
                "host"
                    | "content-length"
                    | "transfer-encoding"
                    | "connection"
                    | "upgrade"
                    | "proxy-authorization"
                    | "proxy-connection"
                    | "te"
                    | "trailer"
            )
        {
            return Err(HttpRequestError("reserved request header"));
        }
    }
    Ok(())
}

/// A complete, structurally checked response reconstructed from authenticated
/// Fetch output. Callers verify signatures and the expected producer first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpFetchResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpFetchResponse {
    pub fn from_output(
        request: &HttpFetchRequest,
        output: &crate::fetch::FetchOutput,
    ) -> Result<Self, HttpRequestError> {
        use crate::output::{AdaptorEvent, HttpResponseEvent, OutputEvent, StopReason};
        let (events, terminal) = output.output_event_payloads();
        let mut response = None;
        for payload in events {
            let event = crate::fetch::decode_fetch_event_payload(payload)
                .map_err(|_| HttpRequestError("response event codec"))?;
            match event {
                OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Head {
                    status,
                    headers,
                })) if response.is_none() => {
                    if !(100..=599).contains(&status) {
                        return Err(HttpRequestError("response status"));
                    }
                    check_headers(&headers, false)?;
                    response = Some(Self {
                        status,
                        headers,
                        body: Vec::new(),
                    });
                }
                OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Body { base64 })) => {
                    let response = response
                        .as_mut()
                        .ok_or(HttpRequestError("response body before head"))?;
                    let bytes = decode_base64(&base64)?;
                    if bytes.is_empty()
                        || response.body.len().saturating_add(bytes.len())
                            > request.max_response_bytes as usize
                    {
                        return Err(HttpRequestError("response body size"));
                    }
                    response.body.extend_from_slice(&bytes);
                }
                _ => return Err(HttpRequestError("unexpected or duplicate response event")),
            }
        }
        if !matches!(
            crate::fetch::decode_fetch_terminal_payload(terminal),
            Ok(crate::fetch::FetchTerminalPayload::Finished {
                stop_reason: StopReason::EndOfText,
                usage: None,
                ..
            })
        ) {
            return Err(HttpRequestError("HTTP terminal"));
        }
        response.ok_or(HttpRequestError("missing response head"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::{
        FetchOutputTranscriptBuilder, encode_fetch_event_payload, encode_fetch_terminal_payload,
        verify_output_events,
    };
    use crate::output::{AdaptorEvent, HttpResponseEvent, OutputEvent, StopReason};
    use crate::{Assurance, Digest, InputCommitment, ProducerSigningKey};

    fn request() -> HttpFetchRequest {
        HttpFetchRequest {
            url: "https://example.com/v1/messages".into(),
            method: "POST".into(),
            headers: vec![],
            body_base64: "e30=".into(),
            tls: HttpTls {
                roots: HttpTrustRoots::WebPki,
                spki_sha256: vec![],
            },
            credential: None,
            max_response_bytes: 3,
        }
    }
    fn output(events: Vec<HttpResponseEvent>) -> crate::fetch::FetchOutput {
        let key = ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
        let input = InputCommitment::from_digest(Digest::from_bytes([2; 32]));
        let mut builder = FetchOutputTranscriptBuilder::new(input, Assurance::ProducerSigned, &key);
        for event in events {
            builder
                .push_event(
                    encode_fetch_event_payload(&OutputEvent::Adaptor(AdaptorEvent::Http(event)))
                        .unwrap(),
                )
                .unwrap();
        }
        let events = builder
            .finish(
                encode_fetch_terminal_payload(&OutputEvent::Finished {
                    stop_reason: StopReason::EndOfText,
                    usage: None,
                })
                .unwrap(),
            )
            .unwrap();
        verify_output_events(input, Assurance::ProducerSigned, &events).unwrap()
    }
    fn head() -> HttpResponseEvent {
        HttpResponseEvent::Head {
            status: 200,
            headers: vec![],
        }
    }
    fn body(bytes: &[u8]) -> HttpResponseEvent {
        HttpResponseEvent::Body {
            base64: STANDARD.encode(bytes),
        }
    }
    #[test]
    fn even_signed_http_responses_must_obey_structure_and_request_limit() {
        let good = output(vec![head(), body(&[0, 255, 3])]);
        assert_eq!(
            HttpFetchResponse::from_output(&request(), &good)
                .unwrap()
                .body,
            vec![0, 255, 3]
        );
        for events in [
            vec![],
            vec![body(b"a"), head()],
            vec![head(), head()],
            vec![head(), body(b"abcd")],
            vec![
                head(),
                HttpResponseEvent::Body {
                    base64: "!!".into(),
                },
            ],
        ] {
            assert!(HttpFetchResponse::from_output(&request(), &output(events)).is_err());
        }
    }
    #[test]
    fn requests_reject_ambiguous_or_unbounded_transport_inputs() {
        for url in [
            "http://example.com/",
            "https://user:secret@example.com/",
            "https://example.com/#fragment",
        ] {
            let mut input = request();
            input.url = url.into();
            assert!(input.validate().is_err());
        }
        for name in [
            "host",
            "content-length",
            "transfer-encoding",
            "proxy-authorization",
        ] {
            let mut input = request();
            input.headers = vec![(name.into(), "x".into())];
            assert!(input.validate().is_err());
        }
        let mut input = request();
        input.headers = vec![("authorization".into(), "x\r\ny".into())];
        assert!(input.validate().is_err());
        input = request();
        input.max_response_bytes = MAX_HTTP_RESPONSE_BYTES + 1;
        assert!(input.validate().is_err());
        input = request();
        input.body_base64 = "e30".into();
        assert!(input.validate().is_err());
    }
}
