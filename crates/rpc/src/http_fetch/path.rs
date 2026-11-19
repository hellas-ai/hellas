//! One canonical voice segment in an otherwise exact credential path.
use super::HttpRequestError;
pub const VOICE: &str = "{voice_id}";
fn invalid() -> HttpRequestError {
    HttpRequestError("invalid canonical voice path")
}

pub fn voice_segment(value: &str) -> Result<String, HttpRequestError> {
    if value.is_empty()
        || value.len() > 256
        || matches!(value, "." | "..")
        || value
            .chars()
            .any(|c| c.is_control() || "/\\%?#".contains(c))
    {
        return Err(invalid());
    }
    let mut encoded = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            encoded.push(char::from(b));
        } else {
            use std::fmt::Write;
            write!(encoded, "%{b:02X}").expect("string write");
        }
    }
    Ok(encoded)
}
fn canonical_segment(segment: &str) -> bool {
    let mut decoded = Vec::new();
    let mut bytes = segment.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let Some(a) = bytes.next().and_then(|b| char::from(b).to_digit(16)) else {
                return false;
            };
            let Some(b) = bytes.next().and_then(|b| char::from(b).to_digit(16)) else {
                return false;
            };
            decoded.push((a * 16 + b) as u8);
        } else {
            decoded.push(b);
        }
    }
    String::from_utf8(decoded)
        .ok()
        .and_then(|s| voice_segment(&s).ok())
        .is_some_and(|s| s == segment)
}
pub fn validate_scope(path: &str) -> Result<(), HttpRequestError> {
    let segments: Vec<_> = path.split('/').collect();
    if !path.starts_with('/')
        || segments.iter().filter(|s| **s == VOICE).count() > 1
        || path.matches(VOICE).count() != segments.iter().filter(|s| **s == VOICE).count()
    {
        return Err(invalid());
    }
    let literal = path.replace(VOICE, "voice");
    let parsed =
        url::Url::parse(&format!("https://scope.invalid{literal}")).map_err(|_| invalid())?;
    if literal.contains(['{', '}'])
        || parsed.path() != literal
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(())
}
pub fn matches(scope: &str, path: &str) -> bool {
    let scope: Vec<_> = scope.split('/').collect();
    let path: Vec<_> = path.split('/').collect();
    scope.len() == path.len()
        && scope.iter().zip(path).all(|(a, b)| {
            if *a == VOICE {
                canonical_segment(b)
            } else {
                *a == b
            }
        })
}
pub fn overlaps(a: &str, b: &str) -> bool {
    let a: Vec<_> = a.split('/').collect();
    let b: Vec<_> = b.split('/').collect();
    a.len() == b.len()
        && a.iter().zip(b).all(|(a, b)| {
            *a == b || (*a == VOICE && canonical_segment(b)) || (b == VOICE && canonical_segment(a))
        })
}
pub fn substitute(url: &str, voice: &str) -> Result<url::Url, HttpRequestError> {
    // URL parsing escapes braces; inspect the literal path before substitution.
    if url.matches(VOICE).count() != 1 {
        return Err(invalid());
    }
    let placeholder = url.replace(VOICE, "voice");
    let parsed = url::Url::parse(&placeholder).map_err(|_| invalid())?;
    let prefix = &parsed[..url::Position::BeforePath];
    let path = url.strip_prefix(prefix).ok_or_else(invalid)?;
    if parsed.query().is_some()
        || parsed.fragment().is_some()
        || !path.split('/').any(|s| s == VOICE)
    {
        return Err(invalid());
    }
    validate_scope(path)?;
    url::Url::parse(&url.replace(VOICE, &voice_segment(voice)?)).map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_scope_accepts_only_one_canonical_segment() {
        let scope = "/v1/text-to-speech/{voice_id}";
        validate_scope(scope).unwrap();
        for voice in ["voice-a", "two words", "voix-é"] {
            let segment = voice_segment(voice).unwrap();
            assert!(matches(scope, &format!("/v1/text-to-speech/{segment}")));
            assert!(overlaps(scope, &format!("/v1/text-to-speech/{segment}")));
        }
        for segment in [
            "", ".", "..", "%2E", "%2F", "%2f", "%252F", "a/b", "a/stream", "a%5Cb", "%61", "a?b",
            "a#b",
        ] {
            assert!(
                !matches(scope, &format!("/v1/text-to-speech/{segment}")),
                "{segment}"
            );
        }
        assert!(!overlaps(scope, "/v1/voices"));
        assert!(overlaps(scope, scope));
        for path in [
            "/a/{voice_id}/{voice_id}",
            "/a/prefix{voice_id}",
            "/a/{anything}",
            "/a/../{voice_id}",
        ] {
            assert!(validate_scope(path).is_err(), "{path}");
        }
        assert!(substitute("https://{voice_id}/v1/x", "voice").is_err());
    }
}
