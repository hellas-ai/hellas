//! The `clientDataJSON` grammar and the challenge encoding it carries.
//!
//! The accepted grammar is deliberately narrower than arbitrary JSON: a
//! top-level object with required unescaped `type` and `challenge` members,
//! where every other member is skipped as long as its value is *simple*
//! (string, boolean, null, or number). Nested objects and arrays are
//! rejected. Browsers deliberately inject unknown members — Chrome's
//! `other_keys_can_be_added_here` decoy exists precisely to break template
//! parsers — so unknown-member tolerance is required by the `WebAuthn`
//! spec's client-data verification algorithm; the simple-value restriction
//! keeps parsing bounded and deterministic.

use crate::Error;

/// Length of the challenge an assertion signs.
pub const CHALLENGE_LEN: usize = 32;
/// Length of [`encode_challenge`]'s output: 32 bytes in unpadded base64url.
pub const ENCODED_CHALLENGE_LEN: usize = 43;

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encodes a challenge the way `clientDataJSON.challenge` carries it:
/// unpadded base64url, the encoding browsers apply to the challenge bytes
/// they were handed.
#[allow(
    clippy::indexing_slicing,
    reason = "const-bounded base64 layout: 32 input bytes emit exactly 43 output bytes"
)]
#[must_use]
pub fn encode_challenge(input: &[u8; CHALLENGE_LEN]) -> [u8; ENCODED_CHALLENGE_LEN] {
    let mut out = [0_u8; ENCODED_CHALLENGE_LEN];
    let mut input_index = 0;
    let mut output_index = 0;

    while input_index + 3 <= input.len() {
        let bits = (u32::from(input[input_index]) << 16)
            | (u32::from(input[input_index + 1]) << 8)
            | u32::from(input[input_index + 2]);
        out[output_index] = BASE64URL[((bits >> 18) & 0x3f) as usize];
        out[output_index + 1] = BASE64URL[((bits >> 12) & 0x3f) as usize];
        out[output_index + 2] = BASE64URL[((bits >> 6) & 0x3f) as usize];
        out[output_index + 3] = BASE64URL[(bits & 0x3f) as usize];
        input_index += 3;
        output_index += 4;
    }

    let bits = (u32::from(input[input_index]) << 16) | (u32::from(input[input_index + 1]) << 8);
    out[output_index] = BASE64URL[((bits >> 18) & 0x3f) as usize];
    out[output_index + 1] = BASE64URL[((bits >> 12) & 0x3f) as usize];
    out[output_index + 2] = BASE64URL[((bits >> 6) & 0x3f) as usize];

    out
}

/// Checks `input` against the grammar and the expected encoded challenge.
#[allow(
    clippy::redundant_pub_crate,
    reason = "the crate denies `unreachable_pub`, which rejects a bare `pub` here"
)]
pub(crate) fn validate(
    input: &[u8],
    expected_challenge: &[u8; ENCODED_CHALLENGE_LEN],
) -> Result<(), Error> {
    let mut parser = JsonParser::new(input);
    parser.skip_ws();
    parser.expect(b'{')?;

    let mut seen_type = false;
    let mut seen_challenge = false;

    parser.skip_ws();
    if parser.consume(b'}') {
        return Err(Error::MissingClientDataField);
    }

    loop {
        parser.skip_ws();
        let key = parser.parse_string()?;
        parser.skip_ws();
        parser.expect(b':')?;
        parser.skip_ws();

        match field_name(key) {
            FieldName::Type => {
                if seen_type {
                    return Err(Error::DuplicateClientDataField);
                }
                seen_type = true;
                let value = parser.parse_string()?;
                if value.escaped || value.bytes != b"webauthn.get" {
                    return Err(Error::InvalidClientDataType);
                }
            }
            FieldName::Challenge => {
                if seen_challenge {
                    return Err(Error::DuplicateClientDataField);
                }
                seen_challenge = true;
                let value = parser.parse_string()?;
                if value.escaped || value.bytes != expected_challenge {
                    return Err(Error::InvalidChallenge);
                }
            }
            // Any other member (browser-injected `origin`, `crossOrigin`,
            // `topOrigin`, Chrome's decoy key, future additions) is
            // skipped, provided its value is simple. Structured values
            // are rejected to keep parsing bounded.
            FieldName::Other => parser.skip_simple_value()?,
        }

        parser.skip_ws();
        if parser.consume(b'}') {
            break;
        }
        parser.expect(b',')?;
    }

    parser.skip_ws();
    if !parser.is_done() {
        return Err(Error::InvalidClientDataJson);
    }
    if !seen_type || !seen_challenge {
        return Err(Error::MissingClientDataField);
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct JsonString<'a> {
    bytes: &'a [u8],
    escaped: bool,
}

#[derive(Debug, Clone, Copy)]
enum FieldName {
    Type,
    Challenge,
    Other,
}

/// Escaped member names never match a required field: `type`/`challenge`
/// must appear literally, and an escaped alias is skipped as unknown.
const fn field_name(value: JsonString<'_>) -> FieldName {
    if value.escaped {
        return FieldName::Other;
    }
    match value.bytes {
        b"type" => FieldName::Type,
        b"challenge" => FieldName::Challenge,
        _ => FieldName::Other,
    }
}

#[derive(Debug, Clone, Copy)]
struct JsonParser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    const fn is_done(&self) -> bool {
        self.pos == self.input.len()
    }

    fn skip_ws(&mut self) {
        while let Some(byte) = self.peek()
            && matches!(byte, b' ' | b'\n' | b'\r' | b'\t')
        {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), Error> {
        if self.consume(byte) {
            Ok(())
        } else {
            Err(Error::InvalidClientDataJson)
        }
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "start <= end <= input.len(): pos only advances past peeked bytes"
    )]
    fn parse_string(&mut self) -> Result<JsonString<'a>, Error> {
        self.expect(b'"')?;
        let start = self.pos;
        let mut escaped = false;

        while let Some(byte) = self.peek() {
            match byte {
                b'"' => {
                    let end = self.pos;
                    self.pos += 1;
                    return Ok(JsonString {
                        bytes: &self.input[start..end],
                        escaped,
                    });
                }
                b'\\' => {
                    escaped = true;
                    self.pos += 1;
                    self.skip_escape()?;
                }
                0x00..=0x1f => return Err(Error::InvalidClientDataJson),
                _ => self.pos += 1,
            }
        }

        Err(Error::InvalidClientDataJson)
    }

    fn skip_escape(&mut self) -> Result<(), Error> {
        let Some(byte) = self.peek() else {
            return Err(Error::InvalidClientDataJson);
        };
        self.pos += 1;
        match byte {
            b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => Ok(()),
            b'u' => {
                for _ in 0..4 {
                    let Some(hex) = self.peek() else {
                        return Err(Error::InvalidClientDataJson);
                    };
                    if !hex.is_ascii_hexdigit() {
                        return Err(Error::InvalidClientDataJson);
                    }
                    self.pos += 1;
                }
                Ok(())
            }
            _ => Err(Error::InvalidClientDataJson),
        }
    }

    /// Skips one *simple* JSON value: string, `true`, `false`, `null`, or
    /// number. Objects and arrays are rejected — unknown members may not
    /// carry structure.
    fn skip_simple_value(&mut self) -> Result<(), Error> {
        match self.peek() {
            Some(b'"') => self.parse_string().map(|_| ()),
            Some(b't') => self.consume_literal(b"true"),
            Some(b'f') => self.consume_literal(b"false"),
            Some(b'n') => self.consume_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.skip_number(),
            _ => Err(Error::InvalidClientDataJson),
        }
    }

    /// Consumes a loose number token. The value is never interpreted, so
    /// full JSON number grammar is not enforced — only that the token is
    /// non-empty and built from number characters.
    fn skip_number(&mut self) -> Result<(), Error> {
        let start = self.pos;
        while let Some(byte) = self.peek() {
            match byte {
                b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E' => self.pos += 1,
                _ => break,
            }
        }
        if self.pos == start {
            return Err(Error::InvalidClientDataJson);
        }
        Ok(())
    }

    fn consume_literal(&mut self, literal: &[u8]) -> Result<(), Error> {
        if self
            .input
            .get(self.pos..self.pos + literal.len())
            .is_none_or(|head| head != literal)
        {
            return Err(Error::InvalidClientDataJson);
        }
        self.pos += literal.len();
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, reason = "test constants are in-bounds")]
mod tests {
    use super::*;

    const ZERO_CHALLENGE: [u8; ENCODED_CHALLENGE_LEN] =
        *b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn challenge_base64url_matches_known_value() {
        assert_eq!(
            encode_challenge(&[0; CHALLENGE_LEN]),
            *b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        assert_eq!(
            encode_challenge(&[0xff; CHALLENGE_LEN]),
            *b"__________________________________________8",
        );
    }

    #[test]
    fn client_data_rejects_nested_challenge_injection() {
        let attack =
            br#"{"type":"webauthn.get","challenge":"bad","extra":{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#;

        assert_eq!(
            validate(attack, &ZERO_CHALLENGE),
            Err(Error::InvalidChallenge),
        );
    }

    #[test]
    fn client_data_accepts_unknown_simple_members_and_whitespace() {
        let input = br#" {
            "origin": "https://example.invalid",
            "type": "webauthn.get",
            "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "crossOrigin": false,
            "topOrigin": "https:\/\/top.example.invalid"
        } "#;

        assert_eq!(validate(input, &ZERO_CHALLENGE), Ok(()));

        // Chrome injects a decoy member specifically to break template
        // parsers; the grammar must skip it (and any other simple-valued
        // unknown member) or real passkey assertions fail.
        let input = br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}"#;

        assert_eq!(validate(input, &ZERO_CHALLENGE), Ok(()));

        let input = br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","crossOrigin":true,"androidPackageName":"com.example.wallet","futureCount":-1.5e3,"futureFlag":null}"#;

        assert_eq!(validate(input, &ZERO_CHALLENGE), Ok(()));

        // An escaped alias of a required member name is skipped as an
        // unknown member; the literal `type` member is what gets checked.
        assert_eq!(
            validate(
                br#"{"ty\u0070e":"evil","type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &ZERO_CHALLENGE,
            ),
            Ok(()),
        );
    }

    #[test]
    fn client_data_rejects_trailing_junk_and_missing_fields() {
        assert_eq!(
            validate(
                br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} true"#,
                &ZERO_CHALLENGE,
            ),
            Err(Error::InvalidClientDataJson),
        );
        assert_eq!(
            validate(
                br#"{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &ZERO_CHALLENGE,
            ),
            Err(Error::MissingClientDataField),
        );
        assert_eq!(
            validate(br#"{"type":"webauthn.get"}"#, &ZERO_CHALLENGE),
            Err(Error::MissingClientDataField),
        );
    }

    #[test]
    fn client_data_rejects_duplicates_and_escaped_required_fields() {
        assert_eq!(
            validate(
                br#"{"type":"webauthn.get","type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &ZERO_CHALLENGE,
            ),
            Err(Error::DuplicateClientDataField),
        );
        assert_eq!(
            validate(
                br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &ZERO_CHALLENGE,
            ),
            Err(Error::DuplicateClientDataField),
        );
        assert_eq!(
            validate(
                br#"{"type":"not-webauthn","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &ZERO_CHALLENGE,
            ),
            Err(Error::InvalidClientDataType),
        );
        assert_eq!(
            validate(
                br#"{"type":"webauthn\u002eget","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &ZERO_CHALLENGE,
            ),
            Err(Error::InvalidClientDataType),
        );
        // An escaped alias of `type` is skipped as an unknown member, so
        // the required literal member is missing here.
        assert_eq!(
            validate(
                br#"{"ty\u0070e":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &ZERO_CHALLENGE,
            ),
            Err(Error::MissingClientDataField),
        );
        // A first *literal* `type` member wins even when a later duplicate
        // holds the expected value - the checked value cannot be displaced.
        assert_eq!(
            validate(
                br#"{"type":"evil","type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &ZERO_CHALLENGE,
            ),
            Err(Error::InvalidClientDataType),
        );
    }

    #[test]
    fn client_data_rejects_structured_and_malformed_unknown_values() {
        // Malformed literal token.
        assert_eq!(
            validate(
                br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","extra":truex}"#,
                &ZERO_CHALLENGE,
            ),
            Err(Error::InvalidClientDataJson),
        );
        // Unknown members may not carry structure (objects/arrays).
        assert_eq!(
            validate(
                br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","extra":{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#,
                &ZERO_CHALLENGE,
            ),
            Err(Error::InvalidClientDataJson),
        );
        assert_eq!(
            validate(
                br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","extra":[1,2]}"#,
                &ZERO_CHALLENGE,
            ),
            Err(Error::InvalidClientDataJson),
        );
        // Truncated literal.
        assert_eq!(
            validate(
                br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","crossOrigin":tru"#,
                &ZERO_CHALLENGE,
            ),
            Err(Error::InvalidClientDataJson),
        );
        // Bad unicode escape inside a skipped string.
        assert_eq!(
            validate(
                br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","topOrigin":"\u12x4"}"#,
                &ZERO_CHALLENGE,
            ),
            Err(Error::InvalidClientDataJson),
        );
        // Raw control character inside a skipped string.
        assert_eq!(
            validate(
                b"{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"\n\"}",
                &ZERO_CHALLENGE,
            ),
            Err(Error::InvalidClientDataJson),
        );
    }
}
