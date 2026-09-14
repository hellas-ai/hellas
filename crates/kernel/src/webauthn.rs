//! `WebAuthn` verification for [`crate::Auth`] witnesses.
//!
//! This follows Tempo's consensus shape: the kernel validates the `WebAuthn`
//! assertion and requires `clientDataJSON.challenge` to be the base64url
//! encoding of the canonical payload hash — the open hash for opens, the
//! close payload hash for cooperative closes. It intentionally does not enforce
//! `origin` or `rpIdHash`; those bytes are still signed by the authenticator,
//! but the verifier treats `WebAuthn` as a portable P-256 transaction-signing
//! envelope. The accepted `clientDataJSON` grammar is deliberately narrower
//! than arbitrary JSON: a top-level object with required unescaped `type` and
//! `challenge` members, where every other member is skipped as long as its
//! value is *simple* (string, boolean, null, or number). Nested objects and
//! arrays are rejected. Browsers deliberately inject unknown members —
//! Chrome's `other_keys_can_be_added_here` decoy exists precisely to break
//! template parsers — so unknown-member tolerance is required by the
//! `WebAuthn` spec's client-data verification algorithm; the simple-value
//! restriction keeps parsing bounded and deterministic.
//!
//! Policy note: this verifier accepts user presence *or* user verification
//! (`UP | UV`) and ignores `origin`. The chain-facing envelope (the
//! `hellas-chain` crate's `domain` module) enforces a stricter
//! browser-shaped policy (UP *and* UV, HTTPS origin allowlist, `rpIdHash`
//! binding) for its own transaction kinds. The two are intentionally
//! different products; do not wire one where the other is expected.

use p256::{
    Sec1Point,
    ecdsa::{Signature as P256Signature, VerifyingKey, signature::hazmat::PrehashVerifier},
};
use sha2::{Digest, Sha256};

use crate::{
    consts::P256_COORDINATE_LENGTH,
    primitive::{Key, PayloadHash},
    tx::WebAuthnAssertion,
};

mod soft_passkey;

/// Deterministic passkey builders and v1 wire fixtures for integration tests.
#[cfg(feature = "test-support")]
pub mod test_support;

pub use soft_passkey::{SoftPasskey, SoftPasskeyError};

const MIN_AUTH_DATA_LEN: usize = 37;
const UP: u8 = 0x01;
const UV: u8 = 0x04;
const AT: u8 = 0x40;
const ED: u8 = 0x80;

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const P256_N_HALF: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// Reason a `WebAuthn` authorization assertion failed verification.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum WebAuthnError {
    /// `authenticatorData || clientDataJSON` is too short to contain both
    /// required pieces.
    DataTooShort,
    /// Neither the user-presence nor user-verification flag is set.
    MissingUserPresence,
    /// Assertion auth data must not carry attested credential data.
    AttestedCredentialDataUnsupported,
    /// Extension data is not supported by the kernel verifier.
    ExtensionsUnsupported,
    /// `clientDataJSON` is not accepted by the kernel's strict parser.
    InvalidClientDataJson,
    /// `clientDataJSON.type` is not `webauthn.get`.
    InvalidClientDataType,
    /// `clientDataJSON.challenge` does not match the expected payload hash.
    InvalidChallenge,
    /// `clientDataJSON` is missing a required top-level field.
    MissingClientDataField,
    /// `clientDataJSON` repeats a required top-level field.
    DuplicateClientDataField,
    /// The supplied P-256 coordinates do not encode a valid public key.
    InvalidPublicKey,
    /// The P-256 public key does not match the party key.
    SignerMismatch,
    /// The P-256 signature uses a high-s value.
    HighS,
    /// The P-256 signature is malformed or does not verify.
    InvalidSignature,
}

/// Verifies a `WebAuthn` assertion against a party key and payload hash.
///
/// The party key is the compressed SEC1 encoding of the P-256 public key
/// carried by the assertion.
///
/// # Errors
///
/// Returns [`WebAuthnError`] when the assertion is malformed, its challenge
/// does not match `hash`, its P-256 key does not match `key`, or its
/// signature fails verification.
pub fn verify_webauthn_assertion(
    assertion: &WebAuthnAssertion,
    key: Key,
    hash: PayloadHash,
) -> Result<(), WebAuthnError> {
    if p256_key(assertion.pub_key_x(), assertion.pub_key_y())? != key {
        return Err(WebAuthnError::SignerMismatch);
    }

    let message_hash = webauthn_message_hash(assertion.webauthn_data().as_slice(), hash)?;
    verify_p256_signature(assertion, &message_hash)
}

/// Returns the compressed P-256 key bytes used as a Hellas party key.
///
/// Use this when constructing `Terms` for a party controlled by a passkey.
///
/// # Errors
///
/// Returns [`WebAuthnError::InvalidPublicKey`] if the coordinates do not
/// encode a valid P-256 public key.
pub fn p256_key(
    pub_key_x: &[u8; P256_COORDINATE_LENGTH],
    pub_key_y: &[u8; P256_COORDINATE_LENGTH],
) -> Result<Key, WebAuthnError> {
    let verifying_key = verifying_key(pub_key_x, pub_key_y)?;
    let encoded = verifying_key.to_sec1_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != Key::LENGTH {
        return Err(WebAuthnError::InvalidPublicKey);
    }

    let mut out = [0_u8; Key::LENGTH];
    out.copy_from_slice(bytes);
    Ok(Key::from_bytes(out))
}

fn verifying_key(
    pub_key_x: &[u8; P256_COORDINATE_LENGTH],
    pub_key_y: &[u8; P256_COORDINATE_LENGTH],
) -> Result<VerifyingKey, WebAuthnError> {
    let mut encoded = [0_u8; 65];
    let (tag, coords) = encoded.split_at_mut(1);
    tag.fill(0x04);
    let (xs, ys) = coords.split_at_mut(P256_COORDINATE_LENGTH);
    xs.copy_from_slice(pub_key_x);
    ys.copy_from_slice(pub_key_y);
    let point = Sec1Point::from_bytes(encoded).map_err(|_| WebAuthnError::InvalidPublicKey)?;
    VerifyingKey::from_sec1_point(&point).map_err(|_| WebAuthnError::InvalidPublicKey)
}

fn verify_p256_signature(
    assertion: &WebAuthnAssertion,
    message_hash: &[u8; PayloadHash::LENGTH],
) -> Result<(), WebAuthnError> {
    if assertion.s() > &P256_N_HALF {
        return Err(WebAuthnError::HighS);
    }

    let verifying_key = verifying_key(assertion.pub_key_x(), assertion.pub_key_y())?;
    let mut sig = [0_u8; 64];
    let (r_half, s_half) = sig.split_at_mut(P256_COORDINATE_LENGTH);
    r_half.copy_from_slice(assertion.r());
    s_half.copy_from_slice(assertion.s());
    let signature = P256Signature::from_slice(&sig).map_err(|_| WebAuthnError::InvalidSignature)?;

    verifying_key
        .verify_prehash(message_hash, &signature)
        .map_err(|_| WebAuthnError::InvalidSignature)
}

fn webauthn_message_hash(
    webauthn_data: &[u8],
    hash: PayloadHash,
) -> Result<[u8; PayloadHash::LENGTH], WebAuthnError> {
    if webauthn_data.len() < MIN_AUTH_DATA_LEN + PayloadHash::LENGTH {
        return Err(WebAuthnError::DataTooShort);
    }

    let flags = *webauthn_data.get(32).ok_or(WebAuthnError::DataTooShort)?;
    if flags & (UP | UV) == 0 {
        return Err(WebAuthnError::MissingUserPresence);
    }
    if flags & AT != 0 {
        return Err(WebAuthnError::AttestedCredentialDataUnsupported);
    }
    if flags & ED != 0 {
        return Err(WebAuthnError::ExtensionsUnsupported);
    }

    let (auth_data, client_data_json) = webauthn_data.split_at(MIN_AUTH_DATA_LEN);
    validate_client_data_json(client_data_json, &base64url_32(hash.as_bytes()))?;

    let client_data_hash = Sha256::digest(client_data_json);
    let mut hasher = Sha256::new();
    hasher.update(auth_data);
    hasher.update(client_data_hash);
    let digest = hasher.finalize();

    let mut out = [0_u8; PayloadHash::LENGTH];
    out.copy_from_slice(&digest);
    Ok(out)
}

#[allow(
    clippy::indexing_slicing,
    reason = "const-bounded base64 layout: 32 input bytes emit exactly 43 output bytes"
)]
fn base64url_32(input: &[u8; PayloadHash::LENGTH]) -> [u8; 43] {
    let mut out = [0_u8; 43];
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

fn validate_client_data_json(
    input: &[u8],
    expected_challenge: &[u8; 43],
) -> Result<(), WebAuthnError> {
    let mut parser = JsonParser::new(input);
    parser.skip_ws();
    parser.expect(b'{')?;

    let mut seen_type = false;
    let mut seen_challenge = false;

    parser.skip_ws();
    if parser.consume(b'}') {
        return Err(WebAuthnError::MissingClientDataField);
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
                    return Err(WebAuthnError::DuplicateClientDataField);
                }
                seen_type = true;
                let value = parser.parse_string()?;
                if value.escaped || value.bytes != b"webauthn.get" {
                    return Err(WebAuthnError::InvalidClientDataType);
                }
            }
            FieldName::Challenge => {
                if seen_challenge {
                    return Err(WebAuthnError::DuplicateClientDataField);
                }
                seen_challenge = true;
                let value = parser.parse_string()?;
                if value.escaped || value.bytes != expected_challenge {
                    return Err(WebAuthnError::InvalidChallenge);
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
        return Err(WebAuthnError::InvalidClientDataJson);
    }
    if !seen_type || !seen_challenge {
        return Err(WebAuthnError::MissingClientDataField);
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

    fn expect(&mut self, byte: u8) -> Result<(), WebAuthnError> {
        if self.consume(byte) {
            Ok(())
        } else {
            Err(WebAuthnError::InvalidClientDataJson)
        }
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "start <= end <= input.len(): pos only advances past peeked bytes"
    )]
    fn parse_string(&mut self) -> Result<JsonString<'a>, WebAuthnError> {
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
                0x00..=0x1f => return Err(WebAuthnError::InvalidClientDataJson),
                _ => self.pos += 1,
            }
        }

        Err(WebAuthnError::InvalidClientDataJson)
    }

    fn skip_escape(&mut self) -> Result<(), WebAuthnError> {
        let Some(byte) = self.peek() else {
            return Err(WebAuthnError::InvalidClientDataJson);
        };
        self.pos += 1;
        match byte {
            b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => Ok(()),
            b'u' => {
                for _ in 0..4 {
                    let Some(hex) = self.peek() else {
                        return Err(WebAuthnError::InvalidClientDataJson);
                    };
                    if !hex.is_ascii_hexdigit() {
                        return Err(WebAuthnError::InvalidClientDataJson);
                    }
                    self.pos += 1;
                }
                Ok(())
            }
            _ => Err(WebAuthnError::InvalidClientDataJson),
        }
    }

    /// Skips one *simple* JSON value: string, `true`, `false`, `null`, or
    /// number. Objects and arrays are rejected — unknown members may not
    /// carry structure.
    fn skip_simple_value(&mut self) -> Result<(), WebAuthnError> {
        match self.peek() {
            Some(b'"') => self.parse_string().map(|_| ()),
            Some(b't') => self.consume_literal(b"true"),
            Some(b'f') => self.consume_literal(b"false"),
            Some(b'n') => self.consume_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.skip_number(),
            _ => Err(WebAuthnError::InvalidClientDataJson),
        }
    }

    /// Consumes a loose number token. The value is never interpreted, so
    /// full JSON number grammar is not enforced — only that the token is
    /// non-empty and built from number characters.
    fn skip_number(&mut self) -> Result<(), WebAuthnError> {
        let start = self.pos;
        while let Some(byte) = self.peek() {
            match byte {
                b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E' => self.pos += 1,
                _ => break,
            }
        }
        if self.pos == start {
            return Err(WebAuthnError::InvalidClientDataJson);
        }
        Ok(())
    }

    fn consume_literal(&mut self, literal: &[u8]) -> Result<(), WebAuthnError> {
        if self
            .input
            .get(self.pos..self.pos + literal.len())
            .is_none_or(|head| head != literal)
        {
            return Err(WebAuthnError::InvalidClientDataJson);
        }
        self.pos += literal.len();
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, reason = "test constants are in-bounds")]
mod tests {
    use super::*;
    use crate::{MAX_WEBAUTHN_DATA_LENGTH, WebAuthnData};

    const ZERO_CHALLENGE: [u8; 43] = *b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const GOOD_CLIENT_DATA: &[u8] =
        br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;

    #[test]
    fn challenge_base64url_matches_known_value() {
        let hash = PayloadHash::from_bytes([0; PayloadHash::LENGTH]);
        assert_eq!(
            base64url_32(hash.as_bytes()),
            *b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );

        let hash = PayloadHash::from_bytes([0xff; PayloadHash::LENGTH]);
        assert_eq!(
            base64url_32(hash.as_bytes()),
            *b"__________________________________________8",
        );
    }

    #[test]
    fn client_data_rejects_nested_challenge_injection() {
        let attack =
            br#"{"type":"webauthn.get","challenge":"bad","extra":{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#;

        assert_eq!(
            validate_client_data_json(attack, &ZERO_CHALLENGE),
            Err(WebAuthnError::InvalidChallenge),
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

        assert_eq!(validate_client_data_json(input, &ZERO_CHALLENGE), Ok(()));

        // Chrome injects a decoy member specifically to break template
        // parsers; the grammar must skip it (and any other simple-valued
        // unknown member) or real passkey assertions fail.
        let input = br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}"#;

        assert_eq!(validate_client_data_json(input, &ZERO_CHALLENGE), Ok(()));

        let input = br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","crossOrigin":true,"androidPackageName":"com.example.wallet","futureCount":-1.5e3,"futureFlag":null}"#;

        assert_eq!(validate_client_data_json(input, &ZERO_CHALLENGE), Ok(()));

        // An escaped alias of a required member name is skipped as an
        // unknown member; the literal `type` member is what gets checked.
        assert_eq!(
            validate_client_data_json(
                br#"{"ty\u0070e":"evil","type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &ZERO_CHALLENGE,
            ),
            Ok(()),
        );
    }

    #[test]
    fn client_data_rejects_trailing_junk_and_missing_fields() {
        assert_eq!(
            validate_client_data_json(
                br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} true"#,
                &ZERO_CHALLENGE,
            ),
            Err(WebAuthnError::InvalidClientDataJson),
        );
        assert_eq!(
            validate_client_data_json(
                br#"{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &ZERO_CHALLENGE,
            ),
            Err(WebAuthnError::MissingClientDataField),
        );
        assert_eq!(
            validate_client_data_json(br#"{"type":"webauthn.get"}"#, &ZERO_CHALLENGE),
            Err(WebAuthnError::MissingClientDataField),
        );
    }

    #[test]
    fn client_data_rejects_duplicates_and_escaped_required_fields() {
        assert_eq!(
            validate_client_data_json(
                br#"{"type":"webauthn.get","type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &ZERO_CHALLENGE,
            ),
            Err(WebAuthnError::DuplicateClientDataField),
        );
        assert_eq!(
            validate_client_data_json(
                br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &ZERO_CHALLENGE,
            ),
            Err(WebAuthnError::DuplicateClientDataField),
        );
        assert_eq!(
            validate_client_data_json(
                br#"{"type":"not-webauthn","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &ZERO_CHALLENGE,
            ),
            Err(WebAuthnError::InvalidClientDataType),
        );
        assert_eq!(
            validate_client_data_json(
                br#"{"type":"webauthn\u002eget","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &ZERO_CHALLENGE,
            ),
            Err(WebAuthnError::InvalidClientDataType),
        );
        // An escaped alias of `type` is skipped as an unknown member, so
        // the required literal member is missing here.
        assert_eq!(
            validate_client_data_json(
                br#"{"ty\u0070e":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &ZERO_CHALLENGE,
            ),
            Err(WebAuthnError::MissingClientDataField),
        );
        // A first *literal* `type` member wins even when a later duplicate
        // holds the expected value - the checked value cannot be displaced.
        assert_eq!(
            validate_client_data_json(
                br#"{"type":"evil","type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                &ZERO_CHALLENGE,
            ),
            Err(WebAuthnError::InvalidClientDataType),
        );
    }

    #[test]
    fn client_data_rejects_structured_and_malformed_unknown_values() {
        // Malformed literal token.
        assert_eq!(
            validate_client_data_json(
                br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","extra":truex}"#,
                &ZERO_CHALLENGE,
            ),
            Err(WebAuthnError::InvalidClientDataJson),
        );
        // Unknown members may not carry structure (objects/arrays).
        assert_eq!(
            validate_client_data_json(
                br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","extra":{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#,
                &ZERO_CHALLENGE,
            ),
            Err(WebAuthnError::InvalidClientDataJson),
        );
        assert_eq!(
            validate_client_data_json(
                br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","extra":[1,2]}"#,
                &ZERO_CHALLENGE,
            ),
            Err(WebAuthnError::InvalidClientDataJson),
        );
        // Truncated literal.
        assert_eq!(
            validate_client_data_json(
                br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","crossOrigin":tru"#,
                &ZERO_CHALLENGE,
            ),
            Err(WebAuthnError::InvalidClientDataJson),
        );
        // Bad unicode escape inside a skipped string.
        assert_eq!(
            validate_client_data_json(
                br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","topOrigin":"\u12x4"}"#,
                &ZERO_CHALLENGE,
            ),
            Err(WebAuthnError::InvalidClientDataJson),
        );
        // Raw control character inside a skipped string.
        assert_eq!(
            validate_client_data_json(
                b"{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"\n\"}",
                &ZERO_CHALLENGE,
            ),
            Err(WebAuthnError::InvalidClientDataJson),
        );
    }

    #[test]
    fn message_hash_rejects_bad_authenticator_data_flags() {
        let hash = PayloadHash::from_bytes([0; PayloadHash::LENGTH]);

        assert_eq!(
            webauthn_message_hash(&[0; MIN_AUTH_DATA_LEN + PayloadHash::LENGTH - 1], hash),
            Err(WebAuthnError::DataTooShort),
        );
        let mut minimum_len_data = [0; MIN_AUTH_DATA_LEN + PayloadHash::LENGTH];
        minimum_len_data[32] = UP;
        assert_eq!(
            webauthn_message_hash(&minimum_len_data, hash),
            Err(WebAuthnError::InvalidClientDataJson),
        );
        assert_eq!(
            message_hash_with_flags(0, GOOD_CLIENT_DATA),
            Err(WebAuthnError::MissingUserPresence),
        );
        assert_eq!(
            message_hash_with_flags(UP | AT, GOOD_CLIENT_DATA),
            Err(WebAuthnError::AttestedCredentialDataUnsupported),
        );
        assert_eq!(
            message_hash_with_flags(UV | ED, GOOD_CLIENT_DATA),
            Err(WebAuthnError::ExtensionsUnsupported),
        );
        assert!(message_hash_with_flags(UP, GOOD_CLIENT_DATA).is_ok());
        assert!(message_hash_with_flags(UV, GOOD_CLIENT_DATA).is_ok());
    }

    #[test]
    fn p256_signature_low_s_boundary_is_not_high_s() {
        let assertion = WebAuthnAssertion::new(
            [1; PayloadHash::LENGTH],
            P256_N_HALF,
            [0; PayloadHash::LENGTH],
            [0; PayloadHash::LENGTH],
            empty_webauthn_data(),
        );

        assert_eq!(
            verify_p256_signature(&assertion, &[0; PayloadHash::LENGTH]),
            Err(WebAuthnError::InvalidPublicKey),
        );
    }

    fn message_hash_with_flags(
        flags: u8,
        client_data: &[u8],
    ) -> Result<[u8; PayloadHash::LENGTH], WebAuthnError> {
        let mut data = [0; MAX_WEBAUTHN_DATA_LENGTH];
        data[32] = flags;
        let len = MIN_AUTH_DATA_LEN + client_data.len();
        data[MIN_AUTH_DATA_LEN..len].copy_from_slice(client_data);

        webauthn_message_hash(
            &data[..len],
            PayloadHash::from_bytes([0; PayloadHash::LENGTH]),
        )
    }

    fn empty_webauthn_data() -> WebAuthnData {
        crate::List::empty(0)
    }
}
