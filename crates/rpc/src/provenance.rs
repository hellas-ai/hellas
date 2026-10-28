//! Execution provenance: the job identity a provider accepted, travelling
//! alongside every gateway/executor RPC and every gateway HTTP response.
//!
//! Wire form: the 32-byte commitment is carried as a `-bin` metadata value in
//! `hellas_wire::Metadata`. Per the gRPC convention, binary metadata keys end
//! with `-bin` and the value is raw bytes (decoded as such by gRPC peers via
//! base64 in HTTP/2 land, but the wire-layer keeps it raw). The provider key
//! is text, in the form [`encode_public_key`] renders.

use std::fmt::Write;

use bytes::Bytes;
use hellas_auth::PublicKey;
use hellas_wire::{Metadata, MetadataValue, WireCode, WireStatus};
use thiserror::Error;

/// Metadata key for the work commitment digest (raw 32 bytes). HTTP
/// responses carry it as lowercase hex under the same name.
pub const COMMITMENT_KEY: &str = "x-hellas-commitment-bin";

/// Metadata key and HTTP header naming the provider that accepted the work.
pub const PROVIDER_KEY: &str = "x-hellas-provider";

/// HTTP trailer (a header on a bodyless response) carrying the base64
/// canonical bytes of the provider-signed transcript.
pub const TRANSCRIPT_KEY: &str = "x-hellas-transcript";

/// The job identity a provider accepted, known before its first output: the
/// work id it signed and the key that signs its transcript. Scheme result
/// commitments live in signed terminal output events, not in this struct.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecutionProvenance {
    pub commitment_id: [u8; 32],
    pub provider: PublicKey,
}

impl std::fmt::Display for ExecutionProvenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} by {}",
            encode_hex(&self.commitment_id),
            encode_public_key(&self.provider)
        )
    }
}

impl std::fmt::Debug for ExecutionProvenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProvenanceError {
    #[error("provenance metadata missing key `{key}`")]
    Missing { key: &'static str },
    #[error("provenance metadata key `{key}` is not 32 bytes (got {len})")]
    BadLength { key: &'static str, len: usize },
    #[error("provenance metadata key `{key}` is not a provider key")]
    BadKey { key: &'static str },
}

impl From<ProvenanceError> for WireStatus {
    fn from(err: ProvenanceError) -> Self {
        WireStatus::new(WireCode::Internal, err.to_string())
    }
}

/// Render a 32-byte digest as 64-char lowercase hex (for logging).
pub fn encode_hex(bytes: &[u8; 32]) -> String {
    lower_hex(bytes)
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        write!(&mut s, "{byte:02x}").expect("writing to String never fails");
    }
    s
}

const SECP256K1: &str = "secp256k1";
const ED25519: &str = "ed25519";
const P256: &str = "p256";

/// A public key as `<kind>:<lowercase hex of its encoded bytes>`, e.g.
/// `secp256k1:02…` for a compressed secp256k1 key.
pub fn encode_public_key(key: &PublicKey) -> String {
    let kind = match key {
        PublicKey::Secp256k1(_) => SECP256K1,
        PublicKey::Ed25519(_) => ED25519,
        PublicKey::P256(_) => P256,
    };
    format!("{kind}:{}", lower_hex(key.bytes()))
}

/// The key [`encode_public_key`] rendered, if `text` is one.
pub fn parse_public_key(text: &str) -> Option<PublicKey> {
    let (kind, hex) = text.split_once(':')?;
    match kind {
        SECP256K1 => hellas_auth::hex::parse(hex).ok().map(PublicKey::Secp256k1),
        ED25519 => hellas_auth::hex::parse(hex).ok().map(PublicKey::Ed25519),
        P256 => hellas_auth::hex::parse(hex).ok().map(PublicKey::P256),
        _ => None,
    }
}

/// Read a `-bin` 32-byte digest from a wire Metadata map.
pub fn digest_bytes_from_metadata(
    md: &Metadata,
    key: &'static str,
) -> Result<[u8; 32], ProvenanceError> {
    let value = md.get(key).ok_or(ProvenanceError::Missing { key })?;
    let bytes = value
        .as_bytes()
        .ok_or(ProvenanceError::BadLength { key, len: 0 })?;
    if bytes.len() != 32 {
        return Err(ProvenanceError::BadLength {
            key,
            len: bytes.len(),
        });
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Read the accepted job's provenance from a wire Metadata map.
pub fn read_provenance_metadata(md: &Metadata) -> Result<ExecutionProvenance, ProvenanceError> {
    let key = PROVIDER_KEY;
    let provider = md
        .get(key)
        .ok_or(ProvenanceError::Missing { key })?
        .as_text()
        .and_then(parse_public_key)
        .ok_or(ProvenanceError::BadKey { key })?;
    Ok(ExecutionProvenance {
        commitment_id: digest_bytes_from_metadata(md, COMMITMENT_KEY)?,
        provider,
    })
}

/// Insert the accepted job's provenance into a wire Metadata map. Used
/// server-side on response headers / trailers.
pub fn write_provenance_metadata(md: &mut Metadata, prov: &ExecutionProvenance) {
    md.insert(
        COMMITMENT_KEY,
        MetadataValue::Bytes(Bytes::copy_from_slice(&prov.commitment_id)),
    );
    md.insert(
        PROVIDER_KEY,
        MetadataValue::Text(encode_public_key(&prov.provider).into()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ExecutionProvenance {
        ExecutionProvenance {
            commitment_id: [0xab; 32],
            provider: PublicKey::Secp256k1([0x02; 33]),
        }
    }

    #[test]
    fn public_keys_round_trip_through_their_text_form() {
        for key in [
            PublicKey::Secp256k1([0x02; 33]),
            PublicKey::Ed25519([0x07; 32]),
            PublicKey::P256([0x03; 33]),
        ] {
            let text = encode_public_key(&key);
            assert_eq!(parse_public_key(&text), Some(key));
        }
        assert_eq!(
            encode_public_key(&PublicKey::Secp256k1([0x02; 33])),
            format!("secp256k1:{}", "02".repeat(33))
        );
        // The kind fixes the length: an Ed25519-length key is not secp256k1.
        assert_eq!(
            parse_public_key(&format!("secp256k1:{}", "07".repeat(32))),
            None
        );
        assert_eq!(parse_public_key(&"02".repeat(33)), None);
    }

    #[test]
    fn encode_hex_renders_lowercase_hex() {
        let s = encode_hex(&[0xab; 32]);
        assert_eq!(s.len(), 64);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(s, "ab".repeat(32));
    }

    #[test]
    fn round_trip_through_metadata() {
        let prov = sample();
        let mut md = Metadata::new();
        write_provenance_metadata(&mut md, &prov);
        let decoded = read_provenance_metadata(&md).expect("round-trip should succeed");
        assert_eq!(decoded, prov);
    }

    #[test]
    fn missing_key_reports_which_key() {
        let mut md = Metadata::new();
        assert_eq!(
            read_provenance_metadata(&md).expect_err("empty metadata must fail"),
            ProvenanceError::Missing { key: PROVIDER_KEY }
        );
        md.insert(
            PROVIDER_KEY,
            MetadataValue::Text(encode_public_key(&sample().provider).into()),
        );
        let err = read_provenance_metadata(&md).expect_err("empty metadata must fail");
        assert_eq!(
            err,
            ProvenanceError::Missing {
                key: COMMITMENT_KEY
            }
        );
    }

    #[test]
    fn bad_length_reports_actual_length() {
        let mut md = Metadata::new();
        md.insert(
            PROVIDER_KEY,
            MetadataValue::Text(encode_public_key(&sample().provider).into()),
        );
        md.insert(
            COMMITMENT_KEY,
            MetadataValue::Bytes(Bytes::from_static(&[0u8; 8])),
        );
        let err = read_provenance_metadata(&md).expect_err("too-short value must fail");
        assert_eq!(
            err,
            ProvenanceError::BadLength {
                key: COMMITMENT_KEY,
                len: 8
            }
        );
    }
}
