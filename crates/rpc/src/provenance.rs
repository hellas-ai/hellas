//! Execution provenance — content-addressed identifiers that travel
//! alongside every gateway/executor RPC.
//!
//! Wire form: 32-byte digest carried as a `-bin` metadata value in
//! `hellas_wire::Metadata`. Per the gRPC convention, binary metadata
//! keys end with `-bin` and the value is raw bytes (decoded as such
//! by gRPC peers via base64 in HTTP/2 land, but the wire-layer keeps
//! it raw).

use std::fmt::Write;

use bytes::Bytes;
use hellas_wire::{Metadata, MetadataValue, WireCode, WireStatus};
use thiserror::Error;

/// Metadata key for the work commitment digest (raw 32 bytes).
pub const COMMITMENT_KEY: &str = "x-hellas-commitment-bin";

/// Pre-flight provenance for a single execution. Scheme result commitments
/// live in signed terminal output events, not in this struct.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecutionProvenance {
    pub commitment_id: [u8; 32],
}

impl std::fmt::Display for ExecutionProvenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.commitment_id {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
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
}

impl From<ProvenanceError> for WireStatus {
    fn from(err: ProvenanceError) -> Self {
        WireStatus::new(WireCode::Internal, err.to_string())
    }
}

/// Render a 32-byte digest as 64-char lowercase hex (for logging).
pub fn encode_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in bytes {
        write!(&mut s, "{byte:02x}").expect("writing to String never fails");
    }
    s
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

/// Read the pre-flight provenance from a wire Metadata map.
pub fn read_provenance_metadata(md: &Metadata) -> Result<ExecutionProvenance, ProvenanceError> {
    Ok(ExecutionProvenance {
        commitment_id: digest_bytes_from_metadata(md, COMMITMENT_KEY)?,
    })
}

/// Insert pre-flight provenance into a wire Metadata map. Used
/// server-side on response headers / trailers.
pub fn write_provenance_metadata(md: &mut Metadata, prov: &ExecutionProvenance) {
    md.insert(
        COMMITMENT_KEY,
        MetadataValue::Bytes(Bytes::copy_from_slice(&prov.commitment_id)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ExecutionProvenance {
        ExecutionProvenance {
            commitment_id: [0xab; 32],
        }
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
        let md = Metadata::new();
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
