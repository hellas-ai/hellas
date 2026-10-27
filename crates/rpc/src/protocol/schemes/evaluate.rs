use serde::{Deserialize, Serialize};

use crate::protocol::value::{CanonicalDecodeError, CanonicalDecoder};
use crate::{Assurance, ContentId, DagCborEncoder, RequestCommitment, Retention};
use hellas_auth::{Digest, PublicKey, SignatureKind};

/// Schema tag of the request commitment preimage. One constant, so the
/// encoder and the decoder below cannot disagree about which array they
/// are writing and reading.
const EVALUATE_REQUEST_SCHEMA: &str = "hellas.evaluate.request.v3";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluateRequest {
    /// Content-addressed TextExecution artifact.
    pub text_execution: Digest,
    pub runner_public_key: PublicKey,
    pub execution_environment: ContentId,
    pub nonce: [u8; 32],
    pub assurance: Assurance,
    #[serde(default)]
    pub retain: bool,
}

impl EvaluateRequest {
    pub const fn retention(&self) -> Retention {
        Retention::from_retain(self.retain)
    }
}

/// Returns the canonical DAG-CBOR array [`Evaluate::commit_request`] hashes.
///
/// Exposed as bytes because a second protocol — the paid-work bundle in
/// `hellas_channel::model::prepared_input::PreparedPaidInputV1` — must carry the
/// exact preimage of the request commitment, not a second spelling of the
/// same fields. There is one encoder and one field order; a caller that
/// re-derived these bytes could disagree with the commitment they claim
/// to prepare.
pub fn evaluate_request_bytes(request: &EvaluateRequest) -> Vec<u8> {
    let mut encoder = DagCborEncoder::new();
    encoder.array(8);
    encoder.str(EVALUATE_REQUEST_SCHEMA);
    encoder.bytes(request.text_execution.as_bytes());
    encoder.bytes(request.execution_environment.as_bytes());
    encoder.bytes(&request.nonce);
    encoder.u64(request.runner_public_key.kind().to_byte() as u64);
    encoder.bytes(request.runner_public_key.bytes());
    encoder.u64(request.assurance.to_byte() as u64);
    encoder.u64(request.retain as u64);
    encoder.into_bytes()
}

/// Reads back the exact bytes [`evaluate_request_bytes`] writes.
///
/// The last line is the strict part: whatever came out of the decoder is
/// re-encoded and compared, so the only byte string that survives is the
/// one this encoder would have produced. A paid-work bundle carrying a
/// re-spelled request — a wider integer, a reordered field, a trailing
/// byte — is refused here rather than becoming a second bundle that
/// commits to the same job.
pub fn decode_evaluate_request(bytes: &[u8]) -> Result<EvaluateRequest, CanonicalDecodeError> {
    let mut decoder = CanonicalDecoder::new(bytes);
    decoder.array_exact(8)?;
    decoder.expect_str(EVALUATE_REQUEST_SCHEMA)?;
    let text_execution = Digest::from_bytes(decoder.bytes_32()?);
    let execution_environment = ContentId::from_bytes(decoder.bytes_32()?);
    let nonce = decoder.bytes_32()?;
    let kind = u8::try_from(decoder.u64()?)
        .map_err(|_| CanonicalDecodeError::new("signature kind exceeds one byte"))?;
    let key_bytes = decoder.bytes()?;
    let runner_public_key = public_key(kind, key_bytes)?;
    let assurance = u8::try_from(decoder.u64()?)
        .map_err(|_| CanonicalDecodeError::new("assurance exceeds one byte"))
        .and_then(|byte| {
            Assurance::from_byte(byte).map_err(|err| CanonicalDecodeError::new(err.to_string()))
        })?;
    let retain = match decoder.u64()? {
        0 => false,
        1 => true,
        other => {
            return Err(CanonicalDecodeError::new(format!(
                "retain must be 0 or 1, got {other}"
            )));
        }
    };
    decoder.finish()?;

    let request = EvaluateRequest {
        text_execution,
        runner_public_key,
        execution_environment,
        nonce,
        assurance,
        retain,
    };
    if evaluate_request_bytes(&request) != bytes {
        return Err(CanonicalDecodeError::new(
            "request is not in canonical evaluate-request form",
        ));
    }
    Ok(request)
}

fn public_key(kind: u8, bytes: &[u8]) -> Result<PublicKey, CanonicalDecodeError> {
    let kind =
        SignatureKind::from_byte(kind).map_err(|err| CanonicalDecodeError::new(err.to_string()))?;
    let wrong_length = || {
        CanonicalDecodeError::new(format!(
            "{kind:?} public key must not be {} bytes",
            bytes.len()
        ))
    };
    match kind {
        SignatureKind::Secp256k1 => bytes
            .try_into()
            .map(PublicKey::Secp256k1)
            .map_err(|_| wrong_length()),
        SignatureKind::Ed25519 => bytes
            .try_into()
            .map(PublicKey::Ed25519)
            .map_err(|_| wrong_length()),
        SignatureKind::P256 => bytes
            .try_into()
            .map(PublicKey::P256)
            .map_err(|_| wrong_length()),
    }
}

pub struct Evaluate;

impl Evaluate {
    pub fn commit_request(request: &EvaluateRequest) -> RequestCommitment {
        RequestCommitment::from_canonical_bytes(&evaluate_request_bytes(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_auth::ProducerSigningKey;

    fn key(byte: u8) -> PublicKey {
        ProducerSigningKey::from_secret_bytes([byte; 32])
            .expect("valid test key")
            .public_key()
    }

    /// The commitment preimage is a wire format two protocols share, so
    /// it is pinned as bytes and not merely as a digest: a field order
    /// that moved in both the encoder and a re-derived comparison would
    /// leave every round-trip test passing.
    #[test]
    fn request_bytes_are_the_pinned_commitment_preimage() {
        let request = EvaluateRequest {
            text_execution: Digest::from_bytes([4; 32]),
            runner_public_key: key(1),
            execution_environment: ContentId::from_bytes([5; 32]),
            nonce: [6; 32],
            assurance: Assurance::ProducerSigned,
            retain: true,
        };
        let bytes = evaluate_request_bytes(&request);
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();

        // 88                      array(8)
        // 78 1a "hellas.evaluate.request.v3"
        // 58 20 04*32             text_execution
        // 58 20 05*32             execution_environment
        // 58 20 06*32             nonce
        // 01                      runner key kind
        // 58 21 <33>              runner key bytes
        // 00                      assurance = ProducerSigned
        // 01                      retain = true
        assert_eq!(
            hex,
            concat!(
                "88",
                "781a",
                "68656c6c61732e6576616c756174652e726571756573742e7633",
                "5820",
                "0404040404040404040404040404040404040404040404040404040404040404",
                "5820",
                "0505050505050505050505050505050505050505050505050505050505050505",
                "5820",
                "0606060606060606060606060606060606060606060606060606060606060606",
                "01",
                "5821",
                "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
                "00",
                "01",
            )
        );
        assert_eq!(
            RequestCommitment::from_canonical_bytes(&bytes),
            Evaluate::commit_request(&request)
        );
    }

    #[test]
    fn request_commitment_binds_runner_key() {
        let text_execution = Digest::from_bytes([4; 32]);
        let first = EvaluateRequest {
            text_execution,
            runner_public_key: key(1),
            execution_environment: ContentId::from_bytes([5; 32]),
            nonce: [6; 32],
            assurance: Assurance::ProducerSigned,
            retain: true,
        };
        let second = EvaluateRequest {
            text_execution,
            runner_public_key: key(2),
            execution_environment: ContentId::from_bytes([5; 32]),
            nonce: [6; 32],
            assurance: Assurance::ProducerSigned,
            retain: true,
        };

        assert_ne!(
            Evaluate::commit_request(&first),
            Evaluate::commit_request(&second)
        );
        let mut third = first.clone();
        third.nonce[0] ^= 1;
        assert_ne!(
            Evaluate::commit_request(&first),
            Evaluate::commit_request(&third)
        );
        let mut fourth = first.clone();
        fourth.assurance = Assurance::AppleAppAttest;
        assert_ne!(
            Evaluate::commit_request(&first),
            Evaluate::commit_request(&fourth)
        );
        let mut fifth = first.clone();
        fifth.retain = false;
        assert_ne!(
            Evaluate::commit_request(&first),
            Evaluate::commit_request(&fifth)
        );
        assert_eq!(
            Evaluate::commit_request(&first).digest().to_string(),
            "f166bb42c7de9a5be0e1daf7a165c8d50241e82b27644b4c50b91bcd8481e4c6"
        );
    }
}
