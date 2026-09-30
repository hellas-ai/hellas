//! Token-id byte encoding — the execute layer's canonical representation
//! of a token stream (little-endian `u32` per id).
//!
//! Not scheme-specific: the evaluate scheme produces these bytes, executor
//! artifacts round-trip them, and a caller-selected presentation layer may
//! decode them. Lives here rather than in the crate root so the primitive has
//! a named home.

const TOKEN_BYTES_LEN: usize = std::mem::size_of::<u32>();

/// Default generation bound for text presentation.
pub const DEFAULT_MAX_NEW_TOKENS: u32 = 16;

/// Maximum distinct caller-selected stop IDs accepted by one token invocation.
///
/// Catena checks this list during every decode step, so it is a work factor,
/// not merely request metadata.
pub const MAX_STOP_TOKEN_IDS: usize = 256;

/// Put stop IDs in the canonical order used by both the committed policy and
/// the Catena invocation.
pub fn normalize_stop_token_ids(stop_token_ids: &mut Vec<u32>) {
    stop_token_ids.sort_unstable();
    stop_token_ids.dedup();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBytesError {
    len: usize,
}

impl std::fmt::Display for TokenBytesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "token byte payload length {} is not divisible by 4",
            self.len
        )
    }
}

impl std::error::Error for TokenBytesError {}

impl From<TokenBytesError> for hellas_wire::WireStatus {
    fn from(err: TokenBytesError) -> Self {
        hellas_wire::WireStatus::new(hellas_wire::WireCode::InvalidArgument, err.to_string())
    }
}

pub fn encode_token_ids(token_ids: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(token_ids.len() * TOKEN_BYTES_LEN);
    for token_id in token_ids {
        bytes.extend_from_slice(&token_id.to_le_bytes());
    }
    bytes
}

pub fn decode_token_ids(bytes: &[u8]) -> Result<Vec<u32>, TokenBytesError> {
    let (chunks, remainder) = bytes.as_chunks::<TOKEN_BYTES_LEN>();
    if !remainder.is_empty() {
        return Err(TokenBytesError { len: bytes.len() });
    }

    Ok(chunks
        .iter()
        .map(|chunk| u32::from_le_bytes(*chunk))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{TokenBytesError, decode_token_ids, encode_token_ids, normalize_stop_token_ids};

    #[test]
    fn token_ids_round_trip_through_bytes() {
        let token_ids = [1, 42, u32::MAX, 7];
        let encoded = encode_token_ids(&token_ids);
        let decoded = decode_token_ids(&encoded).expect("token bytes should decode");
        assert_eq!(decoded, token_ids);
    }

    #[test]
    fn decode_rejects_partial_token_bytes() {
        let err = decode_token_ids(&[1, 2, 3]).expect_err("partial token bytes must fail");
        assert_eq!(err, TokenBytesError { len: 3 });
    }

    #[test]
    fn stop_token_ids_have_one_canonical_order() {
        let mut tokens = vec![9, 2, 9, 1, 2];
        normalize_stop_token_ids(&mut tokens);
        assert_eq!(tokens, [1, 2, 9]);
    }
}
