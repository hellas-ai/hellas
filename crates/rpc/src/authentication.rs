//! Bounded canonical session messages. Responses contain an application secret:
//! send them only after authenticating the server on an encrypted connection,
//! never log them, and clear owned receive buffers after decoding.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use hellas_auth::authority::{
    AuthorityId, CredentialId, CredentialSecret, SessionChallenge, UnixMillis,
};
use hellas_auth::{Digest, Signature, hash_tuple};
use hellas_wire::TransportContext;
use zeroize::Zeroizing;

use crate::protocol::value::{CanonicalDecodeError, CanonicalDecoder, DagCborEncoder};

pub const MAX_AUTHENTICATION_MESSAGE_BYTES: usize = 256;
const CHALLENGE: &str = "hellas.auth.session.challenge.v1";
const RESPONSE: &str = "hellas.auth.session.response.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthenticationWireError {
    #[error("authentication message exceeds its byte limit")]
    Bounds,
    #[error("invalid authentication message")]
    Encoding,
    #[error("connection has no authentication binding")]
    BindingUnavailable,
}

impl From<CanonicalDecodeError> for AuthenticationWireError {
    fn from(_: CanonicalDecodeError) -> Self {
        // Decoder diagnostics can contain peer-supplied strings or secret bytes.
        Self::Encoding
    }
}

/// Both peers derive this from the live transport and the negotiated service.
/// Claimed peer IDs cannot substitute for an exporter.
pub fn session_binding(
    context: &TransportContext,
    alpn: &[u8],
) -> Result<Digest, AuthenticationWireError> {
    if alpn.is_empty() || alpn.len() > 255 {
        return Err(AuthenticationWireError::BindingUnavailable);
    }
    let exporter = context
        .open_exporter
        .as_ref()
        .ok_or(AuthenticationWireError::BindingUnavailable)?;
    Ok(hash_tuple(
        "hellas.auth.session.binding.v1",
        &[exporter, alpn],
    ))
}

pub fn encode_challenge(challenge: &SessionChallenge) -> Result<Vec<u8>, AuthenticationWireError> {
    challenge
        .validate()
        .map_err(|_| AuthenticationWireError::Encoding)?;
    let mut out = DagCborEncoder::new();
    out.array(8);
    out.str(CHALLENGE);
    out.bytes(challenge.authority.0.as_bytes());
    out.u64(challenge.generation);
    out.bytes(&challenge.nonce);
    out.bytes(challenge.binding.as_bytes());
    out.u64(challenge.issued_at.0);
    out.u64(challenge.deadline.0);
    out.u64(challenge.session_expires.0);
    Ok(out.into_bytes())
}

pub fn decode_challenge(bytes: &[u8]) -> Result<SessionChallenge, AuthenticationWireError> {
    let mut input = decoder(bytes, CHALLENGE, 8)?;
    let challenge = SessionChallenge {
        authority: AuthorityId(Digest::from_bytes(input.bytes_32()?)),
        generation: input.u64()?,
        nonce: input.bytes_32()?,
        binding: Digest::from_bytes(input.bytes_32()?),
        issued_at: UnixMillis(input.u64()?),
        deadline: UnixMillis(input.u64()?),
        session_expires: UnixMillis(input.u64()?),
    };
    input.finish()?;
    challenge
        .validate()
        .map_err(|_| AuthenticationWireError::Encoding)?;
    Ok(challenge)
}

pub fn encode_response(
    credential: &CredentialSecret,
    signature: &Signature,
) -> Result<Zeroizing<Vec<u8>>, AuthenticationWireError> {
    let Signature::Secp256k1(signature) = signature else {
        return Err(AuthenticationWireError::Encoding);
    };
    let mut out = DagCborEncoder::new();
    out.array(4);
    out.str(RESPONSE);
    out.bytes(&credential.id().0);
    out.bytes(signature);
    out.bytes(&[0; 32]);
    // Finish allocation before inserting the secret, so encoder reallocations
    // never release a plaintext copy. The returned buffer clears itself on drop.
    let mut bytes = Zeroizing::new(out.into_bytes());
    let offset = bytes
        .len()
        .checked_sub(32)
        .ok_or(AuthenticationWireError::Encoding)?;
    bytes
        .get_mut(offset..)
        .ok_or(AuthenticationWireError::Encoding)?
        .copy_from_slice(credential.expose_secret());
    Ok(bytes)
}

pub fn decode_response(
    bytes: &[u8],
) -> Result<(CredentialSecret, Signature), AuthenticationWireError> {
    let mut input = decoder(bytes, RESPONSE, 4)?;
    let id = input
        .bytes()?
        .try_into()
        .map_err(|_| AuthenticationWireError::Encoding)?;
    let signature = input
        .bytes()?
        .try_into()
        .map_err(|_| AuthenticationWireError::Encoding)?;
    let secret: &[u8; 32] = input
        .bytes()?
        .try_into()
        .map_err(|_| AuthenticationWireError::Encoding)?;
    input.finish()?;
    Ok((
        CredentialSecret::from_parts(CredentialId(id), *secret),
        Signature::Secp256k1(signature),
    ))
}

fn decoder<'a>(
    bytes: &'a [u8],
    schema: &str,
    fields: u64,
) -> Result<CanonicalDecoder<'a>, AuthenticationWireError> {
    if bytes.len() > MAX_AUTHENTICATION_MESSAGE_BYTES {
        return Err(AuthenticationWireError::Bounds);
    }
    let mut input = CanonicalDecoder::new(bytes);
    input.array_exact(fields)?;
    input.expect_str(schema)?;
    Ok(input)
}
