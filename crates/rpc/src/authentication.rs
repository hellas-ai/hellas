//! Bounded canonical session messages. Responses contain an application secret:
//! send them only after authenticating the server on an encrypted connection,
//! never log them, and clear owned receive buffers after decoding.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use hellas_auth::authority::{
    AuthorityId, CredentialId, CredentialSecret, PasskeyAssertion, SessionChallenge, SessionProof,
    UnixMillis,
};
use hellas_auth::{Digest, hash_tuple};
use hellas_wire::TransportContext;
use zeroize::Zeroizing;

use crate::protocol::value::{CanonicalDecodeError, CanonicalDecoder, DagCborEncoder};

/// A response carries at most one `WebAuthn` assertion; everything else fits in
/// the remaining fixed allowance.
pub const MAX_AUTHENTICATION_MESSAGE_BYTES: usize = 256 + hellas_webauthn::MAX_DATA_LEN;
const CHALLENGE: &str = "hellas.auth.session.challenge.v1";
const RESPONSE: &str = "hellas.auth.session.response.v2";
const PROOF_PASSKEY: u64 = 1;
const PROOF_DAILY: u64 = 2;

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

/// `[schema, credential id, proof, secret]`, where `proof` is
/// `[1, signature, authenticatorData, clientDataJSON]` for a passkey session or
/// `[2, signature]` for a daily one.
pub fn encode_response(
    credential: &CredentialSecret,
    proof: &SessionProof,
) -> Result<Zeroizing<Vec<u8>>, AuthenticationWireError> {
    let mut out = DagCborEncoder::new();
    out.array(4);
    out.str(RESPONSE);
    out.bytes(&credential.id().0);
    match proof {
        SessionProof::Passkey(assertion) => {
            out.array(4);
            out.u64(PROOF_PASSKEY);
            out.bytes(assertion.signature());
            out.bytes(assertion.authenticator_data());
            out.bytes(assertion.client_data_json());
        }
        SessionProof::Daily(signature) => {
            out.array(2);
            out.u64(PROOF_DAILY);
            out.bytes(signature);
        }
    }
    out.bytes(&[0; 32]);
    // Finish allocation before inserting the secret, so encoder reallocations
    // never release a plaintext copy. The returned buffer clears itself on drop.
    let mut bytes = Zeroizing::new(out.into_bytes());
    if bytes.len() > MAX_AUTHENTICATION_MESSAGE_BYTES {
        return Err(AuthenticationWireError::Bounds);
    }
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
) -> Result<(CredentialSecret, SessionProof), AuthenticationWireError> {
    let mut input = decoder(bytes, RESPONSE, 4)?;
    let id = input
        .bytes()?
        .try_into()
        .map_err(|_| AuthenticationWireError::Encoding)?;
    let fields = input.array_len()?;
    let proof = match (fields, input.u64()?) {
        (4, PROOF_PASSKEY) => {
            let signature = signature(&mut input)?;
            let authenticator_data = input.bytes()?.to_vec();
            let client_data_json = input.bytes()?.to_vec();
            SessionProof::Passkey(
                PasskeyAssertion::new(signature, authenticator_data, client_data_json)
                    .map_err(|_| AuthenticationWireError::Encoding)?,
            )
        }
        (2, PROOF_DAILY) => SessionProof::Daily(signature(&mut input)?),
        _ => return Err(AuthenticationWireError::Encoding),
    };
    let secret: &[u8; 32] = input
        .bytes()?
        .try_into()
        .map_err(|_| AuthenticationWireError::Encoding)?;
    input.finish()?;
    Ok((
        CredentialSecret::from_parts(CredentialId(id), *secret),
        proof,
    ))
}

fn signature(input: &mut CanonicalDecoder<'_>) -> Result<[u8; 64], AuthenticationWireError> {
    input
        .bytes()?
        .try_into()
        .map_err(|_| AuthenticationWireError::Encoding)
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

#[cfg(test)]
mod tests;
