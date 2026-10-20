//! In-memory software producer for the kernel `WebAuthn` v1 envelope.
//!
//! This is a development integration facility, not production key custody:
//! [`SoftPasskey`] retains its secret scalar in process memory.

use core::fmt;

use hellas_webauthn::{AUTHENTICATOR_DATA_LEN, FLAG_UP, encode_challenge, signed_digest};
use p256::ecdsa::{Signature as P256Signature, SigningKey, signature::hazmat::PrehashSigner};

use super::p256_key;
use crate::{
    Key, List, MAX_WEBAUTHN_DATA_LENGTH, PayloadHash, WebAuthnAssertion,
    consts::P256_COORDINATE_LENGTH,
};

pub(super) const SOFT_PASSKEY_ORIGIN: &[u8] = b"https://wallet.example.invalid";
pub(super) const SOFT_PASSKEY_RP_ID_HASH: [u8; P256_COORDINATE_LENGTH] =
    [0xaa; P256_COORDINATE_LENGTH];

/// Failure while constructing or using an in-memory software passkey.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum SoftPasskeyError {
    /// The supplied bytes are not a valid non-zero P-256 secret scalar.
    InvalidSecretScalar,
    /// P-256 did not expose or accept the derived affine coordinates.
    InvalidPublicKey,
    /// Deterministic P-256 prehash signing failed.
    SigningFailed,
    /// The assertion exceeded [`MAX_WEBAUTHN_DATA_LENGTH`].
    AssertionTooLarge,
}

/// In-memory deterministic P-256 signer for the kernel `WebAuthn` envelope.
#[derive(Clone)]
pub struct SoftPasskey {
    signing_key: SigningKey,
    party_key: Key,
    pub_key_x: [u8; P256_COORDINATE_LENGTH],
    pub_key_y: [u8; P256_COORDINATE_LENGTH],
}

impl fmt::Debug for SoftPasskey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SoftPasskey")
            .field("party_key", &self.party_key)
            .finish_non_exhaustive()
    }
}

impl SoftPasskey {
    /// Derives a software passkey from one canonical 32-byte secret scalar.
    ///
    /// # Errors
    ///
    /// Returns [`SoftPasskeyError::InvalidSecretScalar`] for zero or
    /// out-of-range scalars, or [`SoftPasskeyError::InvalidPublicKey`] if the
    /// derived coordinates cannot be represented as a kernel party key.
    pub fn from_secret_scalar(
        secret_scalar: [u8; P256_COORDINATE_LENGTH],
    ) -> Result<Self, SoftPasskeyError> {
        let signing_key = SigningKey::from_slice(&secret_scalar)
            .map_err(|_| SoftPasskeyError::InvalidSecretScalar)?;
        let point = signing_key.verifying_key().to_sec1_point(false);
        let x = point.x().ok_or(SoftPasskeyError::InvalidPublicKey)?;
        let y = point.y().ok_or(SoftPasskeyError::InvalidPublicKey)?;
        let mut pub_key_x = [0_u8; P256_COORDINATE_LENGTH];
        let mut pub_key_y = [0_u8; P256_COORDINATE_LENGTH];
        pub_key_x.copy_from_slice(x);
        pub_key_y.copy_from_slice(y);
        let party_key =
            p256_key(&pub_key_x, &pub_key_y).map_err(|_| SoftPasskeyError::InvalidPublicKey)?;

        Ok(Self {
            signing_key,
            party_key,
            pub_key_x,
            pub_key_y,
        })
    }

    /// Returns the compressed SEC1 party key controlled by this passkey.
    #[must_use]
    pub const fn party_key(&self) -> Key {
        self.party_key
    }

    /// Returns the P-256 public x-coordinate.
    #[must_use]
    pub const fn pub_key_x(&self) -> &[u8; P256_COORDINATE_LENGTH] {
        &self.pub_key_x
    }

    /// Returns the P-256 public y-coordinate.
    #[must_use]
    pub const fn pub_key_y(&self) -> &[u8; P256_COORDINATE_LENGTH] {
        &self.pub_key_y
    }

    /// Signs `hash` into the canonical v1 assertion envelope.
    ///
    /// The generated authenticator data uses a deterministic ignored
    /// `rpIdHash`, sets `UP`, clears `UV`, `AT`, and `ED`, and uses a zero
    /// signature counter. The client data includes a fixed development origin
    /// and a `false` `crossOrigin` member; neither affects verifier policy.
    ///
    /// # Errors
    ///
    /// Returns [`SoftPasskeyError`] if signing fails or the bounded assertion
    /// cannot be assembled.
    pub fn sign(&self, hash: PayloadHash) -> Result<WebAuthnAssertion, SoftPasskeyError> {
        build_assertion(self, hash)
    }
}

fn build_assertion(
    passkey: &SoftPasskey,
    challenge_hash: PayloadHash,
) -> Result<WebAuthnAssertion, SoftPasskeyError> {
    let mut data = [0_u8; MAX_WEBAUTHN_DATA_LENGTH];
    let mut len = 0;
    append(&mut data, &mut len, &SOFT_PASSKEY_RP_ID_HASH)?;
    append(&mut data, &mut len, &[FLAG_UP])?;
    append(&mut data, &mut len, &[0; 4])?;
    if len != AUTHENTICATOR_DATA_LEN {
        return Err(SoftPasskeyError::AssertionTooLarge);
    }

    append(
        &mut data,
        &mut len,
        b"{\"type\":\"webauthn.get\",\"challenge\":\"",
    )?;
    append(
        &mut data,
        &mut len,
        &encode_challenge(challenge_hash.as_bytes()),
    )?;
    append(&mut data, &mut len, b"\",\"origin\":\"")?;
    append(&mut data, &mut len, SOFT_PASSKEY_ORIGIN)?;
    append(&mut data, &mut len, b"\",\"crossOrigin\":false}")?;

    sign_assertion_data(passkey, data, len)
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "the owned bounded buffer moves directly into the no-alloc List"
)]
pub(super) fn sign_assertion_data(
    passkey: &SoftPasskey,
    data: [u8; MAX_WEBAUTHN_DATA_LENGTH],
    len: usize,
) -> Result<WebAuthnAssertion, SoftPasskeyError> {
    let auth_data = data
        .get(..AUTHENTICATOR_DATA_LEN)
        .ok_or(SoftPasskeyError::AssertionTooLarge)?;
    let client_data_json = data
        .get(AUTHENTICATOR_DATA_LEN..len)
        .ok_or(SoftPasskeyError::AssertionTooLarge)?;
    let signature: P256Signature = passkey
        .signing_key
        .sign_prehash(&signed_digest(auth_data, client_data_json))
        .map_err(|_| SoftPasskeyError::SigningFailed)?;
    let signature = signature.normalize_s();
    let signature_bytes = signature.to_bytes();
    let (r_bytes, s_bytes) = signature_bytes.split_at(P256_COORDINATE_LENGTH);
    let mut r = [0_u8; P256_COORDINATE_LENGTH];
    let mut s = [0_u8; P256_COORDINATE_LENGTH];
    r.copy_from_slice(r_bytes);
    s.copy_from_slice(s_bytes);

    let webauthn_data = List::new(data, len).ok_or(SoftPasskeyError::AssertionTooLarge)?;
    Ok(WebAuthnAssertion::new(
        r,
        s,
        passkey.pub_key_x,
        passkey.pub_key_y,
        webauthn_data,
    ))
}

pub(super) fn append(
    buf: &mut [u8],
    len: &mut usize,
    bytes: &[u8],
) -> Result<(), SoftPasskeyError> {
    let end = len
        .checked_add(bytes.len())
        .ok_or(SoftPasskeyError::AssertionTooLarge)?;
    let destination = buf
        .get_mut(*len..end)
        .ok_or(SoftPasskeyError::AssertionTooLarge)?;
    destination.copy_from_slice(bytes);
    *len = end;
    Ok(())
}
