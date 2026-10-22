//! The one `WebAuthn` assertion verifier, shared by the kernel, the chain and
//! auth.
//!
//! An assertion proves that the holder of a P-256 passkey approved one
//! 32-byte challenge: a transaction hash, a session digest, whatever the
//! caller bound. Every consumer verifies through [`verify`], so there is one
//! policy and no consumer can quietly run a weaker or a stricter one. The
//! policy has no knobs for the same reason.
//!
//! It follows Tempo's protocol rule.
//!
//! **Checked:** `clientDataJSON.type` is `webauthn.get`;
//! `clientDataJSON.challenge` is the caller's challenge in unpadded
//! base64url; the authenticator set user presence (UP) or user verification
//! (UV); attested credential data (AT) and extensions (ED) are absent;
//! authenticator data and `clientDataJSON` are bounded; and the P-256
//! signature over `authenticatorData || SHA-256(clientDataJSON)` verifies
//! under the caller's key with a low `s`.
//!
//! **Not checked:** the `rpIdHash` and the `origin`. They defend against
//! phishing on the client, where the browser or operating system lets a
//! domain request only its own passkeys. What makes an assertion
//! non-replayable is the challenge binding, so pinning a relying party in
//! the protocol would add nothing and weld it to one web domain. Both remain
//! signed; they are simply not policy. The signature counter is not tracked
//! either: a verifier here holds no per-credential state.
//!
//! Low `s` is required because the compact signature is part of what
//! consensus commits to: accepting both `s` and `n - s` would give every
//! assertion two encodings. Authenticators return DER with either parity,
//! so signers normalise; [`signature_from_der`] (feature `der`) does it.

#![no_std]

mod client_data;

use p256::{
    Sec1Point,
    ecdsa::{Signature as P256Signature, VerifyingKey, signature::hazmat::PrehashVerifier},
};
use sha2::{Digest as _, Sha256};

pub use client_data::{CHALLENGE_LEN, ENCODED_CHALLENGE_LEN, encode_challenge};

/// Length of the authenticator data an assertion carries.
///
/// The base form is 37 bytes: `rpIdHash` (32), flags (1) and signature
/// counter (4). Anything beyond it is attested credential data or
/// extensions, both of which the policy rejects, so an accepted assertion
/// has exactly this many.
pub const AUTHENTICATOR_DATA_LEN: usize = 37;

/// Largest authenticator data plus `clientDataJSON` an assertion may carry.
///
/// This is the kernel's `WebAuthnData` bound, the largest envelope any
/// consumer carries today.
pub const MAX_DATA_LEN: usize = 2048;

/// Largest `clientDataJSON` an assertion may carry.
pub const MAX_CLIENT_DATA_JSON_LEN: usize = MAX_DATA_LEN - AUTHENTICATOR_DATA_LEN;

/// Length of a compact `r || s` signature.
pub const SIGNATURE_LEN: usize = 64;

/// Length of a P-256 public key coordinate or signature scalar.
pub const COORDINATE_LEN: usize = 32;

/// Length of a compressed SEC1 P-256 public key.
pub const COMPRESSED_KEY_LEN: usize = 33;

/// Authenticator-data flag: the user was present.
pub const FLAG_UP: u8 = 0x01;
/// Authenticator-data flag: the user was verified (PIN, biometric).
pub const FLAG_UV: u8 = 0x04;
/// Authenticator-data flag: attested credential data follows.
pub const FLAG_AT: u8 = 0x40;
/// Authenticator-data flag: extension data follows.
pub const FLAG_ED: u8 = 0x80;

const FLAGS_OFFSET: usize = 32;

const P256_N_HALF: [u8; COORDINATE_LEN] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// Reason a `WebAuthn` assertion failed verification.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum Error {
    /// The authenticator data is not exactly [`AUTHENTICATOR_DATA_LEN`]
    /// bytes.
    AuthenticatorDataLength,
    /// The `clientDataJSON` exceeds [`MAX_CLIENT_DATA_JSON_LEN`].
    ClientDataJsonTooLong,
    /// Neither the user-presence nor user-verification flag is set.
    MissingUserPresence,
    /// The authenticator data carries attested credential data.
    AttestedCredentialDataUnsupported,
    /// The authenticator data carries extension data.
    ExtensionsUnsupported,
    /// `clientDataJSON` is not accepted by the strict parser.
    InvalidClientDataJson,
    /// `clientDataJSON.type` is not `webauthn.get`.
    InvalidClientDataType,
    /// `clientDataJSON.challenge` is not the expected challenge.
    InvalidChallenge,
    /// `clientDataJSON` is missing a required top-level field.
    MissingClientDataField,
    /// `clientDataJSON` repeats a required top-level field.
    DuplicateClientDataField,
    /// The bytes do not encode a valid P-256 public key.
    InvalidPublicKey,
    /// An envelope that carries its signer's key next to the signature
    /// named a key other than the one the caller expected.
    SignerMismatch,
    /// The signature's `s` is above half the group order.
    HighS,
    /// The signature is malformed or does not verify.
    InvalidSignature,
}

/// A P-256 public key an assertion is verified under.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Builds a key from its affine coordinates, the form `WebAuthn`
    /// credentials expose.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if the point is not on the curve.
    pub fn from_coordinates(
        x: &[u8; COORDINATE_LEN],
        y: &[u8; COORDINATE_LEN],
    ) -> Result<Self, Error> {
        let mut encoded = [0_u8; 1 + 2 * COORDINATE_LEN];
        let (tag, coordinates) = encoded.split_at_mut(1);
        tag.fill(0x04);
        let (xs, ys) = coordinates.split_at_mut(COORDINATE_LEN);
        xs.copy_from_slice(x);
        ys.copy_from_slice(y);
        let point = Sec1Point::from_bytes(encoded).map_err(|_| Error::InvalidPublicKey)?;
        VerifyingKey::from_sec1_point(&point)
            .map(Self)
            .map_err(|_| Error::InvalidPublicKey)
    }

    /// Builds a key from a compressed or uncompressed SEC1 encoding.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if the bytes are not a valid
    /// point encoding.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, Error> {
        VerifyingKey::from_sec1_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidPublicKey)
    }

    /// Returns the affine coordinates used by the kernel assertion envelope.
    #[must_use]
    pub fn to_coordinates(&self) -> ([u8; COORDINATE_LEN], [u8; COORDINATE_LEN]) {
        let point = self.0.to_sec1_point(false);
        let mut x = [0; COORDINATE_LEN];
        let mut y = [0; COORDINATE_LEN];
        for (dst, src) in x
            .iter_mut()
            .chain(y.iter_mut())
            .zip(point.as_bytes().iter().skip(1))
        {
            *dst = *src;
        }
        (x, y)
    }

    /// Returns the compressed SEC1 encoding.
    #[must_use]
    pub fn to_compressed(&self) -> [u8; COMPRESSED_KEY_LEN] {
        let point = self.0.to_sec1_point(true);
        let mut out = [0_u8; COMPRESSED_KEY_LEN];
        // A compressed P-256 point is always 33 bytes, so the copy is exact.
        for (dst, src) in out.iter_mut().zip(point.as_bytes()) {
            *dst = *src;
        }
        out
    }
}

/// The parts of an assertion the verifier reads.
///
/// Envelopes differ between consumers (the kernel concatenates the two data
/// fields, the chain keeps them apart), so this borrows rather than owns.
#[derive(Debug, Clone, Copy)]
pub struct Assertion<'a> {
    /// Compact `r || s` signature.
    pub signature: &'a [u8; SIGNATURE_LEN],
    /// The authenticator data, as the authenticator returned it.
    pub authenticator_data: &'a [u8],
    /// The `clientDataJSON`, as the client returned it.
    pub client_data_json: &'a [u8],
}

/// Verifies that `assertion` approves `challenge` under `key`.
///
/// The policy is described in the crate documentation.
///
/// # Errors
///
/// Returns the first [`Error`] the assertion violates. Checks run in a fixed
/// order (sizes, flags, `clientDataJSON`, `s`, signature), so a given
/// assertion always fails with the same error.
pub fn verify(
    assertion: &Assertion<'_>,
    key: &PublicKey,
    challenge: &[u8; CHALLENGE_LEN],
) -> Result<(), Error> {
    let authenticator_data = assertion.authenticator_data;
    let client_data_json = assertion.client_data_json;
    if authenticator_data.len() != AUTHENTICATOR_DATA_LEN {
        return Err(Error::AuthenticatorDataLength);
    }
    if client_data_json.len() > MAX_CLIENT_DATA_JSON_LEN {
        return Err(Error::ClientDataJsonTooLong);
    }

    let flags = authenticator_data
        .get(FLAGS_OFFSET)
        .copied()
        .ok_or(Error::AuthenticatorDataLength)?;
    if flags & (FLAG_UP | FLAG_UV) == 0 {
        return Err(Error::MissingUserPresence);
    }
    if flags & FLAG_AT != 0 {
        return Err(Error::AttestedCredentialDataUnsupported);
    }
    if flags & FLAG_ED != 0 {
        return Err(Error::ExtensionsUnsupported);
    }

    client_data::validate(client_data_json, &encode_challenge(challenge))?;

    let (_, s) = assertion.signature.split_at(COORDINATE_LEN);
    if s > P256_N_HALF.as_slice() {
        return Err(Error::HighS);
    }
    let signature =
        P256Signature::from_slice(assertion.signature).map_err(|_| Error::InvalidSignature)?;
    key.0
        .verify_prehash(
            &signed_digest(authenticator_data, client_data_json),
            &signature,
        )
        .map_err(|_| Error::InvalidSignature)
}

/// Returns the digest an authenticator signs:
/// `SHA-256(authenticatorData || SHA-256(clientDataJSON))`.
///
/// Software signers sign this as a prehash.
#[must_use]
pub fn signed_digest(authenticator_data: &[u8], client_data_json: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(authenticator_data);
    hasher.update(Sha256::digest(client_data_json));
    hasher.finalize().into()
}

/// Converts the DER signature an authenticator returns into the compact,
/// low-`s` form [`verify`] accepts.
///
/// # Errors
///
/// Returns [`Error::InvalidSignature`] if `der` is not a DER-encoded P-256
/// signature.
#[cfg(feature = "der")]
pub fn signature_from_der(der: &[u8]) -> Result<[u8; SIGNATURE_LEN], Error> {
    let signature = P256Signature::from_der(der).map_err(|_| Error::InvalidSignature)?;
    Ok(signature.normalize_s().to_bytes().into())
}

#[cfg(test)]
mod tests;
