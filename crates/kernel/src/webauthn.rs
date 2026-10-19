//! `WebAuthn` verification for [`crate::Auth`] witnesses.
//!
//! The policy is `hellas-webauthn`'s, the one every Hellas consumer shares;
//! this module only maps the kernel wire form onto it. The kernel requires
//! `clientDataJSON.challenge` to encode the canonical payload hash: the open
//! hash for opens, the close payload hash for cooperative closes. The
//! assertion carries its signer's coordinates, and they must name the party
//! key the transaction commits to. `webauthn_data` has no inner length: the
//! authenticator data is its first 37 bytes and `clientDataJSON` the rest.

use hellas_webauthn::{AUTHENTICATOR_DATA_LEN, Assertion, PublicKey, SIGNATURE_LEN};

use crate::{
    MAX_WEBAUTHN_DATA_LENGTH,
    consts::P256_COORDINATE_LENGTH,
    primitive::{Key, PayloadHash},
    tx::WebAuthnAssertion,
};

mod soft_passkey;

/// Deterministic passkey builders and v1 wire fixtures for integration tests.
#[cfg(feature = "test-support")]
pub mod test_support;

pub use hellas_webauthn::Error as WebAuthnError;
pub use soft_passkey::{SoftPasskey, SoftPasskeyError};

// The kernel envelope and the shared verifier must agree on the largest
// assertion, or the kernel would carry assertions nothing can accept.
const _: () = assert!(MAX_WEBAUTHN_DATA_LENGTH == hellas_webauthn::MAX_DATA_LEN);

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
    let signer = PublicKey::from_coordinates(assertion.pub_key_x(), assertion.pub_key_y())?;
    if Key::from_bytes(signer.to_compressed()) != key {
        return Err(WebAuthnError::SignerMismatch);
    }

    let (authenticator_data, client_data_json) = assertion
        .webauthn_data()
        .as_slice()
        .split_at_checked(AUTHENTICATOR_DATA_LEN)
        .ok_or(WebAuthnError::AuthenticatorDataLength)?;
    let mut signature = [0_u8; SIGNATURE_LEN];
    let (r, s) = signature.split_at_mut(P256_COORDINATE_LENGTH);
    r.copy_from_slice(assertion.r());
    s.copy_from_slice(assertion.s());

    hellas_webauthn::verify(
        &Assertion {
            signature: &signature,
            authenticator_data,
            client_data_json,
        },
        &signer,
        hash.as_bytes(),
    )
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
    PublicKey::from_coordinates(pub_key_x, pub_key_y)
        .map(|key| Key::from_bytes(key.to_compressed()))
}
