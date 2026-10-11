//! Real ECDSA verifier over secp256k1.
//!
//! Production callers can use [`Secp256k1Verifier`] to verify close
//! signatures with the canonical Bitcoin curve. The kernel itself remains
//! crypto-agnostic — this module is gated behind the `secp256k1` feature, and
//! the kernel never references it directly.
//!
//! Backed by pure-Rust [`k256`] (the `RustCrypto` sister of the [`p256`]
//! this crate already uses for `WebAuthn`), so it builds on every target —
//! including `wasm32` — without a C toolchain. Signatures are the
//! identical secp256k1 ECDSA bytes libsecp256k1 produces.
//!
//! Compact-form ECDSA signatures are 64 bytes (`r ‖ s`), matching the
//! kernel's [`Sig`] shape. Compressed public keys are 33 bytes, matching
//! [`Key`]. The 32-byte [`PayloadHash`] is interpreted as the pre-hashed
//! message — the verifier does not hash again. Signatures are produced
//! and required in low-`S` normal form, so ECDSA malleability cannot
//! flip an authorization into a second valid witness.
//!
//! # Scope
//!
//! Real ECDSA covers [`SigVerifier`] cleanly: the open authorizations
//! and the cooperative-close signatures used by [`crate::Proof::Mutual`]
//! and the work-payment `Freeze`. Nothing else needs a verifier: every
//! remaining close is decided structurally by the kernel.

use core::fmt;

use k256::FieldBytes;
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};

use crate::primitive::{Key, PayloadHash, Sig};
use crate::tx::Auth;
use crate::verifier::SigVerifier;

/// Failure while constructing an in-memory native signer.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum Secp256k1SignerError {
    /// The supplied bytes are not a valid non-zero secp256k1 secret scalar.
    InvalidSecretScalar,
}

/// In-memory secp256k1 signer for native kernel authorizations.
#[derive(Clone)]
#[allow(
    missing_copy_implementations,
    reason = "secret-bearing signers must not be implicitly copied"
)]
pub struct Secp256k1Signer {
    signing_key: SigningKey,
    party_key: Key,
}

impl fmt::Debug for Secp256k1Signer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Secp256k1Signer")
            .field("party_key", &self.party_key)
            .finish_non_exhaustive()
    }
}

impl Secp256k1Signer {
    /// Derives a native signer from one canonical 32-byte secret scalar.
    ///
    /// # Errors
    ///
    /// Returns [`Secp256k1SignerError::InvalidSecretScalar`] for zero or
    /// out-of-range scalars.
    pub fn from_secret_scalar(secret_scalar: [u8; 32]) -> Result<Self, Secp256k1SignerError> {
        let signing_key = SigningKey::from_bytes(&FieldBytes::from(secret_scalar))
            .map_err(|_| Secp256k1SignerError::InvalidSecretScalar)?;
        let encoded = signing_key.verifying_key().to_sec1_point(true);
        let party_key = Key::from_bytes(
            encoded
                .as_bytes()
                .try_into()
                .map_err(|_| Secp256k1SignerError::InvalidSecretScalar)?,
        );
        Ok(Self {
            signing_key,
            party_key,
        })
    }

    /// Returns the compressed secp256k1 party key controlled by this signer.
    #[must_use]
    pub const fn party_key(&self) -> Key {
        self.party_key
    }

    /// Signs one canonical kernel payload hash into compact low-`S`
    /// `r || s` form.
    ///
    /// # Panics
    ///
    /// Never in practice: deterministic (RFC 6979) ECDSA over a fixed
    /// 32-byte prehash with a validated key has no reachable failure —
    /// the only error paths are a zero `r`/`s`, which RFC 6979 retries
    /// past internally.
    #[must_use]
    pub fn sign(&self, hash: PayloadHash) -> Sig {
        // Deterministic (RFC 6979) ECDSA over a fixed 32-byte prehash
        // with a valid key: the only error paths are a zero `r`/`s`,
        // which RFC 6979 retries past, so this cannot fail in practice.
        #[allow(
            clippy::expect_used,
            reason = "deterministic sign over a valid 32-byte prehash is infallible"
        )]
        let signature: Signature = self
            .signing_key
            .sign_prehash(&hash.to_bytes())
            .expect("deterministic secp256k1 signature over a 32-byte prehash");
        let signature = signature.normalize_s();
        Sig::from_bytes(signature.to_bytes().into())
    }
}

/// Verifier that accepts compact-form secp256k1 ECDSA signatures from
/// compressed public keys, with the close hash interpreted as the
/// pre-hashed message. High-`S` signatures are rejected.
#[derive(Debug, Clone, Copy, Default)]
pub struct Secp256k1Verifier;

impl Secp256k1Verifier {
    /// Creates a new verifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns whether `party_key` encodes a valid compressed secp256k1 point.
    #[must_use]
    pub fn is_valid_key(party_key: Key) -> bool {
        VerifyingKey::from_sec1_bytes(party_key.as_bytes()).is_ok()
    }
}

impl SigVerifier for Secp256k1Verifier {
    fn verify_sig(&self, sig: Sig, party_key: Key, hash: PayloadHash) -> bool {
        let Ok(pk) = VerifyingKey::from_sec1_bytes(party_key.as_bytes()) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(sig.as_bytes()) else {
            return false;
        };
        // Reject malleable high-`S` witnesses: only the low-`S` normal
        // form this crate signs is admissible.
        if signature.normalize_s() != signature {
            return false;
        }
        pk.verify_prehash(&hash.to_bytes(), &signature).is_ok()
    }

    fn verify_auth(&self, auth: &Auth, party_key: Key, hash: PayloadHash) -> bool {
        match auth {
            Auth::Native(sig) => self.verify_sig(*sig, party_key, hash),
            #[cfg(feature = "webauthn")]
            Auth::WebAuthn(assertion) => {
                crate::webauthn::verify_webauthn_assertion(assertion, party_key, hash).is_ok()
            }
            #[cfg(not(feature = "webauthn"))]
            Auth::WebAuthn(_) => false,
        }
    }
}
