//! One test per policy rule. The `clientDataJSON` grammar has its own
//! tests beside the parser; the kernel's named vectors cover the rest.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test fixtures are known-good and in bounds"
)]

use p256::ecdsa::{Signature as P256Signature, SigningKey, signature::hazmat::PrehashSigner};

use super::*;

const CHALLENGE: [u8; CHALLENGE_LEN] = [0x42; CHALLENGE_LEN];

/// The P-256 group order, big-endian.
const P256_N: [u8; COORDINATE_LEN] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

struct Signed {
    key: PublicKey,
    signature: [u8; SIGNATURE_LEN],
    authenticator_data: [u8; AUTHENTICATOR_DATA_LEN],
    client_data_json: [u8; MAX_CLIENT_DATA_JSON_LEN + 1],
    client_data_len: usize,
}

impl Signed {
    /// Signs well-formed client data over `challenge`, followed by
    /// `padding` bytes of JSON whitespace, with the given flags.
    fn new(flags: u8, challenge: &[u8; CHALLENGE_LEN], padding: usize) -> Self {
        let signing_key = SigningKey::from_slice(&[7; COORDINATE_LEN]).expect("valid scalar");
        let key = PublicKey(*signing_key.verifying_key());

        let mut authenticator_data = [0_u8; AUTHENTICATOR_DATA_LEN];
        authenticator_data[FLAGS_OFFSET] = flags;

        let mut client_data_json = [b' '; MAX_CLIENT_DATA_JSON_LEN + 1];
        let mut len = 0;
        for part in [
            b"{\"type\":\"webauthn.get\",\"challenge\":\"".as_slice(),
            encode_challenge(challenge).as_slice(),
            b"\"}".as_slice(),
        ] {
            client_data_json[len..len + part.len()].copy_from_slice(part);
            len += part.len();
        }
        let client_data_len = len + padding;

        let signature: P256Signature = signing_key
            .sign_prehash(&signed_digest(
                &authenticator_data,
                &client_data_json[..client_data_len],
            ))
            .expect("prehash signing succeeds");
        let signature: [u8; SIGNATURE_LEN] = signature.normalize_s().to_bytes().into();

        Self {
            key,
            signature,
            authenticator_data,
            client_data_json,
            client_data_len,
        }
    }

    fn verify(&self, challenge: &[u8; CHALLENGE_LEN]) -> Result<(), Error> {
        verify(
            &Assertion {
                signature: &self.signature,
                authenticator_data: &self.authenticator_data,
                client_data_json: &self.client_data_json[..self.client_data_len],
            },
            &self.key,
            challenge,
        )
    }
}

#[test]
fn high_s_is_rejected() {
    let mut signed = Signed::new(FLAG_UP, &CHALLENGE, 0);
    assert_eq!(signed.verify(&CHALLENGE), Ok(()));

    // `n - s` is the same signature in its other encoding.
    let (_, s) = signed.signature.split_at_mut(COORDINATE_LEN);
    let mut borrow = 0_i16;
    for (byte, n) in s.iter_mut().zip(P256_N).rev() {
        let difference = i16::from(n) - i16::from(*byte) - borrow;
        borrow = i16::from(difference < 0);
        *byte = u8::try_from(difference.rem_euclid(256)).expect("reduced into a byte");
    }
    assert_eq!(signed.verify(&CHALLENGE), Err(Error::HighS));

    // Exactly half the order is still low.
    signed.signature[COORDINATE_LEN..].copy_from_slice(&P256_N_HALF);
    assert_eq!(signed.verify(&CHALLENGE), Err(Error::InvalidSignature));
}

#[test]
fn user_verification_alone_is_accepted() {
    assert_eq!(
        Signed::new(FLAG_UV, &CHALLENGE, 0).verify(&CHALLENGE),
        Ok(())
    );
}

#[test]
fn attested_data_and_extensions_are_rejected() {
    assert_eq!(
        Signed::new(FLAG_UP | FLAG_AT, &CHALLENGE, 0).verify(&CHALLENGE),
        Err(Error::AttestedCredentialDataUnsupported),
    );
    assert_eq!(
        Signed::new(FLAG_UP | FLAG_ED, &CHALLENGE, 0).verify(&CHALLENGE),
        Err(Error::ExtensionsUnsupported),
    );
}

#[test]
fn wrong_challenge_is_rejected() {
    assert_eq!(
        Signed::new(FLAG_UP, &CHALLENGE, 0).verify(&[0x43; CHALLENGE_LEN]),
        Err(Error::InvalidChallenge),
    );
}

#[test]
fn oversized_input_is_rejected() {
    // The long client data is validly signed and well-formed, so only its
    // length can reject it; the length checks run before anything is read.
    let base = Signed::new(FLAG_UP, &CHALLENGE, 0);
    let padding = MAX_CLIENT_DATA_JSON_LEN + 1 - base.client_data_len;
    let long_client_data = Signed::new(FLAG_UP, &CHALLENGE, padding);
    assert_eq!(
        long_client_data.verify(&CHALLENGE),
        Err(Error::ClientDataJsonTooLong),
    );

    let mut long_authenticator_data = [0_u8; AUTHENTICATOR_DATA_LEN + 1];
    long_authenticator_data[..AUTHENTICATOR_DATA_LEN].copy_from_slice(&base.authenticator_data);
    assert_eq!(
        verify(
            &Assertion {
                signature: &base.signature,
                authenticator_data: &long_authenticator_data,
                client_data_json: &base.client_data_json[..base.client_data_len],
            },
            &base.key,
            &CHALLENGE,
        ),
        Err(Error::AuthenticatorDataLength),
    );
}
