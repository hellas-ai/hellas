//! A principal's `WebAuthn` assertion, as session and ownership proofs carry it.
//! Verification is the shared verifier's policy; this type only bounds sizes.
use super::*;
use crate::Digest;
use hellas_webauthn::{AUTHENTICATOR_DATA_LEN, MAX_CLIENT_DATA_JSON_LEN, SIGNATURE_LEN};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyAssertion {
    signature: [u8; SIGNATURE_LEN],
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
}

impl PasskeyAssertion {
    /// `signature` is the compact low-`s` form; authenticators return DER, which
    /// `hellas_webauthn::signature_from_der` converts.
    pub fn new(
        signature: [u8; SIGNATURE_LEN],
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
    ) -> Result<Self, AuthorityError> {
        if authenticator_data.len() != AUTHENTICATOR_DATA_LEN
            || client_data_json.len() > MAX_CLIENT_DATA_JSON_LEN
        {
            return Err(AuthorityError::Invalid);
        }
        Ok(Self {
            signature,
            authenticator_data,
            client_data_json,
        })
    }

    /// Splits the envelope a software passkey produces: authenticator data
    /// immediately followed by `clientDataJSON`.
    pub fn from_envelope(
        signature: [u8; SIGNATURE_LEN],
        data: &[u8],
    ) -> Result<Self, AuthorityError> {
        let (authenticator_data, client_data_json) = data
            .split_at_checked(AUTHENTICATOR_DATA_LEN)
            .ok_or(AuthorityError::Invalid)?;
        Self::new(
            signature,
            authenticator_data.to_vec(),
            client_data_json.to_vec(),
        )
    }

    pub const fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }
    pub fn authenticator_data(&self) -> &[u8] {
        &self.authenticator_data
    }
    pub fn client_data_json(&self) -> &[u8] {
        &self.client_data_json
    }

    pub(super) fn verify(
        &self,
        principal: PrincipalId,
        challenge: Digest,
    ) -> Result<(), AuthorityError> {
        let key = hellas_webauthn::PublicKey::from_sec1(principal.as_bytes())
            .map_err(|_| AuthorityError::Credential)?;
        hellas_webauthn::verify(
            &hellas_webauthn::Assertion {
                signature: &self.signature,
                authenticator_data: &self.authenticator_data,
                client_data_json: &self.client_data_json,
            },
            &key,
            challenge.as_bytes(),
        )
        .map_err(|_| AuthorityError::Credential)
    }
}

impl Serialize for PasskeyAssertion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (
            serde_bytes::Bytes::new(&self.signature),
            serde_bytes::Bytes::new(&self.authenticator_data),
            serde_bytes::Bytes::new(&self.client_data_json),
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PasskeyAssertion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (signature, authenticator_data, client_data_json): (
            serde_bytes::ByteBuf,
            serde_bytes::ByteBuf,
            serde_bytes::ByteBuf,
        ) = Deserialize::deserialize(deserializer)?;
        let signature = signature
            .as_slice()
            .try_into()
            .map_err(|_| D::Error::custom("assertion signature must be 64 bytes"))?;
        Self::new(
            signature,
            authenticator_data.into_vec(),
            client_data_json.into_vec(),
        )
        .map_err(D::Error::custom)
    }
}
