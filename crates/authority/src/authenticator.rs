//! Passkey approval supplied by an application or its native authenticator.
use hellas_auth::{
    Digest,
    authority::{AuthorityError, PasskeyAssertion},
};
use hellas_kernel::{
    Auth, MAX_WEBAUTHN_DATA_LENGTH, PayloadHash, SoftPasskey, WebAuthnAssertion, WebAuthnData,
};
pub use hellas_webauthn::PublicKey;

/// One source of passkey assertions for sessions, ownership and kernel spends.
/// The caller binds the challenge before invoking the authenticator. Dropping
/// the returned future cancels approval; a cancelled prompt must not be reused.
#[async_trait::async_trait]
pub trait Authenticator: Send + Sync {
    fn public_key(&self) -> Result<PublicKey, AuthorityError>;
    async fn assert(&self, challenge: Digest) -> Result<PasskeyAssertion, AuthorityError>;
}

#[async_trait::async_trait]
impl Authenticator for SoftPasskey {
    fn public_key(&self) -> Result<PublicKey, AuthorityError> {
        PublicKey::from_sec1(&self.party_key().to_bytes()).map_err(|_| AuthorityError::Credential)
    }

    async fn assert(&self, challenge: Digest) -> Result<PasskeyAssertion, AuthorityError> {
        let envelope = self
            .sign(PayloadHash::from_bytes(*challenge.as_bytes()))
            .map_err(|_| AuthorityError::Credential)?;
        let mut signature = [0; 64];
        let (r, s) = signature.split_at_mut(32);
        r.copy_from_slice(envelope.r());
        s.copy_from_slice(envelope.s());
        PasskeyAssertion::from_envelope(signature, envelope.webauthn_data().as_slice())
    }
}

/// Convert an already-produced assertion into the kernel's bounded envelope.
/// This performs no signing and changes none of the signed bytes.
pub fn kernel_auth(key: &PublicKey, assertion: &PasskeyAssertion) -> Result<Auth, AuthorityError> {
    let mut data = [0; MAX_WEBAUTHN_DATA_LENGTH];
    let len = assertion.authenticator_data().len() + assertion.client_data_json().len();
    if len > data.len() {
        return Err(AuthorityError::Invalid);
    }
    for (out, byte) in data.iter_mut().zip(
        assertion
            .authenticator_data()
            .iter()
            .chain(assertion.client_data_json()),
    ) {
        *out = *byte;
    }
    let mut r = [0; 32];
    let mut s = [0; 32];
    let (rs, ss) = assertion.signature().split_at(32);
    r.copy_from_slice(rs);
    s.copy_from_slice(ss);
    let (x, y) = key.to_coordinates();
    Ok(Auth::webauthn(WebAuthnAssertion::new(
        r,
        s,
        x,
        y,
        WebAuthnData::new(data, len).ok_or(AuthorityError::Invalid)?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_kernel::{Encode, Key, Secp256k1Verifier, SigVerifier};

    #[tokio::test]
    async fn software_assertion_preserves_the_exact_kernel_envelope() {
        let key = SoftPasskey::from_secret_scalar([7; 32]).unwrap();
        let digest = Digest::hash(b"one challenge for all passkey consumers");
        let hash = PayloadHash::from_bytes(*digest.as_bytes());
        let expected = Auth::webauthn(key.sign(hash).unwrap());
        let assertion = key.assert(digest).await.unwrap();
        let public = key.public_key().unwrap();
        let actual = kernel_auth(&public, &assertion).unwrap();
        assert_eq!(actual, expected);
        let mut encoded = vec![0; Auth::MAX_ENCODED_SIZE];
        let mut expected_encoded = vec![0; Auth::MAX_ENCODED_SIZE];
        assert_eq!(
            actual.write_to(&mut encoded),
            expected.write_to(&mut expected_encoded)
        );
        assert_eq!(encoded, expected_encoded);
        let owner = Key::from_bytes(public.to_compressed());
        let verifier = Secp256k1Verifier::new();
        assert!(verifier.verify_auth(&actual, owner, hash));
        assert!(!verifier.verify_auth(&actual, owner, PayloadHash::from_bytes([9; 32])));
        let foreign = SoftPasskey::from_secret_scalar([8; 32]).unwrap();
        assert!(!verifier.verify_auth(&actual, foreign.party_key(), hash));
    }
}
