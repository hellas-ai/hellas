//! A provider enrollment bound to its signed stake-bond proposal.
use super::{
    value::{canonical_dag_cbor, decode_canonical_dag_cbor},
    work::xfh,
    work_bundle::WorkChannelSetupBundleV1,
};
use crate::{Digest, ProviderEnrollmentBundle, PublicKey, Signature};
use hellas_kernel::{PayloadHash, Secp256k1Signer, Secp256k1Verifier};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

#[derive(Debug, thiserror::Error)]
pub enum PaidOfferError {
    #[error("malformed paid offer")]
    Malformed,
    #[error("paid offer exceeds its size limit")]
    Size,
    #[error("paid offer enrollment differs from the bond provider")]
    Provider,
    #[error("paid offer signature is invalid")]
    Signature,
    #[error(transparent)]
    Setup(#[from] super::work_bundle::SetupBundleError),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaidOffer {
    #[serde(with = "provider_bytes")]
    pub provider: ProviderEnrollmentBundle,
    #[serde(with = "setup_bytes")]
    pub proposal: WorkChannelSetupBundleV1,
    pub addresses: Vec<String>,
}

impl PaidOffer {
    fn check(&self) -> Result<(), PaidOfferError> {
        self.proposal.check(&Secp256k1Verifier::new())?;
        if self.proposal.revision() != 1
            || self.addresses.len() > 16
            || self
                .addresses
                .iter()
                .any(|a| a.len() > 512 || a.parse::<std::net::SocketAddr>().is_err())
        {
            return Err(PaidOfferError::Malformed);
        }
        check_provider(&self.provider)?;
        if self.provider.genesis.statement.producer_public_key
            != PublicKey::Secp256k1(self.proposal.bond_terms().parties.maker().to_bytes())
        {
            return Err(PaidOfferError::Provider);
        }
        Ok(())
    }

    fn digest(&self) -> Result<Digest, PaidOfferError> {
        let bytes = canonical_dag_cbor(self).map_err(|_| PaidOfferError::Malformed)?;
        if bytes.len() > MAX_OFFER_BYTES {
            return Err(PaidOfferError::Size);
        }
        Ok(xfh(b"hellas.work.paid-offer.v1", &[&bytes]))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPaidOffer {
    offer: PaidOffer,
    signature: Signature,
}

impl SignedPaidOffer {
    pub fn sign(offer: PaidOffer, key: &Secp256k1Signer) -> Result<Self, PaidOfferError> {
        offer.check()?;
        if key.party_key() != offer.proposal.bond_terms().parties.maker() {
            return Err(PaidOfferError::Provider);
        }
        let signature = Signature::Secp256k1(
            *key.sign(PayloadHash::from_bytes(*offer.digest()?.as_bytes()))
                .as_bytes(),
        );
        let signed = Self { offer, signature };
        signed.encode()?;
        Ok(signed)
    }

    pub fn offer(&self) -> &PaidOffer {
        &self.offer
    }

    /// Also used after JSON import; deserialization alone never confers trust.
    pub fn check(&self) -> Result<(), PaidOfferError> {
        self.offer.check()?;
        crate::signature::verify_digest_signature(
            &self.offer.provider.genesis.statement.producer_public_key,
            &self.signature,
            self.offer.digest()?,
        )
        .map_err(|_| PaidOfferError::Signature)
    }

    pub fn encode(&self) -> Result<Vec<u8>, PaidOfferError> {
        let bytes = canonical_dag_cbor(self).map_err(|_| PaidOfferError::Malformed)?;
        if bytes.len() > MAX_OFFER_BYTES {
            return Err(PaidOfferError::Size);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PaidOfferError> {
        if bytes.len() > MAX_OFFER_BYTES {
            return Err(PaidOfferError::Size);
        }
        let signed: Self =
            decode_canonical_dag_cbor(bytes).map_err(|_| PaidOfferError::Malformed)?;
        signed.check()?;
        Ok(signed)
    }
}

mod setup_bytes {
    use super::*;
    pub fn serialize<S: Serializer>(p: &WorkChannelSetupBundleV1, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&p.encode())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<WorkChannelSetupBundleV1, D::Error> {
        WorkChannelSetupBundleV1::decode(&serde_bytes::ByteBuf::deserialize(d)?)
            .map_err(D::Error::custom)
    }
}

const MAX_OFFER_BYTES: usize = 256 * 1024;
const MAX_PROVIDER_BYTES: usize = 32 * 1024;
pub fn check_provider(provider: &ProviderEnrollmentBundle) -> Result<(), PaidOfferError> {
    if provider.canonical_bytes().len() > MAX_PROVIDER_BYTES {
        return Err(PaidOfferError::Size);
    }
    let (PublicKey::Secp256k1(key), PublicKey::Ed25519(_)) = (
        provider.genesis.statement.producer_public_key,
        provider.genesis.statement.transport_public_key,
    ) else {
        return Err(PaidOfferError::Provider);
    };
    k256::ecdsa::VerifyingKey::from_sec1_bytes(&key).map_err(|_| PaidOfferError::Provider)?;
    Ok(())
}
mod provider_bytes {
    use super::*;
    pub fn serialize<S: Serializer>(p: &ProviderEnrollmentBundle, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&p.canonical_bytes())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<ProviderEnrollmentBundle, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(d)?;
        if bytes.len() > MAX_PROVIDER_BYTES {
            return Err(D::Error::custom(PaidOfferError::Size));
        }
        let provider =
            ProviderEnrollmentBundle::from_canonical_bytes(&bytes).map_err(D::Error::custom)?;
        check_provider(&provider).map_err(D::Error::custom)?;
        Ok(provider)
    }
}
