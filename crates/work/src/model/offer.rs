//! A provider enrollment bound to its signed stake-bond proposal.
use crate::model::grant::records::check_grant_provider;
use crate::model::{
    bundle::WorkChannelSetupBundleV2,
    grant::records::{MAX_OFFER_BYTES, provider_bytes},
    work::xfh,
};
use hellas_auth::{Digest, PublicKey, Signature};
use hellas_kernel::{PayloadHash, Secp256k1Signer, Secp256k1Verifier};
use hellas_rpc::ProviderEnrollmentBundle;
use hellas_rpc::protocol::value::{BoundedCborError, decode_canonical_bounded, encode_bounded};
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
    Setup(#[from] crate::model::bundle::SetupBundleError),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaidOffer {
    #[serde(with = "provider_bytes")]
    pub provider: ProviderEnrollmentBundle,
    #[serde(with = "setup_bytes")]
    pub proposal: WorkChannelSetupBundleV2,
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
        check_grant_provider(&self.provider).map_err(|_| PaidOfferError::Provider)?;
        if self.provider.genesis.statement.producer_public_key
            != PublicKey::Secp256k1(
                self.proposal
                    .bond_terms()
                    .parties
                    .maker()
                    .signer()
                    .to_bytes(),
            )
        {
            return Err(PaidOfferError::Provider);
        }
        Ok(())
    }

    fn digest(&self) -> Result<Digest, PaidOfferError> {
        let bytes = encode_bounded(self, MAX_OFFER_BYTES).map_err(|error| match error {
            BoundedCborError::OutputLimit => PaidOfferError::Size,
            _ => PaidOfferError::Malformed,
        })?;
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
        if key.party_key() != offer.proposal.bond_terms().parties.maker().signer() {
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
        hellas_auth::signature::verify_digest_signature(
            &self.offer.provider.genesis.statement.producer_public_key,
            &self.signature,
            self.offer.digest()?,
        )
        .map_err(|_| PaidOfferError::Signature)
    }

    pub fn encode(&self) -> Result<Vec<u8>, PaidOfferError> {
        let bytes = encode_bounded(self, MAX_OFFER_BYTES).map_err(|error| match error {
            BoundedCborError::OutputLimit => PaidOfferError::Size,
            _ => PaidOfferError::Malformed,
        })?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PaidOfferError> {
        let signed: Self =
            decode_canonical_bounded(bytes, MAX_OFFER_BYTES).map_err(|error| match error {
                BoundedCborError::InputLimit => PaidOfferError::Size,
                _ => PaidOfferError::Malformed,
            })?;
        signed.check()?;
        Ok(signed)
    }
}

mod setup_bytes {
    use super::*;
    pub fn serialize<S: Serializer>(p: &WorkChannelSetupBundleV2, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&p.encode())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<WorkChannelSetupBundleV2, D::Error> {
        WorkChannelSetupBundleV2::decode(&serde_bytes::ByteBuf::deserialize(d)?)
            .map_err(D::Error::custom)
    }
}
