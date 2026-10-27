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

/// Bind offer allocation to the client key and this exact transport connection.
pub fn request_digest(
    network: hellas_kernel::NetworkId,
    provider: hellas_rpc::ContentId,
    request: &hellas_rpc::pb::work::RequestOfferRequest,
    exporter: &[u8; 32],
) -> Digest {
    let coins: Vec<_> = request
        .funding_coins
        .iter()
        .flat_map(|coin| coin.iter().copied())
        .collect();
    hellas_auth::hash_tuple(
        "hellas.work.offer-request.v1",
        &[
            network.as_str().as_bytes(),
            provider.as_bytes(),
            &request.client_principal,
            &request.client_key,
            &coins,
            exporter,
        ],
    )
}

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
    pub policy: crate::model::setup::ProviderChannelPolicy,
    pub omission_bond: u64,
    #[serde(with = "funding_bytes")]
    pub payment_funding: hellas_kernel::Funding,
    pub addresses: Vec<String>,
}

impl PaidOffer {
    fn check(&self) -> Result<(), PaidOfferError> {
        self.proposal.check(&Secp256k1Verifier::new())?;
        let payment = &self.payment_funding;
        if payment.maker().is_empty()
            || !payment.taker().is_empty()
            || payment
                .maker()
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != payment.maker().len()
            || payment.maker().iter().any(|coin| {
                self.proposal
                    .bond_funding()
                    .maker()
                    .iter()
                    .chain(self.proposal.bond_funding().taker().iter())
                    .any(|stake| stake == coin)
            })
        {
            return Err(PaidOfferError::Malformed);
        }
        self.policy
            .work_policy
            .check()
            .map_err(|_| PaidOfferError::Malformed)?;
        self.policy
            .payment_policy
            .check()
            .map_err(|_| PaidOfferError::Malformed)?;
        if self.policy.network != self.proposal.network()
            || self.policy.payment_policy.fixed_price > self.proposal.bond_terms().max_job_price
        {
            return Err(PaidOfferError::Malformed);
        }
        let settlement = hellas_kernel::work_payment_settlement(
            self.policy.expected_payment_values,
            self.omission_bond,
        )
        .ok_or(PaidOfferError::Malformed)?;
        crate::model::setup::check_collateral(self.omission_bond, settlement.capacity())
            .map_err(|_| PaidOfferError::Malformed)?;
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

mod funding_bytes {
    use super::*;
    pub fn serialize<S: Serializer>(
        funding: &hellas_kernel::Funding,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let bytes = crate::model::work::encode_kernel(funding);
        s.serialize_bytes(&bytes)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<hellas_kernel::Funding, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(d)?;
        let mut cursor = hellas_kernel::Cursor::new(&bytes);
        let funding = cursor
            .field()
            .ok_or_else(|| D::Error::custom("invalid payment funding"))?;
        if !cursor.is_empty() {
            return Err(D::Error::custom("trailing payment funding bytes"));
        }
        Ok(funding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::pb::work::RequestOfferRequest;
    #[test]
    fn offer_requests_bind_every_field_network_provider_and_live_exporter() {
        let key = Secp256k1Signer::from_secret_scalar([0x21; 32]).unwrap();
        let network = hellas_kernel::NetworkId::new("offer-request-test").unwrap();
        let provider = hellas_rpc::ContentId::from_bytes([9; 32]);
        let exporter = [8; 32];
        let mut original = RequestOfferRequest {
            client_principal: hellas_auth::test_support::actors::FRIEND
                .principal()
                .as_bytes()
                .to_vec(),
            client_key: key.party_key().to_bytes().to_vec(),
            funding_coins: vec![vec![1; 32], vec![2; 32]],
            signature: vec![],
        };
        let digest = request_digest(network, provider, &original, &exporter);
        original.signature = key
            .sign(PayloadHash::from_bytes(*digest.as_bytes()))
            .as_bytes()
            .to_vec();
        let signature = Signature::Secp256k1(original.signature.as_slice().try_into().unwrap());
        let verify = |request: &RequestOfferRequest, network, provider, exporter| {
            hellas_auth::signature::verify_digest_signature(
                &hellas_auth::PublicKey::Secp256k1(key.party_key().to_bytes()),
                &signature,
                request_digest(network, provider, request, exporter),
            )
        };
        verify(&original, network, provider, &exporter).unwrap();
        for field in 0..4 {
            let mut changed = original.clone();
            match field {
                0 => {
                    changed.client_principal = hellas_auth::test_support::actors::ROOT
                        .principal()
                        .as_bytes()
                        .to_vec()
                }
                1 => {
                    changed.client_key = Secp256k1Signer::from_secret_scalar([0x22; 32])
                        .unwrap()
                        .party_key()
                        .to_bytes()
                        .to_vec()
                }
                2 => changed.funding_coins[0][0] ^= 1,
                _ => changed.funding_coins.swap(0, 1),
            }
            assert!(
                verify(&changed, network, provider, &exporter).is_err(),
                "signed field {field}"
            );
        }
        assert!(
            verify(
                &original,
                hellas_kernel::NetworkId::new("another-network").unwrap(),
                provider,
                &exporter
            )
            .is_err()
        );
        assert!(
            verify(
                &original,
                network,
                hellas_rpc::ContentId::from_bytes([7; 32]),
                &exporter
            )
            .is_err()
        );
        assert!(verify(&original, network, provider, &[6; 32]).is_err());
    }
}
