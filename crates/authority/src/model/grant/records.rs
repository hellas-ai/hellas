//! Private grant terms and signed Offers. Decoding is bounded, canonical and
//! revalidates enrollment; no discovery record confers grant authority.
use super::{budget::*, *};
use hellas_auth::authority::ContactCard;
use hellas_auth::{ProducerSigningKey, PublicKey, Signature};
use hellas_channel::model::profile::WorkPolicy;
use hellas_kernel::NetworkId;
use hellas_rpc::protocol::value::{BoundedCborError, canonical_dag_cbor, decode_canonical_bounded};
use hellas_rpc::{
    PlatformCredential, PlatformEnrollment, ProviderEnrollmentBundle, RootKind, RootProof,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::num::NonZeroU64;

pub use hellas_channel::model::grant::records::{
    GrantError, MAX_ENROLLMENT_BYTES, MAX_OFFER_BYTES, check_grant_provider, grant_producer,
    grant_transport, network, provider_bytes,
};

pub const MAX_WORK_POLICIES: usize = 16;

pub const MAX_CONTACT_CARD_BYTES: usize = 4 * 1024;

/// A node's self-attested enrollment, as an operator pins it to reach that
/// node: a software root signs its node and transport keys. This is machine
/// identity, never a principal and never Work authorization.
pub fn decode_enrollment(bytes: &[u8]) -> Result<ProviderEnrollmentBundle, GrantError> {
    if bytes.len() > MAX_ENROLLMENT_BYTES {
        return Err(GrantError::Malformed);
    }
    let bundle =
        ProviderEnrollmentBundle::from_canonical_bytes(bytes).map_err(|_| GrantError::Malformed)?;
    verify_software_enrollment(&bundle)?;
    Ok(bundle)
}
pub fn verify_software_enrollment(provider: &ProviderEnrollmentBundle) -> Result<(), GrantError> {
    check_grant_provider(provider)?;
    let statement = &provider.genesis.statement;
    let RootProof::Software(signature) = &provider.genesis.root_proof else {
        return Err(GrantError::UnsupportedRoot);
    };
    if statement.root_kind != RootKind::Software
        || provider.platform != PlatformEnrollment::Absent
        || statement.platform_credential != PlatformCredential::Absent
    {
        return Err(GrantError::UnsupportedRoot);
    }
    hellas_auth::signature::verify_digest_signature(
        &statement.root_public_key,
        signature,
        Digest::hash(&statement.canonical_bytes()),
    )
    .map_err(|_| GrantError::Signature)
}
/// Canonical, bounded contact card bytes.
pub fn encode_contact_card(card: &ContactCard) -> Result<Vec<u8>, GrantError> {
    let bytes = canonical_dag_cbor(card).map_err(|_| GrantError::Malformed)?;
    if bytes.len() > MAX_CONTACT_CARD_BYTES {
        return Err(GrantError::Malformed);
    }
    Ok(bytes)
}
/// A canonical card whose passkey assertion verifies.
pub fn decode_contact_card(bytes: &[u8]) -> Result<ContactCard, GrantError> {
    decode_canonical_bounded(bytes, MAX_CONTACT_CARD_BYTES).map_err(|_| GrantError::Malformed)
}
/// A node binding its own provider has no independent pins, so an App Attest
/// credential is registered against its own RP-ID hash and CDHash at the
/// enrollment's validation time. Requesters still pin both before trusting it.
pub fn verify_provider(provider: &ProviderEnrollmentBundle) -> Result<(), GrantError> {
    use hellas_attestation::{AnchorTime, AppleCredential, ApplePolicy};
    let PlatformEnrollment::AppleAppAttest(enrollment) = &provider.platform else {
        return verify_software_enrollment(provider);
    };
    check_grant_provider(provider)?;
    let identity = hellas_attestation::apple_credential_identity(&enrollment.attestation_object)
        .map_err(|_| GrantError::Signature)?;
    let credential = hellas_attestation::register_apple(
        &AppleCredential {
            attestation: enrollment.attestation_object.clone(),
            client_data_hash: enrollment.client_data_hash,
        },
        identity.rp_id_hash,
        hellas_attestation::apple_app_attest_root_ca(),
        AnchorTime(enrollment.validation_time),
    )
    .map_err(|_| GrantError::Signature)?;
    hellas_attestation::verify_apple_provider_genesis(
        &provider.genesis,
        &credential,
        &ApplePolicy {
            expected_rp_id_hash: identity.rp_id_hash,
            allowed_cd_hashes: vec![identity.cd_hash],
        },
    )
    .map_err(|_| GrantError::Signature)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantPolicy {
    pub resource: hellas_auth::authority::ResourceId,
    pub account: hellas_auth::authority::ResourceId,
    pub revision: Revision,
    pub name: String,
    #[serde(with = "policy_bytes")]
    pub work: WorkPolicy,
    pub https: Option<super::resource::HttpsResource>,
    pub responses: Option<super::responses::ResponsesResource>,
    pub pricing: super::pricing::Pricing,
}
impl GrantPolicy {
    pub fn validate(&self) -> Result<(), GrantError> {
        if self.revision.0 == 0 || self.name.is_empty() || self.name.len() > 64 {
            return Err(GrantError::Malformed);
        }
        self.work.check().map_err(|_| GrantError::Malformed)?;
        self.pricing.validate().map_err(|_| GrantError::Limits)?;
        if self
            .pricing
            .rates
            .as_ref()
            .is_some_and(|rates| rates.iter().any(|rate| !self.supports(rate.meter)))
        {
            return Err(GrantError::Limits);
        }
        let responses = matches!(&self.work, WorkPolicy::Fetch { contract, .. }
            if contract.schema() == hellas_rpc::FetchSchema::StatelessResponsesV1);
        if responses != self.responses.is_some() {
            return Err(GrantError::Malformed);
        }
        if let Some(resource) = &self.responses {
            if !matches!(
                &self.work,
                WorkPolicy::Fetch {
                    route: hellas_channel::model::fetch::FetchRoutePolicy::SealedRoute { .. },
                    ..
                }
            ) {
                return Err(GrantError::OutOfScope);
            }
            resource.validate().map_err(|_| GrantError::Malformed)?;
        }
        if matches!(&self.work, WorkPolicy::Fetch { contract, .. }
            if contract.schema() == hellas_rpc::FetchSchema::HttpV1)
            && self.https.is_none()
        {
            return Err(GrantError::Malformed);
        }
        if let Some(resource) = &self.https {
            if !matches!(
                &self.work,
                WorkPolicy::Fetch {
                    route: hellas_channel::model::fetch::FetchRoutePolicy::SealedRoute { .. },
                    ..
                }
            ) {
                return Err(GrantError::OutOfScope);
            }
            if !matches!(&self.work, WorkPolicy::Fetch { contract, .. }
                if contract.schema() == hellas_rpc::FetchSchema::HttpV1)
            {
                return Err(GrantError::Malformed);
            }
            resource.validate().map_err(|_| GrantError::Malformed)?;
        }
        Ok(())
    }
    pub fn supports(&self, meter: Meter) -> bool {
        if meter == Meter::UsdMicros {
            return self.pricing.rates.is_some();
        }
        match &self.work {
            WorkPolicy::Evaluate(_) => true,
            WorkPolicy::Fetch { .. } => match meter {
                Meter::Requests => true,
                Meter::OutputTokens => {
                    self.responses.is_some()
                        || self.https.as_ref().is_some_and(|r| {
                            r.accounting != super::resource::AccountingProfile::None
                        })
                }
                Meter::InputTokens | Meter::DeviceMillis | Meter::UsdMicros => false,
            },
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantDef {
    pub id: GrantId,
    pub revision: Revision,
    pub budget: BudgetNode,
    pub policies: Vec<GrantPolicy>,
    pub max_job_millis: NonZeroU64,
    pub enabled: bool,
    pub allow_account_backed: bool,
}
impl GrantDef {
    pub fn validate(&self) -> Result<(), GrantError> {
        if self.revision.0 == 0
            || !matches!(self.budget, BudgetNode::Subject { .. })
            || self.policies.is_empty()
            || self.policies.len() > MAX_WORK_POLICIES
        {
            return Err(GrantError::Limits);
        }
        let mut names = std::collections::BTreeSet::new();
        let mut policies = std::collections::BTreeSet::new();
        for policy in &self.policies {
            policy.validate()?;
            if !names.insert(&policy.name) || !policies.insert(policy.resource) {
                return Err(GrantError::Malformed);
            }
            let account_backed = match &policy.work {
                WorkPolicy::Evaluate(_) => false,
                WorkPolicy::Fetch { .. } => {
                    policy.https.as_ref().is_none_or(|r| r.credential.is_some())
                }
            };
            if !self.allow_account_backed && account_backed {
                return Err(GrantError::AccountBacked);
            }
        }
        Ok(())
    }
    pub fn admit(&self) -> Result<(), GrantError> {
        if self.enabled {
            Ok(())
        } else {
            Err(GrantError::Paused)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    #[serde(with = "network")]
    pub network: NetworkId,
    #[serde(with = "provider_bytes")]
    pub provider: ProviderEnrollmentBundle,
    pub grant: GrantDef,
    pub generation: u64,
    pub sequence: u64,
    pub valid_until: UnixMillis,
    pub addresses: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOffer {
    offer: Offer,
    signature: Signature,
}
impl SignedOffer {
    pub fn sign(offer: Offer, key: &ProducerSigningKey) -> Result<Self, GrantError> {
        offer.validate()?;
        if key.public_key() != PublicKey::Secp256k1(grant_producer(&offer.provider)?.to_bytes()) {
            return Err(GrantError::Signature);
        }
        let signature = key
            .sign_digest(offer.digest()?)
            .map_err(|_| GrantError::Signature)?;
        let signed = Self { offer, signature };
        if signed.encode()?.len() > MAX_OFFER_BYTES {
            return Err(GrantError::StateCapacity);
        }
        Ok(signed)
    }
    pub fn offer(&self) -> &Offer {
        &self.offer
    }
    pub fn encode(&self) -> Result<Vec<u8>, GrantError> {
        canonical_dag_cbor(self).map_err(|_| GrantError::Malformed)
    }
    pub fn decode(bytes: &[u8], now: UnixMillis) -> Result<Self, GrantError> {
        let signed: Self =
            decode_canonical_bounded(bytes, MAX_OFFER_BYTES).map_err(|error| match error {
                BoundedCborError::InputLimit => GrantError::StateCapacity,
                _ => GrantError::Malformed,
            })?;
        signed.offer.validate()?;
        hellas_auth::signature::verify_digest_signature(
            &PublicKey::Secp256k1(grant_producer(&signed.offer.provider)?.to_bytes()),
            &signed.signature,
            signed.offer.digest()?,
        )
        .map_err(|_| GrantError::Signature)?;
        if signed.offer.valid_until <= now {
            return Err(GrantError::Expired);
        }
        Ok(signed)
    }
}
impl Offer {
    fn validate(&self) -> Result<(), GrantError> {
        check_grant_provider(&self.provider)?;
        self.grant.validate()?;
        if self.addresses.len() > 16
            || self.addresses.iter().any(|a| a.len() > 512)
            || self.sequence == 0
        {
            return Err(GrantError::Malformed);
        }
        Ok(())
    }
    fn digest(&self) -> Result<Digest, GrantError> {
        let body = canonical_dag_cbor(self).map_err(|_| GrantError::Malformed)?;
        Ok(hellas_channel::model::work::xfh(
            b"hellas.work.offer.v2",
            &[&body],
        ))
    }
    pub fn channel(&self, client: ChannelClient) -> ChannelId {
        grant_channel_id(
            self.network,
            self.provider.content_id(),
            self.grant.id,
            client,
            self.generation,
        )
    }
}

mod policy_bytes {
    use super::*;
    pub fn serialize<S: Serializer>(p: &WorkPolicy, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&p.encode())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<WorkPolicy, D::Error> {
        WorkPolicy::decode(&serde_bytes::ByteBuf::deserialize(d)?).map_err(D::Error::custom)
    }
}
