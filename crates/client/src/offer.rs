//! Application import boundary: structural Offer decoding never grants trust.
use crate::{ClientError, ClientResult, ProviderTrustAnchor};
use hellas_rpc::protocol::work_grant::{
    PrincipalId, UnixMillis,
    records::{Offer, SignedOffer},
};

pub struct UnpinnedOffer(SignedOffer);
#[derive(Clone, Debug)]
pub struct PinnedOffer {
    signed: SignedOffer,
    trust: ProviderTrustAnchor,
}
impl UnpinnedOffer {
    pub fn decode(bytes: &[u8], audience: PrincipalId, now: UnixMillis) -> ClientResult<Self> {
        SignedOffer::decode(bytes, audience, now)
            .map(Self)
            .map_err(|e| ClientError::source("invalid Offer", e))
    }
    pub fn pin(self, trust: &ProviderTrustAnchor) -> ClientResult<PinnedOffer> {
        let provider = &self.0.offer().provider;
        let assurance = match provider.genesis.statement.root_kind {
            hellas_rpc::RootKind::Software => hellas_rpc::Assurance::ProducerSigned,
            hellas_rpc::RootKind::SecureEnclave => hellas_rpc::Assurance::AppleAppAttest,
        };
        if trust.required_assurance != assurance {
            return Err(ClientError::protocol(
                "grant assurance differs from the provider root",
            ));
        }
        trust.verify_enrollment(provider)?;
        Ok(PinnedOffer {
            signed: self.0,
            trust: trust.clone(),
        })
    }
}
impl PinnedOffer {
    pub fn signed(&self) -> &SignedOffer {
        &self.signed
    }
    pub fn offer(&self) -> &Offer {
        self.signed.offer()
    }
    pub fn trust(&self) -> &ProviderTrustAnchor {
        &self.trust
    }
}
