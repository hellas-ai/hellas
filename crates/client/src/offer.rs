//! Application import boundary: structural Offer decoding never grants trust.
use crate::{ClientError, ClientResult, ProviderTrustAnchor};
use hellas_auth::authority::UnixMillis;
use hellas_authority::model::grant::records::{Offer, SignedOffer};

pub struct UnpinnedOffer(SignedOffer);
#[derive(Clone, Debug)]
pub struct PinnedOffer {
    signed: SignedOffer,
    trust: ProviderTrustAnchor,
}
impl UnpinnedOffer {
    pub fn decode(bytes: &[u8], now: UnixMillis) -> ClientResult<Self> {
        SignedOffer::decode(bytes, now)
            .map(Self)
            .map_err(|e| ClientError::source("invalid Offer", e))
    }
    pub fn pin(self, trust: &ProviderTrustAnchor) -> ClientResult<PinnedOffer> {
        trust.verify_enrollment(&self.0.offer().provider)?;
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
