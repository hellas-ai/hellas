//! A node owner's handoff of shared allowances to a contact: one signed Offer
//! per allowance, plus the one Auth grant and credential the contact connects
//! with. The grant holds a `work.execute` permission for each allowance and the
//! credential is bound to the contact device's node key. It carries the
//! credential secret, so files are private and published once. It carries no
//! provider trust; the contact still approves a trust policy independently.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use crate::node_control::profile::{self, ClientProfile};
use hellas_auth::authority::{
    AuthorityId, CredentialId, CredentialSecret, GrantId, NodeKey, PrincipalId, UnixMillis,
};
use hellas_rpc::protocol::value::{BoundedCborError, canonical_dag_cbor, decode_canonical_bounded};
use hellas_work::model::grant::records::{GrantError, MAX_OFFER_BYTES, SignedOffer};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const TAG: &str = "hellas.access-bundle.v2";
pub const MAX_BUNDLE_OFFERS: usize = 16;
pub const MAX_ACCESS_BUNDLE_BYTES: usize = MAX_BUNDLE_OFFERS * MAX_OFFER_BYTES + 1024;
pub const MAX_LABEL_BYTES: usize = 64;

pub struct AccessBundle {
    /// One Offer per shared allowance, all from one provider on one network.
    pub offers: Vec<SignedOffer>,
    pub authority: AuthorityId,
    /// The contact's Auth grant, with one `work.execute` permission per
    /// allowance; not an allowance ID.
    pub authorization: GrantId,
    /// The credential's subject: the contact's passkey principal.
    pub subject: PrincipalId,
    /// The contact device's node key, which the credential is bound to.
    pub holder: NodeKey,
    pub credential: CredentialSecret,
    /// Grant and credential expiry, for display only.
    pub expires: UnixMillis,
    /// The provider's display name, for display only.
    pub label: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AccessBundleError {
    #[error("access bundle exceeds {MAX_ACCESS_BUNDLE_BYTES} bytes")]
    TooLarge,
    #[error("malformed access bundle")]
    Malformed,
    #[error("access bundle offer is invalid: {0}")]
    Offer(#[source] GrantError),
    #[error("access bundle is addressed to another principal")]
    WrongSubject,
    #[error("access bundle credential is bound to another device")]
    WrongHolder,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    tag: String,
    offers: Vec<serde_bytes::ByteBuf>,
    authority: AuthorityId,
    authorization: GrantId,
    subject: PrincipalId,
    holder: NodeKey,
    credential_id: CredentialId,
    #[serde(with = "serde_bytes")]
    secret: Vec<u8>,
    expires: UnixMillis,
    label: Option<String>,
}
impl Drop for Wire {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Between one and [`MAX_BUNDLE_OFFERS`] offers from one provider on one
/// network, each for a distinct allowance.
fn check_offers(offers: &[SignedOffer]) -> Result<(), AccessBundleError> {
    let first = offers.first().ok_or(AccessBundleError::Malformed)?.offer();
    let mut allowances = std::collections::BTreeSet::new();
    if offers.len() > MAX_BUNDLE_OFFERS
        || offers.iter().any(|offer| {
            let offer = offer.offer();
            offer.provider != first.provider
                || offer.network != first.network
                || !allowances.insert(offer.grant.id)
        })
    {
        return Err(AccessBundleError::Malformed);
    }
    Ok(())
}

impl AccessBundle {
    /// Canonical DAG-CBOR; the same bytes are used for files.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, AccessBundleError> {
        if self
            .label
            .as_ref()
            .is_some_and(|label| label.len() > MAX_LABEL_BYTES)
        {
            return Err(AccessBundleError::Malformed);
        }
        check_offers(&self.offers)?;
        let wire = Wire {
            tag: TAG.into(),
            offers: self
                .offers
                .iter()
                .map(|offer| offer.encode().map(serde_bytes::ByteBuf::from))
                .collect::<Result<_, _>>()
                .map_err(AccessBundleError::Offer)?,
            authority: self.authority,
            authorization: self.authorization,
            subject: self.subject,
            holder: self.holder,
            credential_id: self.credential.id(),
            secret: self.credential.expose_secret().to_vec(),
            expires: self.expires,
            label: self.label.clone(),
        };
        let bytes =
            Zeroizing::new(canonical_dag_cbor(&wire).map_err(|_| AccessBundleError::Malformed)?);
        if bytes.len() > MAX_ACCESS_BUNDLE_BYTES {
            return Err(AccessBundleError::TooLarge);
        }
        Ok(bytes)
    }

    /// Bounded canonical decode. Each Offer signature is verified, regardless
    /// of its expiry, and a bundle for any other principal or device is
    /// refused.
    pub fn decode(
        bytes: &[u8],
        expected_subject: &PrincipalId,
        expected_holder: &NodeKey,
    ) -> Result<Self, AccessBundleError> {
        let mut wire: Wire = decode_canonical_bounded(bytes, MAX_ACCESS_BUNDLE_BYTES).map_err(
            |error| match error {
                BoundedCborError::InputLimit => AccessBundleError::TooLarge,
                _ => AccessBundleError::Malformed,
            },
        )?;
        let secret: [u8; 32] = wire
            .secret
            .as_slice()
            .try_into()
            .map_err(|_| AccessBundleError::Malformed)?;
        let credential = CredentialSecret::from_parts(wire.credential_id, secret);
        if wire.tag != TAG
            || wire
                .label
                .as_ref()
                .is_some_and(|label| label.len() > MAX_LABEL_BYTES)
        {
            return Err(AccessBundleError::Malformed);
        }
        if wire.subject != *expected_subject {
            return Err(AccessBundleError::WrongSubject);
        }
        if wire.holder != *expected_holder {
            return Err(AccessBundleError::WrongHolder);
        }
        let offers = wire
            .offers
            .iter()
            .map(|offer| SignedOffer::decode(offer, UnixMillis(0)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(AccessBundleError::Offer)?;
        check_offers(&offers)?;
        Ok(Self {
            offers,
            authority: wire.authority,
            authorization: wire.authorization,
            subject: wire.subject,
            holder: wire.holder,
            credential,
            expires: wire.expires,
            label: wire.label.take(),
        })
    }

    /// Publish privately once; an existing file is never replaced.
    pub fn save(&self, path: &Path) -> Result<(), AccessBundleError> {
        let bytes = self.encode()?;
        let file = hellas_private::private_tempfile(profile::parent(path), ".access-", ".writing")?;
        Ok(profile::publish_private(file, path, &bytes)?)
    }

    /// Read a bundle file within the decode bound. A received copy usually
    /// arrives with ordinary permissions, so they are not required here; the
    /// credential is stored privately by [`Self::install_profile`].
    pub fn load(
        path: &Path,
        expected_subject: &PrincipalId,
        expected_holder: &NodeKey,
    ) -> Result<Self, AccessBundleError> {
        let bytes = hellas_private::read_bounded_regular_file(path, MAX_ACCESS_BUNDLE_BYTES)
            .map_err(|error| {
                if error
                    .get_ref()
                    .is_some_and(|error| error.is::<hellas_private::ReadLimit>())
                {
                    AccessBundleError::TooLarge
                } else {
                    error.into()
                }
            })?;
        Self::decode(&bytes, expected_subject, expected_holder)
    }

    /// Install the remote-only client profile and its private credential into a
    /// new or empty directory, returning the profile path.
    pub fn install_profile(&self, directory: &Path) -> Result<PathBuf, AccessBundleError> {
        Ok(profile::install_remote(
            directory,
            self.authority,
            self.authorization,
            &self.credential,
        )?)
    }

    /// The Offers to import and the remote-only profile they connect with.
    pub fn into_parts(self) -> (Vec<SignedOffer>, ClientProfile) {
        (
            self.offers,
            ClientProfile {
                authority: self.authority,
                authorization: self.authorization,
                credential: self.credential,
                local: None,
            },
        )
    }
}

#[cfg(test)]
mod tests;
