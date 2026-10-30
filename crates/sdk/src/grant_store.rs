//! Private storage for signed grant Offers and device-bound Work profiles.
use crate::access_bundle::{AccessBundle, AccessBundleError};
use crate::node_control::profile::ClientProfile;
use hellas_auth::authority::{NodeKey, PrincipalId, UnixMillis};
use hellas_authority::model::grant::records::{GrantError, MAX_OFFER_BYTES, SignedOffer};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum GrantStoreError {
    #[error(
        "alias must be 1..64 ASCII letters/digits, dots, underscores or hyphens, starting with a letter or digit"
    )]
    Alias,
    #[error("offer alias names another grant; replace explicitly")]
    Conflict,
    #[error("offer import would roll back saved standing")]
    Rollback,
    #[error("bundle has duplicate or missing policy aliases")]
    BundleAliases,
    #[error(transparent)]
    Offer(#[from] GrantError),
    #[error(transparent)]
    Bundle(#[from] AccessBundleError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
type Result<T> = std::result::Result<T, GrantStoreError>;

pub fn validate_alias(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(GrantStoreError::Alias);
    }
    Ok(())
}

pub struct ImportedOffer {
    pub name: String,
    pub offer: SignedOffer,
}
pub struct ImportedBundle {
    pub offers: Vec<ImportedOffer>,
    pub profile: PathBuf,
}

/// A caller-selected private root; identity and trust remain caller-owned.
pub struct GrantStore {
    root: PathBuf,
}
impl GrantStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    pub fn offer_path(&self, name: &str) -> Result<PathBuf> {
        validate_alias(name)?;
        Ok(self.root.join("offers").join(name))
    }
    pub fn profile_path(&self, name: &str) -> Result<PathBuf> {
        validate_alias(name)?;
        Ok(self.root.join("accesses").join(name).join("profile.json"))
    }
    pub fn load_offer(&self, name: &str) -> Result<SignedOffer> {
        let bytes =
            hellas_private::read_bounded_regular_file(&self.offer_path(name)?, MAX_OFFER_BYTES)?;
        Ok(SignedOffer::decode(&bytes, UnixMillis(0))?)
    }
    pub fn load_profile(
        &self,
        name: &str,
        subject: &PrincipalId,
        holder: &NodeKey,
    ) -> Result<ClientProfile> {
        Ok(ClientProfile::load_bound(
            &self.profile_path(name)?,
            subject,
            holder,
        )?)
    }
    fn lock_offer(&self, name: &str) -> Result<std::fs::File> {
        let path = self.offer_path(name)?;
        hellas_private::create_dir_all_durable(path.parent().ok_or(GrantStoreError::Alias)?)?;
        let lock = hellas_private::open_lock_beside(&path)?;
        lock.try_lock()
            .map_err(|_| std::io::Error::other("offer alias is busy"))?;
        Ok(lock)
    }
    fn check_offer(&self, name: &str, imported: &SignedOffer, replace: bool) -> Result<()> {
        let path = self.offer_path(name)?;
        let previous = match hellas_private::read_bounded_regular_file(&path, MAX_OFFER_BYTES) {
            Ok(bytes) => SignedOffer::decode(&bytes, UnixMillis(0))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let old = previous.offer();
        let new = imported.offer();
        let same = new.provider == old.provider
            && new.grant.id == old.grant.id
            && new.network == old.network;
        if !same && !replace {
            return Err(GrantStoreError::Conflict);
        }
        if same
            && (new.grant.revision < old.grant.revision
                || new.generation < old.generation
                || new.sequence < old.sequence
                || new.valid_until < old.valid_until)
        {
            return Err(GrantStoreError::Rollback);
        }
        Ok(())
    }
    fn save_offer(&self, name: &str, offer: &SignedOffer) -> Result<()> {
        let path = self.offer_path(name)?;
        let parent = path.parent().ok_or(GrantStoreError::Alias)?;
        hellas_private::create_dir_all_durable(parent)?;
        hellas_private::write_atomically(&path, ".record", &offer.encode()?)?;
        Ok(())
    }
    pub fn import_offer(&self, file: &Path, name: &str, replace: bool) -> Result<ImportedOffer> {
        let bytes = hellas_private::read_bounded_regular_file(file, MAX_OFFER_BYTES)?;
        let offer = SignedOffer::decode(&bytes, UnixMillis(0))?;
        let _lock = self.lock_offer(name)?;
        self.check_offer(name, &offer, replace)?;
        self.save_offer(name, &offer)?;
        Ok(ImportedOffer {
            name: name.into(),
            offer,
        })
    }
    pub fn import_bundle(
        &self,
        file: &Path,
        name: &str,
        subject: &PrincipalId,
        holder: &NodeKey,
        replace: bool,
    ) -> Result<ImportedBundle> {
        validate_alias(name)?;
        let bundle = AccessBundle::load(file, subject, holder)?;
        let mut names = std::collections::HashSet::new();
        let mut offers = Vec::with_capacity(bundle.offers.len());
        for offer in &bundle.offers {
            let policy = offer
                .offer()
                .grant
                .policies
                .first()
                .ok_or(GrantStoreError::BundleAliases)?;
            let label = format!("{name}.{}", policy.name);
            validate_alias(&label)?;
            if !names.insert(label.clone()) {
                return Err(GrantStoreError::BundleAliases);
            }
            offers.push(ImportedOffer {
                name: label,
                offer: offer.clone(),
            });
        }
        let mut lock_names: Vec<_> = offers.iter().map(|offer| offer.name.as_str()).collect();
        lock_names.sort_unstable();
        let _locks = lock_names
            .into_iter()
            .map(|name| self.lock_offer(name))
            .collect::<Result<Vec<_>>>()?;
        for item in &offers {
            self.check_offer(&item.name, &item.offer, replace)?;
        }
        let directory = self.root.join("accesses").join(name);
        let profile = bundle.install_profile(&directory)?;
        for item in &offers {
            self.save_offer(&item.name, &item.offer)?;
        }
        Ok(ImportedBundle { offers, profile })
    }
}
