//! Contacts and private Offers belong to the principal a command acts for.
use super::CliResult;
use hellas_auth::authority::{ContactCard, PrincipalId};
use hellas_authority::authenticator::Authenticator;
use hellas_authority::model::grant::records::SignedOffer;
use hellas_private::StoreLocation;
use std::path::{Path, PathBuf};

#[derive(clap::Subcommand)]
pub enum OfferCommand {
    /// Verify the provider signature and save the Work terms.
    Import {
        file: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        replace: bool,
    },
}
/// The principal controlled by this authenticator.
pub fn principal(passkey: &dyn Authenticator) -> CliResult<PrincipalId> {
    Ok(PrincipalId::from_public_key(hellas_auth::PublicKey::P256(
        passkey.public_key()?.to_compressed(),
    ))?)
}
/// The principal of a command that acts for one.
pub fn require_principal(passkey: Option<&dyn Authenticator>) -> CliResult<PrincipalId> {
    principal(passkey.ok_or_else(|| {
        anyhow::anyhow!(
            "this command acts for a principal; pass its software passkey with --passkey"
        )
    })?)
}
/// One private tree per principal, named by its curve and compressed key.
pub(crate) fn data_root(home: &Path, principal: &PrincipalId) -> CliResult<PathBuf> {
    let base = crate::identity::grant_data_path(home);
    Ok(base.join(format!("p256-{}", hex::encode(principal.as_bytes()))))
}
pub(super) fn save(path: &Path, bytes: &[u8]) -> CliResult<()> {
    let directory = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    hellas_private::create_dir_all_durable(directory)?;
    hellas_private::write_atomically(path, ".record", bytes)?;
    Ok(())
}
/// The one string a person sends to be shared with: their principal and
/// display name, signed by the principal key, and this device's node key.
pub async fn contact(
    name: &str,
    passkey: &dyn Authenticator,
    device: &hellas_auth::ProducerSigningKey,
) -> CliResult<String> {
    let principal = principal(passkey)?;
    let assertion = passkey.assert(ContactCard::digest(principal, name)).await?;
    Ok(hellas_sdk::contact::Contact {
        card: ContactCard::new(principal, name.into(), assertion)?,
        holder: hellas_auth::authority::NodeKey::from_public_key(device.public_key())?,
    }
    .encode()?)
}

pub fn offer(
    command: OfferCommand,
    passkey: Option<&dyn Authenticator>,
    home: &Path,
) -> CliResult<()> {
    let identity = require_principal(passkey)?;
    let root = data_root(home, &identity)?;
    let store = hellas_sdk::grant_store::GrantStore::new(root);
    match command {
        OfferCommand::Import {
            file,
            name,
            replace,
        } => {
            let imported = store.import_offer(&file, &name, replace)?;
            println!("{}", hex::encode(imported.offer.offer().grant.id.0));
            offer_fingerprints(&imported.offer)?;
        }
    }
    Ok(())
}

/// The provider is a machine: show its enrollment, never a principal.
pub(super) fn offer_fingerprints(offer: &SignedOffer) -> CliResult<()> {
    eprintln!(
        "Provider enrollment: {}",
        offer.offer().provider.content_id()
    );
    Ok(())
}

pub fn client_journal_root(
    home: &StoreLocation,
    identity: &PrincipalId,
) -> CliResult<StoreLocation> {
    Ok(home.child(data_root(home, identity)?).child("channels"))
}
/// Saved Offer terms may have expired; only use this as a signed locator.
/// GrantSession obtains fresh authenticated standing before proposing a job.
pub fn load_offer(home: &Path, identity: &PrincipalId, name: &str) -> CliResult<SignedOffer> {
    Ok(hellas_sdk::grant_store::GrantStore::new(data_root(home, identity)?).load_offer(name)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn a_contact_names_the_principal_and_this_device() {
        let friend = hellas_kernel::SoftPasskey::from_secret_scalar([0x41; 32]).unwrap();
        let device = hellas_auth::ProducerSigningKey::generate();
        let line = contact("Friend", &friend, &device).await.unwrap();
        let decoded = hellas_sdk::contact::Contact::decode(&line).unwrap();
        assert_eq!(decoded.card.principal(), principal(&friend).unwrap());
        assert_eq!(decoded.card.name(), "Friend");
        assert_eq!(
            decoded.holder,
            hellas_auth::authority::NodeKey::from_public_key(device.public_key()).unwrap()
        );
        assert!(contact("", &friend, &device).await.is_err());
    }
    #[test]
    fn data_roots_name_the_principal_by_curve_and_key() {
        let home = tempfile::tempdir().unwrap();
        let passkey = hellas_kernel::SoftPasskey::from_secret_scalar([0x42; 32]).unwrap();
        let principal = principal(&passkey).unwrap();
        let root = data_root(home.path(), &principal).unwrap();
        assert_eq!(
            root.file_name().unwrap().to_str().unwrap(),
            format!("p256-{}", hex::encode(principal.as_bytes()))
        );
        assert!(require_principal(None).is_err());
    }
}
