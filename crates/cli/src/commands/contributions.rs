//! Contacts and private Offers belong to the principal a command acts for.
use super::{CliResult, read_bounded_regular_file};
use anyhow::ensure;
use hellas_auth::authority::{ContactCard, PrincipalId};
use hellas_authority::authenticator::Authenticator;
use hellas_authority::model::grant::records::{
    MAX_CONTACT_CARD_BYTES, SignedOffer, decode_contact_card, encode_contact_card,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

#[derive(clap::Subcommand)]
pub enum ContactCommand {
    /// Sign this principal's contact card: its passkey public key and a
    /// display name, with the passkey's assertion over both.
    Export {
        /// The display name the card introduces this principal by.
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a contact card and save it under a local alias.
    Import {
        file: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        replace: bool,
    },
}
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
    /// Import an access bundle for this principal and device: install its Work
    /// profile as `NAME` and save each offer as `NAME.POLICY`, after the
    /// offer's first policy.
    ImportBundle {
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
pub(crate) fn data_root(principal: &PrincipalId) -> CliResult<PathBuf> {
    let base = match std::env::var_os("HELLAS_GRANT_DATA_DIR") {
        Some(path) => PathBuf::from(path),
        None => crate::identity::default_grant_data_path()?,
    };
    Ok(base.join(format!("p256-{}", hex::encode(principal.as_bytes()))))
}
fn alias(root: &Path, kind: &str, name: &str) -> CliResult<PathBuf> {
    hellas_sdk::grant_store::validate_alias(name)?;
    Ok(root.join(kind).join(name))
}

/// Load an already imported, verified contact from this principal's address book.
pub(super) fn save(path: &Path, bytes: &[u8]) -> CliResult<()> {
    let directory = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    hellas_private::create_dir_all_durable(directory)?;
    hellas_private::write_atomically(path, ".record", bytes)?;
    Ok(())
}
pub async fn contact(
    command: ContactCommand,
    passkey: Option<&dyn Authenticator>,
) -> CliResult<()> {
    match command {
        ContactCommand::Export { display_name, out } => {
            let passkey = passkey.ok_or_else(|| {
                anyhow::anyhow!("a contact card is signed by the principal's --passkey")
            })?;
            let principal = principal(passkey)?;
            let assertion = passkey
                .assert(ContactCard::digest(principal, &display_name))
                .await?;
            let card = ContactCard::new(principal, display_name, assertion)?;
            let bytes = encode_contact_card(&card)?;
            if let Some(path) = out {
                save(&path, &bytes)?;
            } else {
                std::io::stdout().lock().write_all(&bytes)?;
            }
            eprintln!("Principal fingerprint: {}", principal.fingerprint());
        }
        ContactCommand::Import {
            file,
            name,
            replace,
        } => {
            let bytes = read_bounded_regular_file(&file, "contact card", MAX_CONTACT_CARD_BYTES)?;
            let imported = decode_contact_card(&bytes)?;
            let path = alias(&data_root(&require_principal(passkey)?)?, "contacts", &name)?;
            if path.exists() && !replace {
                let previous = decode_contact_card(&read_bounded_regular_file(
                    &path,
                    "contact card",
                    MAX_CONTACT_CARD_BYTES,
                )?)?;
                ensure!(
                    previous.principal() == imported.principal(),
                    "contact alias already names another principal; use --replace explicitly"
                );
            }
            save(&path, &bytes)?;
            println!(
                "{}",
                serde_json::json!({
                    "principal": hex::encode(imported.principal().as_bytes()),
                    "fingerprint": imported.principal().fingerprint(),
                    "display_name": imported.name(),
                })
            );
        }
    }
    Ok(())
}
/// `identity_node` is this device's node key, which an access bundle's
/// credential must be bound to; plain offer imports need none.
pub fn offer(
    command: OfferCommand,
    passkey: Option<&dyn Authenticator>,
    identity_node: Option<&hellas_auth::ProducerSigningKey>,
) -> CliResult<()> {
    let identity = require_principal(passkey)?;
    let root = data_root(&identity)?;
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
        OfferCommand::ImportBundle {
            file,
            name,
            replace,
        } => {
            let node = hellas_auth::authority::NodeKey::from_public_key(
                identity_node
                    .ok_or_else(|| anyhow::anyhow!("an access bundle is bound to a device"))?
                    .public_key(),
            )?;
            let imported = store.import_bundle(&file, &name, &identity, &node, replace)?;
            for item in &imported.offers {
                offer_fingerprints(&item.offer)?;
            }
            println!(
                "{}",
                serde_json::json!({
                    "offers": imported.offers.iter().map(|item| serde_json::json!({
                        "name": item.name,
                        "grant": hex::encode(item.offer.offer().grant.id.0),
                    })).collect::<Vec<_>>(),
                    "work_profile": imported.profile,
                })
            );
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

pub fn client_journal_root(identity: &PrincipalId) -> CliResult<PathBuf> {
    Ok(data_root(identity)?.join("channels"))
}
/// Saved Offer terms may have expired; only use this as a signed locator.
/// GrantSession obtains fresh authenticated standing before proposing a job.
pub fn load_offer(identity: &PrincipalId, name: &str) -> CliResult<SignedOffer> {
    Ok(hellas_sdk::grant_store::GrantStore::new(data_root(identity)?).load_offer(name)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn aliases_cannot_escape_the_private_store_and_cards_verify() {
        let root = tempfile::tempdir().unwrap();
        for name in ["", "..", "../secret", "/secret", "a/b", "a\\b", " x", "ö"] {
            assert!(alias(root.path(), "contacts", name).is_err(), "{name}");
        }
        assert_eq!(
            alias(root.path(), "contacts", "contact-1").unwrap(),
            root.path().join("contacts/contact-1")
        );
        let friend = hellas_kernel::SoftPasskey::from_secret_scalar([0x41; 32]).unwrap();
        let out = root.path().join("export");
        contact(
            ContactCommand::Export {
                display_name: "Friend".into(),
                out: Some(out.clone()),
            },
            Some(&friend),
        )
        .await
        .unwrap();
        let card = decode_contact_card(&std::fs::read(&out).unwrap()).unwrap();
        assert_eq!(card.principal(), principal(&friend).unwrap());
        assert_eq!(
            card.principal().public_key().kind(),
            hellas_auth::SignatureKind::P256
        );
        assert_eq!(card.name(), "Friend");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(
            contact(
                ContactCommand::Export {
                    display_name: "Nobody".into(),
                    out: None,
                },
                None,
            )
            .await
            .is_err()
        );
    }
    #[test]
    fn data_roots_name_the_principal_by_curve_and_key() {
        let passkey = hellas_kernel::SoftPasskey::from_secret_scalar([0x42; 32]).unwrap();
        let principal = principal(&passkey).unwrap();
        let root = data_root(&principal).unwrap();
        assert_eq!(
            root.file_name().unwrap().to_str().unwrap(),
            format!("p256-{}", hex::encode(principal.as_bytes()))
        );
        assert!(require_principal(None).is_err());
    }
}
