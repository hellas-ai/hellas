//! Contacts and private Offers are scoped to the current portable identity.
use super::{CliResult, read_bounded_regular_file};
use anyhow::ensure;
use hellas_auth::authority::{PrincipalId, UnixMillis};
use hellas_work::model::grant::records::*;
use hellas_work::model::grant::records::{decode_contact, verify_contact};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

#[derive(clap::Subcommand)]
pub enum ContactCommand {
    /// Export the current public enrollment as canonical bytes.
    Export {
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a contact's enrollment and save a local alias.
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
    /// Import an access bundle: save its offer and install its Work profile.
    ImportBundle {
        file: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        replace: bool,
    },
}
pub fn principal(identity: &crate::identity::LocalIdentity) -> CliResult<PrincipalId> {
    Ok(PrincipalId::from_public_key(
        identity.node_key.public_key(),
    )?)
}
pub(crate) fn data_root(identity: &PrincipalId) -> CliResult<PathBuf> {
    let base = match std::env::var_os("HELLAS_GRANT_DATA_DIR") {
        Some(path) => PathBuf::from(path),
        None => crate::identity::default_grant_data_path()?,
    };
    Ok(base.join(hex::encode(identity.as_bytes())))
}
fn alias(root: &Path, kind: &str, name: &str) -> CliResult<PathBuf> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name.as_bytes()[0].is_ascii_alphanumeric()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "alias must be 1..64 ASCII letters/digits, dots, underscores or hyphens, starting with a letter or digit"
    );
    Ok(root.join(kind).join(name))
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
pub fn contact(
    command: ContactCommand,
    identity: &crate::identity::LocalIdentity,
) -> CliResult<()> {
    let enrollment = &identity.enrollment;
    verify_contact(enrollment)?;
    let identity = principal(identity)?;
    match command {
        ContactCommand::Export { out } => {
            let bytes = enrollment.canonical_bytes();
            if let Some(path) = out {
                save(&path, &bytes)?;
            } else {
                std::io::stdout().lock().write_all(&bytes)?;
            }
            eprintln!("Identity fingerprint: {}", identity.fingerprint());
        }
        ContactCommand::Import {
            file,
            name,
            replace,
        } => {
            let bytes = read_bounded_regular_file(&file, "contact", MAX_PRINCIPAL_BYTES)?;
            let imported = decode_contact(&bytes)?;
            let path = alias(&data_root(&identity)?, "contacts", &name)?;
            if path.exists() && !replace {
                let previous = decode_contact(&read_bounded_regular_file(
                    &path,
                    "contact",
                    MAX_PRINCIPAL_BYTES,
                )?)?;
                ensure!(
                    previous == imported,
                    "contact alias already names another principal; use --replace explicitly"
                );
            }
            save(&path, &bytes)?;
            println!("{}", hex::encode(imported.content_id().as_bytes()));
        }
    }
    Ok(())
}
pub fn offer(command: OfferCommand, identity: &crate::identity::LocalIdentity) -> CliResult<()> {
    let identity = principal(identity)?;
    let root = data_root(&identity)?;
    match command {
        OfferCommand::Import {
            file,
            name,
            replace,
        } => {
            let bytes = read_bounded_regular_file(&file, "offer", MAX_OFFER_BYTES)?;
            let imported = SignedOffer::decode(&bytes, UnixMillis(0))?;
            let path = alias(&root, "offers", &name)?;
            check_offer_alias(&path, &imported, replace)?;
            save(&path, &bytes)?;
            println!("{}", hex::encode(imported.offer().grant.id.0));
            offer_fingerprints(&imported)?;
        }
        OfferCommand::ImportBundle {
            file,
            name,
            replace,
        } => {
            let bundle = hellas_sdk::access_bundle::AccessBundle::load(&file, &identity)?;
            let path = alias(&root, "offers", &name)?;
            check_offer_alias(&path, &bundle.offer, replace)?;
            let profile = bundle.install_profile(&alias(&root, "accesses", &name)?)?;
            save(&path, &bundle.offer.encode()?)?;
            println!(
                "{}",
                serde_json::json!({
                    "grant": hex::encode(bundle.offer.offer().grant.id.0),
                    "work_profile": profile,
                })
            );
            offer_fingerprints(&bundle.offer)?;
        }
    }
    Ok(())
}

fn check_offer_alias(path: &Path, imported: &SignedOffer, replace: bool) -> CliResult<()> {
    if !path.exists() || replace {
        return Ok(());
    }
    let previous = SignedOffer::decode(
        &read_bounded_regular_file(path, "offer", MAX_OFFER_BYTES)?,
        UnixMillis(0),
    )?;
    let new = imported.offer();
    let old = previous.offer();
    ensure!(
        new.provider == old.provider && new.grant.id == old.grant.id && new.network == old.network,
        "offer alias already names another grant; use --replace explicitly"
    );
    ensure!(
        new.grant.revision >= old.grant.revision
            && new.generation >= old.generation
            && new.sequence >= old.sequence
            && new.valid_until >= old.valid_until,
        "offer import would roll back saved standing"
    );
    Ok(())
}

pub(super) fn offer_fingerprints(offer: &SignedOffer) -> CliResult<()> {
    let provider = hellas_auth::authority::PrincipalId::from_public_key(
        offer.offer().provider.genesis.statement.producer_public_key,
    )?;
    eprintln!("Provider fingerprint: {}", provider.fingerprint(),);
    Ok(())
}

pub fn client_journal_root(identity: &PrincipalId) -> CliResult<PathBuf> {
    Ok(data_root(identity)?.join("channels"))
}
/// Saved Offer terms may have expired; only use this as a signed locator.
/// GrantSession obtains fresh authenticated standing before proposing a job.
pub fn load_offer(identity: &PrincipalId, name: &str) -> CliResult<SignedOffer> {
    let path = alias(&data_root(identity)?, "offers", name)?;
    Ok(SignedOffer::decode(
        &read_bounded_regular_file(&path, "offer", MAX_OFFER_BYTES)?,
        UnixMillis(0),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aliases_cannot_escape_the_private_store_and_exports_verify() {
        let root = tempfile::tempdir().unwrap();
        for name in ["", "..", "../secret", "/secret", "a/b", "a\\b", " x", "ö"] {
            assert!(alias(root.path(), "contacts", name).is_err(), "{name}");
        }
        assert_eq!(
            alias(root.path(), "contacts", "contact-1").unwrap(),
            root.path().join("contacts/contact-1")
        );
        let identity =
            crate::identity::load_or_create(Some(&root.path().join("identity"))).unwrap();
        let out = root.path().join("export");
        contact(
            ContactCommand::Export {
                out: Some(out.clone()),
            },
            &identity,
        )
        .unwrap();
        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(decode_contact(&bytes).unwrap(), identity.enrollment);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(out).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
