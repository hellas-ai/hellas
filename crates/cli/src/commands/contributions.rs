//! Contacts and private Offers are scoped to the current enrolled identity.
use super::{CliResult, read_bounded_regular_file};
use anyhow::{Context, ensure};
use hellas_rpc::protocol::work_grant::{UnixMillis, records::*};
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
    /// Verify the provider signature and require this identity as the audience.
    Import {
        file: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        replace: bool,
    },
}
pub fn principal(identity: &crate::identity::LocalIdentity) -> CliResult<Principal> {
    Principal::verify(identity.enrollment.clone())
        .context("identity cannot participate in grant Work")
}
pub(crate) fn data_root(identity: &Principal) -> CliResult<PathBuf> {
    let base = match std::env::var_os("HELLAS_GRANT_DATA_DIR") {
        Some(path) => PathBuf::from(path),
        None => crate::identity::default_grant_data_path()?,
    };
    Ok(base.join(identity.id().0.to_string()))
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
    let identity = principal(identity)?;
    match command {
        ContactCommand::Export { out } => {
            let bytes = identity.bundle().canonical_bytes();
            if let Some(path) = out {
                save(&path, &bytes)?;
            } else {
                std::io::stdout().lock().write_all(&bytes)?;
            }
        }
        ContactCommand::Import {
            file,
            name,
            replace,
        } => {
            let bytes = read_bounded_regular_file(&file, "contact", MAX_PRINCIPAL_BYTES)?;
            let imported = Principal::decode(&bytes)?;
            let path = alias(&data_root(&identity)?, "contacts", &name)?;
            if path.exists() && !replace {
                let previous = Principal::decode(&read_bounded_regular_file(
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
            println!("{}", imported.id().0);
        }
    }
    Ok(())
}
pub fn offer(command: OfferCommand, identity: &crate::identity::LocalIdentity) -> CliResult<()> {
    let identity = principal(identity)?;
    match command {
        OfferCommand::Import {
            file,
            name,
            replace,
        } => {
            let bytes = read_bounded_regular_file(&file, "offer", MAX_OFFER_BYTES)?;
            let imported = SignedOffer::decode(&bytes, identity.id(), UnixMillis(0))?;
            let path = alias(&data_root(&identity)?, "offers", &name)?;
            if path.exists() && !replace {
                let previous = SignedOffer::decode(
                    &read_bounded_regular_file(&path, "offer", MAX_OFFER_BYTES)?,
                    identity.id(),
                    UnixMillis(0),
                )?;
                let new = imported.offer();
                let old = previous.offer();
                ensure!(
                    new.provider == old.provider
                        && new.grant.id == old.grant.id
                        && new.network == old.network,
                    "offer alias already names another grant; use --replace explicitly"
                );
                ensure!(
                    new.grant.revision >= old.grant.revision
                        && new.generation >= old.generation
                        && new.sequence >= old.sequence
                        && new.valid_until >= old.valid_until,
                    "offer import would roll back saved standing"
                );
            }
            save(&path, &bytes)?;
            println!("{}", hex::encode(imported.offer().grant.id.0));
        }
    }
    Ok(())
}

#[cfg(feature = "gateway")]
pub fn client_journal_root(identity: &Principal) -> CliResult<PathBuf> {
    Ok(data_root(identity)?.join("channels"))
}
/// Saved Offer terms may have expired; only use this as a signed locator.
/// WorkSession obtains fresh authenticated standing before proposing a job.
#[cfg(feature = "gateway")]
pub fn load_offer(identity: &Principal, name: &str) -> CliResult<SignedOffer> {
    let path = alias(&data_root(identity)?, "offers", name)?;
    Ok(SignedOffer::decode(
        &read_bounded_regular_file(&path, "offer", MAX_OFFER_BYTES)?,
        identity.id(),
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
        assert_eq!(
            Principal::decode(&bytes).unwrap(),
            principal(&identity).unwrap()
        );
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
