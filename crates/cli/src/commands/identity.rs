use crate::commands::CliResult;
use hellas_auth::ProducerSigningKey;
use hellas_rpc::ProviderEnrollmentBundle;
use iroh::SecretKey;

pub fn create_passkey(path: &std::path::Path) -> CliResult<()> {
    use std::io::Write as _;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    hellas_private::create_dir_all_durable(parent)?;
    let secret = loop {
        let secret = rand::random::<[u8; 32]>();
        if hellas_kernel::SoftPasskey::from_secret_scalar(secret).is_ok() {
            break secret;
        }
    };
    let mut file = hellas_private::private_tempfile(parent, ".passkey-", ".pending")?;
    file.write_all(&secret)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)?;
    hellas_private::sync_directory(parent)?;
    eprintln!("Created private owner key: {}", path.display());
    Ok(())
}

pub fn show_node_id(secret_key: &SecretKey) -> CliResult<()> {
    println!("{}", secret_key.public());
    Ok(())
}

pub fn show_enrollment_id(enrollment: &ProviderEnrollmentBundle) -> CliResult<()> {
    println!("{}", enrollment.content_id());
    Ok(())
}

/// The holder a credential for this node names: its node key, curve-tagged.
pub fn show_holder(key: &ProducerSigningKey) -> CliResult<()> {
    let holder = hellas_auth::authority::CredentialHolder::Node(
        hellas_auth::authority::NodeKey::from_public_key(key.public_key())?,
    );
    println!("{}", serde_json::to_string(&holder)?);
    Ok(())
}

pub fn export_enrollment(
    enrollment: &ProviderEnrollmentBundle,
    out: Option<&std::path::Path>,
) -> CliResult<()> {
    let bytes = enrollment.canonical_bytes();
    match out {
        Some(path) => super::contributions::save(path, &bytes)?,
        None => std::io::Write::write_all(&mut std::io::stdout().lock(), &bytes)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn owner_key_creation_is_private_valid_and_never_replaces_a_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("owner.passkey");
        super::create_passkey(&path).unwrap();
        super::super::chain::passkey(&path).unwrap();
        let original = std::fs::read(&path).unwrap();
        assert!(super::create_passkey(&path).is_err());
        assert_eq!(std::fs::read(path).unwrap(), original);
    }
}
