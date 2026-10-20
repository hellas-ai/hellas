use crate::commands::CliResult;
use hellas_auth::ProducerSigningKey;
use hellas_rpc::ProviderEnrollmentBundle;
use iroh::SecretKey;

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
