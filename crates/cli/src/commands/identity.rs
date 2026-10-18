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

pub fn show_producer_key(key: &ProducerSigningKey) -> CliResult<()> {
    let public_key = key.public_key();
    println!("signature_kind: secp256k1");
    println!("public_key: {}", hex::encode(public_key.bytes()));
    println!("producer_id: {}", hex::encode(key.producer_id().as_bytes()));
    Ok(())
}
