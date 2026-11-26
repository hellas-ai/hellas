use hellas_rpc::ProviderEnrollmentBundle;

/// Captured with 2F53L9ZR3N.ai.hellas.app-attest-spike because the installed Gate
/// profile lacked the CDHash opt-in.
pub fn enrollment() -> ProviderEnrollmentBundle {
    ProviderEnrollmentBundle::from_canonical_bytes(include_bytes!("apple-enrollment.cbor")).unwrap()
}
