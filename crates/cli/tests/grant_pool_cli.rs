//! Exercise the real offline gateway command using private provisioning state.
use hellas_auth::authority::{
    AuthorityId, CredentialHolder, CredentialId, CredentialSecret, GrantId, UnixMillis,
};
use hellas_authority::model::grant::records::{Offer, SignedOffer};
use hellas_authority::test_support::definition;
use hellas_channel::test_support::{network, principal, software_enrollment};
use hellas_sdk::{
    access_bundle::AccessBundle,
    grant_store::GrantStore,
    trust_policy::{TrustPolicy, TrustPolicyStore},
};
use std::process::Command;

#[test]
fn gateway_checks_a_real_pool_before_startup() {
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("identity");
    let binary = env!("CARGO_BIN_EXE_hellas");
    let init = Command::new(binary)
        .args([
            "--identity",
            identity.to_str().unwrap(),
            "--software-root",
            "identity",
            "init",
        ])
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let show = Command::new(binary)
        .args([
            "--identity",
            identity.to_str().unwrap(),
            "identity",
            "show-holder",
        ])
        .output()
        .unwrap();
    assert!(
        show.status.success(),
        "{}",
        String::from_utf8_lossy(&show.stderr)
    );
    let CredentialHolder::Node(holder) = serde_json::from_slice(&show.stdout).unwrap() else {
        panic!("expected node holder")
    };
    let subject = principal(7).0;
    let passkey = dir.path().join("passkey");
    std::fs::write(&passkey, [0x87; 32]).unwrap();
    let transport = iroh::SecretKey::from_bytes(&[2; 32]).public();
    let provider = software_enrollment(2, *transport.as_bytes());
    let grant = definition(GrantId([1; 16]), subject);
    let resource = grant.policies[0].resource;
    let offer = SignedOffer::sign(
        Offer {
            network: network(),
            provider: provider.clone(),
            grant,
            generation: 0,
            sequence: 1,
            valid_until: UnixMillis(1000),
            addresses: vec![],
        },
        &principal(2).1,
    )
    .unwrap();
    let bundle = AccessBundle {
        offers: vec![offer],
        authority: AuthorityId(hellas_auth::Digest::hash(b"pool-cli")),
        authorization: GrantId([4; 16]),
        subject,
        holder,
        credential: CredentialSecret::from_parts(CredentialId([5; 16]), [6; 32]),
        expires: UnixMillis(2000),
        label: None,
    };
    let bundle_path = dir.path().join("bundle");
    bundle.save(&bundle_path).unwrap();
    let data = dir.path().join("grants");
    let root = data.join(format!("p256-{}", hex::encode(subject.as_bytes())));
    let imported = GrantStore::new(root)
        .import_bundle(&bundle_path, "shared", &subject, &holder, false)
        .unwrap();
    let trust = dir.path().join("trust");
    TrustPolicyStore::new(&trust)
        .approve(
            "provider",
            0,
            TrustPolicy {
                provider_genesis: provider.content_id(),
                assurance: hellas_rpc::Assurance::ProducerSigned,
                apple: None,
            },
            "test approval".into(),
        )
        .unwrap();
    let config = dir.path().join("pool.json");
    std::fs::write(&config, serde_json::to_vec(&serde_json::json!({"channels":[{"offer":imported.offers[0].name,"work_profile":"shared","trust_policy":"provider","resources":[resource.0.to_string()]}]})).unwrap()).unwrap();
    let check = Command::new(binary)
        .env("HELLAS_GRANT_DATA_DIR", &data)
        .args([
            "--identity",
            identity.to_str().unwrap(),
            "--passkey",
            passkey.to_str().unwrap(),
            "gateway",
            "--grant-pool-config",
            config.to_str().unwrap(),
            "--trust-store",
            trust.to_str().unwrap(),
            "--check-config",
        ])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    assert!(String::from_utf8_lossy(&check.stdout).contains("configuration is valid"));
    std::fs::write(&config, b"{\"channels\":[]}").unwrap();
    let bad = Command::new(binary)
        .env("HELLAS_GRANT_DATA_DIR", &data)
        .args([
            "--identity",
            identity.to_str().unwrap(),
            "--passkey",
            passkey.to_str().unwrap(),
            "gateway",
            "--grant-pool-config",
            config.to_str().unwrap(),
            "--trust-store",
            trust.to_str().unwrap(),
            "--check-config",
        ])
        .output()
        .unwrap();
    assert!(!bad.status.success());
}
