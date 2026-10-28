use super::*;
use clap::Parser as _;

#[tokio::test]
async fn interrupted_bootstrap_reuses_prepared_owner_approval_credential_and_tls() {
    let root = tempfile::tempdir().unwrap();
    let identity = crate::identity::load_or_create(Some(&root.path().join("identity"))).unwrap();
    let cli = crate::Cli::try_parse_from(["hellas", "serve", "--faucet-account", "7"]).unwrap();
    let owner = cli.owner.load().unwrap().unwrap();
    let example =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/examples/faucet-provider.toml");
    let paid = PaidWork::load(&example, root.path().join("provider"), owner).unwrap();
    assert_eq!(paid.chain.chain.network.as_str(), "hellas-devnet-1");
    assert_eq!(paid.policy.payment_policy.fixed_price, 20);
    assert_eq!(paid.policy.expected_payment_values.value(), 401);
    let config = hellas_sdk::grant_config::GrantConfig::unconfigured(&paid.root);
    let first = paid
        .prepare(&config, &identity.enrollment, &identity.node_key)
        .await
        .unwrap()
        .unwrap();
    let certificate = std::fs::read(&config.control_certificate).unwrap();
    let key = std::fs::read(&config.control_private_key).unwrap();
    let approval = std::fs::read(paid.root.join("bootstrap.json")).unwrap();
    // Reproduce the on-disk state before the authority rename, after only the
    // certificate publication. Initialization must finish the prepared key pair.
    std::fs::remove_dir_all(&config.journal_root).unwrap();
    std::fs::remove_file(&config.control_private_key).unwrap();
    let resumed = paid
        .prepare(&config, &identity.enrollment, &identity.node_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resumed.id(), first.id());
    assert_eq!(resumed.expose_secret(), first.expose_secret());
    assert_eq!(
        std::fs::read(paid.root.join("bootstrap.json")).unwrap(),
        approval
    );
    assert_eq!(
        std::fs::read(&config.control_certificate).unwrap(),
        certificate
    );
    assert_eq!(std::fs::read(&config.control_private_key).unwrap(), key);
}
