mod transact;
use super::*;
use clap::Parser as _;
use hellas_chain::test_support::devnet::{Devnet, DevnetConfig, GenesisOwner, run};
use hellas_sdk::{
    paid_client::*,
    work_config::{ChainCrossCheck, WorkConfig},
};
use std::sync::Arc;

async fn sealing<T>(devnet: &mut Devnet, work: impl std::future::Future<Output = T>) -> T {
    sealing_with_period(devnet, work, Duration::from_millis(100)).await
}

async fn sealing_with_period<T>(
    devnet: &mut Devnet,
    work: impl std::future::Future<Output = T>,
    period: Duration,
) -> T {
    tokio::time::timeout(hellas_chain::node::RECOVERY_TIMEOUT.saturating_mul(3), async {
        tokio::pin!(work);
        loop {
            tokio::select! { output = &mut work => return output, () = tokio::time::sleep(period) => {} }
            let seal = devnet.seal();tokio::pin!(seal);
            tokio::select! { output = &mut work => {seal.await;return output}, _ = &mut seal => {} }
        }
    }).await.unwrap()
}

fn config(devnet: &Devnet, root: &Path) -> WorkConfig {
    WorkConfig {
        chain: ChainCrossCheck {
            network: devnet.network(),
            genesis_payload_digest: devnet.genesis_payload().0.into(),
            threshold_identity: devnet.consensus_info().threshold_identity.clone(),
            genesis: Some(devnet.genesis().clone()),
        },
        validators: devnet.light_client_urls(),
        journal_root: root.join("channels"),
        poll: Duration::from_millis(20),
        max_observation_age: Duration::from_secs(60),
    }
}

async fn host(
    startup: &Startup,
    identity: &crate::identity::LocalIdentity,
    cfg: WorkConfig,
    node: hellas_sdk::FullNode,
) -> CliResult<hellas_sdk::node_control::host::HostHandle> {
    host_with_config(startup, identity, cfg, node, None).await
}

async fn host_with_config(
    startup: &Startup,
    identity: &crate::identity::LocalIdentity,
    cfg: WorkConfig,
    node: hellas_sdk::FullNode,
    path: Option<PathBuf>,
) -> CliResult<hellas_sdk::node_control::host::HostHandle> {
    let options = hellas_sdk::ProviderOptions {
        port: None,
        executor: ExecutorSpawnConfig::fetch_only(
            Arc::new(identity.node_key.clone()),
            Assurance::ProducerSigned,
            FetchRouteRegistry::default(),
        ),
        build: String::new(),
        graffiti: vec![],
        work: Some((
            hellas_sdk::paid_provider::WorkRunnerConfig {
                network: cfg.chain.network,
                journal_root: cfg.journal_root,
                poll: cfg.poll,
                max_observation_age: cfg.max_observation_age,
                settlement_key: crate::identity::settlement_signer(identity).unwrap(),
            },
            node.clone(),
        )),
        grants: None,
        discovery: false,
        secret_key: identity.transport_key.clone(),
        open_identity: identity.open_identity(),
    };
    startup.start(options, None, path, None).await
}

struct Case {
    root: tempfile::TempDir,
    faucet_root: PathBuf,
    identity_path: PathBuf,
    startup: Startup,
    identity: crate::identity::LocalIdentity,
    signer: Secp256k1Signer,
    provider_owner: GenesisOwner,
    devnet: Devnet,
    node: hellas_sdk::FullNode,
    cfg: WorkConfig,
    chain: hellas_chain::rpc::LocalLightClient,
    stored: StoredPaidPolicy,
    receipt_before: Vec<u8>,
    restarted: hellas_sdk::node_control::host::HostHandle,
}

#[test]
fn faucet_owner_approves_policy_delegates_and_funds_automatic_bonds_idempotently() {
    run(|runtime| async move {
        let case = Box::pin(allocate_case(runtime)).await;
        let case = Box::pin(shared_account_case(case)).await;
        Box::pin(override_case(case)).await;
    });
}

async fn allocate_case(runtime: commonware_runtime::tokio::Context) -> Box<Case> {
    let root = tempfile::tempdir().unwrap();
    let identity_path = root.path().join("identity");
    let cli = crate::Cli::try_parse_from(["hellas", "serve", "--faucet"]).unwrap();
    let owner = cli
        .owner
        .load_persistent(Some(&identity_path))
        .unwrap()
        .unwrap();
    let faucet_root = crate::owner::OwnerArgs::provider_root(Some(&identity_path)).unwrap();
    let index = std::fs::read(faucet_root.join("account")).unwrap()[0];
    let provider_owner = GenesisOwner::faucet(index);
    let requester = GenesisOwner::faucet((index + 1) % 100);
    assert_eq!(provider_owner.key().into_kernel(), owner.party_key());
    let startup = Startup::new(faucet_root.clone(), owner, PolicyArgs::default()).unwrap();
    let identity = crate::identity::load_or_create(Some(&identity_path)).unwrap();
    let signer = crate::identity::settlement_signer(&identity).unwrap();
    let mut devnet = Devnet::start(
        runtime,
        DevnetConfig {
            name: "cli_faucet_paid",
            owners: vec![provider_owner, requester],
            full_nodes: 1,
        },
    )
    .await;
    devnet.seal().await;
    let node = devnet.full_node(0).clone();
    let cfg = config(&devnet, &faucet_root);
    let provider = sealing(
        &mut devnet,
        host(&startup, &identity, cfg.clone(), node.clone()),
    )
    .await
    .unwrap();
    let admin = provider.administration().unwrap().unwrap();
    let stored = admin.node().paid_policy().await.unwrap().unwrap();
    assert_eq!(stored.revision, Revision(1));
    assert_eq!(stored.policy.payment_policy.fixed_price, 20);
    assert_eq!(stored.policy.jobs_per_channel, 10);
    assert_eq!(stored.policy.expected_payment_values.value(), 401);
    let WorkPolicy::Fetch {
        policy,
        contract,
        route,
    } = &stored.policy.work_policy
    else {
        panic!("real Fetch contract");
    };
    assert_eq!(contract, &hellas_rpc::FetchContract::http().unwrap());
    assert_eq!(policy.allowed_environment, contract.manifest_id());
    assert_eq!(policy.max_upload_bytes, 1024 * 1024);
    assert!(matches!(
        route,
        hellas_work::model::fetch::FetchRoutePolicy::OpenFetch {
            require_spki_pin: true,
            ..
        }
    ));
    let coins = devnet.coins(0, provider_owner.key(), []).await;
    let delegated: Vec<_> = coins
        .iter()
        .filter(|(_, c)| c.delegate == Some(signer.party_key().into()))
        .collect();
    assert_eq!(delegated.len(), 3);
    assert!(delegated.iter().all(|(_, c)| c.value == 12));
    assert!(
        coins
            .iter()
            .any(|(_, c)| c.value == 931_145 - 36 && c.delegate.is_none())
    );
    let receipt_before = std::fs::read(faucet_root.join("delegation.json")).unwrap();
    assert!(
        serde_json::from_slice::<Delegation>(&receipt_before)
            .unwrap()
            .confirmed
    );

    // The requester uses an independent published owner and settlement key.
    let client_key = Secp256k1Signer::from_secret_scalar([0x21; 32]).unwrap();
    let client_root = root.path().join("client");
    let client_owner = Arc::new(
        hellas_sdk::client_owner::ClientOwner::new(
            Arc::new(SoftPasskey::from_secret_scalar(requester.secret_scalar).unwrap()),
            client_key.party_key(),
            &client_root.join("funding"),
        )
        .unwrap(),
    );
    let endpoint = bind_paid_endpoint(iroh::SecretKey::generate())
        .await
        .unwrap();
    let server = provider.provider_endpoint().borrow().clone().unwrap();
    let options = PaidWorkOptions {
        config: cfg.clone(),
        journal_root: client_root.join("channels"),
        provider: server.id(),
        provider_addrs: server
            .bound_sockets()
            .into_iter()
            .filter(|a| a.is_ipv4())
            .map(|mut a| {
                a.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
                a
            })
            .collect(),
        assurance: Assurance::ProducerSigned,
        apple_trust: None,
        expected_price: 20,
        acceptance_blocks: 16,
        terminal_blocks: 64,
        payment_blocks: 32,
        timeout: hellas_chain::node::RECOVERY_TIMEOUT,
    };
    let quote = request_paid_quote(&options, &endpoint, &client_key, client_owner.principal())
        .await
        .unwrap();
    assert_eq!(quote.funding_value, 401);
    let mut session = sealing(
        &mut devnet,
        PaidWorkSession::open(options, endpoint.clone(), client_key.clone(), client_owner),
    )
    .await
    .unwrap();
    let bond = session
        .descriptor()
        .channel()
        .payment_terms()
        .bond_terms
        .clone();
    assert_eq!(
        bond.parties.maker().owner(),
        provider_owner.key().into_kernel()
    );
    assert_eq!(bond.parties.maker().signer(), signer.party_key());
    assert_eq!(
        bond.timeout_outputs.iter().map(|p| p.value()).sum::<u64>(),
        12
    );
    session.shutdown().await;
    endpoint.close().await;
    drop(session);
    drop(admin);
    provider.shutdown().await.unwrap();
    let resumed_cli = crate::Cli::try_parse_from(["hellas", "serve", "--faucet"]).unwrap();
    let resumed_owner = resumed_cli
        .owner
        .load_persistent(Some(&identity_path))
        .unwrap()
        .unwrap();
    assert_eq!(resumed_owner.party_key(), startup.owner.party_key());
    let before = devnet.coins(0, provider_owner.key(), []).await;
    let restarted = sealing(
        &mut devnet,
        host(&startup, &identity, cfg.clone(), node.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        restarted
            .administration()
            .unwrap()
            .unwrap()
            .node()
            .paid_policy()
            .await
            .unwrap()
            .unwrap(),
        stored
    );
    assert_eq!(
        std::fs::read(faucet_root.join("delegation.json")).unwrap(),
        receipt_before
    );
    assert_eq!(
        devnet.coins(0, provider_owner.key(), []).await,
        before,
        "restart cannot delegate change or replace consumed bond principal"
    );

    let chain = node.view().unwrap().client();
    Box::new(Case {
        root,
        faucet_root,
        identity_path,
        startup,
        identity,
        signer,
        provider_owner,
        devnet,
        node,
        cfg,
        chain,
        stored,
        receipt_before,
        restarted,
    })
}

async fn shared_account_case(case: Box<Case>) -> Box<Case> {
    let Case {
        root,
        faucet_root,
        identity_path,
        startup,
        identity,
        signer,
        provider_owner,
        mut devnet,
        node,
        cfg,
        chain,
        stored,
        receipt_before,
        restarted,
    } = *case;
    // A crash before receipt confirmation must recover even after the bond
    // has consumed one of the reshaped output coins.
    let mut interrupted: Delegation = serde_json::from_slice(&receipt_before).unwrap();
    interrupted.confirmed = false;
    hellas_private::write_atomically(
        &faucet_root.join("delegation.json"),
        ".crash",
        &serde_json::to_vec(&interrupted).unwrap(),
    )
    .unwrap();
    startup
        .delegate(&node, &signer, &stored.policy)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(faucet_root.join("delegation.json")).unwrap(),
        receipt_before
    );

    // A second provider sharing the public owner must spend its undelegated
    // change, leaving this node's remaining bond coins alone.
    let other_identity =
        crate::identity::load_or_create(Some(&root.path().join("other-identity"))).unwrap();
    let other = Startup::new(
        root.path().join("other"),
        startup.owner.clone(),
        PolicyArgs::default(),
    )
    .unwrap();
    let held = devnet.coins(0, provider_owner.key(), []).await;
    let own_before: Vec<_> = held
        .iter()
        .filter(|(_, c)| c.delegate == Some(signer.party_key().into()))
        .map(|(id, _)| *id)
        .collect();
    assert!(
        held.iter()
            .filter(|(_, c)| c.value >= 12)
            .min_by_key(|(id, c)| (c.value, *id))
            .unwrap()
            .1
            .delegate
            .is_some(),
        "the first unfiltered candidate is another provider's delegated coin"
    );
    let change = held.iter().find(|(_, c)| c.delegate.is_none()).unwrap().0;
    let other_config = config(&devnet, &other.root);
    let other_host = sealing(
        &mut devnet,
        host(&other, &other_identity, other_config, node.clone()),
    )
    .await
    .unwrap();
    let other_receipt: Delegation =
        serde_json::from_slice(&std::fs::read(other.root.join("delegation.json")).unwrap())
            .unwrap();
    assert_eq!(other_receipt.input, hex::encode(change.to_bytes()));
    let held = devnet.coins(0, provider_owner.key(), []).await;
    let own_after: Vec<_> = held
        .iter()
        .filter(|(_, c)| c.delegate == Some(signer.party_key().into()))
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(
        own_after, own_before,
        "another provider cannot reclaim this node's delegated stake"
    );
    other_host.shutdown().await.unwrap();

    // The input disappearing in another authorized spend is a conflict,
    // never proof that our planned delegation reached finality.
    use hellas_chain::domain::Encode as _;
    let input = held.iter().find(|(_, c)| c.delegate.is_none()).unwrap().0;
    let third_key = Secp256k1Signer::from_secret_scalar([0x25; 32]).unwrap();
    let third = Startup::new(
        root.path().join("conflict"),
        startup.owner.clone(),
        PolicyArgs::default(),
    )
    .unwrap();
    let intended = hellas_sdk::coin_owner::OwnerReshape::prepare(
        &chain,
        devnet.network(),
        startup.owner.party_key(),
        &[input],
        Some(third_key.party_key()),
        Some(12),
    )
    .await
    .unwrap();
    let digest = Digest::from(*intended.payload_hash().as_bytes());
    let intended = Transaction::Kernel(
        intended
            .authorize(
                kernel_auth(
                    &startup.owner.public_key().unwrap(),
                    &startup.owner.assert(digest).await.unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
    );
    let conflict = hellas_sdk::coin_owner::OwnerReshape::prepare(
        &chain,
        devnet.network(),
        startup.owner.party_key(),
        &[input],
        None,
        None,
    )
    .await
    .unwrap();
    let digest = Digest::from(*conflict.payload_hash().as_bytes());
    let conflict = Transaction::Kernel(
        conflict
            .authorize(
                kernel_auth(
                    &startup.owner.public_key().unwrap(),
                    &startup.owner.assert(digest).await.unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
    );
    let receipt = Delegation {
        genesis: interrupted.genesis.clone(),
        owner: hex::encode(startup.owner.party_key().to_bytes()),
        delegate: hex::encode(third_key.party_key().to_bytes()),
        input: hex::encode(input.to_bytes()),
        unit: 12,
        transaction: intended.encode().to_vec(),
        scan_from: devnet.height(),
        confirmed: false,
    };
    publish(
        &third.root.join("delegation.json"),
        &serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
    chain.submit_tx(conflict).await.unwrap();
    devnet.seal().await;
    let error = third
        .delegate(&node, &third_key, &stored.policy)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("another spend consumed"),
        "{error:#}"
    );

    Box::new(Case {
        root,
        faucet_root,
        identity_path,
        startup,
        identity,
        signer,
        provider_owner,
        devnet,
        node,
        cfg,
        chain,
        stored,
        receipt_before,
        restarted,
    })
}

async fn override_case(case: Box<Case>) {
    let Case {
        root: _root,
        faucet_root,
        identity_path: _identity_path,
        startup,
        identity,
        signer: _signer,
        provider_owner: _provider_owner,
        mut devnet,
        node,
        cfg,
        chain,
        stored,
        receipt_before: _receipt_before,
        restarted,
    } = *case;
    restarted.shutdown().await.unwrap();
    let lowering = Startup::new(
        faucet_root.clone(),
        startup.owner.clone(),
        PolicyArgs {
            stake: Some(5),
            ..Default::default()
        },
    )
    .unwrap();
    let error = sealing(
        &mut devnet,
        host(&lowering, &identity, cfg.clone(), node.clone()),
    )
    .await
    .err()
    .expect("ineffective lower stake cap is refused");
    assert!(
        error
            .to_string()
            .contains("lower stake cap has no eligible"),
        "{error:#}"
    );
    let store = NodeStore::open(
        &faucet_root.join("provider"),
        hellas_work::model::grant::grant_network(),
        Some(identity.enrollment.clone()),
        UnixMillis::now().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        store.state().paid_policy(),
        Some(&stored),
        "preflight refusal cannot change policy or salt"
    );
    drop(store);
    let overriding = Startup::new(
        faucet_root.clone(),
        startup.owner.clone(),
        PolicyArgs {
            price: Some(23),
            jobs: Some(7),
            upload: Some(2048),
            timeout: Some(2),
            ..Default::default()
        },
    )
    .unwrap();
    let overridden = sealing(
        &mut devnet,
        host(&overriding, &identity, cfg.clone(), node.clone()),
    )
    .await
    .unwrap();
    let changed = overridden
        .administration()
        .unwrap()
        .unwrap()
        .node()
        .paid_policy()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(changed.revision, Revision(2));
    assert_eq!(changed.policy.payment_policy.fixed_price, 23);
    assert_eq!(changed.policy.jobs_per_channel, 7);
    assert_eq!(changed.policy.expected_payment_values.value(), 323);
    assert_eq!(changed.policy.work_policy.max_upload_bytes(), 2048);
    overridden.shutdown().await.unwrap();
    let plain = Startup::new(
        faucet_root.clone(),
        startup.owner.clone(),
        PolicyArgs::default(),
    )
    .unwrap();
    assert_eq!(plain.policy.timeout, Some(2));
    let plain_host = sealing(&mut devnet, host(&plain, &identity, cfg, node.clone()))
        .await
        .unwrap();
    assert_eq!(
        plain_host
            .administration()
            .unwrap()
            .unwrap()
            .node()
            .paid_policy()
            .await
            .unwrap()
            .unwrap(),
        changed
    );
    plain_host.shutdown().await.unwrap();

    drop(chain);
    drop(node);
    devnet.shutdown().await;
}

#[test]
fn offline_devnet_payload() {
    use commonware_cryptography::Digestible as _;
    use hellas_chain::domain::DecodeExt as _;
    run(|runtime| async move {
        let genesis: hellas_chain::genesis::Genesis =
            serde_json::from_str(hellas_chain::genesis::HELLAS_DEVNET_1_JSON).unwrap();
        let leader = genesis
            .validators
            .iter()
            .map(|v| {
                hellas_chain::domain::PublicKey::decode(
                    hex::decode(&v.public_key).unwrap().as_slice(),
                )
                .unwrap()
            })
            .min()
            .unwrap();
        let allocations = genesis
            .allocations
            .iter()
            .map(|a| (a.address.parse().unwrap(), a.balance))
            .collect();
        let app = hellas_chain::Application::new(
            runtime,
            hellas_kernel::NetworkId::new(&genesis.network_id).unwrap(),
            hellas_chain::genesis_digest(&genesis),
            leader,
            allocations,
            "faucet_genesis_pin",
            hellas_chain::ApplicationConfig::default(),
        )
        .await;
        assert_eq!(
            hex::encode(app.genesis_block().digest()),
            hellas_chain::genesis::HELLAS_DEVNET_1_GENESIS_PAYLOAD.trim()
        );
    });
}

#[test]
fn embedded_defaults_validate_without_rpc_and_reject_identity_reselection() {
    let root = tempfile::tempdir().unwrap();
    let cfg = chain_defaults(root.path()).unwrap();
    assert_eq!(cfg.chain.network.as_str(), "hellas-devnet-1");
    assert_eq!(
        cfg.validators,
        (0..6)
            .map(|n| format!("wss://devnet.hellas.ai/ws/validator-{n}"))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        hex::encode(cfg.chain.genesis_payload_digest.as_bytes()),
        hellas_chain::genesis::HELLAS_DEVNET_1_GENESIS_PAYLOAD.trim()
    );
    let identity = root.path().join("identity");
    let cli = crate::Cli::try_parse_from(["hellas", "serve", "--faucet-account", "7"]).unwrap();
    let first = cli.owner.load_persistent(Some(&identity)).unwrap().unwrap();
    let cli = crate::Cli::try_parse_from(["hellas", "serve", "--faucet"]).unwrap();
    assert_eq!(
        cli.owner
            .load_persistent(Some(&identity))
            .unwrap()
            .unwrap()
            .party_key(),
        first.party_key()
    );
    let cli = crate::Cli::try_parse_from(["hellas", "serve", "--faucet-account", "8"]).unwrap();
    assert!(cli.owner.load_persistent(Some(&identity)).is_err());
    for args in [
        vec!["hellas", "serve", "--faucet", "--paid-price", "0"],
        vec![
            "hellas",
            "serve",
            "--faucet",
            "--paid-execution-timeout-secs",
            "18446744073709551615",
        ],
    ] {
        assert!(crate::Cli::try_parse_from(args).is_err());
    }
}

#[tokio::test]
async fn interrupted_faucet_bootstrap_reuses_prepared_owner_approval_credential_and_tls() {
    let root = tempfile::tempdir().unwrap();
    let identity = crate::identity::load_or_create(Some(&root.path().join("identity"))).unwrap();
    let owner = SoftPasskey::from_secret_scalar(GenesisOwner::faucet(7).secret_scalar).unwrap();
    let startup = Startup::new(root.path().join("faucet"), owner, PolicyArgs::default()).unwrap();
    let config = hellas_sdk::grant_config::GrantConfig::unconfigured(&startup.root);
    let first = startup
        .prepare(&config, &identity.enrollment, &identity.node_key)
        .await
        .unwrap()
        .unwrap();
    let certificate = std::fs::read(&config.control_certificate).unwrap();
    let key = std::fs::read(&config.control_private_key).unwrap();
    let approval = std::fs::read(startup.root.join("bootstrap.json")).unwrap();
    // Reproduce the on-disk state before the authority rename, after only the
    // certificate publication. Initialization must finish the prepared key pair.
    std::fs::remove_dir_all(&config.journal_root).unwrap();
    std::fs::remove_file(&config.control_private_key).unwrap();
    let resumed = startup
        .prepare(&config, &identity.enrollment, &identity.node_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resumed.id(), first.id());
    assert_eq!(resumed.expose_secret(), first.expose_secret());
    assert_eq!(
        std::fs::read(startup.root.join("bootstrap.json")).unwrap(),
        approval
    );
    assert_eq!(
        std::fs::read(&config.control_certificate).unwrap(),
        certificate
    );
    assert_eq!(std::fs::read(&config.control_private_key).unwrap(), key);
}
