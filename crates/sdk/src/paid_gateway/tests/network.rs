use super::*;

#[test]
fn retained_gateway_policy_waits_for_chain_recovery_and_has_a_deadline() {
    use crate::test_support::{PaidFixture, signer};
    use hellas_chain::test_support::devnet::{Devnet, DevnetConfig, GenesisOwner, OwnerKind, run};
    use hellas_channel::model::offer::{PaidOffer, SignedPaidOffer};
    use hellas_channel::work_store::{Role, SetupRecord, SetupStore};
    run(|runtime| {
        Box::pin(async move {
            let mut devnet = Devnet::start(
                runtime,
                DevnetConfig {
                    name: "gateway_policy_recovery",
                    owners: vec![GenesisOwner {
                        kind: OwnerKind::Passkey,
                        secret_scalar: [0x13; 32],
                        balance: 1,
                    }],
                    full_nodes: 1,
                },
            )
            .await;
            devnet.seal().await;
            let fixture = PaidFixture::on_network(devnet.network());
            let content = hellas_authority::test_support::content_store(
                &fixture.root.path().join("pool-content"),
            )
            .await;
            let mut args = pool_options(&fixture, &content).providers.remove(0);
            args.timeout = Some(hellas_chain::node::RECOVERY_TIMEOUT);
            let signed = SignedPaidOffer::sign(
                PaidOffer {
                    provider: crate::test_support::enrollment(args.provider.node).0,
                    proposal: fixture.proposal.clone(),
                    policy: fixture.policy.clone(),
                    omission_bond: 601,
                    payment_funding: hellas_kernel::Funding::new(
                        hellas_kernel::List::take(
                            [hellas_kernel::CoinId::from_bytes([1; 32]); 4],
                            1,
                        ),
                        hellas_kernel::List::empty(hellas_kernel::CoinId::from_bytes([0; 32])),
                    ),
                    addresses: vec![],
                },
                &signer(2),
            )
            .unwrap();
            let mut store = SetupStore::open(
                &args.journal_root,
                devnet.network(),
                signed.offer().proposal.bond_edge(),
                Role::Client,
                &hellas_kernel::Secp256k1Verifier::new(),
                Default::default(),
            )
            .await
            .unwrap();
            store
                .commit(
                    SetupRecord::Offer {
                        peer: *args.provider.node.as_bytes(),
                        floor: None,
                        offer: Box::new(signed),
                    },
                    &hellas_kernel::Secp256k1Verifier::new(),
                )
                .await
                .unwrap();
            drop(store);
            let node = devnet.full_node(0).clone();
            let chain = hellas_chain::WorkBlocks::new(node.view().unwrap().client());
            let endpoint = bind_paid_endpoint(iroh::SecretKey::from_bytes(&[0x54; 32]))
                .await
                .unwrap();
            let owner = hellas_auth::test_support::actors::FRIEND.principal();
            let key = signer(1);
            let chain = chain.with_min_height(devnet.height() + 1);
            let policy = {
                let read = provider_policy(
                    &args,
                    crate::paid_client::offer::RetainedSetups::discover(
                        &args.journal_root,
                        args.config.chain.network,
                        args.provider,
                        Default::default(),
                    )
                    .await
                    .unwrap(),
                    chain.clone(),
                    &endpoint,
                    &key,
                    owner,
                );
                tokio::pin!(read);
                assert!(
                    tokio::time::timeout(args.config.poll, &mut read)
                        .await
                        .is_err()
                );
                let (policy, _) = tokio::join!(read, devnet.seal());
                policy.unwrap()
            };
            assert_eq!(policy, fixture.policy);
            args.timeout = Some(Duration::from_millis(100));
            let chain = chain.with_min_height(devnet.height() + 1);
            let started = tokio::time::Instant::now();
            let error = tokio::time::timeout(
                Duration::from_secs(5),
                provider_policy(
                    &args,
                    crate::paid_client::offer::RetainedSetups::discover(
                        &args.journal_root,
                        args.config.chain.network,
                        args.provider,
                        Default::default(),
                    )
                    .await
                    .unwrap(),
                    chain,
                    &endpoint,
                    &key,
                    owner,
                ),
            )
            .await
            .unwrap()
            .unwrap_err();
            assert!(
                matches!(error, PoolError::Client(PaidClientError::Query(hellas_chain::QueryError::ReadUnavailableTimeout { timeout, .. })) if Some(timeout) == args.timeout),
                "bounded gateway policy expiry: {error}"
            );
            assert!(started.elapsed() >= args.timeout.unwrap());
            endpoint.close().await;
            devnet.shutdown().await;
        })
    });
}
