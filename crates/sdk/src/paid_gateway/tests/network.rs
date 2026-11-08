use super::*;

#[test]
fn retained_gateway_policy_refuses_a_source_behind_its_journal() {
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
            let pool = pool_options(&fixture, &content);
            let mut args = pool
                .providers
                .into_iter()
                .next()
                .unwrap()
                .with_config(pool.config, pool.content);
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
                &args.journal_root(),
                devnet.network(),
                signed.offer().proposal.bond_edge(),
                Role::Client,
                &hellas_kernel::Secp256k1Verifier::new(),
            )
            .await
            .unwrap();
            store
                .commit(
                    SetupRecord::Offer {
                        peer: *args.provider.node.as_bytes(),
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
            // A source behind the journal's own height is refused at once:
            // absence at an older root says nothing, and nothing waits on it.
            let chain = chain.with_min_height(devnet.height() + 1);
            let read = |chain| {
                let args = args.clone();
                let endpoint = endpoint.clone();
                let key = key.clone();
                async move {
                    provider_policy(
                        &args,
                        crate::paid_client::offer::RetainedSetups::discover(
                            &args.journal_root(),
                            args.config.network(),
                            args.provider,
                        )
                        .await
                        .unwrap(),
                        chain,
                        &endpoint,
                        &key,
                        owner,
                    )
                    .await
                }
            };
            let error = read(chain.clone()).await.unwrap_err();
            assert!(
                matches!(
                    error,
                    PoolError::Client(PaidClientError::Query(
                        hellas_chain::QueryError::StateUnavailable(_)
                    ))
                ),
                "a source behind the journal is refused: {error}"
            );
            devnet.seal().await;
            assert_eq!(read(chain).await.unwrap(), fixture.policy);
            endpoint.close().await;
            devnet.shutdown().await;
        })
    });
}
