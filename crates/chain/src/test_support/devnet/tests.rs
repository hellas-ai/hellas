use super::*;
use crate::client::RemoteLightClient;
use crate::light_client::FinalizedBlockQuery;

async fn coin(client: &impl crate::LightClient, id: CoinId) -> Option<Coin> {
    let key = crate::domain::ObjectKey::Coin(id);
    let snapshot = client.get_objects(vec![key]).await.unwrap().unwrap();
    snapshot.coin(id).unwrap()
}

#[test]
fn a_public_faucet_passkey_spends_on_all_six_validators() {
    run(|runtime| async move {
        let owners: Vec<_> = (0..100).map(GenesisOwner::faucet).collect();
        let published: Vec<crate::genesis::FaucetAccount> =
            serde_json::from_str(crate::genesis::HELLAS_DEVNET_3_FAUCET_JSON).unwrap();
        for (owner, account) in owners.iter().zip(&published) {
            assert_eq!(owner.key().to_string(), account.address);
        }
        let sender = owners[7];
        let recipient = owners[8];
        let mut devnet = Devnet::start(
            runtime,
            DevnetConfig {
                name: "faucet_spend",
                owners,
                full_nodes: 1,
            },
        )
        .await;
        devnet.seal().await;
        let input = genesis_coin(devnet.allocations(), sender.key());
        let recipient_genesis = genesis_coin(devnet.allocations(), recipient.key());
        let (tx, outputs) = reshape_authorized(
            &[coin_object_id(input)],
            &[(recipient.key(), None, 42), (sender.key(), None, 931_103)],
            |hash| sender.authorize(hash),
        );
        assert_eq!(
            devnet.light_client(0).submit_tx(tx).await.unwrap(),
            crate::SubmitTxOutcome::Enqueued
        );
        let block = devnet.seal().await;
        assert_eq!(block.txs().len(), 1);
        for validator in 0..VALIDATORS {
            let client = devnet.validator_light_client(validator);
            assert!(coin(&client, input).await.is_none());
            for (output, owner, value) in [
                (outputs[0], recipient.key(), 42),
                (outputs[1], sender.key(), 931_103),
            ] {
                let coin = coin(&client, CoinId::from_bytes(output.0)).await.unwrap();
                assert_eq!(
                    (coin.owner, coin.value, coin.delegate),
                    (owner, value, None)
                );
            }
        }
        let candidates = [
            input,
            recipient_genesis,
            CoinId::from_bytes(outputs[0].0),
            CoinId::from_bytes(outputs[1].0),
        ];
        assert_eq!(
            devnet
                .coins(0, sender.key(), candidates)
                .await
                .iter()
                .map(|(_, c)| c.value)
                .sum::<u64>(),
            931_103
        );
        assert_eq!(
            devnet
                .coins(0, recipient.key(), candidates)
                .await
                .iter()
                .map(|(_, c)| c.value)
                .sum::<u64>(),
            931_187
        );
        devnet.shutdown().await;
    });
}

#[test]
fn a_full_node_recovers_when_its_chain_sync_source_returns_after_an_outage() {
    run(|runtime| async move {
        let owner = GenesisOwner {
            kind: OwnerKind::Native,
            secret_scalar: [0x43; 32],
            balance: 7,
        };
        let mut devnet = Devnet::start(
            runtime,
            DevnetConfig {
                name: "devnet_sync_recovery",
                owners: vec![owner],
                full_nodes: 1,
            },
        )
        .await;
        devnet.seal().await;
        let (tx, _) = delegate_allocation(
            devnet.allocations(),
            &owner,
            native_signer([0x44; 32]).party_key().into(),
        );
        assert_eq!(
            devnet
                .validator_light_client(0)
                .submit_tx(tx)
                .await
                .unwrap(),
            crate::SubmitTxOutcome::Enqueued,
        );

        // Stop the actual transport, including its existing subscriptions.
        // Keep its address so the node's ordinary reconnect path can recover.
        let validator = &devnet.validators[0];
        validator.sync_task.abort();
        // `run` bounds a hang for the whole fixture.
        while !validator.sync_task.is_finished() {
            tokio::task::yield_now().await;
        }
        let (indexer, events, endpoint, database, verifier) = (
            validator.indexer.archive.clone(),
            devnet.sealer.activity[0].clone(),
            validator.sync_endpoint.clone(),
            validator.database.clone(),
            devnet.sealer.fixture.verifier.clone(),
        );
        let started = tokio::time::Instant::now();
        // Long enough for several failed reconnects with growing backoff. The
        // reconnect loop has no attempt limit, so a longer outage only waits.
        let outage = std::time::Duration::from_secs(2);
        devnet.rpc.spawn(async move {
            tokio::time::sleep_until(started + outage).await;
            crate::node::transport::serve_validator_endpoint(
                indexer, events, endpoint, database, verifier,
            )
            .await;
        });
        let block = devnet.seal().await;
        assert_eq!(block.txs().len(), 1, "recovery executes a nonempty block");
        assert!(started.elapsed() >= outage);
        assert_eq!(
            devnet
                .light_client(0)
                .get_latest_block()
                .await
                .unwrap()
                .unwrap()
                .payload,
            block.digest(),
            "the recovered node executed the certified block, not just a notification",
        );
        devnet.shutdown().await;
    });
}

/// A client with no node of its own reads each validator over its
/// light-client URL, checks every answer against the committee the
/// genesis document names, and gets the block a full node that
/// executed the chain itself holds. A verifier for another committee
/// refuses the same answers, so the agreement is the verifier's and
/// not merely the wire's.
#[test]
fn a_remote_light_client_verifies_the_block_a_full_node_finalized() {
    run(|runtime| async move {
        let owner = GenesisOwner {
            kind: OwnerKind::Passkey,
            secret_scalar: [0x41; 32],
            balance: 7,
        };
        let mut devnet = Devnet::start(
            runtime,
            DevnetConfig {
                name: "devnet_remote",
                owners: vec![owner],
                full_nodes: 1,
            },
        )
        .await;
        assert_eq!(devnet.light_client_urls().len(), VALIDATORS);

        // The owner's key file is a software passkey for the funded key.
        let scalar: [u8; 32] = std::fs::read(devnet.owner_key_file(&owner))
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            SettlementKey::from(
                hellas_kernel::SoftPasskey::from_secret_scalar(scalar)
                    .unwrap()
                    .party_key()
            ),
            owner.key(),
        );

        // A non-empty block, submitted by a client with no node.
        devnet.seal().await;
        let node_key = SettlementKey::from(native_signer([0x42; 32]).party_key());
        let (tx, delegated) = delegate_allocation(devnet.allocations(), &owner, node_key);
        let submitter =
            RemoteLightClient::connect(devnet.light_client_url(3), devnet.proof_verifier())
                .await
                .unwrap();
        assert_eq!(
            submitter.submit_tx(tx).await.unwrap(),
            crate::SubmitTxOutcome::Enqueued,
        );
        let block = devnet.seal().await;
        assert_eq!(block.txs().len(), 1, "the submitted reshape is finalized");

        let full_node = devnet.light_client(0);
        let latest = full_node.get_latest_block().await.unwrap().unwrap();
        assert_eq!(latest.height, 2);
        assert_eq!(latest.payload, block.digest());
        let finalized = full_node
            .get_finalized_block(FinalizedBlockQuery::Height(2))
            .await
            .unwrap()
            .unwrap();
        for url in devnet.light_client_urls() {
            let remote = RemoteLightClient::connect(url.clone(), devnet.proof_verifier())
                .await
                .unwrap();
            assert_eq!(
                remote.get_latest_block().await.unwrap().as_ref(),
                Some(&latest),
                "{url}",
            );
            assert_eq!(
                remote
                    .get_finalized_block(FinalizedBlockQuery::Height(2))
                    .await
                    .unwrap()
                    .as_ref(),
                Some(&finalized),
                "{url}",
            );
            let held = remote
                .get_holdings(owner.key(), None)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                held.owned_coins(owner.key())
                    .into_iter()
                    .map(|(id, coin)| (id, coin.value))
                    .collect::<Vec<_>>(),
                vec![(delegated, owner.balance)],
                "{url}",
            );

            let stranger = crate::execution::test_support::consensus_fixture_in(
                rand::random(),
                VALIDATORS as u64,
                TEST_NETWORK,
                crate::genesis_digest(devnet.genesis()),
            );
            let profile = devnet.profile(0);
            let mut trust = profile.trust().clone();
            trust.epochs[0].threshold_identity =
                hex::encode(stranger.assembler.identity().encode());
            let foreign = std::sync::Arc::new(
                crate::proof_verify::ProofVerifier::with_digest(trust, profile.consensus_digest())
                    .unwrap(),
            );
            let refused = RemoteLightClient::connect(url.clone(), foreign)
                .await
                .unwrap();
            assert!(
                refused.get_latest_block().await.is_err(),
                "another committee's verifier refuses {url}",
            );
        }
        devnet.shutdown().await;
    });
}

#[test]
fn unwinding_keeps_fixture_storage_until_aborted_tasks_finish() {
    use commonware_runtime::Spawner as _;
    use futures::FutureExt as _;
    use std::panic::AssertUnwindSafe;

    run(|runtime| async move {
        let mut devnet = Devnet::start(
            runtime.child("fixture"),
            DevnetConfig {
                name: "unwind_storage",
                owners: vec![GenesisOwner::faucet(0)],
                full_nodes: 0,
            },
        )
        .await;
        let path = devnet.storage().to_owned();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let (finished, stopped) = tokio::sync::oneshot::channel();
        struct CleanupProbe {
            path: PathBuf,
            released: std::sync::mpsc::Receiver<()>,
            finished: Option<tokio::sync::oneshot::Sender<bool>>,
        }
        impl Drop for CleanupProbe {
            fn drop(&mut self) {
                // Observe only after the primary fixture's Drop has returned.
                let _ = self.released.recv();
                let _ = self.finished.take().unwrap().send(self.path.exists());
            }
        }
        let probe = runtime.child("cleanup_probe").spawn(move |_| async move {
            let _probe = CleanupProbe {
                path,
                released,
                finished: Some(finished),
            };
            let _ = started.send(());
            std::future::pending::<()>().await;
        });
        let archive = std::mem::replace(&mut devnet.validators[0].task, probe);
        archive.abort();
        let _ = archive.await;
        ready.await.unwrap();
        let panic = AssertUnwindSafe(async move {
            let _fixture = devnet;
            panic!("intentional fixture unwind");
        })
        .catch_unwind()
        .await;
        assert!(panic.is_err());
        release.send(()).unwrap();
        assert!(
            tokio::time::timeout(hellas_channel::test_support::HANG_GUARD, stopped)
                .await
                .unwrap()
                .unwrap(),
            "fixture storage was removed before task cleanup"
        );
    });
}
