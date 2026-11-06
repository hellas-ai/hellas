use super::*;
use hellas_chain::test_support::devnet::{Devnet, DevnetConfig, GenesisOwner, OwnerKind, run};
use hellas_kernel::{Payout, Secp256k1Signer, SoftPasskey};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Approval {
    key: SoftPasskey,
    count: AtomicUsize,
    pause: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
}
impl Approval {
    fn new() -> Self {
        Self {
            key: SoftPasskey::from_secret_scalar([0x13; 32]).unwrap(),
            count: AtomicUsize::new(0),
            pause: AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
        }
    }
}
#[async_trait::async_trait]
impl Authenticator for Approval {
    fn public_key(&self) -> Result<PublicKey, AuthorityError> {
        self.key.public_key()
    }
    async fn assert(
        &self,
        challenge: Digest,
    ) -> Result<hellas_auth::authority::PasskeyAssertion, AuthorityError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        if self.pause.load(Ordering::SeqCst) {
            self.release.acquire().await.unwrap().forget();
        }
        self.key.assert(challenge).await
    }
}
#[derive(Default)]
struct Gate {
    approved: AtomicUsize,
    requests: AtomicUsize,
    recovered: AtomicUsize,
}
impl crate::paid_client::FundingApproval for Gate {
    fn reservation(&self, _: NetworkId, _: iroh::EndpointId) -> [u8; 16] {
        [7; 16]
    }
    fn reserve(
        &self,
        id: [u8; 16],
        amount: u64,
    ) -> futures::future::BoxFuture<'_, std::result::Result<(), crate::paid_client::PaidClientError>>
    {
        Box::pin(async move {
            assert_eq!((id, amount), ([7; 16], 200));
            self.requests.fetch_add(1, Ordering::SeqCst);
            self.approved.store(1, Ordering::SeqCst);
            Ok(())
        })
    }
    fn recover(
        &self,
        id: [u8; 16],
        amount: u64,
    ) -> futures::future::BoxFuture<'_, std::result::Result<(), crate::paid_client::PaidClientError>>
    {
        Box::pin(async move {
            assert_eq!((id, amount), ([7; 16], 200));
            self.recovered.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}
struct Deny;
impl crate::paid_client::FundingApproval for Deny {
    fn reservation(&self, _: NetworkId, _: iroh::EndpointId) -> [u8; 16] {
        [9; 16]
    }
    fn reserve(
        &self,
        _: [u8; 16],
        _: u64,
    ) -> futures::future::BoxFuture<'_, std::result::Result<(), crate::paid_client::PaidClientError>>
    {
        Box::pin(async {
            Err(crate::paid_client::PaidClientError::InvalidOptions(
                "denied",
            ))
        })
    }
    fn recover(
        &self,
        _: [u8; 16],
        _: u64,
    ) -> futures::future::BoxFuture<'_, std::result::Result<(), crate::paid_client::PaidClientError>>
    {
        Box::pin(async {
            Err(crate::paid_client::PaidClientError::InvalidOptions(
                "denied",
            ))
        })
    }
}
const OWNER: GenesisOwner = GenesisOwner {
    kind: OwnerKind::Passkey,
    secret_scalar: [0x13; 32],
    balance: 1000,
};
fn delegate() -> Key {
    Secp256k1Signer::from_secret_scalar([0x21; 32])
        .unwrap()
        .party_key()
}
fn provider(n: u8) -> iroh::EndpointId {
    iroh::SecretKey::from_bytes(&[n; 32]).public()
}

#[test]
fn owner_state_uses_the_consensus_digest() {
    let home = tempfile::tempdir().unwrap();
    let network = NetworkId::new("same-sdk-network").unwrap();
    let first = crate::test_support::chain_dir_with_variant(home.path(), network, 1);
    let second = crate::test_support::chain_dir_with_variant(home.path(), network, 2);
    assert_eq!(first.network_id(), second.network_id());
    let approval = Arc::new(Approval::new());
    let a = ClientOwner::new(approval.clone(), delegate(), &first).unwrap();
    let b = ClientOwner::new(approval, delegate(), &second).unwrap();
    assert_ne!(a.root, b.root);
    assert_eq!(a.chain().as_path(), first.as_path());
    assert_eq!(b.chain().as_path(), second.as_path());
}
async fn sealing<T>(devnet: &mut Devnet, work: impl Future<Output = T>) -> T {
    tokio::time::timeout(hellas_chain::node::RECOVERY_TIMEOUT.saturating_mul(2), async {
        tokio::pin!(work);
        loop {
            tokio::select! { output = &mut work => return output, () = tokio::time::sleep(Duration::from_millis(500)) => {} }
            let seal = devnet.seal(); tokio::pin!(seal);
            tokio::select! { output = &mut work => { seal.await; return output }, _ = &mut seal => {} }
        }
    }).await.unwrap()
}
#[test]
fn durable_funding_retries_one_signature_and_reserves_other_providers() {
    run(|runtime| {
        Box::pin(async move {
            let root = tempfile::tempdir().unwrap();
            let mut devnet = Devnet::start(
                runtime,
                DevnetConfig {
                    name: "client_wallet",
                    owners: vec![OWNER],
                    full_nodes: 0,
                },
            )
            .await;
            let state = crate::test_support::chain_dir_with_genesis(root.path(), devnet.genesis());
            devnet.seal().await;
            let chain =
                RemoteLightClient::connect(devnet.light_client_url(0), devnet.proof_verifier())
                    .await
                    .unwrap();
            let approval = Arc::new(Approval::new());
            let gate = Gate::default();
            let owner = ClientOwner::new(approval.clone(), delegate(), &state).unwrap();
            assert!(matches!(
                ClientOwner::new(approval.clone(), delegate(), &state),
                Err(ClientOwnerError::Locked(_))
            ));
            assert!(
                owner
                    .fund_with_approval(
                        &chain,
                        provider(3),
                        200,
                        FundingControls {
                            poll: Duration::from_millis(10),
                            timeout: hellas_chain::node::RECOVERY_TIMEOUT,
                            approval: Some(&Deny),
                            before_sign: None,
                        },
                    )
                    .await
                    .is_err()
            );
            assert_eq!(approval.count.load(Ordering::SeqCst), 0);
            assert!(owner.records().unwrap().is_empty());
            approval.pause.store(true, Ordering::SeqCst);
            {
                let funding = owner.fund_with_approval(
                    &chain,
                    provider(3),
                    200,
                    FundingControls {
                        poll: Duration::from_millis(10),
                        timeout: hellas_chain::node::RECOVERY_TIMEOUT,
                        approval: Some(&gate),
                        before_sign: None,
                    },
                );
                tokio::pin!(funding);
                tokio::select! {
                    result = &mut funding => panic!("funding completed before owner approval: {result:?}"),
                    () = approval.entered.notified() => {},
                }
            }
            assert!(owner.records().unwrap().is_empty());
            assert_eq!(gate.approved.load(Ordering::SeqCst), 1);
            approval.pause.store(false, Ordering::SeqCst);
            {
                let funding = owner.fund_with_approval(
                    &chain,
                    provider(3),
                    200,
                    FundingControls {
                        poll: Duration::from_millis(10),
                        timeout: hellas_chain::node::RECOVERY_TIMEOUT,
                        approval: Some(&gate),
                        before_sign: None,
                    },
                );
                tokio::pin!(funding);
                tokio::time::timeout(Duration::from_secs(10), async {
                tokio::select! {
                    result = &mut funding => panic!("funding completed before a block was sealed: {result:?}"),
                    () = async { while owner.records().unwrap().is_empty() { tokio::task::yield_now().await; } } => {},
                }
            }).await.expect("the signed approval reaches durable storage before cancellation");
                // Let the original signed intent reach the validator, then
                // finalize it without polling the caller's response.
                tokio::select! {
                    result = &mut funding => panic!("funding completed without finality: {result:?}"),
                    () = tokio::time::sleep(Duration::from_millis(300)) => {},
                }
                let (_, _, reshape) = owner.records().unwrap().remove(0);
                let output =
                    Reshape::output_ids(devnet.network(), reshape.inputs(), reshape.outputs())
                        .as_slice()[0];
                tokio::time::timeout(Duration::from_secs(20), devnet.seal())
                    .await
                    .expect("funding block finalized");
                let snapshot = tokio::time::timeout(
                    Duration::from_secs(20),
                    devnet
                        .validator_light_client(0)
                        .get_objects(vec![coin_object_id(output)]),
                )
                .await
                .expect("funding proof returned")
                .unwrap()
                .unwrap();
                assert!(
                    snapshot.objects.contains_key(&coin_object_id(output)),
                    "original funding was finalized before the response was lost"
                );
            }
            assert_eq!(approval.count.load(Ordering::SeqCst), 2);
            let approved = owner.records().unwrap().remove(0).1.reshape;
            assert_eq!(gate.approved.load(Ordering::SeqCst), 1);
            assert_eq!(gate.requests.load(Ordering::SeqCst), 2);
            // Simulate interruption after the signed archive but before
            // publishing the active record.
            std::fs::remove_file(owner.path(provider(3))).unwrap();
            drop(owner);
            let owner = ClientOwner::new(approval.clone(), delegate(), &state).unwrap();
            let network = devnet.network();
            let first = sealing(
                &mut devnet,
                owner.fund_with_approval(
                    &chain,
                    provider(3),
                    200,
                    FundingControls {
                        poll: Duration::from_millis(10),
                        timeout: hellas_chain::node::RECOVERY_TIMEOUT,
                        approval: Some(&gate),
                        before_sign: None,
                    },
                ),
            )
            .await
            .unwrap();
            assert_eq!(
                owner.records().unwrap().remove(0).1.reshape,
                approved,
                "retry submits the identical durable approval"
            );
            assert_eq!(approval.count.load(Ordering::SeqCst), 2);
            assert_eq!(gate.approved.load(Ordering::SeqCst), 1);
            assert_eq!(gate.recovered.load(Ordering::SeqCst), 1);
            let intents = owner.funding_intents().await.unwrap();
            assert_eq!(intents.len(), 1);
            assert_eq!(intents[0].reservation, [7; 16]);
            assert_eq!(intents[0].network, network);
            assert_eq!(intents[0].provider, provider(3));
            assert_eq!(intents[0].amount, 200);
            assert_eq!(intents[0].funding, first);
            let recovered = owner
                .recover_funding_intent(
                    &chain,
                    provider(3),
                    [7; 16],
                    FundingControls {
                        poll: Duration::from_millis(10),
                        timeout: hellas_chain::node::RECOVERY_TIMEOUT,
                        approval: Some(&gate),
                        before_sign: None,
                    },
                )
                .await
                .unwrap();
            assert_eq!(recovered, first);
            assert_eq!(gate.approved.load(Ordering::SeqCst), 1);
            assert_eq!(gate.recovered.load(Ordering::SeqCst), 2);
            assert_eq!(approval.count.load(Ordering::SeqCst), 2);
            let (parallel_a, parallel_b) = tokio::join!(
                owner.fund_with_approval(
                    &chain,
                    provider(3),
                    200,
                    FundingControls {
                        poll: Duration::from_millis(10),
                        timeout: hellas_chain::node::RECOVERY_TIMEOUT,
                        approval: Some(&gate),
                        before_sign: None,
                    }
                ),
                owner.fund_with_approval(
                    &chain,
                    provider(3),
                    200,
                    FundingControls {
                        poll: Duration::from_millis(10),
                        timeout: hellas_chain::node::RECOVERY_TIMEOUT,
                        approval: Some(&gate),
                        before_sign: None,
                    }
                ),
            );
            assert_eq!(parallel_a.unwrap(), first);
            assert_eq!(parallel_b.unwrap(), first);
            assert_eq!(gate.approved.load(Ordering::SeqCst), 1);
            assert_eq!(gate.requests.load(Ordering::SeqCst), 2);
            assert_eq!(approval.count.load(Ordering::SeqCst), 2);
            let (second, third) = sealing(&mut devnet, async {
                tokio::join!(
                    owner.fund(
                        &chain,
                        provider(4),
                        200,
                        Duration::from_millis(10),
                        hellas_chain::node::RECOVERY_TIMEOUT
                    ),
                    owner.fund(
                        &chain,
                        provider(5),
                        200,
                        Duration::from_millis(10),
                        hellas_chain::node::RECOVERY_TIMEOUT
                    )
                )
            })
            .await;
            let second = second.unwrap();
            let third = third.unwrap();
            let coins: BTreeSet<_> = [first, second, third]
                .into_iter()
                .map(|funding| funding.maker().as_slice()[0])
                .collect();
            assert_eq!(
                coins.len(),
                3,
                "parallel providers receive disjoint exact funding"
            );
            assert_eq!(approval.count.load(Ordering::SeqCst), 4);
            let snapshot = chain
                .get_objects(coins.into_iter().map(coin_object_id).collect())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(snapshot.objects.len(), 3);
            for object in snapshot.objects.values() {
                let Object::Coin(coin) = object else {
                    panic!("coin")
                };
                assert_eq!(coin.value, 200);
                assert_eq!(coin.delegate, Some(delegate().into()));
            }
            devnet.shutdown().await;
        })
    });
}

#[test]
fn competing_owner_spend_releases_conflicted_inputs_for_another_provider() {
    run(|runtime| {
        Box::pin(async move {
            let root = tempfile::tempdir().unwrap();
            let owner_spec = GenesisOwner {
                balance: 400,
                ..OWNER
            };
            let mut devnet = Devnet::start(
                runtime,
                DevnetConfig {
                    name: "client_wallet_conflict",
                    owners: vec![owner_spec],
                    full_nodes: 0,
                },
            )
            .await;
            let state = crate::test_support::chain_dir_with_genesis(root.path(), devnet.genesis());
            devnet.seal().await;
            let chain =
                RemoteLightClient::connect(devnet.light_client_url(0), devnet.proof_verifier())
                    .await
                    .unwrap();
            let genesis =
                hellas_chain::test_support::devnet::genesis_coin(devnet.allocations(), OWNER.key());
            let inputs = List::take([genesis; hellas_kernel::MAX_EDGE_INPUTS], 1);
            let payouts = List::take([Payout::new(OWNER.key().into_kernel(), 200); 4], 2);
            let auth =
                owner_spec.authorize(Reshape::payload_hash(devnet.network(), &inputs, &payouts));
            let split = Reshape::new(inputs, payouts, auth);
            let ids = Reshape::output_ids(devnet.network(), split.inputs(), split.outputs());
            chain
                .submit_tx(Transaction::Kernel(Tx::Owner(split)))
                .await
                .unwrap();
            devnet.seal().await;
            let approval = Arc::new(Approval::new());
            approval.pause.store(true, Ordering::SeqCst);
            let owner = ClientOwner::new(approval.clone(), delegate(), &state).unwrap();
            let funding = owner.fund(
                &chain,
                provider(3),
                300,
                Duration::from_millis(10),
                hellas_chain::node::RECOVERY_TIMEOUT,
            );
            tokio::pin!(funding);
            tokio::select! { result = &mut funding => panic!("approval was not held: {result:?}"), () = approval.entered.notified() => {} }
            let competing = OwnerReshape::prepare(
                &chain,
                devnet.network(),
                OWNER.key().into_kernel(),
                &ids.as_slice()[..1],
                Some(
                    Secp256k1Signer::from_secret_scalar([0x22; 32])
                        .unwrap()
                        .party_key(),
                ),
                None,
            )
            .await
            .unwrap();
            chain
                .submit_tx(Transaction::Kernel(
                    competing
                        .clone()
                        .authorize(owner_spec.authorize(competing.payload_hash()))
                        .unwrap(),
                ))
                .await
                .unwrap();
            devnet.seal().await;
            approval.pause.store(false, Ordering::SeqCst);
            approval.release.add_permits(1);
            assert!(
                matches!(funding.await, Err(ClientOwnerError::InputsSpent)),
                "missing inputs cannot imply successful funding"
            );
            assert!(
                owner
                    .records()
                    .unwrap()
                    .iter()
                    .any(|(_, record, _)| record.state == FundingState::Conflicted)
            );
            let other = sealing(
                &mut devnet,
                owner.fund(
                    &chain,
                    provider(4),
                    100,
                    Duration::from_millis(10),
                    hellas_chain::node::RECOVERY_TIMEOUT,
                ),
            )
            .await
            .unwrap();
            assert_eq!(approval.count.load(Ordering::SeqCst), 2);
            assert_eq!(
                chain
                    .get_objects(other.maker().iter().copied().map(coin_object_id).collect())
                    .await
                    .unwrap()
                    .unwrap()
                    .objects
                    .len(),
                1
            );
            let retry = sealing(
                &mut devnet,
                owner.fund(
                    &chain,
                    provider(3),
                    100,
                    Duration::from_millis(10),
                    hellas_chain::node::RECOVERY_TIMEOUT,
                ),
            )
            .await
            .unwrap();
            assert_ne!(
                retry, other,
                "the conflicted provider can approve fresh, unreserved change"
            );
            assert_eq!(approval.count.load(Ordering::SeqCst), 3);
            devnet.shutdown().await;
        })
    });
}
