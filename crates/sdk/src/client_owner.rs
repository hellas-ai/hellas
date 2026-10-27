//! Owner-approved channel funding, serialized across a requester's providers.
use crate::coin_owner::{CoinOwnerError, OwnerReshape};
use hellas_auth::{
    Digest,
    authority::{AuthorityError, PrincipalId},
};
use hellas_chain::{
    LightClient as _, QueryError,
    client::RemoteLightClient,
    domain::{Object, Transaction, coin_object_id},
};
use hellas_kernel::{
    CoinId, Decode as _, Encode as _, Funding, Key, List, NetworkId, Reshape, Secp256k1Verifier,
    SigVerifier, Tx,
};
use hellas_work::authenticator::{Authenticator, PublicKey, kernel_auth};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[derive(Debug, thiserror::Error)]
pub enum ClientOwnerError {
    #[error(transparent)]
    Approval(#[from] AuthorityError),
    #[error(transparent)]
    Plan(#[from] CoinOwnerError),
    #[error(transparent)]
    Chain(#[from] QueryError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("invalid client funding record: {0}")]
    Record(&'static str),
    #[error("client funding wallet is already open: {0}")]
    Locked(String),
    #[error("owner funding timed out after {0:?}")]
    Timeout(Duration),
    #[error("owner funding inputs changed; retry to approve a fresh exact split")]
    InputsSpent,
}

/// The requester's passkey and funding metadata. It starts no authority or node.
/// Clones of its Arc share both the prompt lock and pending coin reservations.
pub struct ClientOwner {
    authenticator: Arc<dyn Authenticator>,
    public: PublicKey,
    principal: PrincipalId,
    owner: Key,
    delegate: Key,
    root: PathBuf,
    serial: tokio::sync::Mutex<()>,
    _writer: std::fs::File,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum FundingState {
    Pending,
    Offered,
    Conflicted,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    network: String,
    provider: String,
    need: u64,
    reshape: String,
    state: FundingState,
    floor_height: u64,
    floor_payload: [u8; 32],
}

impl ClientOwner {
    pub fn new(
        authenticator: Arc<dyn Authenticator>,
        delegate: Key,
        root: &Path,
    ) -> Result<Self, ClientOwnerError> {
        let public = authenticator.public_key()?;
        let principal =
            PrincipalId::from_public_key(hellas_auth::PublicKey::P256(public.to_compressed()))?;
        let owner = Key::from_bytes(public.to_compressed());
        let root = root.join(format!(
            "{}-{}",
            hex::encode(owner.to_bytes()),
            hex::encode(delegate.to_bytes())
        ));
        hellas_private::create_dir_all_durable(&root)?;
        let writer = hellas_private::open_lock_beside(&root.join("writer"))?;
        writer
            .try_lock()
            .map_err(|error| ClientOwnerError::Locked(error.to_string()))?;
        Ok(Self {
            authenticator,
            public,
            principal,
            owner,
            delegate,
            root,
            serial: tokio::sync::Mutex::new(()),
            _writer: writer,
        })
    }

    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }
    pub const fn delegate(&self) -> Key {
        self.delegate
    }

    fn path(&self, network: NetworkId, provider: iroh::EndpointId) -> PathBuf {
        let key = hellas_auth::hash_tuple(
            "hellas.client.funding.v1",
            &[network.as_str().as_bytes(), provider.as_bytes()],
        );
        self.root
            .join(format!("{}.json", hex::encode(key.as_bytes())))
    }

    fn decode(
        &self,
        record: &Record,
    ) -> Result<(NetworkId, iroh::EndpointId, Reshape), ClientOwnerError> {
        let network = NetworkId::new(&record.network).ok_or(ClientOwnerError::Record("network"))?;
        let provider = record
            .provider
            .parse()
            .map_err(|_| ClientOwnerError::Record("provider"))?;
        let bytes = hex::decode(&record.reshape)
            .map_err(|_| ClientOwnerError::Record("reshape encoding"))?;
        let reshape =
            Reshape::decode_exact(&bytes).map_err(|_| ClientOwnerError::Record("reshape"))?;
        let outputs = reshape.outputs().as_slice();
        if record.need == 0
            || reshape.inputs().is_empty()
            || !(1..=2).contains(&outputs.len())
            || outputs[0]
                != hellas_kernel::Payout::delegated(self.owner, Some(self.delegate), record.need)
            || outputs.get(1).is_some_and(|change| {
                change.owner() != self.owner || change.delegate().is_some() || change.value() == 0
            })
            || !Secp256k1Verifier::new().verify_auth(
                reshape.auth(),
                self.owner,
                Reshape::payload_hash(network, reshape.inputs(), reshape.outputs()),
            )
        {
            return Err(ClientOwnerError::Record("owner authorization or outputs"));
        }
        Ok((network, provider, reshape))
    }

    fn records(&self) -> Result<Vec<(PathBuf, Record, Reshape)>, ClientOwnerError> {
        let mut records = Vec::new();
        for entry in std::fs::read_dir(&self.root)? {
            let path = entry?.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let bytes = hellas_private::read_bounded_regular_file(
                &path,
                Reshape::MAX_ENCODED_SIZE * 2 + 1024,
            )?;
            let record: Record = serde_json::from_slice(&bytes)?;
            let (network, provider, reshape) = self.decode(&record)?;
            if path != self.path(network, provider) {
                return Err(ClientOwnerError::Record("file binding"));
            }
            records.push((path, record, reshape));
        }
        Ok(records)
    }

    fn write(path: &Path, record: &Record) -> Result<(), ClientOwnerError> {
        hellas_private::write_atomically(path, ".pending", &serde_json::to_vec(record)?)?;
        Ok(())
    }

    pub(crate) async fn claim(
        &self,
        network: NetworkId,
        provider: iroh::EndpointId,
        funding: &Funding,
    ) -> Result<(), ClientOwnerError> {
        let _serial = self.serial.lock().await;
        let path = self.path(network, provider);
        for (found, mut record, reshape) in self.records()? {
            if found != path {
                continue;
            }
            if funding
                != &one_coin(
                    Reshape::output_ids(network, reshape.inputs(), reshape.outputs()).as_slice()[0],
                )
            {
                return Err(ClientOwnerError::Record("offer funding differs"));
            }
            record.state = FundingState::Offered;
            Self::write(&path, &record)?;
        }
        Ok(())
    }

    pub(crate) async fn fund(
        &self,
        chain: &RemoteLightClient,
        network: NetworkId,
        provider: iroh::EndpointId,
        need: u64,
        poll: Duration,
        timeout: Duration,
    ) -> Result<Funding, ClientOwnerError> {
        tokio::time::timeout(timeout, async {
            let _serial = self.serial.lock().await;
            let path = self.path(network, provider);
            let mut reserved = BTreeSet::new();
            for (found, mut record, reshape) in self.records()? {
                let record_network =
                    NetworkId::new(&record.network).ok_or(ClientOwnerError::Record("network"))?;
                let coin = Reshape::output_ids(record_network, reshape.inputs(), reshape.outputs())
                    .as_slice()[0];
                if found == path {
                    if record.state == FundingState::Pending {
                        let funding = match self
                            .finish(
                                chain,
                                network,
                                &reshape,
                                (record.floor_height, record.floor_payload),
                                poll,
                            )
                            .await
                        {
                            Err(ClientOwnerError::InputsSpent) => {
                                record.state = FundingState::Conflicted;
                                Self::write(&path, &record)?;
                                return Err(ClientOwnerError::InputsSpent);
                            }
                            result => result?,
                        };
                        if record.need == need {
                            return Ok(funding);
                        }
                    }
                } else if record_network == network && record.state != FundingState::Conflicted {
                    reserved.extend(reshape.inputs().iter().copied());
                    reserved.insert(coin);
                }
            }
            let plan = loop {
                match OwnerReshape::split_avoiding(
                    chain,
                    network,
                    self.owner,
                    need,
                    self.delegate,
                    &reserved,
                )
                .await
                {
                    Err(CoinOwnerError::Query(
                        QueryError::StateUnavailable(_) | QueryError::ChannelClosed,
                    )) => tokio::time::sleep(poll).await,
                    result => break result?,
                }
            };
            let floor = plan
                .floor()
                .ok_or(ClientOwnerError::Record("missing finalized planning root"))?;
            let assertion = self
                .authenticator
                .assert(Digest::from(*plan.payload_hash().as_bytes()))
                .await?;
            let Tx::Owner(reshape) = plan.authorize(kernel_auth(&self.public, &assertion)?)? else {
                return Err(ClientOwnerError::Record("owner reshape"));
            };
            let mut bytes = vec![0; Reshape::MAX_ENCODED_SIZE];
            let written = reshape.write_to(&mut bytes);
            bytes.truncate(written);
            Self::write(
                &path,
                &Record {
                    network: network.as_str().into(),
                    provider: provider.to_string(),
                    need,
                    reshape: hex::encode(bytes),
                    state: FundingState::Pending,
                    floor_height: floor.0,
                    floor_payload: floor.1,
                },
            )?;
            let result = self.finish(chain, network, &reshape, floor, poll).await;
            if matches!(result, Err(ClientOwnerError::InputsSpent)) {
                for (found, mut record, _) in self.records()? {
                    if found == path {
                        record.state = FundingState::Conflicted;
                        Self::write(&path, &record)?;
                    }
                }
            }
            result
        })
        .await
        .map_err(|_| ClientOwnerError::Timeout(timeout))?
    }

    async fn finish(
        &self,
        chain: &RemoteLightClient,
        network: NetworkId,
        reshape: &Reshape,
        floor: (u64, [u8; 32]),
        poll: Duration,
    ) -> Result<Funding, ClientOwnerError> {
        let coin = Reshape::output_ids(network, reshape.inputs(), reshape.outputs()).as_slice()[0];
        let mut submitted = false;
        loop {
            let keys = std::iter::once(coin)
                .chain(reshape.inputs().iter().copied())
                .map(coin_object_id)
                .collect();
            let snapshot = match chain.get_objects(keys).await {
                Err(QueryError::StateUnavailable(_) | QueryError::ChannelClosed) => {
                    tokio::time::sleep(poll).await;
                    continue;
                }
                result => result?.ok_or(CoinOwnerError::NoSnapshot)?,
            };
            if snapshot.network != network {
                return Err(CoinOwnerError::Network.into());
            }
            if snapshot.block.height < floor.0 {
                tokio::time::sleep(poll).await;
                continue;
            }
            if snapshot.block.height == floor.0 && snapshot.block.payload != floor.1.into() {
                return Err(ClientOwnerError::Record(
                    "planning root differs at its finalized height",
                ));
            }
            if let Some(Object::Coin(actual)) = snapshot.objects.get(&coin_object_id(coin)) {
                let expected = reshape.outputs().as_slice()[0];
                if actual.owner != self.owner.into()
                    || actual.delegate != Some(self.delegate.into())
                    || actual.value != expected.value()
                {
                    return Err(ClientOwnerError::Record("finalized funding output"));
                }
                return Ok(one_coin(coin));
            }
            if reshape
                .inputs()
                .iter()
                .any(|input| !snapshot.objects.contains_key(&coin_object_id(*input)))
            {
                return Err(ClientOwnerError::InputsSpent);
            }
            if !submitted {
                let outcome = chain
                    .submit_tx(Transaction::Kernel(Tx::Owner(reshape.clone())))
                    .await?;
                if !matches!(
                    outcome,
                    hellas_rpc::SubmitTxOutcome::Enqueued | hellas_rpc::SubmitTxOutcome::Duplicate
                ) {
                    return Err(ClientOwnerError::Record("owner reshape was refused"));
                }
                submitted = true;
            }
            tokio::time::sleep(poll).await;
        }
    }
}

fn one_coin(coin: CoinId) -> Funding {
    Funding::new(
        List::take([coin; hellas_kernel::MAX_PARTY_INPUTS], 1),
        List::empty(CoinId::from_bytes([0; CoinId::LENGTH])),
    )
}

#[cfg(test)]
mod tests {
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
                devnet.seal().await;
                let chain = RemoteLightClient::connect(devnet.light_client_url(0))
                    .await
                    .unwrap()
                    .with_consensus_verifier(devnet.consensus_verifier());
                let approval = Arc::new(Approval::new());
                let owner = ClientOwner::new(approval.clone(), delegate(), root.path()).unwrap();
                assert!(matches!(
                    ClientOwner::new(approval.clone(), delegate(), root.path()),
                    Err(ClientOwnerError::Locked(_))
                ));
                {
                    let funding = owner.fund(
                        &chain,
                        devnet.network(),
                        provider(3),
                        200,
                        Duration::from_millis(10),
                        hellas_chain::node::RECOVERY_TIMEOUT,
                    );
                    tokio::pin!(funding);
                    tokio::time::timeout(Duration::from_secs(10), async {
                    tokio::select! {
                        result = &mut funding => panic!("funding completed before a block was sealed: {result:?}"),
                        () = async { while owner.records().unwrap().is_empty() { tokio::task::yield_now().await; } } => {},
                    }
                }).await.expect("the signed approval reaches durable storage before cancellation");
                }
                assert_eq!(approval.count.load(Ordering::SeqCst), 1);
                let approved = owner.records().unwrap().remove(0).1.reshape;
                drop(owner);
                let owner = ClientOwner::new(approval.clone(), delegate(), root.path()).unwrap();
                let network = devnet.network();
                let first = sealing(
                    &mut devnet,
                    owner.fund(
                        &chain,
                        network,
                        provider(3),
                        200,
                        Duration::from_millis(10),
                        hellas_chain::node::RECOVERY_TIMEOUT,
                    ),
                )
                .await
                .unwrap();
                assert_eq!(
                    owner.records().unwrap().remove(0).1.reshape,
                    approved,
                    "retry submits the identical durable approval"
                );
                assert_eq!(approval.count.load(Ordering::SeqCst), 1);
                let network = devnet.network();
                let (second, third) = sealing(&mut devnet, async {
                    tokio::join!(
                        owner.fund(
                            &chain,
                            network,
                            provider(4),
                            200,
                            Duration::from_millis(10),
                            hellas_chain::node::RECOVERY_TIMEOUT
                        ),
                        owner.fund(
                            &chain,
                            network,
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
                assert_eq!(approval.count.load(Ordering::SeqCst), 3);
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
                devnet.seal().await;
                let chain = RemoteLightClient::connect(devnet.light_client_url(0))
                    .await
                    .unwrap()
                    .with_consensus_verifier(devnet.consensus_verifier());
                let genesis = hellas_chain::test_support::devnet::genesis_coin(
                    devnet.allocations(),
                    OWNER.key(),
                );
                let inputs = List::take([genesis; hellas_kernel::MAX_EDGE_INPUTS], 1);
                let payouts = List::take([Payout::new(OWNER.key().into_kernel(), 200); 4], 2);
                let auth = owner_spec.authorize(Reshape::payload_hash(
                    devnet.network(),
                    &inputs,
                    &payouts,
                ));
                let split = Reshape::new(inputs, payouts, auth);
                let ids = Reshape::output_ids(devnet.network(), split.inputs(), split.outputs());
                chain
                    .submit_tx(Transaction::Kernel(Tx::Owner(split)))
                    .await
                    .unwrap();
                devnet.seal().await;
                let approval = Arc::new(Approval::new());
                approval.pause.store(true, Ordering::SeqCst);
                let owner = ClientOwner::new(approval.clone(), delegate(), root.path()).unwrap();
                let funding = owner.fund(
                    &chain,
                    devnet.network(),
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
                let network = devnet.network();
                let other = sealing(
                    &mut devnet,
                    owner.fund(
                        &chain,
                        network,
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
                        network,
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
}
