//! Owner-approved channel funding, serialized across a requester's providers.
use crate::coin_owner::{CoinOwnerError, OwnerReshape};
use hellas_auth::{
    Digest,
    authority::{AuthorityError, PrincipalId},
};
use hellas_authority::authenticator::{Authenticator, PublicKey, kernel_auth};
use hellas_chain::{
    LightClient as _, QueryError,
    client::RemoteLightClient,
    domain::{Object, Transaction, coin_object_id},
};
use hellas_kernel::{
    CoinId, Decode as _, Encode as _, Funding, Key, List, NetworkId, Reshape, Secp256k1Verifier,
    SigVerifier, Tx,
};
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
    Purchase(#[from] crate::transact::PurchaseError),
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reservation: Option<[u8; 16]>,
    reshape: String,
    state: FundingState,
    floor_height: u64,
    floor_payload: [u8; 32],
}

pub(crate) struct FundingIntent {
    pub reservation: [u8; 16],
    pub network: NetworkId,
    pub provider: iroh::EndpointId,
    pub amount: u64,
    pub funding: Funding,
}

pub(crate) type FundingBinding<'a> =
    Box<dyn FnOnce() -> Result<(), crate::transact::PurchaseError> + Send + 'a>;

pub(crate) struct FundingControls<'a> {
    pub poll: Duration,
    pub timeout: Duration,
    pub approval: Option<&'a dyn crate::paid_client::FundingApproval>,
    /// Runs after application reservation, before owner signing or replay submission.
    pub before_sign: Option<FundingBinding<'a>>,
}

impl ClientOwner {
    pub(crate) fn recover_funding_intent<'a>(
        &'a self,
        chain: &'a RemoteLightClient,
        network: NetworkId,
        provider: iroh::EndpointId,
        reservation: [u8; 16],
        controls: FundingControls<'a>,
    ) -> impl Future<Output = Result<Funding, ClientOwnerError>> + 'a {
        Box::pin(self.recover_funding_intent_inner(chain, network, provider, reservation, controls))
    }

    async fn recover_funding_intent_inner(
        &self,
        chain: &RemoteLightClient,
        network: NetworkId,
        provider: iroh::EndpointId,
        reservation: [u8; 16],
        controls: FundingControls<'_>,
    ) -> Result<Funding, ClientOwnerError> {
        let FundingControls {
            poll,
            timeout,
            approval,
            mut before_sign,
        } = controls;
        tokio::time::timeout(timeout, async {
            let _serial = self.serial.lock().await;
            let path = self
                .root
                .join("funding-intents")
                .join(format!("{}.json", hex::encode(reservation)));
            let bytes = hellas_private::read_bounded_regular_file(
                &path,
                Reshape::MAX_ENCODED_SIZE * 2 + 1024,
            )?;
            let record: Record = serde_json::from_slice(&bytes)?;
            let (record_network, record_provider, reshape) = self.decode(&record)?;
            if record_network != network
                || record_provider != provider
                || record.reservation != Some(reservation)
            {
                return Err(ClientOwnerError::Record("funding archive identity"));
            }
            if let Some(gate) = approval {
                if gate.reservation(network, provider) != reservation {
                    return Err(ClientOwnerError::Record("funding reservation mismatch"));
                }
                gate.recover(reservation, record.need)
                    .await
                    .map_err(|_| ClientOwnerError::Record("funding approval recovery denied"))?;
            }
            if let Some(bind) = before_sign.take() {
                bind()?;
            }
            self.finish(
                chain,
                network,
                &reshape,
                (record.floor_height, record.floor_payload),
                poll,
            )
            .await
        })
        .await
        .map_err(|_| ClientOwnerError::Timeout(timeout))?
    }

    pub(crate) async fn funding_intents(&self) -> Result<Vec<FundingIntent>, ClientOwnerError> {
        let _serial = self.serial.lock().await;
        let history = self.root.join("funding-intents");
        let entries = match std::fs::read_dir(&history) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut intents = Vec::new();
        for (index, entry) in entries.enumerate() {
            if index >= 4096 {
                return Err(ClientOwnerError::Record("too many funding intents"));
            }
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
            let reservation = record
                .reservation
                .ok_or(ClientOwnerError::Record("untagged funding archive"))?;
            if path != history.join(format!("{}.json", hex::encode(reservation))) {
                return Err(ClientOwnerError::Record("funding archive identity"));
            }
            intents.push(FundingIntent {
                reservation,
                network,
                provider,
                amount: record.need,
                funding: one_coin(
                    Reshape::output_ids(network, reshape.inputs(), reshape.outputs()).as_slice()[0],
                ),
            });
        }
        Ok(intents)
    }
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

    #[cfg(test)]
    pub(crate) async fn fund(
        &self,
        chain: &RemoteLightClient,
        network: NetworkId,
        provider: iroh::EndpointId,
        need: u64,
        poll: Duration,
        timeout: Duration,
    ) -> Result<Funding, ClientOwnerError> {
        self.fund_with_approval(
            chain,
            network,
            provider,
            need,
            FundingControls {
                poll,
                timeout,
                approval: None,
                before_sign: None,
            },
        )
        .await
    }

    pub(crate) fn fund_with_approval<'a>(
        &'a self,
        chain: &'a RemoteLightClient,
        network: NetworkId,
        provider: iroh::EndpointId,
        need: u64,
        controls: FundingControls<'a>,
    ) -> impl Future<Output = Result<Funding, ClientOwnerError>> + 'a {
        Box::pin(self.fund_with_approval_inner(chain, network, provider, need, controls))
    }

    async fn fund_with_approval_inner(
        &self,
        chain: &RemoteLightClient,
        network: NetworkId,
        provider: iroh::EndpointId,
        need: u64,
        controls: FundingControls<'_>,
    ) -> Result<Funding, ClientOwnerError> {
        let FundingControls {
            poll,
            timeout,
            approval,
            mut before_sign,
        } = controls;
        tokio::time::timeout(timeout, async {
            let _serial = self.serial.lock().await;
            let path = self.path(network, provider);
            if let Some(gate) = approval {
                let reservation = gate.reservation(network, provider);
                let archive = self
                    .root
                    .join("funding-intents")
                    .join(format!("{}.json", hex::encode(reservation)));
                if archive.try_exists()? {
                    let bytes = hellas_private::read_bounded_regular_file(
                        &archive,
                        Reshape::MAX_ENCODED_SIZE * 2 + 1024,
                    )?;
                    let record: Record = serde_json::from_slice(&bytes)?;
                    let (record_network, record_provider, _) = self.decode(&record)?;
                    if record_network != network
                        || record_provider != provider
                        || record.need != need
                        || record.reservation != Some(reservation)
                        || record.state != FundingState::Pending
                    {
                        return Err(ClientOwnerError::Record("funding archive identity"));
                    }
                    let active: Option<Record> = match hellas_private::read_bounded_regular_file(
                        &path,
                        Reshape::MAX_ENCODED_SIZE * 2 + 1024,
                    ) {
                        Ok(bytes) => Some(serde_json::from_slice(&bytes)?),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                        Err(error) => return Err(error.into()),
                    };
                    if active.as_ref().is_some_and(|active| {
                        active.state == FundingState::Pending
                            && active.reservation != Some(reservation)
                    }) {
                        return Err(ClientOwnerError::Record(
                            "another funding intent is pending",
                        ));
                    }
                    if active.as_ref().is_some_and(|active| {
                        active.reservation == Some(reservation)
                            && active.state != FundingState::Pending
                    }) {
                        return Err(ClientOwnerError::Record(
                            "funding reservation is already consumed",
                        ));
                    }
                    if active.as_ref().is_some_and(|active| {
                        active.reservation == Some(reservation)
                            && (active.reshape != record.reshape
                                || active.need != record.need
                                || active.network != record.network
                                || active.provider != record.provider)
                    }) {
                        return Err(ClientOwnerError::Record(
                            "funding archive differs from active intent",
                        ));
                    }
                    if active
                        .as_ref()
                        .is_none_or(|active| active.reservation != Some(reservation))
                    {
                        Self::write(&path, &record)?;
                    }
                }
            }
            let mut reserved = BTreeSet::new();
            for (found, mut record, reshape) in self.records()? {
                let record_network =
                    NetworkId::new(&record.network).ok_or(ClientOwnerError::Record("network"))?;
                let coin = Reshape::output_ids(record_network, reshape.inputs(), reshape.outputs())
                    .as_slice()[0];
                if found == path {
                    if record.state == FundingState::Pending {
                        if let Some(gate) = approval {
                            let reservation = record
                                .reservation
                                .ok_or(ClientOwnerError::Record("untagged pending funding"))?;
                            if reservation != gate.reservation(network, provider) {
                                return Err(ClientOwnerError::Record(
                                    "funding reservation mismatch",
                                ));
                            }
                            gate.recover(reservation, record.need).await.map_err(|_| {
                                ClientOwnerError::Record("funding approval recovery denied")
                            })?;
                        }
                        if let Some(bind) = before_sign.take() {
                            bind()?;
                        }
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
            let reservation = if let Some(gate) = approval {
                let reservation = gate.reservation(network, provider);
                gate.reserve(reservation, need)
                    .await
                    .map_err(|_| ClientOwnerError::Record("application funding denied"))?;
                Some(reservation)
            } else {
                None
            };
            if let Some(bind) = before_sign.take() {
                bind()?;
            }
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
            let record = Record {
                network: network.as_str().into(),
                provider: provider.to_string(),
                need,
                reservation,
                reshape: hex::encode(bytes),
                state: FundingState::Pending,
                floor_height: floor.0,
                floor_payload: floor.1,
            };
            if let Some(reservation) = reservation {
                let history = self.root.join("funding-intents");
                hellas_private::create_dir_all_durable(&history)?;
                let archive = history.join(format!("{}.json", hex::encode(reservation)));
                if archive.try_exists()? {
                    return Err(ClientOwnerError::Record("reservation identity reused"));
                }
                Self::write(&archive, &record)?;
            }
            Self::write(&path, &record)?;
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
        ) -> futures::future::BoxFuture<
            '_,
            std::result::Result<(), crate::paid_client::PaidClientError>,
        > {
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
        ) -> futures::future::BoxFuture<
            '_,
            std::result::Result<(), crate::paid_client::PaidClientError>,
        > {
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
        ) -> futures::future::BoxFuture<
            '_,
            std::result::Result<(), crate::paid_client::PaidClientError>,
        > {
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
        ) -> futures::future::BoxFuture<
            '_,
            std::result::Result<(), crate::paid_client::PaidClientError>,
        > {
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
    fn legacy_signed_funding_record_decodes_and_verifies() {
        let bytes = include_bytes!("../tests/fixtures/legacy-funding.json");
        let record: Record = serde_json::from_slice(bytes).unwrap();
        let root = tempfile::tempdir().unwrap();
        let owner = ClientOwner::new(Arc::new(Approval::new()), delegate(), root.path()).unwrap();
        let (_, actual_provider, _) = owner.decode(&record).unwrap();
        assert_eq!(actual_provider, provider(3));
        assert_eq!(record.need, 200);
        assert!(matches!(record.state, FundingState::Pending));
        assert_eq!(serde_json::to_vec(&record).unwrap(), bytes);
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
                let gate = Gate::default();
                let owner = ClientOwner::new(approval.clone(), delegate(), root.path()).unwrap();
                assert!(matches!(
                    ClientOwner::new(approval.clone(), delegate(), root.path()),
                    Err(ClientOwnerError::Locked(_))
                ));
                assert!(
                    owner
                        .fund_with_approval(
                            &chain,
                            devnet.network(),
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
                        devnet.network(),
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
                        devnet.network(),
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
                std::fs::remove_file(owner.path(devnet.network(), provider(3))).unwrap();
                drop(owner);
                let owner = ClientOwner::new(approval.clone(), delegate(), root.path()).unwrap();
                let network = devnet.network();
                let first = sealing(
                    &mut devnet,
                    owner.fund_with_approval(
                        &chain,
                        network,
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
                        network,
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
                        network,
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
                        network,
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
