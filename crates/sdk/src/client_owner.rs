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
    network: NetworkId,
    chain_root: PathBuf,
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
        if network != self.network {
            return Err(ClientOwnerError::Record(
                "funding network differs from selected chain",
            ));
        }
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
        chain: &hellas_chain::genesis::ChainDir,
    ) -> Result<Self, ClientOwnerError> {
        let public = authenticator.public_key()?;
        let principal =
            PrincipalId::from_public_key(hellas_auth::PublicKey::P256(public.to_compressed()))?;
        let owner = Key::from_bytes(public.to_compressed());
        let root = chain.client().join("owners").join(format!(
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
            network: NetworkId::new(chain.network_id()).expect("validated chain profile"),
            chain_root: chain.as_path().to_path_buf(),
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
    pub fn chain_root(&self) -> &Path {
        &self.chain_root
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
        if network != self.network {
            return Err(ClientOwnerError::Record(
                "funding network differs from selected chain",
            ));
        }
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

    #[cfg(all(test, feature = "integration-tests"))]
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
        if network != self.network {
            return Err(ClientOwnerError::Record(
                "funding network differs from selected chain",
            ));
        }
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

#[cfg(all(test, feature = "integration-tests"))]
mod tests;
