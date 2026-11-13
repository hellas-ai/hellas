use super::Result;
use crate::{
    Backend, BackendEntry, BackendState,
    daemon_config::{BackendKind, Trust},
};
use hellas_auth::authority::{NodeKey, PrincipalId, UnixMillis};
use hellas_store::content::DiskStore;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
mod models;
pub(super) use models::Files;

pub struct Options {
    pub discovery: bool,
    pub endpoint: Option<iroh::Endpoint>,
    pub remote_control: crate::node_control::RemoteControlAdmission,
    pub prover: Option<Arc<dyn hellas_attestation::RootProver>>,
    pub home: hellas_private::StoreLocation,
    pub signer: Arc<hellas_auth::ProducerSigningKey>,
    pub transport: iroh::SecretKey,
    pub settlement: hellas_kernel::Secp256k1Signer,
    pub owner: Option<Arc<dyn hellas_authority::authenticator::Authenticator>>,
    pub chain: hellas_chain::chain_dir::ChainDir,
    pub node: hellas_authority::node::NodeCoordinator,
    /// Provider content; the core restores all retained chains before cleanup.
    pub content: DiskStore,
}

pub(super) struct Runtime {
    pub options: Options,
    pub paid: tokio::sync::Mutex<BTreeMap<PathBuf, Arc<super::iroh_listener::Paid>>>,
    pub endpoint: tokio::sync::Mutex<Option<iroh::Endpoint>>,
    clients: tokio::sync::Mutex<
        std::collections::BTreeMap<
            std::path::PathBuf,
            (Arc<crate::client_owner::ClientOwner>, DiskStore),
        >,
    >,
    consumer: tokio::sync::OnceCell<iroh::Endpoint>,
    #[cfg(feature = "compute")]
    executors:
        tokio::sync::Mutex<std::collections::BTreeMap<String, hellas_executor::ExecutorHandle>>,
    #[cfg(feature = "compute")]
    indexed: tokio::sync::Mutex<Files>,
    models: tokio::sync::Mutex<BTreeMap<PathBuf, models::Cached>>,
}

pub(super) enum PreparedBackend {
    Ready(BackendEntry),
    Paid {
        options: Box<crate::paid_client::PaidWorkOptions>,
        endpoint: iroh::Endpoint,
        evaluator: Option<String>,
        capacity: std::num::NonZeroUsize,
    },
}
impl PreparedBackend {
    pub fn ready(entry: BackendEntry) -> Self {
        Self::Ready(entry)
    }
    pub fn unavailable(configured: &crate::daemon_config::Backend, reason: String) -> Self {
        let evaluator = match &configured.kind {
            BackendKind::Local { evaluator, .. } => {
                #[cfg(feature = "compute")]
                {
                    Some(evaluator.clone().unwrap_or_else(|| {
                        hellas_executor::catena::evaluator(hellas_executor::catena::default_gpu())
                    }))
                }
                #[cfg(not(feature = "compute"))]
                {
                    evaluator.clone()
                }
            }
            BackendKind::Grant { evaluator, .. } | BackendKind::Paid { evaluator, .. } => {
                evaluator.clone()
            }
            BackendKind::Fetch { .. } => None,
        };
        Self::ready(BackendEntry {
            backend: Backend::unavailable(reason),
            evaluator,
            max_in_flight: configured.max_in_flight,
        })
    }
    pub fn info(&self, id: &str) -> hellas_gateway::BackendInfo {
        let (evaluator, capacity) = match self {
            Self::Ready(entry) => (&entry.evaluator, entry.max_in_flight),
            Self::Paid {
                evaluator,
                capacity,
                ..
            } => (evaluator, *capacity),
        };
        hellas_gateway::BackendInfo {
            id: id.into(),
            instance: rand::random(),
            evaluator: evaluator.clone(),
            max_in_flight: capacity.get(),
            in_flight: 0,
            down: matches!(self, Self::Ready(entry) if entry.backend.error().is_some()),
            error: match self {
                Self::Ready(entry) => entry.backend.error(),
                _ => None,
            },
        }
    }
    pub async fn activate(self, runtime: &Runtime) -> Result<BackendEntry> {
        match self {
            Self::Ready(entry) => Ok(entry),
            Self::Paid {
                mut options,
                endpoint,
                evaluator,
                capacity,
            } => {
                options.config.chain.persist()?;
                let (owner, content) = runtime.client_resources(&options.config.chain).await?;
                options.content = content;
                Ok(BackendEntry {
                    backend: Backend::paid(
                        None,
                        *options,
                        endpoint,
                        runtime.options.settlement.clone(),
                        owner,
                    ),
                    evaluator,
                    max_in_flight: capacity,
                })
            }
        }
    }
}

impl Runtime {
    pub fn new(mut options: Options) -> Self {
        Self {
            endpoint: tokio::sync::Mutex::new(options.endpoint.take()),
            options,
            paid: Default::default(),
            clients: Default::default(),
            consumer: Default::default(),
            #[cfg(feature = "compute")]
            executors: Default::default(),
            #[cfg(feature = "compute")]
            indexed: Default::default(),
            models: Default::default(),
        }
    }

    pub fn consumer_endpoints(&self) -> impl Iterator<Item = iroh::Endpoint> {
        self.consumer.get().cloned().into_iter()
    }

    pub(super) async fn consumer_endpoint(&self) -> Result<iroh::Endpoint> {
        // Outgoing sessions share one endpoint, distinct from the enrolled listener.
        let key = hellas_auth::hash_tuple(
            "hellas.daemon.client-transport.v1",
            &[&self.options.transport.to_bytes()],
        );
        Ok(self
            .consumer
            .get_or_try_init(|| {
                crate::paid_client::bind_paid_endpoint(iroh::SecretKey::from_bytes(key.as_bytes()))
            })
            .await?
            .clone())
    }

    pub async fn shutdown(&self) -> Result<()> {
        let mut failure = None;
        for paid in self.paid.lock().await.values() {
            if let Err(error) = paid.shutdown().await {
                failure.get_or_insert(error);
            }
        }
        for (_, content) in self.clients.lock().await.values() {
            content.close().await;
        }
        if let Some(endpoint) = self.consumer.get() {
            endpoint.close().await;
        }
        failure.map_or(Ok(()), Err)
    }

    pub async fn client_resources(
        &self,
        chain: &hellas_chain::chain_dir::ChainDir,
    ) -> Result<(Arc<crate::client_owner::ClientOwner>, DiskStore)> {
        let mut clients = self.clients.lock().await;
        if let Some(existing) = clients.get(chain.as_path()) {
            return Ok(existing.clone());
        }
        let principal = self
            .options
            .owner
            .clone()
            .ok_or("a paid backend requires the owner identity")?;
        let owner = Arc::new(crate::client_owner::ClientOwner::new(
            principal,
            self.options.settlement.party_key(),
            chain,
        )?);
        let content = crate::chain_home::open_client_content(chain).await?;
        clients.insert(chain.as_path().to_owned(), (owner.clone(), content.clone()));
        Ok((owner, content))
    }

    pub(super) fn chain(
        &self,
        profile: &Option<hellas_chain::genesis::CustomChainFile>,
    ) -> Result<hellas_chain::chain_dir::ChainDir> {
        match profile {
            Some(profile) => Ok(hellas_chain::chain_dir::ChainDir::prepare(
                &self.options.home,
                &hellas_chain::genesis::ChainProfile::custom(profile.clone())?,
            )?),
            None => Ok(self.options.chain.clone()),
        }
    }

    fn principal(&self) -> Result<PrincipalId> {
        Ok(PrincipalId::from_public_key(hellas_auth::PublicKey::P256(
            self.options
                .owner
                .as_ref()
                .ok_or("a consumer backend requires the owner identity")?
                .public_key()?
                .to_compressed(),
        ))?)
    }

    fn trust(
        &self,
        trust: &Option<Trust>,
        counters: Arc<dyn hellas_attestation::AssertionCounterStore + Send + Sync>,
    ) -> Result<Option<hellas_client::ProviderTrustAnchor>> {
        trust
            .as_ref()
            .map(|trust| {
                let store = crate::trust_policy::TrustPolicyStore::new(&trust.store);
                Ok(store.approved(&trust.policy, counters.clone())?)
            })
            .transpose()
    }

    pub fn approval_current(&self, configured: &BackendKind, active: &Backend) -> Result<bool> {
        let (trust, active) = match (configured, &active.state) {
            (BackendKind::Grant { trust, .. }, BackendState::Grant(grant)) => {
                (trust, grant.options.target.trust().clone())
            }
            (BackendKind::Paid { trust, .. }, BackendState::Paid(paid)) => {
                (trust, paid.options.trust()?)
            }
            (BackendKind::Local { .. }, BackendState::Local { .. })
            | (BackendKind::Fetch { .. }, BackendState::Fetch { .. }) => return Ok(true),
            _ => return Ok(false),
        };
        let Some(approved) = self.trust(
            trust,
            Arc::new(crate::FilesystemAssertionCounterStore::in_home(
                &self.options.home,
            )),
        )?
        else {
            return Ok(true);
        };
        let apple_pins = |trust: &hellas_client::ProviderTrustAnchor| {
            trust
                .apple_app_attest
                .as_ref()
                .map(|apple| (apple.app_id.clone(), apple.allowed_cd_hashes.clone()))
        };
        Ok(active.expected_genesis == approved.expected_genesis
            && active.required_assurance == approved.required_assurance
            && apple_pins(&active) == apple_pins(&approved))
    }

    pub async fn open_backend(
        &self,
        configured: &crate::daemon_config::Backend,
        counters: Arc<crate::counter_store::FilesystemAssertionCounterStore>,
    ) -> Result<PreparedBackend> {
        let (backend, evaluator) = match &configured.kind {
            BackendKind::Fetch { .. } => (
                configured.open_fetch(self.options.signer.clone()).await?,
                None,
            ),
            BackendKind::Grant {
                access,
                resource,
                evaluator,
                trust,
            } => {
                let principal = self.principal()?;
                let holder = NodeKey::from_public_key(self.options.signer.public_key())?;
                let (offers, application) = crate::access_bundle::AccessBundle::decode(
                    &base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        access.as_deref().ok_or("missing grant access")?,
                    )?,
                    &principal,
                    &holder,
                )?
                .into_parts();
                let (offer, policy) = {
                    let mut selected = offers.iter().flat_map(|offer| {
                        offer.offer().grant.policies.iter().map(move |policy: &hellas_authority::model::grant::records::GrantPolicy| (offer, policy))
                    }).filter(|(_, policy)| resource.is_none_or(|id| policy.resource == id));
                    let (offer, policy) = selected
                        .next()
                        .ok_or("grant contains no matching resource")?;
                    if selected.next().is_some() {
                        return Err("grant resource is ambiguous".into());
                    }
                    (offer.clone(), policy.clone())
                };
                let provider = hellas_client::ProviderAddress::of(&offer.offer().provider)?;
                let trust = self.trust(trust, counters.clone())?.unwrap_or(
                    hellas_client::ProviderTrustAnchor {
                        expected_genesis: provider.enrollment,
                        required_assurance: hellas_rpc::Assurance::ProducerSigned,
                        apple_app_attest: None,
                    },
                );
                let target =
                    crate::grant_client::UnpinnedOffer::decode(&offer.encode()?, UnixMillis(0))?
                        .pin(&trust)?;
                let endpoint = self.consumer_endpoint().await?;
                (
                    Backend::grant(
                        policy.clone(),
                        crate::grant_client::GrantSessionOptions {
                            target,
                            principal,
                            signer: self.options.signer.clone(),
                            application: Arc::new(application),
                            journal_root: self
                                .options
                                .home
                                .child("grants")
                                .child(format!("p256-{}", hex::encode(principal.as_bytes())))
                                .child("channels"),
                            control_timeout: std::time::Duration::from_secs(90),
                        },
                        crate::grant_client::GrantTransport::Remote(endpoint),
                    ),
                    evaluator.clone(),
                )
            }
            BackendKind::Paid {
                addresses,
                acceptance_blocks,
                terminal_blocks,
                payment_blocks,
                timeout_seconds,
                chain,
                provider,
                max_price,
                evaluator,
                trust,
            } => {
                let provider = provider.parse()?;
                let chain = self.chain(chain)?;
                let endpoint = self.consumer_endpoint().await?;
                let apple_trust = self.trust(trust, counters.clone())?;
                let options = crate::paid_client::PaidWorkOptions {
                    // Quoting reads no content. Activation supplies the recovered client store.
                    content: self.options.content.clone(),
                    config: crate::work_config::WorkConfig::from_chain_dir(chain)?,
                    provider,
                    provider_addrs: addresses.clone(),
                    assurance: apple_trust
                        .as_ref()
                        .map_or(hellas_rpc::Assurance::ProducerSigned, |trust| {
                            trust.required_assurance
                        }),
                    apple_trust,
                    expected_price: *max_price,
                    acceptance_blocks: *acceptance_blocks,
                    terminal_blocks: *terminal_blocks,
                    payment_blocks: *payment_blocks,
                    timeout: timeout_seconds.map(std::time::Duration::from_secs),
                };
                return Ok(PreparedBackend::Paid {
                    options: Box::new(options),
                    endpoint,
                    evaluator: evaluator.clone(),
                    capacity: configured.max_in_flight,
                });
            }
            BackendKind::Local { evaluator, .. } => {
                #[cfg(not(feature = "compute"))]
                {
                    let _ = evaluator;
                    return Err("local backends require the compute build".into());
                }
                #[cfg(feature = "compute")]
                {
                    let dialect = evaluator
                        .as_deref()
                        .map(hellas_executor::catena::registered_evaluator)
                        .transpose()?
                        .unwrap_or_else(hellas_executor::catena::default_gpu);
                    let evaluator = hellas_executor::catena::evaluator(dialect);
                    let mut executors = self.executors.lock().await;
                    let backend = match executors.entry(evaluator.clone()) {
                        std::collections::btree_map::Entry::Occupied(entry) => entry.get().clone(),
                        std::collections::btree_map::Entry::Vacant(entry) => entry
                            .insert(
                                crate::execution::local::spawn(
                                    self.options.signer.clone(),
                                    hellas_executor::GpuConfig {
                                        backend: dialect,
                                        ..Default::default()
                                    },
                                )
                                .await?,
                            )
                            .clone(),
                    };
                    drop(executors);
                    (
                        Backend::local(
                            crate::execution::local::LocalExecution {
                                backend,
                                content: self.options.content.clone(),
                            },
                            std::time::Duration::from_secs(86_400),
                        ),
                        Some(evaluator),
                    )
                }
            }
        };
        Ok(PreparedBackend::Ready(BackendEntry {
            backend,
            evaluator,
            max_in_flight: configured.max_in_flight,
        }))
    }
}
