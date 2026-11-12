use super::Result;
use crate::{
    Backend, BackendEntry,
    daemon_config::{BackendKind, Document, Trust},
};
use hellas_auth::authority::{NodeKey, PrincipalId, UnixMillis};
use hellas_store::content::DiskStore;
#[cfg(feature = "compute")]
use hellas_store::content::{ContentStore, IndexMode, PinName, PinPolicy, PinValue, Scope, Target};
use std::sync::Arc;
#[cfg(feature = "compute")]
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

pub struct Options {
    pub prover: Option<Arc<crate::ProviderOpen>>,
    pub home: hellas_private::StoreLocation,
    pub signer: Arc<hellas_auth::ProducerSigningKey>,
    pub transport: iroh::SecretKey,
    pub settlement: hellas_kernel::Secp256k1Signer,
    pub owner: Arc<dyn hellas_authority::authenticator::Authenticator>,
    pub chain: hellas_chain::chain_dir::ChainDir,
    pub node: hellas_authority::node::NodeCoordinator,
    pub access: Option<hellas_gateway::GatewayAccess>,
    /// The host restores all Work roots before opening this recovery barrier.
    pub content: DiskStore,
}

pub(super) struct Runtime {
    pub options: Options,
    owner: tokio::sync::OnceCell<Arc<crate::client_owner::ClientOwner>>,
    grant: tokio::sync::OnceCell<iroh::Endpoint>,
    paid: tokio::sync::OnceCell<iroh::Endpoint>,
    #[cfg(feature = "compute")]
    hip: tokio::sync::OnceCell<hellas_executor::ExecutorHandle>,
    #[cfg(feature = "compute")]
    cuda: tokio::sync::OnceCell<hellas_executor::ExecutorHandle>,
    #[cfg(feature = "compute")]
    indexed: tokio::sync::Mutex<BTreeSet<PathBuf>>,
}
impl Runtime {
    pub fn new(options: Options) -> Self {
        Self {
            options,
            owner: Default::default(),
            grant: Default::default(),
            paid: Default::default(),
            #[cfg(feature = "compute")]
            hip: Default::default(),
            #[cfg(feature = "compute")]
            cuda: Default::default(),
            #[cfg(feature = "compute")]
            indexed: Default::default(),
        }
    }

    pub async fn shutdown(&self) {
        for endpoint in [self.grant.get(), self.paid.get()].into_iter().flatten() {
            endpoint.close().await;
        }
    }

    fn principal(&self) -> Result<PrincipalId> {
        Ok(PrincipalId::from_public_key(hellas_auth::PublicKey::P256(
            self.options.owner.public_key()?.to_compressed(),
        ))?)
    }

    fn trust(&self, trust: &Option<Trust>) -> Result<Option<hellas_client::ProviderTrustAnchor>> {
        trust
            .as_ref()
            .map(|trust| {
                crate::trust_policy::TrustPolicyStore::new(&trust.store)
                    .resolve(
                        &trust.policy,
                        hellas_rpc::Assurance::AppleAppAttest,
                        Arc::new(crate::FilesystemAssertionCounterStore::in_home(
                            &self.options.home,
                        )),
                    )
                    .map_err(Into::into)
            })
            .transpose()
    }

    pub async fn open_backend(
        &self,
        id: &str,
        configured: &crate::daemon_config::Backend,
        document: &Document,
    ) -> Result<BackendEntry> {
        let (mut backend, evaluator) = match &configured.kind {
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
                let (offers, application) =
                    crate::access_bundle::AccessBundle::load(access, &principal, &holder)?
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
                let trust = self
                    .trust(trust)?
                    .unwrap_or(hellas_client::ProviderTrustAnchor {
                        expected_genesis: provider.enrollment,
                        required_assurance: hellas_rpc::Assurance::ProducerSigned,
                        apple_app_attest: None,
                    });
                let target =
                    crate::grant_client::UnpinnedOffer::decode(&offer.encode()?, UnixMillis(0))?
                        .pin(&trust)?;
                let endpoint = self
                    .grant
                    .get_or_try_init(|| {
                        crate::grant_client::bind_endpoint(self.options.transport.clone())
                    })
                    .await?
                    .clone();
                (
                    Backend::Grant {
                        options: crate::grant_client::GrantSessionOptions {
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
                        transport: crate::grant_client::GrantTransport::Remote(endpoint),
                        policy: policy.clone(),
                    },
                    evaluator.clone(),
                )
            }
            BackendKind::Paid {
                provider,
                max_price,
                evaluator,
                trust,
            } => {
                let provider = provider.parse()?;
                let owner = self
                    .owner
                    .get_or_try_init(|| async {
                        crate::client_owner::ClientOwner::new(
                            self.options.owner.clone(),
                            self.options.settlement.party_key(),
                            &self.options.chain,
                        )
                        .map(Arc::new)
                    })
                    .await?
                    .clone();
                let endpoint = self
                    .paid
                    .get_or_try_init(|| {
                        crate::paid_client::bind_paid_endpoint(self.options.transport.clone())
                    })
                    .await?
                    .clone();
                let apple_trust = self.trust(trust)?;
                let options = crate::paid_client::PaidWorkOptions {
                    content: self.options.content.clone(),
                    journal_kind: crate::paid_client::PaidJournalKind::Client,
                    config: crate::work_config::WorkConfig::from_chain_dir(
                        self.options.chain.clone(),
                    )?,
                    provider,
                    provider_addrs: vec![],
                    assurance: if apple_trust.is_some() {
                        hellas_rpc::Assurance::AppleAppAttest
                    } else {
                        hellas_rpc::Assurance::ProducerSigned
                    },
                    apple_trust,
                    expected_price: *max_price,
                    acceptance_blocks: 300,
                    terminal_blocks: 3000,
                    payment_blocks: 600,
                    timeout: None,
                };
                (
                    Backend::Paid {
                        options,
                        policy: None,
                        endpoint,
                        settlement_key: self.options.settlement.clone(),
                        owner,
                    },
                    evaluator.clone(),
                )
            }
            BackendKind::Local { runtime, content } => {
                #[cfg(not(feature = "compute"))]
                {
                    let _ = (id, document, runtime, content);
                    return Err("local backends require the compute build".into());
                }
                #[cfg(feature = "compute")]
                {
                    let dialect = match runtime.as_str() {
                        "cuda" => hellas_executor::GpuDialect::Cuda,
                        "hip" => hellas_executor::GpuDialect::Hip,
                        "auto" if Path::new("/dev/nvidiactl").exists() => {
                            hellas_executor::GpuDialect::Cuda
                        }
                        "auto" => hellas_executor::GpuDialect::Hip,
                        _ => return Err("GPU runtime must be auto, hip, or cuda".into()),
                    };
                    let executor = match dialect {
                        hellas_executor::GpuDialect::Hip => &self.hip,
                        hellas_executor::GpuDialect::Cuda => &self.cuda,
                    };
                    let backend = executor
                        .get_or_try_init(|| async {
                            let mut config = hellas_executor::ExecutorSpawnConfig::new(
                                self.options.signer.clone(),
                                Default::default(),
                            );
                            config.gpu_config.backend = dialect;
                            hellas_executor::Executor::spawn_configured(config).await
                        })
                        .await?
                        .clone();
                    let mut paths = content.clone();
                    paths.extend(
                        document
                            .routes
                            .iter()
                            .filter(|route| route.backends.contains(&id.to_owned()))
                            .filter_map(|route| {
                                if let hellas_gateway::Presentation::Model { package, .. } =
                                    &route.presentation
                                {
                                    Some(package.clone())
                                } else {
                                    None
                                }
                            }),
                    );
                    self.index(paths).await?;
                    (
                        Backend::Local {
                            execution: crate::execution::local::LocalExecution {
                                backend,
                                content: self.options.content.clone(),
                            },
                            timeout: std::time::Duration::from_secs(86_400),
                        },
                        Some(hellas_executor::catena::evaluator(dialect)),
                    )
                }
            }
        };
        let price = backend.quote().await?;
        if let BackendKind::Paid { max_price, .. } = configured.kind
            && price > max_price
        {
            return Err("quoted price exceeds the backend limit".into());
        }
        Ok(BackendEntry {
            backend,
            evaluator,
            max_in_flight: configured.max_in_flight,
        })
    }

    /// Indexing is a content cache; it never replaces the serving document or drops old objects.
    #[cfg(feature = "compute")]
    async fn index(&self, paths: Vec<PathBuf>) -> Result<()> {
        let mut indexed = self.indexed.lock().await;
        let mut next = indexed.clone();
        let mut files = Vec::new();
        for path in paths {
            let path = std::fs::canonicalize(path)?;
            if next.insert(path.clone()) {
                collect_files(&path, &mut files)?;
            }
        }
        if files.is_empty() {
            return Ok(());
        }
        self.options
            .content
            .rescan(next.iter().cloned().collect(), IndexMode::Resume)
            .await?;
        for file in files {
            let object = hellas_store::content::file_content(&file)?;
            let name = PinName::new(format!("models/{}", object.id()))?;
            let old = hellas_store::content::owner_pin(&self.options.content, &name).await?;
            let value = PinValue {
                target: Target::Object(object),
                policy: PinPolicy::Jobs,
                expires: None,
            };
            if old.as_ref() != Some(&value) {
                self.options
                    .content
                    .set_pin(&Scope::Owner, &name, old.as_ref(), Some(value))
                    .await?;
            }
        }
        *indexed = next;
        Ok(())
    }
}
#[cfg(feature = "compute")]
fn collect_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let kind = std::fs::symlink_metadata(path)?.file_type();
    if kind.is_file() {
        files.push(path.to_owned());
    } else if kind.is_dir() {
        for entry in std::fs::read_dir(path)? {
            collect_files(&entry?.path(), files)?;
        }
    } else {
        return Err("model content must contain regular files or directories".into());
    }
    Ok(())
}
