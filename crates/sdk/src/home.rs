//! A native application's identity, chain directory and execution targets.
use crate::BackendState;
use crate::execution::{ExecutionAttempt, ExecutionTarget, ExecutionTerms, Executor};
use crate::grant_client::{GrantSessionOptions, UnpinnedOffer};
use crate::job::Job;
use crate::paid_client::{PaidWorkOptions, bind_paid_endpoint};
use crate::transact::PaidAttemptPath;
use anyhow::{Context as _, bail, ensure};
use hellas_auth::ProducerSigningKey;
use hellas_auth::authority::{NodeKey, PrincipalId, ResourceId, UnixMillis};
use hellas_kernel::Secp256k1Signer;
use hellas_private::StoreLocation;
use hellas_rpc::Assurance;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

/// Resolved placement is the same runtime type used by every gateway backend.
pub use crate::Backend as Target;

pub struct Home {
    transport: iroh::SecretKey,
    pub settlement: Secp256k1Signer,
    pub producer: ProducerSigningKey,
    owner: std::sync::OnceLock<hellas_kernel::SoftPasskey>,
    pub home: StoreLocation,
    pub chain: hellas_chain::chain_dir::ChainDir,
    /// Bound on first use; [`Home::close`] closes them however the command ends,
    /// after the executor that borrowed them has finished.
    paid_endpoint: tokio::sync::OnceCell<iroh::Endpoint>,
    grant_endpoint: tokio::sync::OnceCell<iroh::Endpoint>,
    #[cfg(feature = "compute")]
    pub local_content: tokio::sync::OnceCell<hellas_store::content::DiskStore>,
}

impl Home {
    pub fn new(
        identity: &crate::identity::LocalIdentity,
        owner: Option<&hellas_kernel::SoftPasskey>,
        home: &StoreLocation,
        chain: &hellas_chain::genesis::ChainProfile,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            transport: identity.transport_key.clone(),
            settlement: crate::identity::settlement_signer(identity)?,
            producer: identity.node_key.clone(),
            owner: owner
                .cloned()
                .map_or_else(std::sync::OnceLock::new, Into::into),
            home: home.clone(),
            chain: hellas_chain::chain_dir::ChainDir::open(home, chain)?,
            paid_endpoint: tokio::sync::OnceCell::new(),
            grant_endpoint: tokio::sync::OnceCell::new(),
            #[cfg(feature = "compute")]
            local_content: tokio::sync::OnceCell::new(),
        })
    }

    /// Release command-owned endpoints and local content on every return path.
    pub async fn command(
        &self,
        work: impl std::future::Future<Output = anyhow::Result<()>>,
    ) -> anyhow::Result<()> {
        let result = work.await;
        self.close().await;
        result
    }

    /// Paid and granted work act for the principal, whose home key is
    /// created on first use; local work needs none.
    pub fn owner(&self) -> anyhow::Result<&hellas_kernel::SoftPasskey> {
        if let Some(owner) = self.owner.get() {
            return Ok(owner);
        }
        let owner = crate::identity::principal(&self.home)?;
        Ok(self.owner.get_or_init(|| owner))
    }

    pub async fn paid_endpoint(&self) -> anyhow::Result<iroh::Endpoint> {
        let bind = || bind_paid_endpoint(self.transport.clone());
        Ok(self.paid_endpoint.get_or_try_init(bind).await?.clone())
    }

    async fn grant_endpoint(&self) -> anyhow::Result<iroh::Endpoint> {
        let bind = || crate::grant_client::bind_endpoint(self.transport.clone());
        Ok(self.grant_endpoint.get_or_try_init(bind).await?.clone())
    }
}

pub fn select_attempt(
    path: &PaidAttemptPath,
    job: &Job,
    buy_again: bool,
) -> anyhow::Result<ExecutionAttempt> {
    let parent = path
        .as_path()
        .parent()
        .context("purchase directory is missing")?;
    path.durability().create_dir_all(parent)?;
    let pointer = path.as_path().with_extension("latest");
    struct AttemptPointerLock(std::fs::File);
    impl Drop for AttemptPointerLock {
        fn drop(&mut self) {
            let _ = self.0.unlock();
        }
    }
    let lock = hellas_private::open_lock_beside(&pointer)?;
    lock.try_lock()
        .map_err(|_| anyhow::anyhow!("another command is selecting this job's attempt"))?;
    let _lock = AttemptPointerLock(lock);
    let existing = match hellas_private::read_bounded_regular_file(&pointer, 32) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if !buy_again && let Some(id) = existing {
        let id = std::str::from_utf8(&id)?;
        ensure!(
            id.len() == 32
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "invalid purchase attempt pointer"
        );
        let nonce: [u8; 16] = hex::decode(id)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid purchase attempt pointer"))?;
        let attempt_path = path.with_nonce(nonce);
        return Ok(ExecutionAttempt::open_existing_paid(
            &attempt_path,
            job.input(),
            job.price(),
        )?);
    }
    if !buy_again {
        let prefix = format!("{}.", job.digest());
        for entry in std::fs::read_dir(parent)? {
            let name = entry?.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Some(id) = name
                .strip_prefix(&prefix)
                .and_then(|name| name.strip_suffix(".json"))
                && id.len() == 32
                && id.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                bail!(
                    "purchase attempt pointer is missing; recover the existing attempt before starting another"
                );
            }
        }
    }
    let nonce = rand::random::<[u8; 16]>();
    let id = hex::encode(nonce);
    let attempt_path = path.with_nonce(nonce);
    ensure!(
        !attempt_path.as_path().try_exists()?,
        "purchase attempt identity already exists"
    );
    let attempt = ExecutionAttempt::open_paid(&attempt_path, job.input(), job.price())?;
    path.durability()
        .write_atomically(&pointer, ".writing", id.as_bytes())?;
    Ok(attempt)
}

pub fn select_policy<'a>(
    policies: impl IntoIterator<Item = &'a hellas_authority::model::grant::records::GrantPolicy>,
    resource: Option<ResourceId>,
) -> anyhow::Result<&'a hellas_authority::model::grant::records::GrantPolicy> {
    let mut selected = policies
        .into_iter()
        .filter(|policy| resource.is_none_or(|id| policy.resource == id));
    let policy = selected
        .next()
        .context("grant contains no matching resource")?;
    ensure!(
        selected.next().is_none(),
        "grant resource is ambiguous; select --resource"
    );
    Ok(policy)
}

/// Inputs for placement. Model rendering stays with the client.
pub enum TargetSpec {
    Access {
        file: PathBuf,
        provider: Option<hellas_client::ProviderAddress>,
        trust: Option<Box<hellas_client::ProviderTrustAnchor>>,
        resource: Option<ResourceId>,
    },
    Paid(Box<PaidWorkOptions>),
    #[cfg(feature = "compute")]
    Local {
        content: hellas_store::content::DiskStore,
        gpu: hellas_executor::GpuConfig,
        timeout: Duration,
    },
}

impl Home {
    /// Load or create the home's identity and principal, then open its chain directory.
    pub fn open(
        location: &StoreLocation,
        chain: &hellas_chain::genesis::ChainProfile,
    ) -> anyhow::Result<Self> {
        let identity = crate::identity::load_or_create(&location.join("identity"))?;
        let principal = crate::identity::principal(location)?;
        Self::new(&identity, Some(&principal), location, chain)
    }
    pub fn principal(&self) -> anyhow::Result<PrincipalId> {
        Ok(PrincipalId::from_public_key(hellas_auth::PublicKey::P256(
            self.owner()?.party_key().to_bytes(),
        ))?)
    }
    pub async fn close(&self) {
        #[cfg(feature = "compute")]
        if let Some(content) = self.local_content.get() {
            content.close().await;
        }

        for endpoint in [self.paid_endpoint.get(), self.grant_endpoint.get()]
            .into_iter()
            .flatten()
        {
            endpoint.close().await;
        }
    }
    pub async fn target(&self, spec: TargetSpec) -> anyhow::Result<Target> {
        match spec {
            TargetSpec::Access {
                file,
                provider,
                trust,
                resource,
            } => {
                let principal = self.principal()?;
                let holder = NodeKey::from_public_key(self.producer.public_key())?;
                let bundle = crate::access_bundle::AccessBundle::load(&file, &principal, &holder)
                    .with_context(|| format!("access file {}", file.display()))?;
                ensure!(
                    bundle.offers.len() == 1,
                    "a job uses an access file with one offer"
                );
                access_target(
                    bundle,
                    resource,
                    provider,
                    trust.map(|trust| *trust),
                    Arc::new(self.producer.clone()),
                    &self.home,
                    self.grant_endpoint().await?,
                )
            }
            TargetSpec::Paid(options) => {
                ensure!(
                    options.expected_price > 0,
                    "paid execution requires --pay MAX; select --access for grant work"
                );
                let owner = Arc::new(crate::client_owner::ClientOwner::new(
                    Arc::new(self.owner()?.clone()),
                    self.settlement.party_key(),
                    &self.chain,
                )?);
                Ok(Target::paid(
                    None,
                    *options,
                    self.paid_endpoint().await?,
                    self.settlement.clone(),
                    owner,
                ))
            }
            #[cfg(feature = "compute")]
            TargetSpec::Local {
                content,
                gpu,
                timeout,
            } => {
                let backend = crate::execution::local::spawn(
                    Arc::new(self.producer.clone()),
                    gpu,
                    &Default::default(),
                )
                .await;
                match backend {
                    Ok(backend) => Ok(Target::local(
                        crate::execution::local::LocalExecution { backend, content },
                        timeout,
                    )),
                    Err(error) => {
                        content.close().await;
                        Err(error.into())
                    }
                }
            }
        }
    }
}

/// Resolve the same signed grant for an access file or an embedded gateway document.
pub(crate) fn access_target(
    bundle: crate::access_bundle::AccessBundle,
    resource: Option<ResourceId>,
    expected: Option<hellas_client::ProviderAddress>,
    trust: Option<hellas_client::ProviderTrustAnchor>,
    signer: Arc<ProducerSigningKey>,
    home: &StoreLocation,
    endpoint: iroh::Endpoint,
) -> anyhow::Result<Target> {
    let principal = bundle.subject;
    let (offers, application) = bundle.into_parts();
    let policy = select_policy(
        offers
            .iter()
            .flat_map(|offer| &offer.offer().grant.policies),
        resource,
    )?;
    let offer = offers
        .iter()
        .find(|offer| {
            offer
                .offer()
                .grant
                .policies
                .iter()
                .any(|p| p.resource == policy.resource)
        })
        .context("selected grant offer is missing")?;
    let provider = hellas_client::ProviderAddress::of(&offer.offer().provider)?;
    ensure!(
        expected.is_none_or(|expected| provider == expected),
        "offer does not match --provider"
    );
    let trust = trust.unwrap_or(hellas_client::ProviderTrustAnchor {
        expected_genesis: provider.enrollment,
        required_assurance: Assurance::ProducerSigned,
        apple_app_attest: None,
    });
    let target = UnpinnedOffer::decode(&offer.encode()?, UnixMillis(0))?.pin(&trust)?;
    Ok(Target::grant(
        policy.clone(),
        GrantSessionOptions {
            target,
            principal,
            signer,
            application: Arc::new(application),
            journal_root: home.child(data_root(home, &principal)?).child("channels"),
            control_timeout: Duration::from_secs(90),
        },
        crate::grant_client::GrantTransport::Remote(endpoint),
    ))
}

/// One private tree per principal, named by its curve and compressed key.
pub fn data_root(home: &Path, principal: &PrincipalId) -> anyhow::Result<PathBuf> {
    let base = crate::identity::grant_data_path(home);
    Ok(base.join(format!("p256-{}", hex::encode(principal.as_bytes()))))
}
impl Target {
    /// Construct a job executor using the existing journals and attempt format.
    pub fn executor(
        &self,
        job: &Job,
        attempt: Option<&Path>,
        buy_again: bool,
    ) -> anyhow::Result<Executor> {
        ensure!(
            !buy_again || matches!(self.state, BackendState::Paid(_)),
            "only paid work can be bought again"
        );
        let mut executor = Executor::new(self.clone());
        match &self.state {
            BackendState::Unavailable(error) => bail!("{error}"),
            BackendState::Paid(paid) => {
                let path = PaidAttemptPath::new(
                    &paid.options.config.chain,
                    paid.options.provider,
                    paid.owner.principal(),
                    job.digest(),
                );
                ensure!(
                    attempt.is_none(),
                    "explicit attempt paths are for grant work"
                );
                executor.attempt = Some(select_attempt(&path, job, buy_again)?);
            }
            BackendState::Grant(grant) => {
                let crate::GrantBackend {
                    options, policy, ..
                } = grant.as_ref();
                job.input().admits(&policy.invocation_policy, false)?;
                let offer = options.target.offer();
                let provider = hellas_client::ProviderAddress::of(&offer.provider)?;
                let grants = options
                    .journal_root
                    .parent()
                    .and_then(Path::parent)
                    .context("grant journal root is missing")?;
                let default_attempt = grants
                    .join("grant-attempts")
                    .join(provider.to_string())
                    .join(offer.grant.id.to_string())
                    .join(format!("{}.json", job.digest()));
                let mut attempt = ExecutionAttempt::open(
                    attempt.unwrap_or(&default_attempt),
                    job.input(),
                    ExecutionTerms::Grant {
                        resource: policy.resource,
                    },
                )?;
                attempt.bind_target(ExecutionTarget {
                    network: offer.network,
                    provider,
                })?;
                executor.attempt = Some(attempt);
            }
            BackendState::Fetch { .. } | BackendState::Local { .. } => {}
        }
        Ok(executor)
    }
}

#[cfg(test)]
mod tests;
