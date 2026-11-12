//! `serve --paid-work-config FILE`: use the exact owner-approved paid terms.
//! An optional owner passkey also bootstraps approval and delegates stake.
use super::*;
use anyhow::ensure;
use hellas_auth::{Digest, authority::*};
use hellas_chain::{LightClient as _, client::RemoteLightClient, domain::Transaction};
use hellas_kernel::{CoinId, EdgeValues, Fees, SoftPasskey};
use hellas_private::StoreLocation;
use hellas_rpc::protocol::invocation::{
    Admission, ComputePrograms, InvocationPolicy, Limits, compute,
    fetch::{FetchAdmission, FetchLimits},
};
use hellas_sdk::node_control::profile;
use std::path::Path;
use {
    hellas_authority::authenticator::Authenticator, hellas_authority::authenticator::kernel_auth,
    hellas_authority::grant_service::WorkAdministration,
    hellas_authority::model::grant::admin::WorkControlCommand, hellas_authority::node::SessionKey,
    hellas_authority::work_store::grant::NodeStore,
    hellas_authority::work_store::grant::NodeStoreError,
    hellas_authority::work_store::grant::OwnerApproval,
    hellas_authority::work_store::grant::PreparedBootstrap, hellas_channel::model::paid_policy::*,
    hellas_channel::model::work::*,
};

/// The provider's paid terms. Every value is the operator's; nothing defaults.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PaidWorkFile {
    jobs_per_channel: u64,
    payment: JobPaymentPolicyV2,
    channel: PaidChannelPolicyV1,
    offers: OfferPolicy,
    limits: Limits,
    /// Admit any program of one compute id, or only the listed programs.
    compute: Option<ComputeTerms>,
    /// Admit caller-signed HTTPS Fetch under these bounds.
    fetch: Option<FetchFile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
enum ComputeTerms {
    Any(String),
    Only(Vec<compute::ProgramId>),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchFile {
    route: hellas_rpc::protocol::invocation::fetch::FetchRoutePolicy,
    limits: FetchLimits,
}

pub struct PaidWork {
    pub chain: WorkConfig,
    root: StoreLocation,
    owner: Option<SoftPasskey>,
    policy: PaidPolicy,
}

impl PaidWork {
    /// Whether these terms admit Compute programs nobody configured.
    pub fn admits_any_program(&self) -> bool {
        self.policy.invocation_policy.admits_any_program()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    approval: PreparedBootstrap,
    credential_id: CredentialId,
    credential_secret: [u8; 32],
    certificate: Vec<u8>,
    private_key: Vec<u8>,
}
impl Bootstrap {
    fn secret(&self) -> CredentialSecret {
        CredentialSecret::from_parts(self.credential_id, self.credential_secret)
    }
}

fn publish(path: &Path, bytes: &[u8]) -> CliResult<()> {
    let parent = path.parent().context("paid state needs a parent")?;
    hellas_private::create_dir_all_durable(parent)?;
    let file = hellas_private::private_tempfile(parent, ".paid-", ".new")?;
    profile::publish_private(file, path, bytes)?;
    Ok(())
}

impl PaidWorkFile {
    fn read(path: &Path) -> CliResult<Self> {
        let bytes = hellas_private::read_bounded_regular_file(path, 64 * 1024)
            .with_context(|| format!("failed to read {}", path.display()))?;
        toml::from_str(std::str::from_utf8(&bytes).context("paid-work config must be UTF-8")?)
            .with_context(|| format!("failed to parse {}", path.display()))
    }

    fn checked_policy(self, path: &Path, fetch_config: Option<&Path>) -> CliResult<PaidPolicy> {
        let fetch_contract = self
            .fetch
            .as_ref()
            .map(|fetch| paid_fetch_contract(fetch_config, &fetch.route))
            .transpose()?;
        self.policy(fetch_contract)
            .with_context(|| format!("invalid paid terms in {}", path.display()))
    }

    fn policy(self, fetch_contract: Option<hellas_rpc::FetchContract>) -> CliResult<PaidPolicy> {
        let capacity = self
            .payment
            .fixed_price
            .checked_mul(self.jobs_per_channel)
            .context("paid channel capacity overflow")?;
        let value = capacity
            .checked_add(self.offers.omission_bond)
            .context("paid funding overflow")?;
        let mut admissions = Vec::new();
        match self.compute {
            Some(ComputeTerms::Any(evaluator)) => admissions.push(Admission::Compute {
                evaluator,
                programs: ComputePrograms::Any {},
            }),
            Some(ComputeTerms::Only(programs)) => {
                admissions.push(Admission::compute_only(&programs)?);
            }
            None => {}
        }
        if let Some(fetch) = self.fetch {
            admissions.push(Admission::Fetch {
                admission: FetchAdmission {
                    contract: fetch_contract.context("paid Fetch terms have no route contract")?,
                    route: fetch.route,
                    limits: fetch.limits,
                },
            });
        }
        let policy = PaidPolicy {
            channel_policy: self.channel,
            invocation_policy: InvocationPolicy {
                admissions,
                limits: self.limits,
            },
            payment_policy: self.payment,
            expected_payment_values: EdgeValues::new(value, 0, Fees::ZERO),
            jobs_per_channel: self.jobs_per_channel,
            offers: self.offers,
        };
        policy.check()?;
        Ok(policy)
    }
}

impl PaidWork {
    pub fn approval(
        path: &Path,
        fetch_config: Option<&Path>,
        expected_revision: Revision,
    ) -> CliResult<WorkControlCommand> {
        Ok(WorkControlCommand::SetPaidPolicy {
            expected_revision,
            policy: Box::new(PaidWorkFile::read(path)?.checked_policy(path, fetch_config)?),
        })
    }
    /// Read and check the whole file before anything binds.
    ///
    /// `fetch_config` is the same `--fetch-config` this node will serve: the
    /// paid Fetch admission's contract is the route's actual sealed contract,
    /// not an assumed one.
    pub fn load(
        path: &Path,
        home: StoreLocation,
        owner: Option<SoftPasskey>,
        fetch_config: Option<&Path>,
        profile: hellas_chain::genesis::ChainProfile,
    ) -> CliResult<Self> {
        let file = PaidWorkFile::read(path)?;
        let chain = WorkConfig::for_chain(profile, &home)?;
        let root = hellas_sdk::grant_config::GrantConfig::provider_dir(&home);
        let policy = file.checked_policy(path, fetch_config)?;
        hellas_private::create_dir_all_durable(&root)?;
        hellas_private::create_dir_all_durable(&chain.chain.provider())?;
        Ok(Self {
            chain,
            root,
            owner,
            policy,
        })
    }

    pub(super) async fn start(
        &self,
        mut provider: hellas_sdk::ProviderOptions,
        grants: Option<hellas_sdk::grant_config::GrantConfig>,
        path: Option<PathBuf>,
    ) -> CliResult<hellas_sdk::node_control::host::HostHandle> {
        ensure!(
            provider
                .open_identity
                .enrollment()
                .genesis
                .statement
                .root_kind
                == hellas_rpc::RootKind::Software,
            "paid startup requires producer-signed assurance"
        );
        let (work, _) = provider
            .work
            .as_ref()
            .context("paid startup requires a paid-work chain")?;
        let key = work.settlement_key.clone();
        let grants = grants.unwrap_or_else(|| {
            hellas_sdk::grant_config::GrantConfig::unconfigured(self.chain.chain.home())
        });
        let credential = self
            .prepare(
                &grants,
                provider.open_identity.enrollment(),
                &provider.executor.producer_key,
            )
            .await?;
        let admits_fetch = self
            .policy
            .invocation_policy
            .admissions
            .iter()
            .any(|admission| matches!(admission, Admission::Fetch { .. }));
        if admits_fetch && path.is_none() {
            provider.executor.fetch_routes.register(
                FetchRoute::new("http", "request"),
                hellas_providers::HttpProviderConfig::default()
                    .into_entry(hellas_executor::FetchRoutePolicy::default())?,
            )?;
        }
        self.validate_fetch_admission(&provider.executor.fetch_routes)?;
        let host = super::configuration::start_host(
            provider,
            Some(grants),
            path,
            None,
            self.chain.chain.home(),
        )
        .await?;
        let ready = async {
            self.preflight_stake(&key).await?;
            let admin = host
                .administration()?
                .context("paid administration is unavailable")?;
            let policy = self.configure(&admin, credential.as_ref()).await?;
            self.delegate(&key, &policy).await
        }
        .await;
        if let Err(error) = ready {
            host.shutdown().await?;
            return Err(error);
        }
        Ok(host)
    }

    /// Every paid Fetch admission names the trusted manifest the executor
    /// compares against the route it dispatches to. Check that the routes this
    /// node actually serves implement the derived contract before binding.
    fn validate_fetch_admission(&self, routes: &FetchRouteRegistry) -> CliResult<()> {
        use hellas_rpc::protocol::invocation::fetch::FetchRoutePolicy;
        for admission in &self.policy.invocation_policy.admissions {
            let Admission::Fetch { admission } = admission else {
                continue;
            };
            let expected = admission.contract.manifest_id();
            match &admission.route {
                FetchRoutePolicy::SealedRoute { service, method } => {
                    let entry = routes
                        .entry(&FetchRoute::new(service, method))
                        .with_context(|| {
                            format!(
                                "paid Fetch admits route {service}/{method}, but this node does not serve it"
                            )
                        })?;
                    ensure!(
                        entry.execution_environment() == expected,
                        "paid Fetch admission names contract {expected}, but route {service}/{method} implements {}",
                        entry.execution_environment()
                    );
                }
                FetchRoutePolicy::OpenFetch { .. } => {
                    ensure!(
                        routes.has_environment(expected),
                        "paid Fetch admission names the HTTP contract {expected}, but this node serves no route that implements it"
                    );
                }
            }
        }
        Ok(())
    }

    /// A verified source for this provider's own delegation reads.
    async fn chain(&self) -> CliResult<RemoteLightClient> {
        Ok(hellas_sdk::client_chain::connect_at(
            &self.chain,
            hellas_channel::work::MAX_CERTIFIED_AGE,
            0,
        )
        .await?)
    }

    /// A lowered stake cap needs an already delegated coin that fits it.
    async fn preflight_stake(&self, key: &Secp256k1Signer) -> CliResult<()> {
        let Some(owner) = &self.owner else {
            return Ok(());
        };
        let cap = self.policy.offers.max_stake_per_client;
        let path = self.chain.chain.provider().join("delegation.json");
        if !path.try_exists()? {
            return Ok(());
        }
        let receipt: Delegation = serde_json::from_slice(
            &hellas_private::read_bounded_regular_file(&path, 64 * 1024)?,
        )?;
        if receipt.unit <= cap {
            return Ok(());
        }
        let client = self.chain().await?;
        let delegate = key.party_key().into();
        let mut after = None;
        loop {
            let Some(page) = client.get_holdings(delegate, after).await? else {
                break;
            };
            if page.delegated_coins(delegate).iter().any(|(_, coin)| {
                coin.value > 0 && coin.value <= cap && coin.owner.into_kernel() == owner.party_key()
            }) {
                return Ok(());
            }
            let Some(next) = page.next_holdings() else {
                break;
            };
            after = Some(next);
        }
        anyhow::bail!(
            "lower stake cap has no eligible delegated coin; reshape unused stake with chain delegate --split before changing the policy"
        )
    }

    pub(super) async fn prepare(
        &self,
        config: &hellas_sdk::grant_config::GrantConfig,
        enrollment: &hellas_rpc::ProviderEnrollmentBundle,
        producer: &ProducerSigningKey,
    ) -> CliResult<Option<CredentialSecret>> {
        let now = UnixMillis::now()?;
        let network = hellas_authority::model::grant::grant_network();
        let bootstrap_path = self.root.join("bootstrap.json");
        let store = match NodeStore::open(
            &config.journal_root(),
            network,
            Some(enrollment.clone()),
            now,
        )
        .await
        {
            Ok(store) => store,
            Err(NodeStoreError::Uninitialized) => {
                let owner = self.owner.as_ref().context(
                        "paid startup without a passkey requires an initialized authority and an owner-approved paid policy",
                    )?;
                if !bootstrap_path.try_exists()? {
                    let authority = AuthorityId(Digest::hash(&enrollment.canonical_bytes()));
                    let subject = crate::commands::contributions::principal(owner)?;
                    let mut permissions: BTreeSet<_> = [
                        GRANT_ISSUE,
                        GRANT_REVOKE,
                        GRANT_ADMINISTER,
                        CREDENTIAL_ISSUE,
                        CREDENTIAL_REVOKE,
                    ]
                    .into_iter()
                    .map(|name| {
                        Ok(Permission {
                            operation: OperationId::new(name)?,
                            resource: authority.resource(),
                        })
                    })
                    .collect::<Result<_, hellas_auth::authority::AuthorityError>>()?;
                    for op in hellas_authority::operations::OPERATIONS
                        .iter()
                        .filter(|op| {
                            !matches!(op.scope, hellas_authority::operations::Scope::Allowance)
                        })
                    {
                        permissions.insert(op.permission(authority, None)?);
                    }
                    let administrator = GrantSpec {
                        authority,
                        subject,
                        issuance: Some(IssuanceCeiling {
                            operations: permissions.iter().map(|p| p.operation.clone()).collect(),
                            resources: CeilingResources::Authority,
                            max_validity_ms: u64::MAX,
                            max_delegation_depth: MAX_DELEGATION_DEPTH,
                        }),
                        permissions,
                        not_before: now,
                        expires: UnixMillis(u64::MAX),
                        delegation_depth: 0,
                    };
                    let holder = NodeKey::from_public_key(producer.public_key())?;
                    let root = GrantId([0; 16]);
                    let approval = OwnerApproval {
                        assertion: owner
                            .assert(ownership_digest(
                                Ownership::Bootstrap { root, target: None },
                                &administrator,
                                &administrator,
                                holder,
                            ))
                            .await?,
                        administrator: administrator.clone(),
                        credential: administrator,
                        holder,
                    };
                    let (approval, secret) = approval.prepare(None)?;
                    let (certificate, private_key) = match (
                        config.control_certificate().try_exists()?,
                        config.control_private_key().try_exists()?,
                    ) {
                        (true, true) => {
                            profile::server_identity(
                                &config.control_certificate(),
                                &config.control_private_key(),
                            )?;
                            (
                                hellas_private::read_bounded_regular_file(
                                    &config.control_certificate(),
                                    64 * 1024,
                                )?,
                                hellas_private::read_bounded_regular_file(
                                    &config.control_private_key(),
                                    64 * 1024,
                                )?,
                            )
                        }
                        (false, false) => {
                            let tls = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
                            (tls.cert.der().to_vec(), tls.signing_key.serialize_der())
                        }
                        _ => anyhow::bail!("paid control TLS configuration is incomplete"),
                    };
                    publish(
                        &bootstrap_path,
                        &serde_json::to_vec(&Bootstrap {
                            approval,
                            credential_id: secret.id(),
                            credential_secret: *secret.expose_secret(),
                            certificate,
                            private_key,
                        })?,
                    )?;
                }
                let data: Bootstrap = serde_json::from_slice(
                    &hellas_private::read_bounded_regular_file(&bootstrap_path, 64 * 1024)?,
                )?;
                // Resume either file publication from the same prepared pair.
                for (path, bytes) in [
                    (config.control_certificate(), &data.certificate),
                    (config.control_private_key(), &data.private_key),
                ] {
                    if path.try_exists()? {
                        ensure!(
                            hellas_private::read_bounded_regular_file(&path, 64 * 1024)? == *bytes,
                            "paid control TLS differs from its saved initialization"
                        );
                    } else {
                        publish(&path, bytes)?;
                    }
                }
                NodeStore::bootstrap_prepared(
                    &config.journal_root(),
                    network,
                    GrantId([0; 16]),
                    data.approval,
                    Some(enrollment.clone()),
                    now,
                )
                .await?
            }
            Err(error) => return Err(error.into()),
        };
        let store = store.into_state().await;
        let Some(owner) = &self.owner else {
            ensure!(
                store
                    .paid_policy()
                    .is_some_and(|current| current.policy == self.policy),
                "paid terms differ from the owner-approved policy; approve the exact policy with the owner's admin profile before starting"
            );
            return Ok(None);
        };
        let authority = store.authority();
        let principal = crate::commands::contributions::principal(owner)?;
        ensure!(
            authority
                .grant(authority.root_grant())
                .is_some_and(|g| g.spec().subject == principal),
            "selected owner is not this provider's owner"
        );
        let id = authority.authority();
        let authorization = authority.root_grant();
        if !bootstrap_path.try_exists()? {
            return Ok(None);
        }
        let data: Bootstrap = serde_json::from_slice(&hellas_private::read_bounded_regular_file(
            &bootstrap_path,
            64 * 1024,
        )?)?;
        let credential = self.root.join("credential");
        if !credential.try_exists()? {
            let file = hellas_private::private_tempfile(&self.root, ".credential-", ".new")?;
            profile::save_credential(file, &credential, &data.secret())?;
        }
        let admin = self.root.join("admin.json");
        let bytes = serde_json::to_vec(
            &serde_json::json!({ "authority": id, "authorization": authorization, "credential": std::path::absolute(&credential)?, "local": { "certificate": std::path::absolute(config.control_certificate())?, "server_name": "localhost" } }),
        )?;
        hellas_private::write_atomically(&admin, ".new", &bytes)?;
        eprintln!("paid administration profile: {}", admin.display());
        Ok(Some(data.secret()))
    }

    /// Commit the file's policy unless the authority already holds exactly it.
    pub(super) async fn configure(
        &self,
        admin: &WorkAdministration,
        credential: Option<&CredentialSecret>,
    ) -> CliResult<PaidPolicy> {
        let node = admin.node();
        if let Some(owner) = &self.owner {
            ensure!(
                node.owner().await? == crate::commands::contributions::principal(owner)?,
                "selected owner is not this provider's owner"
            );
        }
        let current = node.paid_policy().await?;
        if current
            .as_ref()
            .is_none_or(|current| current.policy != self.policy)
        {
            let owner = self.owner.as_ref().context(
                "paid terms differ from the owner-approved policy; approve the exact policy with the owner's admin profile before starting",
            )?;
            let caller = node
                .authenticate_session(
                    credential.context(
                        "this authority was not initialized by paid startup; approve its paid policy with the owner's admin profile",
                    )?,
                    SessionKey::Passkey(owner),
                )
                .await?;
            admin
                .execute(
                    &caller,
                    GrantId([0; 16]),
                    WorkControlCommand::SetPaidPolicy {
                        expected_revision: current.map_or(Revision(0), |current| current.revision),
                        policy: Box::new(self.policy.clone()),
                    },
                )
                .await?;
        }
        Ok(node
            .paid_policy()
            .await?
            .context("paid policy was not committed")?
            .policy)
    }

    pub(super) async fn delegate(
        &self,
        key: &Secp256k1Signer,
        policy: &PaidPolicy,
    ) -> CliResult<()> {
        if self.owner.is_none() {
            // Fleet owners delegate stake from their own machine. The paid
            // runner admits only live stake belonging to the authority owner.
            return Ok(());
        }
        let client = self.chain().await?;
        self.delegate_once(&client, key, policy).await
    }

    async fn delegate_once(
        &self,
        client: &RemoteLightClient,
        key: &Secp256k1Signer,
        policy: &PaidPolicy,
    ) -> CliResult<()> {
        use hellas_chain::domain::{DecodeExt as _, Encode as _};
        let signer = self
            .owner
            .as_ref()
            .context("stake delegation requires an owner passkey")?;
        let owner = signer.party_key();
        let path = self.chain.chain.provider().join("delegation.json");
        // The chain this delegation was made on: its consensus identity.
        let genesis = hex::encode(self.chain.chain.consensus_digest());
        let network = self.chain.network();
        let receipt: Delegation = if path.try_exists()? {
            serde_json::from_slice(&hellas_private::read_bounded_regular_file(
                &path,
                64 * 1024,
            )?)?
        } else {
            let mut blocks = client.finalized_blocks().await?;
            let input = 'search: loop {
                let mut after = None;
                while let Some(page) = client.get_holdings(owner.into(), after).await? {
                    let selected = page
                        .owned_coins(owner.into())
                        .into_iter()
                        .filter(|(_, coin)| {
                            coin.delegate.is_none()
                                && coin.value >= policy.offers.max_stake_per_client
                        })
                        .min_by_key(|(id, coin)| (coin.value, *id));
                    if let Some((id, _)) = selected {
                        break 'search id;
                    }
                    let Some(next) = page.next_holdings() else {
                        break;
                    };
                    after = Some(next);
                }
                blocks.next().await?;
            };
            let plan = hellas_sdk::coin_owner::OwnerReshape::prepare(
                client,
                network,
                owner,
                &[input],
                Some(key.party_key()),
                Some(policy.offers.max_stake_per_client),
            )
            .await?;
            let assertion = signer
                .assert(Digest::from(*plan.payload_hash().as_bytes()))
                .await?;
            let tx = Transaction::Kernel(
                plan.authorize(kernel_auth(&signer.public_key()?, &assertion)?)?,
            );
            let receipt = Delegation {
                genesis: genesis.clone(),
                owner: hex::encode(owner.to_bytes()),
                delegate: hex::encode(key.party_key().to_bytes()),
                input: hex::encode(input.to_bytes()),
                unit: policy.offers.max_stake_per_client,
                transaction: tx.encode().to_vec(),
                confirmed: false,
            };
            publish(&path, &serde_json::to_vec(&receipt)?)?;
            receipt
        };
        ensure!(
            receipt.genesis == genesis
                && receipt.owner == hex::encode(owner.to_bytes())
                && receipt.delegate == hex::encode(key.party_key().to_bytes()),
            "stake delegation belongs to another owner, node or chain"
        );
        if receipt.confirmed {
            return Ok(());
        }
        let input = CoinId::from_bytes(
            hex::decode(&receipt.input)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid delegation input"))?,
        );
        let tx = Transaction::decode(receipt.transaction.as_slice())?;
        let Transaction::Kernel(hellas_kernel::Tx::Owner(reshape)) = &tx else {
            anyhow::bail!("stake delegation receipt is not an owner reshape");
        };
        // Included means the input is gone and the coins the reshape issues
        // exist, at one certified state.
        let issued: Vec<CoinId> =
            hellas_kernel::Reshape::output_ids(network, reshape.inputs(), reshape.outputs())
                .as_slice()
                .to_vec();
        let keys: Vec<_> = issued
            .iter()
            .chain([&input])
            .map(|id| hellas_chain::domain::ObjectKey::Coin(*id))
            .collect();
        let mut submitted = false;
        let mut blocks = client.finalized_blocks().await?;
        loop {
            let read = client
                .get_objects(keys.clone())
                .await?
                .context("no certified chain state")?;
            let input_live = read.coin(input)?.is_some();
            let mut outputs_live = true;
            for id in &issued {
                outputs_live &= read.coin(*id)?.is_some();
            }
            if !input_live && outputs_live {
                let mut receipt = receipt;
                receipt.confirmed = true;
                hellas_private::write_atomically(
                    &path,
                    ".confirmed",
                    &serde_json::to_vec(&receipt)?,
                )?;
                return Ok(());
            }
            ensure!(
                input_live,
                "another spend consumed the delegation input before it was included"
            );
            if !submitted {
                client.submit_tx(tx.clone()).await?;
                submitted = true;
            }
            blocks.next().await?;
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Delegation {
    genesis: String,
    owner: String,
    delegate: String,
    input: String,
    unit: u64,
    transaction: Vec<u8>,
    confirmed: bool,
}

#[cfg(test)]
mod tests;
