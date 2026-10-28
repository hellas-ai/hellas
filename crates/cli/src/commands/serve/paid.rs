//! `serve --paid-work-config FILE`: the selected owner approves exactly the
//! file's paid terms at startup and delegates the stake its offers bond.
use super::*;
use anyhow::ensure;
use hellas_auth::{Digest, authority::*};
use hellas_chain::{LightClient as _, domain::Transaction};
use hellas_kernel::{CoinId, EdgeValues, Fees, SoftPasskey};
use hellas_rpc::protocol::invocation::{
    Admission, InvocationPolicy, Limits,
    fetch::{FetchAdmission, FetchLimits},
};
use hellas_sdk::node_control::profile;
use std::path::Path;
use std::time::Duration;
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
    /// JSON chain configuration for a custom network; omit for the shipped devnet.
    chain_config: Option<PathBuf>,
    jobs_per_channel: u64,
    min_omit_response_blocks: u64,
    payment: JobPaymentPolicyV2,
    channel: PaidChannelPolicyV1,
    offers: OfferPolicy,
    limits: Limits,
    /// Admit Catena compute jobs.
    compute: bool,
    /// Admit caller-signed HTTPS Fetch under these bounds.
    fetch: Option<FetchFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchFile {
    route: hellas_rpc::protocol::invocation::fetch::FetchRoutePolicy,
    limits: FetchLimits,
}

pub struct PaidWork {
    pub chain: WorkConfig,
    root: PathBuf,
    owner: SoftPasskey,
    policy: PaidPolicy,
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
    fn policy(self) -> CliResult<PaidPolicy> {
        let capacity = self
            .payment
            .fixed_price
            .checked_mul(self.jobs_per_channel)
            .context("paid channel capacity overflow")?;
        let value = capacity
            .checked_add(self.offers.omission_bond)
            .context("paid funding overflow")?;
        let mut admissions = Vec::new();
        if self.compute {
            admissions.push(Admission::Compute {
                evaluator: hellas_rpc::protocol::invocation::compute::EVALUATOR.into(),
            });
        }
        if let Some(fetch) = self.fetch {
            admissions.push(Admission::Fetch {
                admission: FetchAdmission {
                    contract: hellas_rpc::FetchContract::http()?,
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
            min_omit_response_blocks: self.min_omit_response_blocks,
            jobs_per_channel: self.jobs_per_channel,
            offers: self.offers,
        };
        policy.check()?;
        Ok(policy)
    }
}

impl PaidWork {
    /// Read and check the whole file before anything binds.
    pub fn load(path: &Path, root: PathBuf, owner: SoftPasskey) -> CliResult<Self> {
        let bytes = hellas_private::read_bounded_regular_file(path, 64 * 1024)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let file: PaidWorkFile =
            toml::from_str(std::str::from_utf8(&bytes).context("paid-work config must be UTF-8")?)
                .with_context(|| format!("failed to parse {}", path.display()))?;
        let chain = match &file.chain_config {
            Some(chain) => load_work_config(&path.parent().unwrap_or(Path::new(".")).join(chain))?,
            None => hellas_sdk::client_chain::devnet(&root)?,
        };
        let policy = file
            .policy()
            .with_context(|| format!("invalid paid terms in {}", path.display()))?;
        hellas_private::create_dir_all_durable(&root)?;
        Ok(Self {
            chain,
            root,
            owner,
            policy,
        })
    }

    pub(super) async fn start<R: hellas_attestation::RootProver + Send + Sync + 'static>(
        &self,
        mut provider: hellas_sdk::ProviderOptions<R>,
        grants: Option<hellas_sdk::grant_config::GrantConfig>,
        path: Option<PathBuf>,
        transport: Option<iroh::Endpoint>,
    ) -> CliResult<hellas_sdk::node_control::host::HostHandle> {
        ensure!(
            provider.executor.assurance == Assurance::ProducerSigned,
            "paid startup requires producer-signed assurance"
        );
        let (work, chain) = provider
            .work
            .as_ref()
            .context("paid startup requires a chain node")?;
        let chain = chain.clone();
        let key = work.settlement_key.clone();
        let grants = grants
            .unwrap_or_else(|| hellas_sdk::grant_config::GrantConfig::unconfigured(&self.root));
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
        let host =
            super::configuration::start_host(provider, Some(grants), path, transport).await?;
        let ready = async {
            self.preflight_stake(&chain, &key).await?;
            let admin = host
                .administration()?
                .context("paid administration is unavailable")?;
            let policy = self.configure(&admin, credential.as_ref()).await?;
            self.delegate(&chain, &key, &policy).await
        }
        .await;
        if let Err(error) = ready {
            host.shutdown().await?;
            return Err(error);
        }
        Ok(host)
    }

    /// A lowered stake cap needs an already delegated coin that fits it.
    async fn preflight_stake(
        &self,
        chain: &hellas_sdk::FullNode,
        key: &Secp256k1Signer,
    ) -> CliResult<()> {
        let cap = self.policy.offers.max_stake_per_client;
        let path = self.root.join("delegation.json");
        if !path.try_exists()? {
            return Ok(());
        }
        let receipt: Delegation = serde_json::from_slice(
            &hellas_private::read_bounded_regular_file(&path, 64 * 1024)?,
        )?;
        if receipt.unit <= cap {
            return Ok(());
        }
        tokio::time::timeout(hellas_chain::node::RECOVERY_TIMEOUT, async {
            loop {
                let check = async {
                    let client = chain.view()?.client();
                    if let Some(listing) = client.get_coins_by_delegate(key.party_key().into()).await? {
                        for (id, value) in listing.coins {
                            if value > 0 && value <= cap
                                && let Some(coin) = client.get_coin(listing.snapshot.payload, id).await?
                                && coin.owner.into_kernel() == self.owner.party_key()
                                && coin.delegate == Some(key.party_key().into())
                            { return Ok::<_, anyhow::Error>(true); }
                        }
                    }
                    Ok(false)
                }.await;
                match check {
                    Err(error) if error.chain().any(|cause| matches!(cause.downcast_ref::<hellas_chain::QueryError>(), Some(hellas_chain::QueryError::StateUnavailable(_)))) => tokio::time::sleep(Duration::from_millis(100)).await,
                    result => return result,
                }
            }
        }).await.context("stake-cap preflight exceeded chain recovery bound")??.then_some(()).context("lower stake cap has no eligible delegated coin; reshape unused stake with chain delegate --split before changing the policy")
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
        let store =
            match NodeStore::open(&config.journal_root, network, Some(enrollment.clone()), now)
                .await
            {
                Ok(store) => store,
                Err(NodeStoreError::Uninitialized) => {
                    if !bootstrap_path.try_exists()? {
                        let authority = AuthorityId(Digest::hash(&enrollment.canonical_bytes()));
                        let subject = crate::commands::contributions::principal(&self.owner)?;
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
                                operations: permissions
                                    .iter()
                                    .map(|p| p.operation.clone())
                                    .collect(),
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
                            assertion: self
                                .owner
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
                            config.control_certificate.try_exists()?,
                            config.control_private_key.try_exists()?,
                        ) {
                            (true, true) => {
                                profile::server_identity(
                                    &config.control_certificate,
                                    &config.control_private_key,
                                )?;
                                (
                                    hellas_private::read_bounded_regular_file(
                                        &config.control_certificate,
                                        64 * 1024,
                                    )?,
                                    hellas_private::read_bounded_regular_file(
                                        &config.control_private_key,
                                        64 * 1024,
                                    )?,
                                )
                            }
                            (false, false) => {
                                let tls =
                                    rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
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
                        (&config.control_certificate, &data.certificate),
                        (&config.control_private_key, &data.private_key),
                    ] {
                        if path.try_exists()? {
                            ensure!(
                                hellas_private::read_bounded_regular_file(path, 64 * 1024)?
                                    == *bytes,
                                "paid control TLS differs from its saved initialization"
                            );
                        } else {
                            publish(path, bytes)?;
                        }
                    }
                    NodeStore::bootstrap_prepared(
                        &config.journal_root,
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
        let authority = store.state().authority();
        let principal = crate::commands::contributions::principal(&self.owner)?;
        ensure!(
            authority
                .grant(authority.root_grant())
                .is_some_and(|g| g.spec().subject == principal),
            "selected owner is not this provider's owner"
        );
        let id = authority.authority();
        let authorization = authority.root_grant();
        drop(store);
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
            &serde_json::json!({ "authority": id, "authorization": authorization, "credential": std::path::absolute(&credential)?, "local": { "certificate": std::path::absolute(&config.control_certificate)?, "server_name": "localhost" } }),
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
        ensure!(
            node.owner().await? == crate::commands::contributions::principal(&self.owner)?,
            "selected owner is not this provider's owner"
        );
        let current = node.paid_policy().await?;
        if current
            .as_ref()
            .is_none_or(|current| current.policy != self.policy)
        {
            let caller = node
                .authenticate_session(
                    credential.context(
                        "this authority was not initialized by paid startup; approve its paid policy with the owner's admin profile",
                    )?,
                    SessionKey::Passkey(&self.owner),
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
        chain: &hellas_sdk::FullNode,
        key: &Secp256k1Signer,
        policy: &PaidPolicy,
    ) -> CliResult<()> {
        let deadline = tokio::time::Instant::now() + hellas_chain::node::RECOVERY_TIMEOUT;
        tokio::time::timeout_at(deadline, async {
            loop {
                match self.delegate_once(chain, key, policy).await {
                    Err(error)
                        if error.chain().any(|cause| {
                            matches!(
                                cause.downcast_ref::<hellas_chain::QueryError>(),
                                Some(hellas_chain::QueryError::StateUnavailable(_))
                            )
                        }) =>
                    {
                        tokio::time::sleep(Duration::from_millis(100)).await
                    }
                    result => return result,
                }
            }
        })
        .await
        .context("stake delegation exceeded chain recovery bound")?
    }

    async fn delegate_once(
        &self,
        chain: &hellas_sdk::FullNode,
        key: &Secp256k1Signer,
        policy: &PaidPolicy,
    ) -> CliResult<()> {
        use hellas_chain::domain::{DecodeExt as _, Encode as _};
        let client = chain.view()?.client();
        let owner = self.owner.party_key();
        let path = self.root.join("delegation.json");
        let mut pins = Vec::from(hellas_chain::genesis_digest(&chain.config().genesis).as_ref());
        pins.extend_from_slice(chain.config().genesis_payload.as_ref());
        pins.extend_from_slice(&chain.config().threshold_identity);
        let genesis = hex::encode(Digest::hash(&pins).as_bytes());
        let mut receipt: Delegation = if path.try_exists()? {
            serde_json::from_slice(&hellas_private::read_bounded_regular_file(
                &path,
                64 * 1024,
            )?)?
        } else {
            let (input, height) = loop {
                if let Some(listing) = client.get_coins_by_owner(owner.into()).await? {
                    let mut selected = None;
                    let mut coins = listing.coins;
                    coins.sort_by_key(|(id, value)| (*value, *id));
                    for (id, value) in coins {
                        if value < policy.offers.max_stake_per_client {
                            continue;
                        }
                        if let Some(coin) = client.get_coin(listing.snapshot.payload, id).await?
                            && coin.owner.into_kernel() == owner
                            && coin.delegate.is_none()
                            && coin.value == value
                        {
                            selected = Some((id, listing.snapshot.height));
                            break;
                        }
                    }
                    if let Some(selected) = selected {
                        break selected;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            };
            let input = CoinId::from_bytes(input.0);
            let network = hellas_kernel::NetworkId::new(&chain.config().genesis.network_id)
                .context("invalid chain network")?;
            let plan = hellas_sdk::coin_owner::OwnerReshape::prepare(
                &client,
                network,
                owner,
                &[input],
                Some(key.party_key()),
                Some(policy.offers.max_stake_per_client),
            )
            .await?;
            let assertion = self
                .owner
                .assert(Digest::from(*plan.payload_hash().as_bytes()))
                .await?;
            let tx = Transaction::Kernel(
                plan.authorize(kernel_auth(&self.owner.public_key()?, &assertion)?)?,
            );
            let receipt = Delegation {
                genesis: genesis.clone(),
                owner: hex::encode(owner.to_bytes()),
                delegate: hex::encode(key.party_key().to_bytes()),
                input: hex::encode(input.to_bytes()),
                unit: policy.offers.max_stake_per_client,
                transaction: tx.encode().to_vec(),
                scan_from: height,
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
        let mut scan = receipt.scan_from;
        let mut submitted = false;
        loop {
            let Some(tip) = client.get_latest_block().await? else {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            while scan <= tip.height {
                let finalized = client
                    .get_finalized_block(hellas_chain::FinalizedBlockQuery::Height(scan))
                    .await?
                    .context("delegation history is unavailable")?;
                let block = hellas_chain::block_view::FinalizedBlockView::decode(&finalized)?;
                ensure!(block.height() == scan, "delegation history height mismatch");
                if block.position_of(&tx).is_some() {
                    receipt.confirmed = true;
                    hellas_private::write_atomically(
                        &path,
                        ".confirmed",
                        &serde_json::to_vec(&receipt)?,
                    )?;
                    return Ok(());
                }
                scan = scan.checked_add(1).context("delegation height overflow")?;
            }
            ensure!(
                client
                    .get_coin(tip.payload, input.to_bytes().into())
                    .await?
                    .is_some(),
                "another spend consumed the delegation input before it finalized"
            );
            if !submitted {
                client.submit_tx(tx.clone()).await?;
                submitted = true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
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
    scan_from: u64,
    confirmed: bool,
}

#[cfg(test)]
mod tests;
