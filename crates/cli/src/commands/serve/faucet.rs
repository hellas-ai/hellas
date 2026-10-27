//! Explicit public-devnet owner acts on the normal paid provider path.
use super::*;
use anyhow::ensure;
use hellas_auth::{Digest, authority::*};
use hellas_chain::{LightClient as _, domain::Transaction};
use hellas_kernel::{CoinId, EdgeValues, Fees, SoftPasskey};
use hellas_sdk::node_control::profile;
use hellas_work::{
    authenticator::{Authenticator, kernel_auth},
    grant_service::WorkAdministration,
    model::{
        fetch::*, grant::admin::WorkControlCommand, paid_policy::*, profile::WorkPolicy, work::*,
    },
    node::SessionKey,
    work_store::grant::{NodeStore, NodeStoreError, OwnerApproval, PreparedBootstrap},
};
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Debug, Default, Serialize, Deserialize, clap::Args)]
#[serde(deny_unknown_fields)]
pub struct PolicyArgs {
    /// Flat job price for faucet onboarding (default: 20).
    #[arg(long = "paid-price", value_parser = clap::value_parser!(u64).range(1..))]
    price: Option<u64>,
    /// Jobs funded by one channel (default: 10).
    #[arg(long = "paid-jobs-per-channel", value_parser = clap::value_parser!(u64).range(1..))]
    jobs: Option<u64>,
    /// Maximum provider stake per client (default: 12).
    #[arg(long = "paid-max-stake-per-client", value_parser = clap::value_parser!(u64).range(1..))]
    stake: Option<u64>,
    /// Maximum simultaneous offers/channels (default: 3).
    #[arg(long = "paid-max-open-offers", value_parser = clap::value_parser!(u32).range(1..))]
    open_offers: Option<u32>,
    /// Bond admission horizon from finalized height (default: 256 blocks).
    #[arg(long = "paid-bond-lifetime-blocks", value_parser = clap::value_parser!(u64).range(1..=1_000_000))]
    lifetime: Option<u64>,
    /// Signed per-job upload ceiling (default: 1048576 bytes).
    #[arg(long = "paid-max-upload-bytes", value_parser = clap::value_parser!(u64).range(1..))]
    upload: Option<u64>,
    /// Paid Fetch execution limit, retained across restarts (default: 90 seconds).
    #[arg(long = "paid-execution-timeout-secs", value_parser = clap::value_parser!(u64).range(1..=86_400))]
    pub timeout: Option<u64>,
}

pub struct Startup {
    pub root: PathBuf,
    pub owner: SoftPasskey,
    pub policy: PolicyArgs,
    overrides: PolicyArgs,
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

/// Initial terms use the built-in Fetch contract and checked channel economics.
pub(super) fn default_policy(args: &PolicyArgs) -> CliResult<PaidPolicy> {
    let price = args.price.unwrap_or(20);
    let jobs = args.jobs.unwrap_or(10);
    let capacity = price
        .checked_mul(jobs)
        .context("paid channel capacity overflow")?;
    let omission = capacity
        .checked_add(1)
        .context("paid collateral overflow")?;
    let value = capacity
        .checked_add(omission)
        .context("paid funding overflow")?;
    let credit = price.checked_mul(2).context("paid credit overflow")?;
    let contract = hellas_rpc::FetchContract::http()?;
    let route = hellas_work::model::fetch::FetchRoutePolicy::open_fetch(true, vec![]);
    let policy = PaidPolicy {
        channel_policy: PaidChannelPolicyV1 {
            compute_credit_limit: credit,
            delivery_credit_limit: credit,
        },
        work_policy: WorkPolicy::Fetch {
            policy: FetchPolicyV2 {
                allowed_environment: contract.manifest_id(),
                route_commitment: fetch_route_commitment(&route.canonical_body_bytes())?,
                max_request_body_bytes: 64 * 1024,
                max_output_events: 1024,
                max_output_bytes: 1024 * 1024,
                max_spool_bytes: 4 * 1024 * 1024,
                max_encoded_result_frame: 1024 * 1024,
                max_encoded_prepared_input: 1024 * 1024,
                max_upload_bytes: args.upload.unwrap_or(1024 * 1024),
            },
            route,
            contract,
        },
        payment_policy: JobPaymentPolicyV2 {
            fixed_price: price,
            dispatch_margin_blocks: 4,
            delivery_margin_blocks: 2,
            oracle_grace_blocks: 6,
        },
        expected_payment_values: EdgeValues::new(value, 0, Fees::ZERO),
        min_omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        jobs_per_channel: jobs,
        offers: OfferPolicy {
            max_stake_per_client: args.stake.unwrap_or(12),
            bond_lifetime_blocks: args.lifetime.unwrap_or(256),
            max_open_offers: args.open_offers.unwrap_or(3),
            omission_bond: omission,
            redelegate_payout: true,
        },
    };
    policy.check()?;
    Ok(policy)
}

pub(crate) fn chain_defaults(root: &Path) -> CliResult<WorkConfig> {
    hellas_sdk::client_chain::devnet(root).map_err(Into::into)
}

fn publish(path: &Path, bytes: &[u8]) -> CliResult<()> {
    let parent = path.parent().context("faucet state needs a parent")?;
    hellas_private::create_dir_all_durable(parent)?;
    let file = hellas_private::private_tempfile(parent, ".faucet-", ".new")?;
    profile::publish_private(file, path, bytes)?;
    Ok(())
}

impl PolicyArgs {
    pub fn any(&self) -> bool {
        self.price.is_some()
            || self.jobs.is_some()
            || self.stake.is_some()
            || self.open_offers.is_some()
            || self.lifetime.is_some()
            || self.upload.is_some()
            || self.timeout.is_some()
    }
}

impl Startup {
    pub fn new(root: PathBuf, owner: SoftPasskey, overrides: PolicyArgs) -> CliResult<Self> {
        let path = root.join("settings.json");
        let saved: PolicyArgs = if path.try_exists()? {
            serde_json::from_slice(&hellas_private::read_bounded_regular_file(&path, 4096)?)?
        } else {
            PolicyArgs::default()
        };
        let policy = PolicyArgs {
            price: overrides.price.or(saved.price).or(Some(20)),
            jobs: overrides.jobs.or(saved.jobs).or(Some(10)),
            stake: overrides.stake.or(saved.stake).or(Some(12)),
            open_offers: overrides.open_offers.or(saved.open_offers).or(Some(3)),
            lifetime: overrides.lifetime.or(saved.lifetime).or(Some(256)),
            upload: overrides.upload.or(saved.upload).or(Some(1024 * 1024)),
            timeout: overrides.timeout.or(saved.timeout).or(Some(90)),
        };
        default_policy(&policy)?;
        ensure!(
            (1..=86_400).contains(&policy.timeout.unwrap_or(90)),
            "paid execution timeout must be within 1..=86400 seconds"
        );
        hellas_private::create_dir_all_durable(&root)?;
        Ok(Self {
            root,
            owner,
            policy,
            overrides,
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
            "faucet startup requires producer-signed assurance"
        );
        let (work, chain) = provider
            .work
            .as_ref()
            .context("faucet paid startup requires a chain node")?;
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
        if path.is_none() {
            provider.executor.fetch_routes.register(
                FetchRoute::new("http", "request"),
                hellas_providers::HttpProviderConfig::default()
                    .into_entry(hellas_executor::FetchRoutePolicy::default())?,
            )?;
        }
        provider.executor.paid_fetch_timeout =
            Duration::from_secs(self.policy.timeout.unwrap_or(90));
        let host =
            super::configuration::start_host(provider, Some(grants), path, transport).await?;
        let ready = async {
            self.preflight_stake(&chain, &key).await?;
            hellas_private::write_atomically(
                &self.root.join("settings.json"),
                ".new",
                &serde_json::to_vec(&self.policy)?,
            )?;
            let admin = host
                .administration()?
                .context("faucet paid administration is unavailable")?;
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

    async fn preflight_stake(
        &self,
        chain: &hellas_sdk::FullNode,
        key: &Secp256k1Signer,
    ) -> CliResult<()> {
        let Some(cap) = self.overrides.stake else {
            return Ok(());
        };
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
        }).await.context("faucet stake-cap preflight exceeded chain recovery bound")??.then_some(()).context("lower stake cap has no eligible delegated coin; reshape unused stake with chain delegate --split before changing the policy")
    }

    pub(super) async fn prepare(
        &self,
        config: &hellas_sdk::grant_config::GrantConfig,
        enrollment: &hellas_rpc::ProviderEnrollmentBundle,
        producer: &ProducerSigningKey,
    ) -> CliResult<Option<CredentialSecret>> {
        let now = UnixMillis::now()?;
        let network = hellas_work::model::grant::grant_network();
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
                        for op in hellas_work::operations::OPERATIONS.iter().filter(|op| {
                            !matches!(op.scope, hellas_work::operations::Scope::Allowance)
                        }) {
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
                            _ => anyhow::bail!("faucet control TLS configuration is incomplete"),
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
                                "faucet control TLS differs from its saved initialization"
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
            "selected faucet account is not this provider's owner"
        );
        let needs_policy = store.state().paid_policy().is_none();
        let id = authority.authority();
        let authorization = authority.root_grant();
        drop(store);
        if !bootstrap_path.try_exists()? {
            ensure!(
                !needs_policy,
                "existing authority needs an owner-approved paid policy before faucet startup"
            );
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
        eprintln!("faucet administration profile: {}", admin.display());
        Ok(Some(data.secret()))
    }

    pub(super) async fn configure(
        &self,
        admin: &WorkAdministration,
        credential: Option<&CredentialSecret>,
    ) -> CliResult<PaidPolicy> {
        let node = admin.node();
        ensure!(
            node.owner().await? == crate::commands::contributions::principal(&self.owner)?,
            "selected faucet account is not this provider's owner"
        );
        let current = node.paid_policy().await?;
        let mut desired = match &current {
            Some(current) => current.policy.clone(),
            None => default_policy(&self.policy)?,
        };
        if current.is_some() && self.overrides.any() {
            let args = &self.overrides;
            if let Some(price) = args.price {
                desired.payment_policy.fixed_price = price;
                desired.channel_policy.compute_credit_limit =
                    desired.channel_policy.compute_credit_limit.max(price);
                desired.channel_policy.delivery_credit_limit =
                    desired.channel_policy.delivery_credit_limit.max(price);
            }
            if let Some(jobs) = args.jobs {
                desired.jobs_per_channel = jobs;
            }
            if args.price.is_some() || args.jobs.is_some() {
                let capacity = desired
                    .payment_policy
                    .fixed_price
                    .checked_mul(desired.jobs_per_channel)
                    .context("paid capacity overflow")?;
                desired.offers.omission_bond = capacity
                    .checked_add(1)
                    .context("paid collateral overflow")?;
                desired.expected_payment_values = EdgeValues::new(
                    capacity
                        .checked_add(desired.offers.omission_bond)
                        .context("paid funding overflow")?,
                    0,
                    Fees::ZERO,
                );
            }
            if let Some(stake) = args.stake {
                desired.offers.max_stake_per_client = stake;
            }
            if let Some(open) = args.open_offers {
                desired.offers.max_open_offers = open;
            }
            if let Some(lifetime) = args.lifetime {
                desired.offers.bond_lifetime_blocks = lifetime;
            }
            if let Some(upload) = args.upload {
                match &mut desired.work_policy {
                    WorkPolicy::Fetch { policy, .. } => policy.max_upload_bytes = upload,
                    WorkPolicy::Evaluate(policy) => policy.max_upload_bytes = upload,
                }
            }
        }
        desired.check()?;
        if current
            .as_ref()
            .is_none_or(|current| current.policy != desired)
        {
            let caller = node
                .authenticate_session(
                    credential.context("faucet owner credential is missing")?,
                    SessionKey::Passkey(&self.owner),
                )
                .await?;
            admin
                .execute(
                    &caller,
                    GrantId([0; 16]),
                    WorkControlCommand::SetPaidPolicy {
                        expected_revision: current.map_or(Revision(0), |current| current.revision),
                        policy: Box::new(desired),
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
        .context("faucet stake delegation exceeded chain recovery bound")?
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
            "faucet delegation belongs to another owner, node or chain"
        );
        if receipt.confirmed {
            return Ok(());
        }
        let input = CoinId::from_bytes(
            hex::decode(&receipt.input)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid faucet delegation input"))?,
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
                    .context("faucet delegation history is unavailable")?;
                let block = hellas_chain::block_view::FinalizedBlockView::decode(&finalized)?;
                ensure!(
                    block.height() == scan,
                    "faucet delegation history height mismatch"
                );
                if block.position_of(&tx).is_some() {
                    receipt.confirmed = true;
                    hellas_private::write_atomically(
                        &path,
                        ".confirmed",
                        &serde_json::to_vec(&receipt)?,
                    )?;
                    return Ok(());
                }
                scan = scan
                    .checked_add(1)
                    .context("faucet delegation height overflow")?;
            }
            ensure!(
                client
                    .get_coin(tip.payload, input.to_bytes().into())
                    .await?
                    .is_some(),
                "another spend consumed the faucet input before this delegation finalized"
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
