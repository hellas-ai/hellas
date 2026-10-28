//! Reusable paid gateway pool over durable client-owned state channels.

use crate::gateway_work::{
    Completed, GatewayEvent, Requester, WorkGateway, WorkRequest, WorkSource,
};
use crate::job::{Job, JobInput};
use crate::paid_client::{
    PaidClientError, PaidWorkOptions, PaidWorkResult, PaidWorkSession, bind_paid_endpoint,
};
use futures::future::BoxFuture;
use hellas_channel::content::{EphemeralContent, InvocationContent};
use hellas_channel::model::setup::ProviderChannelPolicy;
use hellas_gateway::{WorkGatewayError, WorkShutdownError};
use hellas_kernel::Secp256k1Signer;
use hellas_rpc::output::OutputEvent as FetchEvent;
use iroh::Endpoint;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;
use tracing::Instrument;

mod config;
mod error;
pub use config::{PaidGatewayOptions, load_pool_options};
pub use error::PoolError;
type Result<T, E = PoolError> = std::result::Result<T, E>;

const UNREACHABLE_PROVIDER_BACKOFF: Duration = Duration::from_secs(30);
// Opening a route is control-plane work. It must not inherit the model's
// execution allowance: an offline provider should yield to another route.
const PROVIDER_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
// A retained job is durable, but it must not monopolize the channel that
// serves interactive requests after a restart or a provider interruption.
const RECOVERY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
// Bound queueing while another funded provider may be eligible. The last
// candidate waits for its channel until the request deadline.
const CHANNEL_QUEUE_BUDGET: Duration = Duration::from_secs(1);

struct Provider {
    args: PaidWorkOptions,
    policy: ProviderChannelPolicy,
    /// A setup/channel journal has a single owner even with concurrent HTTP calls.
    serial: AsyncMutex<Option<PaidWorkSession>>,
    pending: AtomicUsize,
    unavailable_until: Mutex<Option<Instant>>,
}

impl Provider {
    fn available(&self) -> bool {
        self.unavailable_until
            .lock()
            .expect("provider availability poisoned")
            .is_none_or(|until| until <= Instant::now())
    }

    fn connection_failed(&self) {
        *self
            .unavailable_until
            .lock()
            .expect("provider availability poisoned") =
            Some(Instant::now() + UNREACHABLE_PROVIDER_BACKOFF);
    }

    fn connection_succeeded(&self) {
        *self
            .unavailable_until
            .lock()
            .expect("provider availability poisoned") = None;
    }

    fn route(&self) -> Route {
        Route {
            pending: self.pending.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy)]
struct Route {
    pending: usize,
}

struct ProviderUse(Arc<Provider>);
impl ProviderUse {
    fn new(provider: Arc<Provider>) -> Self {
        provider.pending.fetch_add(1, Ordering::Relaxed);
        Self(provider)
    }
}

impl Drop for ProviderUse {
    fn drop(&mut self) {
        self.0.pending.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A pool of funded provider channels: the paid [`WorkSource`].
pub struct PaidPool {
    providers: Vec<Arc<Provider>>,
    endpoint: Endpoint,
    owner: Arc<crate::client_owner::ClientOwner>,
    settlement_key: Secp256k1Signer,
    producer_key: hellas_auth::ProducerSigningKey,
}

pub type PaidGateway = WorkGateway<PaidPool>;

/// One paid request, routed to its candidate providers.
pub struct PaidRequest(Routed);

enum Routed {
    /// A new job. The first route is reserved when the request is accepted so
    /// concurrent HTTP requests see both queued and executing work.
    Job {
        candidates: Vec<(Arc<Provider>, Route, JobInput)>,
        occupied: ProviderUse,
    },
    /// Restart recovery of retained work, never a new job.
    Recover(Arc<Provider>),
}

/// Every pooled request is bounded; [`PaidGatewayOptions::validate`] requires it.
fn request_timeout(args: &PaidWorkOptions) -> Duration {
    args.timeout
        .expect("validated paid gateway providers carry a request timeout")
}

async fn provider_policy<
    C: hellas_chain::LightClient + hellas_chain::work_view::FinalizedWorkView,
>(
    args: &PaidWorkOptions,
    chain: hellas_chain::WorkBlocks<C>,
    endpoint: &Endpoint,
    settlement_key: &Secp256k1Signer,
    owner: hellas_auth::authority::PrincipalId,
) -> Result<ProviderChannelPolicy> {
    let chain = chain.with_read_retry(
        args.config.poll,
        crate::paid_client::read_timeout(args.timeout),
    );
    Ok(
        match crate::paid_client::offer::retained_offer(
            &args.journal_root,
            args.config.chain.network,
            args.provider,
            &chain,
        )
        .await?
        {
            Some((_, signed)) => signed.offer().policy.clone(),
            None => {
                tokio::time::timeout(
                    request_timeout(args),
                    crate::paid_client::request_paid_quote(args, endpoint, settlement_key, owner),
                )
                .await
                .map_err(|_| PoolError::ConnectionTimeout(request_timeout(args)))??
                .policy
            }
        },
    )
}

impl PaidGateway {
    /// Open a reusable pool. Funding, recovery, queueing and payment are shared
    /// by CLI and embedding applications. Call `drain` during host shutdown.
    pub async fn open(
        options: PaidGatewayOptions,
        identity: crate::NodeIdentity,
        owner: Arc<crate::client_owner::ClientOwner>,
    ) -> Result<Arc<Self>> {
        options.validate()?;
        for provider in &options.providers {
            provider.config.clone().validate()?;
        }
        let settlement_key = Secp256k1Signer::from_secret_scalar(identity.node_secret_bytes())
            .map_err(|_| PoolError::Invalid("node key is not a secp256k1 channel signer"))?;
        let endpoint = bind_paid_endpoint(identity.transport_key()).await?;
        if owner.delegate() != settlement_key.party_key() {
            return Err(PoolError::Invalid(
                "funding delegate differs from the gateway settlement key",
            ));
        }
        let mut providers = Vec::with_capacity(options.providers.len());
        for args in options.providers {
            let remote = crate::client_chain::connect(
                &args.config,
                crate::paid_client::read_timeout(args.timeout),
            )
            .await
            .map_err(PaidClientError::from)?;
            let chain = hellas_chain::WorkBlocks::new(remote);
            let policy =
                provider_policy(&args, chain, &endpoint, &settlement_key, owner.principal())
                    .await?;
            if policy.payment_policy.fixed_price != args.expected_price {
                return Err(PoolError::Price {
                    provider: args.provider,
                    quoted: policy.payment_policy.fixed_price,
                    expected: args.expected_price,
                });
            }
            providers.push(Arc::new(Provider {
                policy,
                args,
                serial: AsyncMutex::new(None),
                pending: AtomicUsize::new(0),
                unavailable_until: Mutex::new(None),
            }));
        }
        let gateway = Arc::new(WorkGateway::new(
            PaidPool {
                providers,
                // One transport identity has one relay registration, shared by every
                // provider and request for the lifetime of this gateway.
                endpoint,
                owner,
                settlement_key,
                producer_key: identity.node_key().clone(),
            },
            options.max_pending_requests,
        ));
        // Restart recovery uses the retained input and certificate, never a new job.
        // Empty journal roots do not fund a channel until an HTTP request arrives.
        for provider in &gateway.source.providers {
            let _recovery = gateway
                .submit::<FetchEvent>(PaidRequest(Routed::Recover(provider.clone())), None)?;
        }
        Ok(gateway)
    }
}

impl PaidPool {
    /// Tries each candidate in order until one accepts the request. A provider
    /// that fails before this request is proposed yields to the next one.
    async fn route<E: GatewayEvent>(
        &self,
        candidates: Vec<(Arc<Provider>, Route, Option<JobInput>)>,
        mut occupied: Option<ProviderUse>,
        deadline: tokio::time::Instant,
        requester: &Requester<E, PoolError>,
    ) -> Result<Option<PaidWorkResult>> {
        let span = tracing::Span::current();
        let recovery = occupied.is_none();
        let streamed = !recovery;
        let progress = requester.progress();
        let accepted = requester.accepted();
        let mut provider_errors = Vec::new();
        let last = candidates.len() - 1;
        for (index, (provider, route, input)) in candidates.into_iter().enumerate() {
            let _occupied = occupied
                .take()
                .or_else(|| streamed.then(|| ProviderUse::new(provider.clone())));
            span.record(
                "hellas.provider.id",
                tracing::field::display(provider.args.provider),
            );
            span.record("hellas.route.pending", route.pending);
            // Serialize jobs on one funded channel; its observer runs independently.
            let mut session = if recovery || index == last {
                before_proposal(requester, streamed, deadline, |_| {
                    provider.serial.lock().instrument(
                        hellas_rpc::request_span!(target: "hellas_request", "paid.queue"),
                    )
                })
                .await?
            } else {
                match tokio::time::timeout(CHANNEL_QUEUE_BUDGET, provider.serial.lock()).await {
                    Ok(session) => session,
                    Err(_) => {
                        provider_errors
                            .push(format!("{}: paid channel is busy", provider.args.provider));
                        continue;
                    }
                }
            };
            if recovery && !has_retained_setup(&provider.args).await? {
                continue;
            }
            // Recheck after queueing, including restored channels whose
            // setup journal opened without contacting the provider.
            if !provider.available() {
                provider_errors.push(format!(
                    "{}: provider is backing off",
                    provider.args.provider
                ));
                continue;
            }
            if session.is_none() {
                let opened = connect_before_deadline(
                    requester,
                    streamed,
                    deadline,
                    PROVIDER_CONNECTION_TIMEOUT,
                    async {
                        PaidWorkSession::open(
                            provider.args.clone(),
                            self.endpoint.clone(),
                            self.settlement_key.clone(),
                            self.owner.clone(),
                        )
                        .await
                        .map_err(PoolError::from)
                    },
                )
                .await;
                match opened {
                    Ok(opened) => *session = Some(opened),
                    Err(error) => {
                        if !recovery && matches!(error, PoolError::Stopped(_)) {
                            return Err(error);
                        }
                        provider.connection_failed();
                        tracing::debug!(provider = %provider.args.provider, error = %format!("{error:#}"),
                            recovery, "paid provider channel could not be opened");
                        provider_errors.push(format!("{}: {error:#}", provider.args.provider));
                        continue;
                    }
                }
            }
            let session = session.as_mut().expect("channel was opened");
            if streamed && session.needs_recovery() {
                let recovery_deadline =
                    deadline.min(tokio::time::Instant::now() + RECOVERY_ATTEMPT_TIMEOUT);
                let recovered = tokio::time::timeout_at(
                    recovery_deadline,
                    session.run(None, &empty_content(), true, None),
                )
                .await
                .map_err(|_| PoolError::RecoveryTimeout)
                .and_then(|result| result.map_err(PoolError::from));
                if let Err(error) = recovered {
                    // Nothing in this path has proposed the fresh request.
                    // Keep the journal for a later recovery and route this
                    // interactive request to another paid provider now.
                    provider.connection_failed();
                    tracing::debug!(provider = %provider.args.provider, error = %format!("{error:#}"),
                        "retained paid work deferred before a fresh request");
                    provider_errors.push(format!(
                        "{}: retained work recovery deferred: {error:#}",
                        provider.args.provider
                    ));
                    continue;
                }
            }
            // ClientEndpoint journals the proposal nonce before releasing
            // its signature. Recovery and a failed dial need not propose
            // this request; a lost acceptance response does advance it.
            let proposal_nonce = session
                .with_state(|state| state.proposal_nonce_high_water())
                .await?;
            let request_session = &mut *session;
            let job = input
                .map(|input| Job::from_input(provider.args.expected_price, input))
                .transpose()?;
            let signer = self.producer_key.clone();
            let on_progress = streamed.then(|| progress.clone());
            let on_accepted = streamed.then(|| accepted.clone());
            let result = before_proposal(requester, streamed, deadline, |proposed| async move {
                match job {
                    Some(job) => crate::transact::transact(
                        request_session,
                        &job,
                        &signer,
                        crate::transact::TransactionOptions {
                            new_purchase: true,
                            progress: on_progress,
                            accepted: on_accepted,
                            proposed: Some(&proposed),
                            ..Default::default()
                        },
                    )
                    .await
                    .map(Some)
                    .map_err(|error| match error {
                        crate::transact::TransactError::Client(client) => PoolError::Client(client),
                        error => PoolError::Transaction(Box::new(error)),
                    }),
                    None => request_session
                        .run(None, &empty_content(), true, on_progress)
                        .await
                        .map_err(PoolError::from),
                }
            })
            .await
            .flatten();
            if let Err(error) = &result {
                if !recovery
                    && matches!(error, PoolError::Stopped(_))
                    && session
                        .with_state(|state| state.proposal_nonce_high_water())
                        .await?
                        == proposal_nonce
                {
                    return result;
                }
                if recovery {
                    provider.connection_failed();
                    return result.map_err(|source| PoolError::Provider {
                        provider: provider.args.provider,
                        source: Box::new(source),
                    });
                }
                // A failed journal append can leave a durable proposal that
                // is not reflected in memory yet. Keep that failure with
                // this provider, just like a proposal with no response.
                let uncertain_append = matches!(
                    error,
                    PoolError::Client(PaidClientError::Propose(
                        hellas_channel::work::ProposeError::Store(_)
                    )),
                );
                if !uncertain_append
                    && session
                        .with_state(|state| state.proposal_nonce_high_water())
                        .await?
                        == proposal_nonce
                {
                    provider.connection_failed();
                    tracing::debug!(provider = %provider.args.provider, error = %format!("{error:#}"),
                        "paid provider failed before proposing new work");
                    provider_errors.push(format!("{}: {error:#}", provider.args.provider));
                    continue;
                }
            } else {
                provider.connection_succeeded();
            }
            return result.map_err(|source| PoolError::Provider {
                provider: provider.args.provider,
                source: Box::new(source),
            });
        }
        Err(PoolError::ProvidersUnavailable(provider_errors))
    }
}

fn empty_content() -> InvocationContent {
    InvocationContent::Ephemeral(EphemeralContent::default())
}

async fn has_retained_setup(options: &PaidWorkOptions) -> Result<bool> {
    let found = hellas_channel::work_store::discover_setups(
        &options.journal_root,
        options.config.chain.network,
    )
    .await?;
    // Counter files and other metadata alone must never trigger channel funding.
    // Unidentified setup journals still go through ordinary recovery and fail
    // closed; discovery is only a prefilter, not a signature check.
    Ok(!found.unidentified.is_empty()
        || found
            .setups
            .iter()
            .any(|setup| setup.role == hellas_channel::work_store::Role::Client))
}

impl WorkSource for PaidPool {
    type Error = PoolError;
    type Request = PaidRequest;

    fn fetch_routes(&self) -> Vec<hellas_gateway::FetchRoute> {
        self.providers
            .iter()
            .flat_map(|provider| {
                crate::gateway_work::fetch_routes(
                    provider.args.provider,
                    [&provider.policy.invocation_policy],
                )
            })
            .collect()
    }

    /// Every provider whose policy admits the request, least loaded first.
    /// A pinned request has at most its own provider: account and session
    /// selection is final, so it never fails over.
    fn request(&self, request: WorkRequest) -> Result<PaidRequest> {
        let pinned = request.pinned();
        let mut refusal = None;
        let mut candidates = self
            .providers
            .iter()
            .filter(|provider| pinned.is_none_or(|pin| pin == provider.args.provider))
            .filter_map(|provider| {
                match request.admitted(
                    &provider.policy.invocation_policy,
                    None,
                    provider.args.assurance,
                    true,
                ) {
                    Ok(input) => Some((provider.clone(), provider.route(), input)),
                    Err(error) => {
                        refusal = Some(error);
                        None
                    }
                }
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|(provider, route, _)| (!provider.available(), route.pending));
        let Some((first, _, _)) = candidates.first() else {
            return Err(match (pinned, refusal) {
                (_, Some(error)) => error.into(),
                (Some(pin), None) => WorkGatewayError::Provider(pin).into(),
                (None, None) => PoolError::NoMatchingPolicy,
            });
        };
        let occupied = ProviderUse::new(first.clone());
        Ok(PaidRequest(Routed::Job {
            candidates,
            occupied,
        }))
    }

    fn run<E: GatewayEvent>(
        self: Arc<Self>,
        request: PaidRequest,
        requester: Requester<E, PoolError>,
    ) -> BoxFuture<'static, Result<Option<Completed>>> {
        let (candidates, occupied) = match request.0 {
            Routed::Job {
                candidates,
                occupied,
            } => (
                candidates
                    .into_iter()
                    .map(|(provider, route, input)| (provider, route, Some(input)))
                    .collect::<Vec<_>>(),
                Some(occupied),
            ),
            Routed::Recover(provider) => {
                let route = provider.route();
                (vec![(provider, route, None)], None)
            }
        };
        let (first, _route, _) = &candidates[0];
        let recovery = occupied.is_none();
        let span = hellas_rpc::request_span!(
            target: "hellas_request", "paid.gateway",
            hellas.provider.id = %first.args.provider,
            hellas.work.recovery = recovery,
            hellas.route.pending = _route.pending,
        );
        // Queueing, recovery and fallback all consume the same request budget.
        let timeout = if recovery {
            RECOVERY_ATTEMPT_TIMEOUT
        } else {
            request_timeout(&first.args)
        };
        let deadline = tokio::time::Instant::now() + timeout;
        Box::pin(
            async move {
                let result = self
                    .route(candidates, occupied, deadline, &requester)
                    .await;
                if let Err(error) = &result {
                    if recovery {
                        tracing::debug!(error = %format!("{error:#}"),
                            "retained paid-work recovery deferred");
                    } else {
                        tracing::error!(error = %format!("{error:#}"),
                            "paid gateway operation failed; durable journals retained for recovery");
                    }
                }
                // A disconnected request stops before proposal. After proposal, it
                // still collects and pays until the deadline; journals retain any
                // unfinished operation for recovery.
                Ok(result?.map(|output| Completed {
                    output: output.output,
                    provider: output.provider_key,
                    transcript: output.transcript,
                }))
            }
            .instrument(span),
        )
    }

    fn timeout(&self) -> Duration {
        self.providers
            .iter()
            .map(|provider| request_timeout(&provider.args))
            .max()
            .unwrap_or_default()
    }

    fn gateway_error(error: PoolError) -> WorkGatewayError {
        match error {
            PoolError::Gateway(error) => error,
            error => WorkGatewayError::Execution(Box::new(error)),
        }
    }

    fn shutdown(&self) -> BoxFuture<'_, Result<(), WorkShutdownError>> {
        Box::pin(async move {
            for provider in &self.providers {
                if let Some(session) = provider.serial.lock().await.as_mut() {
                    session.shutdown().await;
                }
            }
            self.endpoint.close().await;
            Ok(())
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RequestStopped {
    #[error("paid request disconnected before proposal")]
    Disconnected,
    #[error("paid request deadline elapsed, including queue wait")]
    Deadline,
}

// A route's short connection allowance is recoverable by trying another
// provider; only the enclosing request deadline or disconnect is terminal.
async fn connect_before_deadline<T, E: GatewayEvent>(
    requester: &Requester<E, PoolError>,
    cancel_on_disconnect: bool,
    deadline: tokio::time::Instant,
    connection_timeout: Duration,
    connection: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let connection_deadline = deadline.min(tokio::time::Instant::now() + connection_timeout);
    before_proposal(requester, cancel_on_disconnect, deadline, |_| async {
        tokio::time::timeout_at(connection_deadline, connection)
            .await
            .map_err(|_| PoolError::ConnectionTimeout(connection_timeout))?
    })
    .await?
}

/// Cancel an unproposed HTTP operation without interrupting work whose
/// proposal signature may already have reached a provider.
async fn before_proposal<T, F: std::future::Future<Output = T>, E: GatewayEvent>(
    requester: &Requester<E, PoolError>,
    cancel_on_disconnect: bool,
    deadline: tokio::time::Instant,
    operation: impl FnOnce(Arc<AtomicBool>) -> F,
) -> Result<T> {
    if tokio::time::Instant::now() >= deadline {
        return Err(RequestStopped::Deadline.into());
    }
    // This flag belongs to this operation, never to retained matching input.
    // A prior journal record may prevent fallback but cannot authorize a new
    // request after its HTTP receiver has gone away.
    let proposed = Arc::new(AtomicBool::new(false));
    let operation = tokio::time::timeout_at(deadline, operation(proposed.clone()));
    tokio::pin!(operation);
    let result = tokio::select! {
        biased;
        _ = requester.closed(), if cancel_on_disconnect => {
            if !proposed.load(Ordering::Acquire) {
                return Err(RequestStopped::Disconnected.into());
            }
            operation.await
        }
        result = &mut operation => result,
    };
    result.map_err(|_| RequestStopped::Deadline.into())
}

#[cfg(test)]
use hellas_channel::test_support::test_responses_contract;

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_gateway::WorkFetchRequest;
    use hellas_rpc::protocol::invocation::{Admission, fetch::FetchRoutePolicy};
    use iroh::Endpoint;

    fn pool_options(fixture: &crate::test_support::PaidFixture) -> PaidGatewayOptions {
        PaidGatewayOptions {
            max_pending_requests: 4,
            providers: vec![PaidWorkOptions {
                config: fixture.config.clone(),
                journal_root: fixture.root.path().join("client"),
                provider: iroh::SecretKey::from_bytes(&[3; 32]).public(),
                provider_addrs: Vec::new(),
                apple_trust: None,
                assurance: hellas_rpc::Assurance::ProducerSigned,
                expected_price: crate::test_support::PRICE,
                acceptance_blocks: 16,
                terminal_blocks: 64,
                payment_blocks: 32,
                timeout: Some(Duration::from_secs(30)),
            }],
        }
    }

    #[test]
    fn retained_gateway_policy_waits_for_chain_recovery_and_has_a_deadline() {
        use crate::test_support::{PaidFixture, signer};
        use hellas_chain::test_support::devnet::{
            Devnet, DevnetConfig, GenesisOwner, OwnerKind, run,
        };
        use hellas_channel::model::offer::{PaidOffer, SignedPaidOffer};
        use hellas_channel::work_store::{Role, SetupRecord, SetupStore};
        run(|runtime| {
            Box::pin(async move {
                let mut devnet = Devnet::start(
                    runtime,
                    DevnetConfig {
                        name: "gateway_policy_recovery",
                        owners: vec![GenesisOwner {
                            kind: OwnerKind::Passkey,
                            secret_scalar: [0x13; 32],
                            balance: 1,
                        }],
                        full_nodes: 1,
                    },
                )
                .await;
                devnet.seal().await;
                let fixture = PaidFixture::on_network(devnet.network());
                let mut args = pool_options(&fixture).providers.remove(0);
                args.timeout = Some(hellas_chain::node::RECOVERY_TIMEOUT);
                let signed = SignedPaidOffer::sign(
                    PaidOffer {
                        provider: crate::test_support::enrollment(args.provider).0,
                        proposal: fixture.proposal.clone(),
                        policy: fixture.policy.clone(),
                        omission_bond: 601,
                        payment_funding: hellas_kernel::Funding::new(
                            hellas_kernel::List::take(
                                [hellas_kernel::CoinId::from_bytes([1; 32]); 4],
                                1,
                            ),
                            hellas_kernel::List::empty(hellas_kernel::CoinId::from_bytes([0; 32])),
                        ),
                        addresses: vec![],
                    },
                    &signer(2),
                )
                .unwrap();
                let mut store = SetupStore::open(
                    &args.journal_root,
                    devnet.network(),
                    signed.offer().proposal.bond_edge(),
                    Role::Client,
                    &hellas_kernel::Secp256k1Verifier::new(),
                )
                .await
                .unwrap();
                store
                    .commit(
                        SetupRecord::Offer {
                            peer: *args.provider.as_bytes(),
                            floor: None,
                            offer: Box::new(signed),
                        },
                        &hellas_kernel::Secp256k1Verifier::new(),
                    )
                    .await
                    .unwrap();
                drop(store);
                let node = devnet.full_node(0).clone();
                let chain = hellas_chain::WorkBlocks::new(node.view().unwrap().client());
                let endpoint = bind_paid_endpoint(iroh::SecretKey::from_bytes(&[0x54; 32]))
                    .await
                    .unwrap();
                let owner = hellas_auth::test_support::actors::FRIEND.principal();
                let key = signer(1);
                node.require_finalized_height_for_test(devnet.height() + 1);
                let policy = {
                    let read = provider_policy(&args, chain.clone(), &endpoint, &key, owner);
                    tokio::pin!(read);
                    assert!(
                        tokio::time::timeout(args.config.poll, &mut read)
                            .await
                            .is_err()
                    );
                    let (policy, _) = tokio::join!(read, devnet.seal());
                    policy.unwrap()
                };
                assert_eq!(policy, fixture.policy);
                args.timeout = Some(Duration::from_millis(100));
                node.require_finalized_height_for_test(devnet.height() + 1);
                let started = tokio::time::Instant::now();
                let error = tokio::time::timeout(
                    Duration::from_secs(5),
                    provider_policy(&args, chain, &endpoint, &key, owner),
                )
                .await
                .unwrap()
                .unwrap_err();
                assert!(
                    matches!(error, PoolError::Client(PaidClientError::Query(hellas_chain::QueryError::ReadUnavailableTimeout { timeout, .. })) if Some(timeout) == args.timeout),
                    "bounded gateway policy expiry: {error}"
                );
                assert!(started.elapsed() >= args.timeout.unwrap());
                endpoint.close().await;
                devnet.shutdown().await;
            })
        });
    }

    #[test]
    fn invalid_pool_options_are_refused_without_starting_a_gateway() {
        let fixture = crate::test_support::PaidFixture::new();
        assert!(pool_options(&fixture).validate().is_ok());

        let mut zero = pool_options(&fixture);
        zero.max_pending_requests = 0;
        assert!(matches!(zero.validate(), Err(PoolError::Invalid(_))));

        let mut duplicate = pool_options(&fixture);
        let mut second = duplicate.providers[0].clone();
        second.journal_root = fixture.root.path().join("second");
        duplicate.providers.push(second);
        assert!(matches!(
            duplicate.validate(),
            Err(PoolError::DuplicateProvider(_))
        ));

        let mut shared = pool_options(&fixture);
        let mut other = shared.providers[0].clone();
        other.journal_root = fixture.root.path().join("other");
        other.provider = iroh::SecretKey::from_bytes(&[4; 32]).public();
        shared.providers.push(other);
        assert!(shared.validate().is_ok());
    }

    async fn test_pool(
        fixture: &crate::test_support::PaidFixture,
        policy: ProviderChannelPolicy,
    ) -> PaidPool {
        let args = pool_options(fixture).providers.remove(0);
        PaidPool {
            owner: Arc::new(
                crate::client_owner::ClientOwner::new(
                    Arc::new(hellas_auth::test_support::actors::FRIEND.passkey()),
                    Secp256k1Signer::from_secret_scalar([7; 32])
                        .unwrap()
                        .party_key(),
                    &fixture.root.path().join("funding"),
                )
                .unwrap(),
            ),
            providers: vec![Arc::new(Provider {
                args,
                policy,
                serial: AsyncMutex::new(None),
                pending: AtomicUsize::new(0),
                unavailable_until: Mutex::new(None),
            })],
            endpoint: Endpoint::builder(iroh::endpoint::presets::Minimal)
                .bind()
                .await
                .unwrap(),
            settlement_key: Secp256k1Signer::from_secret_scalar([7; 32]).unwrap(),
            producer_key: hellas_auth::ProducerSigningKey::from_secret_bytes([7; 32]).unwrap(),
        }
    }

    fn fetch(pool: &PaidPool, method: &str) -> WorkRequest {
        WorkRequest::Fetch(WorkFetchRequest {
            provider: pool.providers[0].args.provider,
            service: "openai".into(),
            method: method.into(),
            body: crate::test_support::BODY.to_vec(),
        })
    }

    fn admitted(request: Result<PaidRequest>) -> JobInput {
        let PaidRequest(Routed::Job { mut candidates, .. }) = request.unwrap() else {
            panic!("an admitted paid request")
        };
        assert_eq!(candidates.len(), 1, "a pinned request has one route");
        candidates.remove(0).2
    }

    #[tokio::test]
    async fn paid_responses_backend_uses_its_manifest_and_refuses_route_mismatch_before_funding() {
        let fixture = crate::test_support::PaidFixture::new();
        let pool = test_pool(&fixture, fixture.policy.clone()).await;
        let input = admitted(pool.request(fetch(&pool, "responses")));
        assert_eq!(
            input.manifest().unwrap().content_id(),
            test_responses_contract().manifest_id()
        );
        assert!(pool.request(fetch(&pool, "another-route")).is_err());
        assert!(!fixture.root.path().join("client").exists());
        pool.endpoint.close().await;
    }

    #[tokio::test]
    async fn supported_contract_is_prepared_without_vendor_dispatch_and_stale_terms_deny() {
        let fixture = crate::test_support::PaidFixture::new();
        let contract = hellas_rpc::FetchContract::new(
            "independent-responses-1",
            hellas_rpc::FetchSchema::StatelessResponsesV1,
            "independent-driver-1",
            hellas_rpc::FetchEgress::FixedHttps("https://example.com/responses".into()),
        )
        .unwrap();
        let mut quoted = fixture.policy.clone();
        let Admission::Fetch { admission } = &mut quoted.invocation_policy.admissions[0] else {
            panic!("Fetch fixture")
        };
        admission.contract = contract.clone();
        let pool = test_pool(&fixture, quoted.clone()).await;
        let input = admitted(pool.request(fetch(&pool, "responses")));
        assert_eq!(input.manifest().unwrap(), contract.manifest());
        pool.endpoint.close().await;
        drop(pool);

        let Admission::Fetch { admission } = &mut quoted.invocation_policy.admissions[0] else {
            panic!("Fetch fixture")
        };
        admission.route = FetchRoutePolicy::sealed_route("openai", "other").unwrap();
        let pool = test_pool(&fixture, quoted).await;
        assert!(pool.request(fetch(&pool, "responses")).is_err());
        assert!(!fixture.root.path().join("client").exists());
        pool.endpoint.close().await;
    }

    #[tokio::test]
    async fn two_admitting_contracts_are_refused_not_chosen_between() {
        let fixture = crate::test_support::PaidFixture::new();
        let mut quoted = fixture.policy.clone();
        let Admission::Fetch { admission } = &quoted.invocation_policy.admissions[0] else {
            panic!("Fetch fixture")
        };
        let mut second = admission.clone();
        second.contract = hellas_rpc::FetchContract::new(
            "independent-responses-1",
            hellas_rpc::FetchSchema::StatelessResponsesV1,
            "independent-driver-1",
            hellas_rpc::FetchEgress::FixedHttps("https://example.com/responses".into()),
        )
        .unwrap();
        quoted
            .invocation_policy
            .admissions
            .push(Admission::Fetch { admission: second });
        let pool = test_pool(&fixture, quoted).await;
        let refused = pool.request(fetch(&pool, "responses")).err().unwrap();
        assert!(
            refused.to_string().contains("several Fetch contracts"),
            "{refused}"
        );
        pool.endpoint.close().await;
    }

    #[tokio::test]
    async fn counter_files_do_not_trigger_funding_but_incomplete_setup_recovers() {
        let fixture = crate::test_support::PaidFixture::new();
        let options = pool_options(&fixture);
        let provider = &options.providers[0];
        assert!(!has_retained_setup(provider).await.unwrap());
        std::fs::create_dir_all(provider.journal_root.join("apple-counters")).unwrap();
        std::fs::write(
            provider
                .journal_root
                .join("apple-counters/producer.counter"),
            [1],
        )
        .unwrap();
        assert!(!has_retained_setup(provider).await.unwrap());
        let store = hellas_channel::work_store::SetupStore::open(
            &provider.journal_root,
            provider.config.chain.network,
            fixture.descriptor.bond_edge(),
            hellas_channel::work_store::Role::Client,
            &hellas_kernel::Secp256k1Verifier::new(),
        )
        .await
        .unwrap();
        drop(store);
        assert!(
            !has_retained_setup(provider).await.unwrap(),
            "an unsigned header carries no recovery obligation"
        );
        let store = hellas_channel::work_store::SetupStore::open(
            &provider.journal_root,
            provider.config.chain.network,
            fixture.descriptor.bond_edge(),
            hellas_channel::work_store::Role::Client,
            &hellas_kernel::Secp256k1Verifier::new(),
        )
        .await
        .unwrap();
        let mut endpoint = hellas_channel::work_handshake::SetupEndpoint::new(
            store,
            crate::test_support::signer(1),
            hellas_channel::work_handshake::PaymentAdmission::Proposes(Box::new(
                fixture.policy.clone(),
            )),
        );
        endpoint.import(&fixture.proposal.encode()).await.unwrap();
        drop(endpoint);
        assert!(has_retained_setup(provider).await.unwrap());
    }

    #[tokio::test]
    async fn shared_pool_rejects_reused_journal_before_opening_or_writing() {
        let fixture = crate::test_support::PaidFixture::new();
        let mut options = pool_options(&fixture);
        let mut second = options.providers[0].clone();
        second.provider = iroh::SecretKey::from_bytes(&[4; 32]).public();
        options.providers.push(second);
        let identity = crate::NodeIdentity::generate();
        let owner = Arc::new(
            crate::client_owner::ClientOwner::new(
                Arc::new(hellas_auth::test_support::actors::FRIEND.passkey()),
                Secp256k1Signer::from_secret_scalar(identity.node_secret_bytes())
                    .unwrap()
                    .party_key(),
                &fixture.root.path().join("funding"),
            )
            .unwrap(),
        );
        let result = PaidGateway::open(options, identity, owner).await;
        assert!(matches!(
            result,
            Err(PoolError::Invalid(
                "paid providers must have distinct journal roots"
            ))
        ));
        assert!(!fixture.root.path().join("client").exists());
    }

    #[tokio::test]
    async fn disconnected_queued_request_never_starts_work() {
        let (sender, receiver) = Requester::<FetchEvent, PoolError>::new();
        drop(receiver);
        let started = AtomicBool::new(false);
        let result = before_proposal(
            &sender,
            true,
            tokio::time::Instant::now() + Duration::from_secs(1),
            |_| async {
                started.store(true, Ordering::Relaxed);
            },
        )
        .await;
        assert!(result.is_err());
        assert!(!started.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn disconnect_after_proposal_still_finishes_payment() {
        let (sender, receiver) = Requester::<FetchEvent, PoolError>::new();
        let (proposal_sent, proposal_seen) = tokio::sync::oneshot::channel();
        let (payment_ready, payment_wait) = tokio::sync::oneshot::channel();
        let work = before_proposal(
            &sender,
            true,
            tokio::time::Instant::now() + Duration::from_secs(1),
            |proposed| async move {
                proposed.store(true, Ordering::Release);
                proposal_sent.send(()).unwrap();
                payment_wait.await.unwrap();
                "payment acknowledged"
            },
        );
        let disconnect = async {
            proposal_seen.await.unwrap();
            drop(receiver);
            tokio::task::yield_now().await;
            payment_ready.send(()).unwrap();
        };
        let (result, ()) = tokio::join!(work, disconnect);
        assert_eq!(result.unwrap(), "payment acknowledged");
    }

    #[tokio::test]
    async fn disconnect_during_dial_cancels_before_signature_release() {
        let (sender, receiver) = Requester::<FetchEvent, PoolError>::new();
        let signed = AtomicBool::new(false);
        let signed_ref = &signed;
        let (dial_started, dial_seen) = tokio::sync::oneshot::channel();
        let operation = before_proposal(
            &sender,
            true,
            tokio::time::Instant::now() + Duration::from_secs(1),
            |proposed| async move {
                dial_started.send(()).unwrap();
                std::future::pending::<()>().await;
                proposed.store(true, Ordering::Release);
                signed_ref.store(true, Ordering::Release);
            },
        );
        let disconnect = async {
            dial_seen.await.unwrap();
            drop(receiver);
        };
        let (result, ()) = tokio::join!(operation, disconnect);
        assert!(matches!(result.unwrap_err(), PoolError::Stopped(_)));
        assert!(!signed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn connection_timeout_allows_fallback_within_the_request_deadline() {
        let (sender, _receiver) = Requester::<FetchEvent, PoolError>::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let failed = connect_before_deadline(
            &sender,
            true,
            deadline,
            Duration::from_millis(10),
            std::future::pending::<Result<()>>(),
        )
        .await
        .unwrap_err();
        assert!(!matches!(failed, PoolError::Stopped(_)));
        assert_eq!(
            connect_before_deadline(&sender, true, deadline, Duration::from_millis(10), async {
                Ok("second provider")
            },)
            .await
            .unwrap(),
            "second provider"
        );
        let expired = connect_before_deadline(
            &sender,
            true,
            tokio::time::Instant::now(),
            Duration::from_secs(10),
            async { Ok(()) },
        )
        .await
        .unwrap_err();
        assert!(matches!(expired, PoolError::Stopped(_)));
    }

    #[tokio::test]
    async fn previous_proposal_does_not_authorize_disconnected_next_operation() {
        let (sender, receiver) = Requester::<FetchEvent, PoolError>::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        before_proposal(&sender, true, deadline, |proposed| async move {
            proposed.store(true, Ordering::Release);
        })
        .await
        .unwrap();
        // A retained proposal from the earlier operation may still exist, but
        // the next operation must establish its own signature-release boundary.
        drop(receiver);
        let started = AtomicBool::new(false);
        let result = before_proposal(&sender, true, deadline, |_| async {
            started.store(true, Ordering::Release);
        })
        .await;
        assert!(matches!(result.unwrap_err(), PoolError::Stopped(_)));
        assert!(!started.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn shutdown_rejects_admitted_work_not_yet_registered() {
        let fixture = crate::test_support::PaidFixture::new();
        let pool = test_pool(&fixture, fixture.policy.clone()).await;
        let provider = pool.providers[0].clone();
        let gateway = WorkGateway::new(pool, 1);
        // Deterministically pause execute at the point after admission but
        // before preparation/routing has reached task registration.
        let permit = gateway.admission.clone().try_acquire_owned().unwrap();
        hellas_gateway::WorkExecutionBackend::drain(&gateway)
            .await
            .unwrap();
        let result =
            gateway.submit::<FetchEvent>(PaidRequest(Routed::Recover(provider)), Some(permit));
        assert!(matches!(
            result.err().expect("submission after drain"),
            PoolError::Gateway(WorkGatewayError::Busy(_))
        ));
        assert_eq!(gateway.admission.available_permits(), 1);
    }

    #[tokio::test]
    async fn queue_wait_uses_the_execution_deadline() {
        let (sender, _receiver) = Requester::<FetchEvent, PoolError>::new();
        let serial = AsyncMutex::new(());
        let _busy = serial.lock().await;
        let result = before_proposal(
            &sender,
            true,
            tokio::time::Instant::now() + Duration::from_millis(20),
            |_| serial.lock(),
        )
        .await;
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("including queue wait")
        );
    }

    #[tokio::test]
    async fn expired_request_does_not_start_a_fallback_provider() {
        let (sender, _receiver) = Requester::<FetchEvent, PoolError>::new();
        let started = AtomicBool::new(false);
        let result = before_proposal(&sender, true, tokio::time::Instant::now(), |_| async {
            started.store(true, Ordering::Relaxed);
        })
        .await;
        assert!(result.is_err());
        assert!(!started.load(Ordering::Relaxed));
    }
}
