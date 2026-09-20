//! HTTP gateway adapter over the same durable paid-work client as the CLI.

use super::*;
use futures::future::BoxFuture;
use futures::stream::BoxStream;
use hellas_gateway::{
    ExecutionEvent, Outcome, PaidExecutionBackend, PaidExecutionRequest, StopReason,
};
use hellas_rpc::protocol::artifacts::{
    BoundTermId, InputAddressed as _, OutputAddressed as _, SourceRef, TextArtifact, TextExecution,
    TextPolicy, TokenIds,
};
use serde::Deserialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::JoinHandle;
use tracing::Instrument;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolFile {
    providers: Vec<ProviderFile>,
    #[serde(default = "acceptance_blocks")]
    acceptance_blocks: u64,
    #[serde(default = "terminal_blocks")]
    terminal_blocks: u64,
    #[serde(default = "payment_blocks")]
    payment_blocks: u64,
    #[serde(default = "timeout_secs")]
    timeout_secs: u64,
}

const fn acceptance_blocks() -> u64 {
    16
}
const fn terminal_blocks() -> u64 {
    64
}
const fn payment_blocks() -> u64 {
    32
}
const fn timeout_secs() -> u64 {
    300
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderFile {
    work_config: PathBuf,
    journal_root: PathBuf,
    provider: EndpointId,
    #[serde(default)]
    provider_addrs: Vec<SocketAddr>,
    bond: String,
    payment_coins: Vec<String>,
    omission_bond: u64,
}

struct Provider {
    args: RunArgs,
    policy: ProviderChannelPolicy,
    /// A setup/channel journal has a single owner even with concurrent HTTP calls.
    serial: AsyncMutex<Option<OpenPaidChannel>>,
    pending: AtomicUsize,
    last_input: Mutex<Vec<u32>>,
}

struct ProviderUse(Arc<Provider>);
impl Drop for ProviderUse {
    fn drop(&mut self) {
        self.0.pending.fetch_sub(1, Ordering::Relaxed);
    }
}

struct PaidGateway {
    providers: Vec<Arc<Provider>>,
    next: AtomicUsize,
    endpoint: Endpoint,
    settlement_key: Secp256k1Signer,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    followers: Mutex<Vec<JoinHandle<()>>>,
}

pub async fn load_gateway_backend(
    path: &Path,
    transport_key: SecretKey,
    settlement_key: Secp256k1Signer,
) -> CliResult<Arc<dyn PaidExecutionBackend>> {
    let bytes =
        crate::commands::read_bounded_regular_file(path, "paid gateway config", MAX_RECORD_BYTES)?;
    let file: PoolFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid paid gateway config {}", path.display()))?;
    anyhow::ensure!(
        !file.providers.is_empty(),
        "paid gateway requires at least one provider"
    );
    anyhow::ensure!(
        file.timeout_secs > 0,
        "paid gateway timeout_secs must be greater than zero"
    );
    anyhow::ensure!(
        file.acceptance_blocks > 0 && file.terminal_blocks > 0 && file.payment_blocks > 0,
        "paid gateway deadline spans must be greater than zero"
    );
    let mut providers = Vec::new();
    let mut journals = std::collections::BTreeSet::new();
    let mut endpoints = std::collections::BTreeSet::new();
    let mut funding = std::collections::BTreeSet::new();
    for provider in file.providers {
        anyhow::ensure!(
            provider.work_config.is_absolute() && provider.journal_root.is_absolute(),
            "paid gateway work_config and journal_root must be absolute runtime paths"
        );
        anyhow::ensure!(
            journals.insert(provider.journal_root.clone()),
            "paid providers must have distinct journal roots"
        );
        anyhow::ensure!(
            endpoints.insert(provider.provider),
            "paid gateway repeats provider {}",
            provider.provider
        );
        anyhow::ensure!(
            !provider.payment_coins.is_empty(),
            "paid provider needs payment_coins"
        );
        coins(&provider.payment_coins)?;
        edge_id("bond", &provider.bond)?;
        for coin in &provider.payment_coins {
            anyhow::ensure!(
                funding.insert(fixed_hex::<32>("payment_coins", coin)?),
                "a payment coin cannot fund two provider channels"
            );
        }
        let config = load_work_config(&provider.work_config)?;
        providers.push(Arc::new(Provider {
            policy: config.provider_policy(),
            args: RunArgs {
                work_config: provider.work_config,
                journal_root: provider.journal_root,
                provider: provider.provider,
                provider_addrs: provider.provider_addrs,
                bond: provider.bond,
                payment_coins: provider.payment_coins,
                omission_bond: provider.omission_bond,
                prepared_input: PathBuf::new(),
                output: None,
                acceptance_blocks: file.acceptance_blocks,
                terminal_blocks: file.terminal_blocks,
                payment_blocks: file.payment_blocks,
                timeout_secs: file.timeout_secs,
                settle: false,
            },
            serial: AsyncMutex::new(None),
            pending: AtomicUsize::new(0),
            last_input: Mutex::new(Vec::new()),
        }));
    }
    let gateway = Arc::new(PaidGateway {
        providers,
        next: AtomicUsize::new(0),
        // One transport identity has one relay registration, shared by every
        // provider and request for the lifetime of this gateway.
        endpoint: bind_paid_endpoint(transport_key).await?,
        settlement_key,
        tasks: Mutex::new(Vec::new()),
        followers: Mutex::new(Vec::new()),
    });
    // Restart recovery uses the retained input and certificate, never a new job.
    // Empty journal roots do not fund a channel until an HTTP request arrives.
    for provider in &gateway.providers {
        let _recovery = gateway.submit(provider.clone(), None);
        let provider = provider.clone();
        gateway.followers.lock().expect("paid followers poisoned").push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let mut session = provider.serial.lock().await;
                if let Some(session) = session.as_mut() && let Err(error) = session.follow_chain().await {
                    tracing::warn!(provider = %provider.args.provider, %error, "paid channel chain follower will retry");
                }
            }
        }));
    }
    Ok(gateway)
}

impl PaidGateway {
    fn submit(
        &self,
        provider: Arc<Provider>,
        prepared: Option<PreparedPaidInputV1>,
    ) -> BoxStream<'static, CliResult<ExecutionEvent>> {
        let endpoint = self.endpoint.clone();
        let settlement_key = self.settlement_key.clone();
        let (sender, receiver) = mpsc::unbounded_channel();
        let span = hellas_rpc::request_span!(target: "hellas_request", "paid.gateway", hellas.provider.id = %provider.args.provider, hellas.work.recovery = prepared.is_none());
        let occupied = prepared.as_ref().map(|_| ProviderUse(provider.clone()));
        let task = tokio::spawn(async move {
            let _occupied = occupied;
            let mut session = provider.serial.lock().instrument(hellas_rpc::request_span!(target: "hellas_request", "paid.queue")).await;
            let timeout = Duration::from_secs(provider.args.timeout_secs);
            let token_sender = sender.clone();
            let streamed = prepared.is_some();
            let progress: hellas_work::work::PaidProgress = Arc::new(move |event| {
                let delta = hellas_rpc::evaluate::decode_token_delta_payload(event.payload())
                    .map_err(|error| hellas_work::work::BackendFault::new(error.to_string()))?;
                let position = delta.end_position().map_err(|error| hellas_work::work::BackendFault::new(error.to_string()))?;
                let _ = token_sender.send(Ok(ExecutionEvent::Chunk { position, tokens: delta.token_bytes() }));
                Ok(())
            });
            let result = tokio::time::timeout(
                timeout,
                async {
                    if prepared.is_none() && (!provider.args.journal_root.try_exists()? || std::fs::read_dir(&provider.args.journal_root)?.next().is_none()) {
                        return Ok(None);
                    }
                    if session.is_none() {
                        *session = Some(OpenPaidChannel::open(provider.args.clone(), endpoint, settlement_key).await?);
                    }
                    session.as_mut().expect("channel was opened").run(prepared, true, streamed.then_some(progress)).await
                },
            )
            .await
            .map_err(|_| anyhow::anyhow!("paid execution exceeded its {timeout:?} limit"))
            .and_then(|result| result)
            .and_then(|output| output.map(output_events).transpose())
            .map(Option::unwrap_or_default);
            if let Err(error) = &result {
                tracing::error!(provider = %provider.args.provider, error = %format!("{error:#}"),
                    "paid gateway operation failed; durable journals retained for recovery");
            }
            // Dropping an HTTP request drops only its receiver. The task still
            // collects and pays for accepted work, then releases the journal.
            match result {
                Ok(events) => for event in events {
                    if !streamed || matches!(event, ExecutionEvent::Done(_)) {
                        let _ = sender.send(Ok(event));
                    }
                },
                Err(error) => { let _ = sender.send(Err(error)); }
            }
        }.instrument(span));
        let mut tasks = self.tasks.lock().expect("paid task list poisoned");
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
        Box::pin(futures::stream::unfold(
            receiver,
            |mut receiver| async move { receiver.recv().await.map(|event| (event, receiver)) },
        ))
    }
}

impl PaidExecutionBackend for PaidGateway {
    fn execute(
        &self,
        request: PaidExecutionRequest,
    ) -> CliResult<BoxStream<'static, CliResult<ExecutionEvent>>> {
        let input_ids = request.input_ids.clone();
        let prepared = prepare_request(request, &self.settlement_key)?;
        let eligible = self
            .providers
            .iter()
            .filter(|provider| check_policy_input(&provider.policy, &prepared).is_ok())
            .collect::<Vec<_>>();
        anyhow::ensure!(
            !eligible.is_empty(),
            "no provider policy matches this environment, token limit, and stop token list"
        );
        let start = self.next.fetch_add(1, Ordering::Relaxed) % eligible.len();
        let provider = (0..eligible.len())
            .map(|offset| eligible[(start + offset) % eligible.len()])
            .max_by_key(|provider| {
                let previous = provider.last_input.lock().expect("provider input poisoned");
                let shared = previous
                    .iter()
                    .zip(&input_ids)
                    .take_while(|(left, right)| left == right)
                    .count();
                (
                    std::cmp::Reverse(provider.pending.load(Ordering::Relaxed)),
                    shared,
                )
            })
            .expect("eligible provider exists")
            .clone();
        *provider.last_input.lock().expect("provider input poisoned") = input_ids;
        provider.pending.fetch_add(1, Ordering::Relaxed);
        Ok(self.submit(provider, Some(prepared)))
    }

    fn drain(&self) -> BoxFuture<'_, ()> {
        for follower in self
            .followers
            .lock()
            .expect("paid followers poisoned")
            .drain(..)
        {
            follower.abort();
        }
        let tasks = std::mem::take(&mut *self.tasks.lock().expect("paid task list poisoned"));
        Box::pin(async move {
            for task in tasks {
                if let Err(error) = task.await {
                    tracing::error!(%error, "paid gateway task failed during shutdown");
                }
            }
            self.endpoint.close().await;
        })
    }
}

fn prepare_request(
    request: PaidExecutionRequest,
    signer: &Secp256k1Signer,
) -> CliResult<PreparedPaidInputV1> {
    anyhow::ensure!(
        request.max_new_tokens > 0,
        "max_new_tokens must be greater than zero"
    );
    let manifest = request.environment.manifest();
    hellas_client::iroh::validate_causal_lm_quote_request(
        &hellas_rpc::pb::courtesy::QuoteTokensRequest {
            program_manifest: manifest.canonical_bytes(),
            prompt_token_ids: request.input_ids.clone(),
            max_new_tokens: Some(request.max_new_tokens),
            stop_token_ids: request.stop_token_ids.clone(),
            ..Default::default()
        },
        manifest.content_id(),
        &request.environment,
    )?;
    let tokens = TokenIds::from_u32s(request.input_ids);
    let policy = TextPolicy::from_u32_stop_tokens(request.max_new_tokens, request.stop_token_ids);
    let identity = TextArtifact::identity(BoundTermId::from_digest(manifest.content_id().digest()));
    let execution = TextExecution::new(
        SourceRef::output(identity.output_id()),
        tokens.output_id(),
        policy.output_id(),
    );
    let evaluate = hellas_rpc::EvaluateRequest {
        text_execution: execution.input_id().digest(),
        runner_public_key: hellas_rpc::PublicKey::Secp256k1(signer.party_key().to_bytes()),
        execution_environment: manifest.content_id(),
        nonce: rand::random(),
        assurance: hellas_rpc::Assurance::ProducerSigned,
        retain: true,
    };
    Ok(PreparedPaidInputV1::new(
        &evaluate, &manifest, &execution, &tokens, &policy, &identity,
    ))
}

fn output_events(output: PaidOutput) -> CliResult<Vec<ExecutionEvent>> {
    let events =
        hellas_rpc::protocol::work::decode_transcript(&output.transcript, MAX_RECORD_BYTES)?;
    let verified = hellas_rpc::evaluate::verify_output_events_for_producer(
        output.input,
        hellas_rpc::Assurance::ProducerSigned,
        &output.provider_key,
        &events,
    )?;
    let mut result = Vec::with_capacity(verified.token_deltas.len() + 1);
    for delta in verified.token_deltas {
        result.push(ExecutionEvent::Chunk {
            position: delta.end_position()?,
            tokens: delta.token_bytes(),
        });
    }
    let terminal = verified.terminal;
    let stop_reason =
        if terminal.stop_reason == hellas_rpc::evaluate::EvaluateStopReason::STOP_TOKEN {
            StopReason::StopToken(
                terminal
                    .matched_stop_token_id
                    .context("signed stop-token result omitted its token ID")?,
            )
        } else {
            StopReason::MaxNewTokens
        };
    result.push(ExecutionEvent::Done(Outcome::Completed {
        total_tokens: terminal.usage.billable_units()?,
        stop_reason,
        text_artifact: terminal.text_artifact,
        output_events: events,
    }));
    Ok(result)
}
