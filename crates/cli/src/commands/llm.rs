use crate::commands::CliResult;
#[cfg(feature = "evaluate")]
use anyhow::Context;
use futures::StreamExt;
use hellas_client::ExecutionRoute;
use hellas_client::execution::{
    CausalLmExecutionEnvironment, CliRuntime, ExecutionEvent, ExecutionRequest,
    ExecutionRequestOptions, ExecutionStrategy, Outcome,
};
#[cfg(feature = "evaluate")]
use hellas_executor::{
    ArtifactStoreConfig, CausalLmEnvironmentSource, Executor, ExecutorMetrics, ExecutorSpawnConfig,
    FetchAccessPolicy, FetchRouteRegistry, FetchTranscriptStoreBackend, GpuConfig,
};
use hellas_presentation::{TextOutputDecoder, TextPresentation};
use hellas_rpc::{Assurance, ContentId, ProducerSigningKey, Retention};
#[cfg(feature = "evaluate")]
use hellas_store::ContentStore;
use iroh::{EndpointId, SecretKey};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Canonical evaluator metadata loaded from an operator-selected root file.
///
/// The caller-selected or locally derived manifest is the only evaluator
/// identity sent in a remote quote. The environment body stays local and
/// supplies the bounded causal-LM metadata used to validate the token request.
pub(crate) struct LoadedCausalLmEnvironment {
    execution: CausalLmExecutionEnvironment,
    #[cfg(feature = "evaluate")]
    manifest_bytes: Vec<u8>,
}

impl LoadedCausalLmEnvironment {
    pub(crate) fn execution(&self) -> &CausalLmExecutionEnvironment {
        &self.execution
    }

    pub(crate) fn into_execution(self) -> CausalLmExecutionEnvironment {
        self.execution
    }
}

/// Strictly load one canonical causal-LM root and enforce any caller-selected
/// manifest identity before constructing a local or remote route.
pub(crate) fn load_environment(
    path: &Path,
    manifest_id: Option<ContentId>,
) -> CliResult<LoadedCausalLmEnvironment> {
    let bytes = super::read_bounded_regular_file(
        path,
        "environment",
        hellas_rpc::MAX_CAUSAL_LM_ENVIRONMENT_BYTES,
    )?;
    let environment =
        hellas_rpc::CausalLmEnvironment::from_canonical_bytes(&bytes).map_err(|error| {
            anyhow::anyhow!("invalid canonical environment {}: {error}", path.display())
        })?;
    let manifest = environment.manifest();
    let manifest_bytes = manifest.canonical_bytes();
    let derived_manifest_id = manifest.content_id();
    let expected_manifest_id = manifest_id.unwrap_or(derived_manifest_id);
    anyhow::ensure!(
        derived_manifest_id == expected_manifest_id,
        "environment {} derives manifest {derived_manifest_id}, not caller-pinned {expected_manifest_id}",
        path.display()
    );
    let execution = CausalLmExecutionEnvironment::from_canonical_bytes(
        expected_manifest_id,
        manifest_bytes.clone(),
        bytes,
    )
    .map_err(|error| anyhow::anyhow!("invalid causal-LM execution environment: {error}"))?;
    Ok(LoadedCausalLmEnvironment {
        execution,
        #[cfg(feature = "evaluate")]
        manifest_bytes,
    })
}

/// Build the local, verified content view required by a local execution leg.
///
/// No acquisition occurs here. The environment root is indexed alongside the
/// operator-named program/static files, then the executor seam proves that all
/// exact content references are present before a route is started.
#[cfg(feature = "evaluate")]
pub(crate) fn local_content_store(
    enabled: bool,
    environment_path: &Path,
    environment: &LoadedCausalLmEnvironment,
    mut content_paths: Vec<PathBuf>,
    content_roots: Vec<PathBuf>,
    content_index: Option<PathBuf>,
) -> CliResult<Option<ContentStore>> {
    if !enabled {
        anyhow::ensure!(
            content_paths.is_empty() && content_roots.is_empty() && content_index.is_none(),
            "--content, --content-root, and --content-index require --local or --verify-local"
        );
        return Ok(None);
    }
    anyhow::ensure!(
        !content_paths.is_empty() || !content_roots.is_empty(),
        "--local and --verify-local require at least one --content or --content-root"
    );
    if !content_paths.iter().any(|path| path == environment_path) {
        content_paths.push(environment_path.to_owned());
    }
    let content_index = content_index
        .or_else(hellas_store::state::records_path)
        .context("no content-store state directory; pass --content-index FILE")?;
    let store = crate::commands::environment::index_content(
        &content_paths,
        &content_roots,
        &content_index,
    )?;
    let source =
        CausalLmEnvironmentSource::from_manifest_bytes(&store, &environment.manifest_bytes)
            .context("local content does not satisfy the causal-LM environment")?;
    anyhow::ensure!(
        source.manifest_id() == environment.execution.manifest_id(),
        "local content resolved a different program manifest"
    );
    Ok(Some(store))
}

pub struct ExecuteOptions {
    pub output_cache: hellas_rpc::cache::CacheOptions,
    pub node_id: Option<EndpointId>,
    pub node_addrs: Vec<SocketAddr>,
    /// Presentation label. It never enters a quote or manifest.
    pub model_name: String,
    pub causal_lm: CausalLmExecutionEnvironment,
    #[cfg(feature = "evaluate")]
    pub local_content_store: Option<ContentStore>,
    pub tokenizer: PathBuf,
    pub stop_token_ids: Vec<u32>,
    pub prompt: String,
    pub max_new_tokens: u32,
    pub retries: usize,
    #[cfg(feature = "evaluate")]
    pub local: bool,
    #[cfg(feature = "evaluate")]
    pub verify_local: bool,
    pub producer_key: ProducerSigningKey,
    #[cfg(feature = "evaluate")]
    pub provider_genesis: Vec<u8>,
    pub expected_provider_genesis: Option<ContentId>,
    pub apple_app_attest_app_id: Option<String>,
    pub apple_app_attest_cdhashes: Vec<[u8; 32]>,
    pub assurance: Assurance,
    pub retain: bool,
}

pub async fn run(options: ExecuteOptions, secret_key: SecretKey) -> CliResult<()> {
    let cache = hellas_client::cache::OutputCache::open(&options.output_cache)?;
    #[cfg(feature = "evaluate")]
    anyhow::ensure!(
        cache.is_none() || !options.verify_local,
        "verification requires live execution; disable inference caching"
    );
    let replay_only = options.output_cache.policy == hellas_rpc::cache::CachePolicy::ReplayOnly;
    #[cfg(feature = "evaluate")]
    let uses_remote = !replay_only && (!options.local || options.verify_local);
    #[cfg(not(feature = "evaluate"))]
    let uses_remote = !replay_only;
    let provider_trust = if uses_remote {
        Some(crate::identity::provider_trust(
            options.expected_provider_genesis,
            options.assurance,
            options.apple_app_attest_app_id.clone(),
            options.apple_app_attest_cdhashes.clone(),
        )?)
    } else {
        None
    };

    // Presentation is an explicitly separate local input. Hellas commits the
    // resulting token IDs, not this tokenizer, label, or decoded text.
    let presentation = Arc::new(TextPresentation::load(&options.tokenizer)?);
    let input_ids = presentation.encode(&options.prompt)?;
    let mut decoder = TextOutputDecoder::new(presentation);
    let manifest_id = options.causal_lm.manifest_id();
    info!(program_manifest = %manifest_id, "using canonical causal-LM environment");
    let runner_key = options.producer_key.clone();

    #[cfg(feature = "evaluate")]
    let runtime = if replay_only {
        CliRuntime::default()
    } else if options.local || options.verify_local {
        let content_store = options
            .local_content_store
            .context("local Catena execution requires a verified local content store")?;
        let executor = Executor::spawn_configured(ExecutorSpawnConfig {
            output_cache: options.output_cache.clone(),
            execute_policy: hellas_rpc::policy::ExecutePolicy::Any,
            queue_capacity: hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY,
            metrics: Arc::new(ExecutorMetrics::default()),
            producer_key: Arc::new(runner_key.clone()),
            provider_genesis: Arc::new(options.provider_genesis),
            assurance: options.assurance,
            fetch_access_policy: FetchAccessPolicy::trusted_callers([runner_key.public_key()]),
            fetch_routes: FetchRouteRegistry::default(),
            fetch_max_in_flight: hellas_rpc::DEFAULT_FETCH_MAX_IN_FLIGHT,
            fetch_queue_capacity: hellas_rpc::DEFAULT_FETCH_QUEUE_CAPACITY,
            fetch_replay_max_in_flight: hellas_rpc::DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT,
            fetch_store: FetchTranscriptStoreBackend::memory(),
            artifact_store: ArtifactStoreConfig::memory(),
            content_store,
            gpu_config: GpuConfig::default(),
        })
        .await
        .context("failed to initialize local Catena executor")?;
        let runtime = CliRuntime::local(executor);
        if options.verify_local {
            runtime.with_remote(secret_key.clone()).await?
        } else {
            runtime
        }
    } else {
        CliRuntime::remote(secret_key.clone()).await?
    };
    #[cfg(not(feature = "evaluate"))]
    let runtime = if replay_only {
        CliRuntime::default()
    } else {
        CliRuntime::remote(secret_key.clone()).await?
    };

    #[cfg(feature = "evaluate")]
    let strategy = if replay_only {
        ExecutionStrategy::Replay
    } else if options.verify_local {
        info!(program_manifest = %manifest_id, "executing remotely and verifying against local Catena");
        ExecutionStrategy::Verify {
            primary: ExecutionRoute::remote(
                options.node_id,
                options.node_addrs,
                options.retries,
                provider_trust.expect("remote route requires provider trust"),
            ),
            shadow: ExecutionRoute::Local,
        }
    } else if options.local {
        info!(program_manifest = %manifest_id, "executing locally with Catena");
        ExecutionStrategy::Run(ExecutionRoute::Local)
    } else {
        info!(program_manifest = %manifest_id, "executing remotely with Catena");
        ExecutionStrategy::Run(ExecutionRoute::remote(
            options.node_id,
            options.node_addrs,
            options.retries,
            provider_trust.expect("remote route requires provider trust"),
        ))
    };
    #[cfg(not(feature = "evaluate"))]
    let strategy = if replay_only {
        ExecutionStrategy::Replay
    } else {
        ExecutionStrategy::Run(ExecutionRoute::remote(
            options.node_id,
            options.node_addrs,
            options.retries,
            provider_trust.expect("remote route requires provider trust"),
        ))
    };

    info!(model = %options.model_name, "using presentation label");
    let remote_runtime = uses_remote.then(|| runtime.clone());
    let request = ExecutionRequest::new(
        runtime,
        options.causal_lm,
        input_ids,
        options.stop_token_ids,
        ExecutionRequestOptions {
            max_new_tokens: options.max_new_tokens,
            assurance: options.assurance,
            retention: Retention::from_retain(options.retain),
        },
        strategy,
        runner_key,
    )?;
    // The local executor already owns this cache; avoid a second pipeline.
    #[cfg(feature = "evaluate")]
    let cache = if options.local && !replay_only {
        None
    } else {
        cache
    };
    let request = request.with_cache(cache);
    let uses_remote = request.uses_remote_transport();
    let result: anyhow::Result<()> = async {
        let stream = request.stream();
        tokio::pin!(stream);
        let mut completed = false;
        while let Some(event) = stream.next().await {
            match event? {
                ExecutionEvent::Chunk { tokens, .. } => {
                    let delta = decoder.push_bytes(&tokens)?;
                    if !delta.is_empty() {
                        print!("{delta}");
                        io::stdout().flush()?;
                    }
                }
                ExecutionEvent::Done(Outcome::Completed { .. }) => {
                    completed = true;
                    break;
                }
                ExecutionEvent::Done(Outcome::Failed { error, .. }) => {
                    anyhow::bail!("execution failed: {error}");
                }
            }
        }
        if !completed {
            anyhow::bail!("execution stream ended without terminal outcome");
        }
        Ok(())
    }
    .await;

    if uses_remote {
        crate::tracing_config::suppress_execute_tail_logs();
    }
    if let Some(runtime) = remote_runtime {
        runtime.close_remote().await;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::{CausalLmEnvironment, ContentId, ContentRef, StaticSlice};

    fn fixture_environment(program: &[u8], weights: &[u8]) -> CausalLmEnvironment {
        CausalLmEnvironment::new(
            ContentRef::new(ContentId::hash(program), program.len() as u64),
            "model",
            vec![ContentRef::new(
                ContentId::hash(weights),
                weights.len() as u64,
            )],
            vec![StaticSlice::new(0, 0, weights.len() as u64)],
            Vec::new(),
            256,
            1_024,
        )
        .expect("fixture environment is valid")
    }

    #[test]
    fn loading_an_environment_derives_its_exact_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("model.environment");
        let environment = fixture_environment(b"program", b"weights");
        std::fs::write(&path, environment.canonical_bytes()).unwrap();

        let loaded = load_environment(&path, None).unwrap();
        assert_eq!(
            loaded.into_execution().manifest_id(),
            environment.manifest().content_id()
        );
    }

    #[test]
    fn loading_an_environment_accepts_its_explicit_manifest_pin() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("model.environment");
        let environment = fixture_environment(b"program", b"weights");
        let manifest_id = environment.manifest().content_id();
        std::fs::write(&path, environment.canonical_bytes()).unwrap();

        let loaded = load_environment(&path, Some(manifest_id)).unwrap();
        assert_eq!(loaded.into_execution().manifest_id(), manifest_id);
    }

    #[test]
    fn loading_an_environment_rejects_a_mismatched_manifest_pin() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("model.environment");
        let environment = fixture_environment(b"program", b"weights");
        std::fs::write(&path, environment.canonical_bytes()).unwrap();

        let expected = ContentId::from_bytes([0x55; 32]);
        let error = load_environment(&path, Some(expected))
            .err()
            .expect("a mismatched caller pin must be refused");
        let message = error.to_string();
        assert!(message.contains("not caller-pinned"), "{message}");
        assert!(message.contains(&expected.to_string()), "{message}");
    }

    #[test]
    fn loading_an_environment_reads_only_the_protocol_bound() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("oversized.environment");
        std::fs::write(
            &path,
            vec![0; hellas_rpc::MAX_CAUSAL_LM_ENVIRONMENT_BYTES + 1],
        )
        .unwrap();

        let error = load_environment(&path, None)
            .err()
            .expect("oversize is refused");
        assert!(error.to_string().contains("over the"));
    }

    #[cfg(unix)]
    #[test]
    fn loading_an_environment_rejects_a_fifo_without_waiting_for_a_writer() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("model.environment.fifo");
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c_path` is a live, NUL-terminated path for this call.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let (sender, receiver) = std::sync::mpsc::channel();
        let thread_path = path.clone();
        let thread = std::thread::spawn(move || {
            sender.send(load_environment(&thread_path, None)).unwrap();
        });
        let result = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("environment loading blocked while opening a FIFO");
        let error = result.err().expect("a FIFO must be refused");
        assert!(format!("{error:#}").contains("not a regular file"));
        thread.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn loading_an_environment_rejects_a_device_before_reading_from_it() {
        let error = load_environment(Path::new("/dev/zero"), None)
            .err()
            .expect("a device must not be accepted as an environment");
        assert!(format!("{error:#}").contains("not a regular file"));
    }

    #[cfg(feature = "evaluate")]
    #[test]
    fn local_content_is_bound_before_executor_startup() {
        let directory = tempfile::tempdir().unwrap();
        let program_path = directory.path().join("model.hex");
        let weights_path = directory.path().join("weights.bin");
        let environment_path = directory.path().join("model.environment");
        let index_path = directory.path().join("fastresume.bin");
        let program = b"program";
        let weights = b"weights";
        std::fs::write(&program_path, program).unwrap();
        std::fs::write(&weights_path, weights).unwrap();
        let environment = fixture_environment(program, weights);
        std::fs::write(&environment_path, environment.canonical_bytes()).unwrap();
        let loaded = load_environment(&environment_path, None).unwrap();

        let store = local_content_store(
            true,
            &environment_path,
            &loaded,
            vec![program_path, weights_path],
            Vec::new(),
            Some(index_path),
        )
        .unwrap();
        assert!(store.is_some());
    }
}
