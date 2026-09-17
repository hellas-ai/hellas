use crate::commands::CliResult;
use futures::StreamExt;
use hellas_client::cache::{CacheOptions, CachePolicy, OutputCache, fetch_output_stream};
use hellas_client::{ExecutionRoute, ExecutionRuntime};
use hellas_rpc::fetch::{MAX_FETCH_REQUEST_BODY_BYTES, build_input_events_with_retention};
use hellas_rpc::pb::fetch::FetchRequest;
use hellas_rpc::stream::input_event_to_pb;
use hellas_rpc::{Assurance, ContentId, ProducerSigningKey, Retention};
use iroh::{EndpointId, SecretKey};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::Path;
use tracing::trace;

/// Load a Fetch body from an ordinary file without allowing a special file to
/// block the CLI before the protocol's body bound is enforced.
pub(crate) fn load_payload_file(path: &Path) -> CliResult<Vec<u8>> {
    super::read_bounded_regular_file(path, "--payload-file", MAX_FETCH_REQUEST_BODY_BYTES)
}

pub struct ExecuteOptions {
    pub output_cache: CacheOptions,
    pub node_id: Option<EndpointId>,
    pub node_addrs: Vec<SocketAddr>,
    pub service: String,
    pub method: String,
    pub execution_environment: ContentId,
    pub payload: Vec<u8>,
    pub retries: usize,
    pub retain: bool,
    pub producer_key: ProducerSigningKey,
    pub expected_provider_genesis: Option<ContentId>,
    pub apple_app_attest_app_id: Option<String>,
    pub apple_app_attest_cdhashes: Vec<[u8; 32]>,
    pub assurance: Assurance,
}

pub async fn run(options: ExecuteOptions, secret_key: SecretKey) -> CliResult<()> {
    serde_json::from_slice::<serde_json::Value>(&options.payload)
        .map_err(|err| anyhow::anyhow!("--payload must be UTF-8 JSON: {err}"))?;

    let caller_key = options.producer_key;

    let caller_key = std::sync::Arc::new(caller_key);

    let replay_only = options.output_cache.policy == CachePolicy::ReplayOnly;
    let cache = OutputCache::open(&options.output_cache)?;
    let (runtime, route) = if replay_only {
        (ExecutionRuntime::<()>::default(), None)
    } else {
        let provider_trust = crate::identity::provider_trust(
            options.expected_provider_genesis,
            options.assurance,
            options.apple_app_attest_app_id,
            options.apple_app_attest_cdhashes,
        )?;
        let route = ExecutionRoute::remote(
            options.node_id,
            options.node_addrs.clone(),
            options.retries,
            provider_trust,
        );
        let runtime = ExecutionRuntime::<()>::remote(secret_key).await?;
        (runtime, Some(route))
    };

    let request = FetchRequest {
        input: signed_input_events(
            &options.service,
            &options.method,
            &options.payload,
            options.execution_environment,
            options.assurance,
            &caller_key,
            Retention::from_retain(options.retain),
        )?,
    };
    let mut stream = fetch_output_stream(runtime, request, route, caller_key, cache)
        .await?
        .events;

    let mut completed = false;
    while let Some(event) = stream.next().await {
        let event = event?;
        trace!("fetch output event");
        if let hellas_rpc::output::OutputEvent::Error { message, .. } = &event {
            anyhow::bail!("fetch execution failed: {message}");
        }
        completed |= matches!(event, hellas_rpc::output::OutputEvent::Finished { .. });
        serde_json::to_writer(&mut io::stdout(), &event)?;
        io::stdout().write_all(b"\n")?;
        io::stdout().flush()?;
        if completed {
            break;
        }
    }
    if !completed {
        anyhow::bail!("fetch execution stream ended without terminal outcome");
    }

    crate::tracing_config::suppress_execute_tail_logs();
    Ok(())
}

pub(crate) fn signed_input_events(
    service: &str,
    method: &str,
    payload: &[u8],
    execution_environment: ContentId,
    assurance: Assurance,
    key: &ProducerSigningKey,
    retention: Retention,
) -> anyhow::Result<Vec<hellas_rpc::pb::execute::InputEventEnvelope>> {
    let events = build_input_events_with_retention(
        service,
        method,
        payload,
        execution_environment,
        assurance,
        key,
        retention,
    )?;
    Ok(events.iter().map(input_event_to_pb).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_file_accepts_the_exact_protocol_bound() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("request.json");
        let mut payload = vec![b' '; MAX_FETCH_REQUEST_BODY_BYTES];
        payload[..2].copy_from_slice(b"{}");
        std::fs::write(&path, payload).unwrap();

        let loaded = load_payload_file(&path).unwrap();
        assert_eq!(loaded.len(), MAX_FETCH_REQUEST_BODY_BYTES);
        serde_json::from_slice::<serde_json::Value>(&loaded).unwrap();
    }

    #[test]
    fn payload_file_rejects_one_byte_over_the_protocol_bound() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("request.json");
        std::fs::write(&path, vec![b' '; MAX_FETCH_REQUEST_BODY_BYTES + 1]).unwrap();

        let error = load_payload_file(&path).expect_err("oversized payload must be refused");
        assert!(error.to_string().contains("over the 1048576-byte limit"));
    }

    #[cfg(unix)]
    #[test]
    fn payload_file_rejects_a_fifo_without_waiting_for_a_writer() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("request.fifo");
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c_path` is a live, NUL-terminated path for this call.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let (sender, receiver) = std::sync::mpsc::channel();
        let thread_path = path.clone();
        let thread = std::thread::spawn(move || {
            sender.send(load_payload_file(&thread_path)).unwrap();
        });
        let error = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("--payload-file blocked while opening a FIFO")
            .expect_err("a FIFO must be refused");
        assert!(format!("{error:#}").contains("not a regular file"));
        thread.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn payload_file_rejects_a_device_before_reading_from_it() {
        let error = load_payload_file(Path::new("/dev/zero"))
            .expect_err("a device must not be accepted as a payload file");
        assert!(format!("{error:#}").contains("not a regular file"));
    }
}
