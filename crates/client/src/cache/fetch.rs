use std::sync::Arc;

use futures::StreamExt;
use hellas_adaptors::{BackendStream, Provenance};
use hellas_rpc::ProducerSigningKey;
use hellas_rpc::pb::fetch::FetchRequest;

use super::{CacheKey, OutputCache, backend_error, cache_error, replay};
use crate::{
    ClientResult, ExecutionRoute, ExecutionRuntime, FetchExecutionEvent, FetchOutcome,
    verified_fetch_input,
};

/// Verified Fetch output, optionally recorded by inference identity. A replay
/// needs neither a route nor a connected runtime and preserves the original
/// provenance. General Fetch routes bypass recording; replay-only never runs
/// potentially side-effecting work.
pub async fn fetch_output_stream<L: Send + Sync + 'static>(
    runtime: ExecutionRuntime<L>,
    request: FetchRequest,
    route: Option<ExecutionRoute>,
    runner_key: Arc<ProducerSigningKey>,
    cache: Option<Arc<OutputCache>>,
) -> ClientResult<BackendStream> {
    let input = verified_fetch_input(&request)?;
    let mut recording = None;
    if let Some(cache) = cache
        && let Some(key) = CacheKey::fetch_for_policy(
            cache.policy,
            input.execution_environment,
            &input.service,
            &input.method,
            input.body.as_bytes(),
        )
        .map_err(cache_error)?
    {
        if let Some(entry) = cache.read(key.clone()).await? {
            return Ok(replay(entry));
        }
        let guard = cache.acquire(&key).await?;
        if let Some(entry) = cache.read(key.clone()).await? {
            return Ok(replay(entry));
        }
        recording = Some((cache, key, guard));
    }
    let route = route.ok_or_else(|| cache_error("no Fetch route on cache miss"))?;
    let provenance = Some(Provenance {
        call_commitment: Some(input.input_commitment.digest().to_string()),
    });
    let events = async_stream::try_stream! {
        let stream = crate::iroh::fetch_execution_stream(runtime, request, route, runner_key);
        tokio::pin!(stream);
        while let Some(event) = stream.next().await {
            match event? {
                FetchExecutionEvent::Chunk { event, .. } => yield event,
                FetchExecutionEvent::Done(FetchOutcome::Completed { terminal, .. }) => {
                    yield terminal.to_output_event();
                    return;
                }
                FetchExecutionEvent::Done(FetchOutcome::Failed { position, error }) => {
                    Err(cache_error(format!("Fetch failed at {position}: {error}")))?;
                }
            }
        }
        Err(cache_error("Fetch stream ended without terminal outcome"))?;
    }
    .boxed();
    let events = match recording {
        Some((cache, key, guard)) => cache.record(key, provenance.clone(), events, guard),
        None => events,
    };
    Ok(BackendStream::new(
        events.map(|event| event.map_err(backend_error)),
        provenance,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{CachePolicy, CacheStore, MemoryCacheStore, Transcript};
    use hellas_rpc::fetch::build_input_events;
    use hellas_rpc::output::{OutputEvent, StopReason, ToolCallEnd, ToolCallStart};
    use hellas_rpc::stream::input_event_to_pb;

    #[tokio::test]
    async fn replay_preserves_tool_calls_and_original_provenance_without_a_route() {
        let environment = hellas_rpc::FetchEnvironment::OpenAiResponses.manifest_id();
        let payload = br#"{"input":"hello"}"#;
        let key = CacheKey::fetch(environment, "openai", "responses", payload).unwrap();
        let events = vec![
            OutputEvent::ToolCallStart(ToolCallStart {
                index: 0,
                id: Some("call-recorded".into()),
                name: "write".into(),
            }),
            OutputEvent::ToolCallEnd(ToolCallEnd {
                index: 0,
                arguments: serde_json::json!({"path": "result.txt"}),
            }),
            OutputEvent::Finished {
                stop_reason: StopReason::ToolCall,
                usage: None,
            },
        ];
        let transcript = Transcript {
            version: 1,
            key: key.clone(),
            initial_provenance: Some(Provenance {
                call_commitment: Some("original".into()),
            }),
            events: events.clone(),
        };
        let store = Arc::new(MemoryCacheStore::default());
        store
            .insert(&key, &serde_ipld_dagcbor::to_vec(&transcript).unwrap(), 0)
            .unwrap();
        let cache = Arc::new(OutputCache::new(CachePolicy::ReplayOnly, store));
        for caller in [1, 2] {
            let key = Arc::new(ProducerSigningKey::from_secret_bytes([caller; 32]).unwrap());
            let input = build_input_events(
                "openai",
                "responses",
                payload,
                environment,
                hellas_rpc::Assurance::ProducerSigned,
                &key,
            )
            .unwrap();
            let stream = fetch_output_stream(
                ExecutionRuntime::<()>::default(),
                FetchRequest {
                    input: input.iter().map(input_event_to_pb).collect(),
                },
                None,
                key,
                Some(cache.clone()),
            )
            .await
            .unwrap();
            assert_eq!(stream.initial_provenance, transcript.initial_provenance);
            assert_eq!(
                stream.events.map(Result::unwrap).collect::<Vec<_>>().await,
                events
            );
        }
    }

    #[tokio::test]
    async fn record_bypasses_unknown_environment_and_reaches_route_selection() {
        let signer = Arc::new(ProducerSigningKey::from_secret_bytes([1; 32]).unwrap());
        let input = build_input_events(
            "shell",
            "run",
            br#"{"command":"one"}"#,
            hellas_rpc::ContentId::from_bytes([0; 32]),
            hellas_rpc::Assurance::ProducerSigned,
            &signer,
        )
        .unwrap();
        let error = fetch_output_stream(
            ExecutionRuntime::<()>::default(),
            FetchRequest {
                input: input.iter().map(input_event_to_pb).collect(),
            },
            None,
            signer,
            Some(Arc::new(OutputCache::new(
                CachePolicy::Record,
                Arc::new(MemoryCacheStore::default()),
            ))),
        )
        .await
        .err()
        .unwrap();
        assert!(error.to_string().contains("no Fetch route"), "{error}");
    }

    #[test]
    fn fetch_identity_separates_routes_and_bodies_and_rejects_unknown_environments() {
        let environment = hellas_rpc::FetchEnvironment::OpenAiResponses.manifest_id();
        let key = CacheKey::fetch(environment, "openai", "responses", b"one").unwrap();
        assert_ne!(
            key,
            CacheKey::fetch(environment, "other", "responses", b"one").unwrap()
        );
        assert_ne!(
            key,
            CacheKey::fetch(environment, "openai", "responses", b"two").unwrap()
        );
        assert_ne!(
            key,
            CacheKey::fetch(
                hellas_rpc::FetchEnvironment::CodexResponses.manifest_id(),
                "openai",
                "responses",
                b"one"
            )
            .unwrap()
        );
        assert!(
            CacheKey::fetch(
                hellas_rpc::ContentId::from_bytes([0; 32]),
                "shell",
                "run",
                b"one"
            )
            .is_err()
        );
    }
}
