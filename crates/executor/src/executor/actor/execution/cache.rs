//! Reuse inference payloads, not request-bound signatures. Admission and
//! authorization still run for each ticket; replay authenticates the original
//! transcript against this producer before signing one for the new ticket.

use hellas_rpc::cache::{CacheKey, CacheLocks, CacheOptions, CachePolicy, Transcript};
use hellas_rpc::fetch::{
    decode_fetch_event_payload, encode_fetch_event_payload, encode_fetch_terminal_payload,
};
use hellas_rpc::output::{OutputEvent, Provenance};
use serde::{Deserialize, Serialize};

use crate::fetch::FetchQuote;

use super::*;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Recording {
    // Keep the client-readable projection, but never use it as signing authority.
    #[serde(flatten)]
    transcript: Transcript<OutputEvent, Provenance>,
    signed: FetchTranscript,
}

pub(in crate::executor) struct FetchCache {
    options: CacheOptions,
    locks: CacheLocks<tokio::sync::Mutex<()>>,
}

impl FetchCache {
    pub(super) fn policy(&self) -> CachePolicy {
        self.options.policy
    }
    pub(in crate::executor) fn open(
        options: CacheOptions,
    ) -> Result<Option<Arc<Self>>, ExecutorError> {
        if options.policy == CachePolicy::Off {
            return Ok(None);
        }
        if options.store.is_none() {
            return Err(ExecutorError::ArtifactStore(
                "enabled inference cache requires a store".into(),
            ));
        }
        Ok(Some(Arc::new(Self {
            options,
            locks: CacheLocks::default(),
        })))
    }
}

pub(in crate::executor) struct FetchCacheRequest {
    cache: Arc<FetchCache>,
    key: CacheKey,
    quote: FetchQuote,
    recording: Option<hellas_rpc::cache::CacheRecording>,
}

impl FetchCacheRequest {
    pub(super) fn new(
        cache: Arc<FetchCache>,
        key: CacheKey,
        quote: FetchQuote,
    ) -> hellas_rpc::cache::CacheResult<Self> {
        let recording = cache.options.recording()?;
        Ok(Self {
            cache,
            key,
            quote,
            recording,
        })
    }

    pub(super) async fn read(
        &self,
    ) -> Result<(Option<Recording>, tokio::sync::OwnedMutexGuard<()>), FetchProviderFailure> {
        let guard = self.cache.locks.for_key(&self.key).lock_owned().await;
        let store = self.cache.options.store.clone().expect("validated store");
        let key = self.key.clone();
        let bytes = tokio::task::spawn_blocking(move || store.get(&key))
            .await
            .map_err(failure)?
            .map_err(failure)?;
        let recording = match bytes {
            Some(bytes) => {
                let recording: Recording =
                    serde_ipld_dagcbor::from_slice(&bytes).map_err(failure)?;
                recording
                    .transcript
                    .validate(&self.key, OutputEvent::terminal)
                    .map_err(failure)?;
                Some(recording)
            }
            None if self.cache.options.policy == CachePolicy::ReplayOnly => {
                return Err(failure(format!("replay miss: fetch/{}", self.key.identity)));
            }
            None => None,
        };
        Ok((recording, guard))
    }

    pub(super) async fn record(&self, run: &FetchProviderRun) -> Result<(), FetchProviderFailure> {
        if self.cache.options.policy != CachePolicy::Record {
            return Ok(());
        }
        let (last, prefix) = run
            .output_events
            .split_last()
            .ok_or_else(|| failure("empty output"))?;
        let mut events = prefix
            .iter()
            .map(|event| decode_fetch_event_payload(event.payload()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(failure)?;
        events.push(
            decode_fetch_terminal_payload(last.payload())
                .map_err(failure)?
                .to_output_event(),
        );
        let recording = Recording {
            transcript: Transcript {
                version: 1,
                key: self.key.clone(),
                initial_provenance: Some(Provenance {
                    call_commitment: Some(self.quote.input_commitment.digest().to_string()),
                }),
                events,
            },
            signed: FetchTranscript::from_quote(&self.quote, run.output_events.clone()),
        };
        recording
            .transcript
            .validate(&self.key, OutputEvent::terminal)
            .map_err(failure)?;
        let bytes = serde_ipld_dagcbor::to_vec(&recording).map_err(failure)?;
        let recording = self.recording.clone().expect("recording cache");
        let key = self.key.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(failure)?
            .as_secs();
        tokio::task::spawn_blocking(move || recording.insert(&key, &bytes, now))
            .await
            .map_err(failure)?
            .map_err(failure)
    }
}

pub(super) async fn replay(
    recording: Recording,
    input: InputCommitment,
    assurance: hellas_rpc::Assurance,
    producer_key: &ProducerSigningKey,
    sender: &mpsc::Sender<Result<WorkEvent, hellas_wire::WireStatus>>,
) -> Result<FetchProviderRun, FetchProviderFailure> {
    let original = recording
        .signed
        .verify(&producer_key.public_key())
        .map_err(failure)?;
    let key = CacheKey::fetch(
        original.execution_environment,
        &original.service,
        &original.method,
        original.body.as_bytes(),
    )
    .map_err(failure)?;
    recording
        .transcript
        .validate(&key, OutputEvent::terminal)
        .map_err(failure)?;
    if original.assurance != assurance {
        return Err(failure(
            "cached assurance does not match requested assurance",
        ));
    }
    if recording
        .transcript
        .initial_provenance
        .as_ref()
        .and_then(|p| p.call_commitment.as_deref())
        != Some(original.input_commitment.digest().to_string().as_str())
    {
        return Err(failure(
            "cached input commitment disagrees with its signed transcript",
        ));
    }
    let mut builder = FetchOutputTranscriptBuilder::new(input, assurance, producer_key);
    let mut terminal = None;
    let mut budget = FetchProjectionBudget::default();
    let mut position = 0;
    // Encode and validate the entire recording before emitting any prefix.
    let projected = recording
        .transcript
        .events
        .iter()
        .map(|event| {
            if matches!(event, OutputEvent::Finished { .. }) {
                encode_fetch_terminal_payload(event).map(ProjectedFetch::Terminal)
            } else {
                encode_fetch_event_payload(event).map(ProjectedFetch::Event)
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(failure)?;
    let signed = recording.signed.into_output_events();
    if !projected.iter().zip(&signed).all(|(event, signed)| {
        let payload = match event {
            ProjectedFetch::Event(payload) | ProjectedFetch::Terminal(payload) => payload,
        };
        payload == signed.payload()
    }) || projected.len() != signed.len()
    {
        return Err(failure(
            "cached output disagrees with its signed transcript",
        ));
    }
    process_projected_fetch(
        projected,
        &mut builder,
        &mut terminal,
        &mut budget,
        &mut position,
        sender,
    )
    .await?;
    let output_events = builder
        .finish(terminal.ok_or_else(|| failure("missing terminal"))?)
        .map_err(failure)?;
    Ok(FetchProviderRun {
        output_events,
        position,
    })
}

fn failure(error: impl std::fmt::Display) -> FetchProviderFailure {
    FetchProviderFailure {
        position: 0,
        error: FetchProviderError::failed(format!("inference cache: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::cache::{CacheStore, MemoryCacheStore};
    use hellas_rpc::fetch::{build_input_events, verify_input_events};
    use hellas_rpc::output::StopReason;
    use hellas_rpc::output::TextChannel;
    use hellas_rpc::{Assurance, FetchEnvironment};

    async fn recorded_request(
        producer: &ProducerSigningKey,
        store: Arc<MemoryCacheStore>,
    ) -> FetchCacheRequest {
        let input = build_input_events(
            "openai",
            "responses",
            br#"{"input":"hello"}"#,
            FetchEnvironment::OpenAiResponses.manifest_id(),
            Assurance::ProducerSigned,
            producer,
        )
        .unwrap();
        let verified = verify_input_events(&input).unwrap();
        let quote = FetchQuote::from_verified(&verified, input);
        let key = CacheKey::fetch(
            verified.execution_environment,
            &verified.service,
            &verified.method,
            verified.body.as_bytes(),
        )
        .unwrap();
        let request = FetchCacheRequest::new(
            FetchCache::open(CacheOptions {
                policy: CachePolicy::Record,
                store: Some(store),
            })
            .unwrap()
            .unwrap(),
            key,
            quote,
        )
        .unwrap();
        let mut output = FetchOutputTranscriptBuilder::new(
            verified.input_commitment,
            verified.assurance,
            producer,
        );
        let payload = encode_fetch_event_payload(&OutputEvent::TextDelta {
            index: 0,
            delta: "recorded".into(),
            channel: TextChannel::Output,
        })
        .unwrap();
        let position = payload.len() as u64;
        output.push_event(payload).unwrap();
        let terminal = encode_fetch_terminal_payload(&OutputEvent::Finished {
            stop_reason: StopReason::EndOfText,
            usage: None,
        })
        .unwrap();
        request
            .record(&FetchProviderRun {
                output_events: output.finish(terminal).unwrap(),
                position,
            })
            .await
            .unwrap_or_else(|err| panic!("{}", err.error));
        request
    }

    #[tokio::test]
    async fn reset_prevents_an_old_fetch_request_from_repopulating_the_index() {
        let producer = ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
        let store = Arc::new(MemoryCacheStore::default());
        let request = recorded_request(&producer, store.clone()).await;
        let bytes = store.get(&request.key).unwrap().unwrap();
        let recording: Recording = serde_ipld_dagcbor::from_slice(&bytes).unwrap();
        store
            .evict(&hellas_rpc::cache::Eviction::default())
            .unwrap();
        request
            .record(&FetchProviderRun {
                output_events: recording.signed.into_output_events(),
                position: 0,
            })
            .await
            .unwrap_or_else(|err| panic!("{}", err.error));
        assert!(store.list().unwrap().is_empty());
        recorded_request(&producer, store.clone()).await;
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unauthenticated_fetch_cache_fails_before_emitting_any_output() {
        let producer = ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
        let store = Arc::new(MemoryCacheStore::default());
        let request = recorded_request(&producer, store.clone()).await;
        let bytes = store.get(&request.key).unwrap().unwrap();
        let original: Recording = serde_ipld_dagcbor::from_slice(&bytes).unwrap();
        // Executor evidence is additive: client/CLI readers keep their projection.
        let projection: Transcript<OutputEvent, Provenance> =
            serde_ipld_dagcbor::from_slice(&bytes).unwrap();
        assert_eq!(projection.events, original.transcript.events);

        let mut cases = Vec::new();
        let mut missing = original.clone();
        missing.signed = FetchTranscript::from_quote(&request.quote, Vec::new());
        cases.push(("missing signatures", missing));

        let attacker = ProducerSigningKey::from_secret_bytes([8; 32]).unwrap();
        let mut forged = FetchOutputTranscriptBuilder::new(
            request.quote.input_commitment,
            request.quote.assurance,
            &attacker,
        );
        let (last, prefix) = original.signed.output_events().split_last().unwrap();
        for event in prefix {
            forged.push_event(event.payload()).unwrap();
        }
        let mut foreign = original.clone();
        foreign.signed =
            FetchTranscript::from_quote(&request.quote, forged.finish(last.payload()).unwrap());
        cases.push(("different producer", foreign));

        let mut corrupt = original.clone();
        let mut output = corrupt.signed.into_output_events();
        let mut envelope = output_event_to_pb(&output[0]);
        envelope.signature = Some(hellas_rpc::run_ticket::signature_to_pb(
            &hellas_rpc::Signature::Secp256k1([0; 64]),
        ));
        output[0] = hellas_rpc::stream::output_event_from_pb(envelope).unwrap();
        corrupt.signed = FetchTranscript::from_quote(&request.quote, output);
        cases.push(("corrupt signature", corrupt));

        let mut changed_input = original.clone();
        changed_input.signed = FetchTranscript::new(
            InputCommitment::from_digest(Digest::from_bytes([99; 32])),
            request.quote.input.clone(),
            original.signed.output_events().to_vec(),
        );
        cases.push(("different input commitment", changed_input));

        let mut transplanted = original.clone();
        transplanted.transcript.key = CacheKey::fetch(
            FetchEnvironment::OpenAiResponses.manifest_id(),
            "openai",
            "responses",
            br#"{"input":"different"}"#,
        )
        .unwrap();
        cases.push(("different inference identity", transplanted));

        let mut unsigned = original.clone();
        unsigned.transcript.events[0] = OutputEvent::TextDelta {
            index: 0,
            delta: "forged".into(),
            channel: TextChannel::Output,
        };
        cases.push(("rewritten decoded payload", unsigned));

        let mut unsigned_terminal = original.clone();
        *unsigned_terminal.transcript.events.last_mut().unwrap() = OutputEvent::Finished {
            stop_reason: StopReason::MaxOutputTokens,
            usage: None,
        };
        cases.push(("rewritten terminal", unsigned_terminal));

        for (name, recording) in cases {
            let key = recording.transcript.key.clone();
            store.remove(&key).unwrap();
            store
                .insert(&key, &serde_ipld_dagcbor::to_vec(&recording).unwrap(), 0)
                .unwrap();
            for policy in [CachePolicy::Record, CachePolicy::ReplayOnly] {
                let lookup = FetchCacheRequest::new(
                    FetchCache::open(CacheOptions {
                        policy,
                        store: Some(store.clone()),
                    })
                    .unwrap()
                    .unwrap(),
                    key.clone(),
                    request.quote.clone(),
                )
                .unwrap();
                let (recording, _guard) = lookup
                    .read()
                    .await
                    .unwrap_or_else(|err| panic!("{}", err.error));
                let (sender, mut receiver) = mpsc::channel(4);
                assert!(
                    replay(
                        recording.unwrap(),
                        InputCommitment::from_digest(Digest::from_bytes([42; 32])),
                        Assurance::ProducerSigned,
                        &producer,
                        &sender,
                    )
                    .await
                    .is_err(),
                    "{name}: accepted in {policy:?}"
                );
                assert!(
                    matches!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
                    "{name}: emitted unauthenticated output"
                );
            }
        }

        let (sender, mut receiver) = mpsc::channel(4);
        assert!(
            replay(
                original.clone(),
                request.quote.input_commitment,
                Assurance::AppleAppAttest,
                &producer,
                &sender,
            )
            .await
            .is_err()
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        // Old client-only recordings cannot authorize executor re-signing.
        store.remove(&request.key).unwrap();
        store
            .insert(
                &request.key,
                &serde_ipld_dagcbor::to_vec(&original.transcript).unwrap(),
                0,
            )
            .unwrap();
        assert!(request.read().await.is_err());
    }
}
