use super::*;
use hellas_rpc::{Assurance, Digest};

#[test]
fn gpu_configuration_is_bounded() {
    let one = Duration::from_secs(1);
    assert!(GpuConfig::new(0, 1, 1, 1, one, one).is_err());
    assert!(GpuConfig::new(1, 0, 1, 1, one, one).is_err());
    assert!(GpuConfig::new(1, 1, 0, 1, one, one).is_err());
    assert!(GpuConfig::new(1, 1, 1, 0, one, one).is_err());
    assert!(GpuConfig::new(1, 1, 1, 1, Duration::ZERO, one).is_err());
    assert!(GpuConfig::new(1, 1, 1, 1, one, Duration::ZERO).is_err());
    assert!(GpuConfig::new(1, 1, MAX_GPU_GENERATION_CAPACITY + 1, 1, one, one).is_err());
    assert!(GpuConfig::new(1, MAX_RESIDENT_ASSET_BYTES + 1, 1, 1, one, one).is_err());
    assert!(
        GpuConfig::new(1, MAX_RESIDENT_ASSET_BYTES, 1, 1, one, one).is_ok(),
        "Catena's exact session asset-byte ceiling remains configurable"
    );

    let config = GpuConfig::new(
        3,
        5,
        7,
        11,
        Duration::from_secs(13),
        Duration::from_secs(17),
    )
    .unwrap();
    assert_eq!(config.session_programs(), 3);
    assert_eq!(config.session_asset_bytes(), 5);
    assert_eq!(config.max_generation_capacity(), 7);
    assert_eq!(config.max_generation_device_bytes(), 11);
    assert_eq!(config.compile_timeout(), Duration::from_secs(13));
    assert_eq!(config.execution_timeout(), Duration::from_secs(17));
    assert!(GpuConfig::new(1, 1, MAX_GPU_GENERATION_CAPACITY, 1, one, one).is_ok());
}

#[test]
fn generation_resource_limits_use_checked_arithmetic() {
    assert_eq!(MAX_CAUSAL_LM_STATIC_BYTES, MAX_MODEL_STATIC_BYTES);
    validate_static_input_bytes([MAX_MODEL_STATIC_BYTES]).unwrap();
    assert!(validate_static_input_bytes([MAX_MODEL_STATIC_BYTES, 1]).is_err());
    assert!(validate_static_input_bytes([u64::MAX, 1]).is_err());

    let config =
        GpuConfig::new(1, 1, 7, 164, Duration::from_secs(1), Duration::from_secs(1)).unwrap();
    assert_eq!(minimum_generation_device_bytes(&[4, 8], 7, 4), Ok(164));
    validate_generation_limits(config, 7, &[4, 8], 4).unwrap();
    assert!(validate_generation_limits(config, 8, &[4], 4).is_err());

    let one_byte_below_required =
        GpuConfig::new(1, 1, 7, 163, Duration::from_secs(1), Duration::from_secs(1)).unwrap();
    let error = validate_generation_limits(one_byte_below_required, 7, &[4, 8], 4)
        .expect_err("one byte below Catena's floor must be rejected");
    assert!(error.contains("164 minimum generation device bytes"));

    let overflow_envelope = GpuConfig::new(
        1,
        1,
        MAX_GPU_GENERATION_CAPACITY,
        u64::MAX,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .unwrap();
    assert!(
        validate_generation_limits(
            overflow_envelope,
            MAX_GPU_GENERATION_CAPACITY,
            &[u64::MAX],
            1,
        )
        .is_err()
    );
    assert!(
        validate_generation_limits(
            overflow_envelope,
            MAX_GPU_GENERATION_CAPACITY,
            &[u64::MAX / 2, u64::MAX / 2],
            1,
        )
        .is_err()
    );
    assert!(validate_generation_limits(overflow_envelope, 1, &[], u64::MAX).is_err());
    assert!(validate_generation_limits(overflow_envelope, 1, &[u64::MAX], 1).is_err());
}

#[test]
fn fixed_schedule_is_charged_before_generation_and_rejects_excess_tokens() {
    let environment = CausalLmEnvironment::new(
        ContentRef::new(ContentId::from_bytes([1; 32]), 1),
        "model",
        vec![],
        vec![],
        vec![4],
        16,
        16,
        hellas_rpc::CausalLmGenerationSchedule {
            fixed_capacity: 16,
            prefill_chunk_tokens: 2,
        },
    )
    .unwrap();
    let invocation = Invocation {
        input_ids: vec![1, 2],
        max_new_tokens: 2,
        stop_token_ids: vec![],
    };
    let one = Duration::from_secs(1);
    let limited_capacity = GpuConfig::new(1, 1, 4, 4096, one, one).unwrap();
    assert!(
        limited_capacity
            .validate_environment_invocation_resources(&invocation, &environment)
            .is_err()
    );
    let limited_bytes = GpuConfig::new(1, 1, 16, 120, one, one).unwrap();
    assert!(
        limited_bytes
            .validate_environment_invocation_resources(&invocation, &environment)
            .is_err()
    );
    let sufficient = GpuConfig::new(1, 1, 16, 4096, one, one).unwrap();
    sufficient
        .validate_environment_invocation_resources(&invocation, &environment)
        .unwrap();
    let oversized = Invocation {
        max_new_tokens: 15,
        ..invocation
    };
    assert!(
        sufficient
            .validate_environment_invocation_resources(&oversized, &environment)
            .is_err()
    );
}

#[test]
fn session_program_and_asset_limits_recycle_before_runtime_rejection() {
    let one = Duration::from_secs(1);
    let config = GpuConfig::new(1, 10, 1, 1, one, one).unwrap();
    let at_program_limit = SessionUsage {
        programs: 1,
        assets: 0,
        asset_bytes: 0,
    };
    let no_missing_assets = MissingAssets { count: 0, bytes: 0 };
    assert!(!session_requires_recycle(
        true,
        at_program_limit,
        no_missing_assets,
        config
    ));
    assert!(session_requires_recycle(
        false,
        at_program_limit,
        no_missing_assets,
        config
    ));
    assert!(!session_requires_recycle(
        true,
        SessionUsage {
            asset_bytes: 8,
            ..at_program_limit
        },
        MissingAssets { count: 0, bytes: 2 },
        config
    ));
    assert!(session_requires_recycle(
        true,
        SessionUsage {
            asset_bytes: 8,
            ..at_program_limit
        },
        MissingAssets { count: 0, bytes: 3 },
        config
    ));
    let just_below_asset_limit = SessionUsage {
        assets: MAX_RESIDENT_ASSETS - 1,
        ..at_program_limit
    };
    assert!(!session_requires_recycle(
        true,
        just_below_asset_limit,
        MissingAssets { count: 1, bytes: 0 },
        config
    ));
    assert!(session_requires_recycle(
        true,
        just_below_asset_limit,
        MissingAssets { count: 2, bytes: 0 },
        config
    ));

    let mut programs = ExactContentCache::default();
    let id = ContentId::from_bytes([9; 32]);
    programs.insert(ContentRef::new(id, 10), ());
    assert!(programs.get(ContentRef::new(id, 11)).is_err());
}

#[test]
fn program_pressure_preserves_assets_but_asset_pressure_resets_owner() {
    let one = Duration::from_secs(1);
    let config = GpuConfig::new(1, 10, 1, 1, one, one).unwrap();
    let resident = SessionUsage {
        programs: 1,
        assets: 1,
        asset_bytes: 8,
    };
    let no_missing = MissingAssets { count: 0, bytes: 0 };
    assert!(session_requires_recycle(
        false, resident, no_missing, config
    ));
    assert!(!asset_owner_requires_recycle(
        resident.assets,
        resident.asset_bytes,
        no_missing,
        config,
    ));
    assert!(asset_owner_requires_recycle(
        resident.assets,
        resident.asset_bytes,
        MissingAssets { count: 1, bytes: 3 },
        config,
    ));
    assert!(asset_owner_requires_recycle(
        MAX_RESIDENT_ASSETS,
        0,
        MissingAssets { count: 1, bytes: 0 },
        config,
    ));
    assert!(asset_owner_requires_recycle(
        0,
        u64::MAX,
        MissingAssets { count: 0, bytes: 1 },
        config,
    ));
}

#[test]
fn a_stalled_consumer_fails_instead_of_blocking_the_worker() {
    let producer_key = ProducerSigningKey::from_secret_bytes([7; 32]).unwrap();
    let request = EvaluateRequest {
        text_execution: Digest::from_bytes([1; 32]),
        runner_public_key: producer_key.public_key(),
        execution_environment: ContentId::from_bytes([2; 32]),
        nonce: [3; 32],
        assurance: Assurance::ProducerSigned,
        retain: false,
    };
    let mut builder = EvaluateOutputTranscriptBuilder::new(
        input_commitment(&request),
        request.assurance,
        &producer_key,
    );
    let mut output_events = Vec::new();
    let mut position = 0;
    let (sender, mut receiver) = tokio_mpsc::channel(2);
    let terminal_sender = sender.clone();
    let mut progress = make_on_progress(
        &mut position,
        sender,
        "test-execution".to_string(),
        &mut builder,
        &mut output_events,
    );

    progress(11).unwrap();
    let error = progress(12).expect_err("the full channel must not block");
    assert!(matches!(error, crate::ExecutorError::Execution(_)));
    drop(progress);
    assert_eq!(position, 1);
    terminal_sender
        .try_send(Ok(PbWorkEvent { kind: None }))
        .expect("progress always preserves the actor's terminal slot");
    assert!(matches!(
        receiver.try_recv().unwrap().unwrap().kind,
        Some(PbEvent::Chunk(_))
    ));
    assert!(receiver.try_recv().unwrap().unwrap().kind.is_none());
}

#[cfg(feature = "otel")]
#[test]
fn inference_telemetry_records_typed_outcomes_and_success_only_token_timings() {
    use opentelemetry::metrics::MeterProvider;
    use opentelemetry::trace::{SpanKind, Status, TracerProvider};
    use opentelemetry::{Array, Value};
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, SdkMeterProvider};
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
    use tracing_subscriber::prelude::*;

    let metric_exporter = InMemoryMetricExporter::default();
    let meter_provider = SdkMeterProvider::builder()
        .with_periodic_exporter(metric_exporter.clone())
        .build();
    let metrics = InferenceMetrics::from_meter(meter_provider.meter("test"));
    let span_exporter = InMemorySpanExporter::default();
    let tracer_provider = SdkTracerProvider::builder()
        .with_simple_exporter(span_exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("test")));
    tracing::subscriber::with_default(subscriber, || {
        // Queue time is included in server duration/TTFT, but excluded from
        // decoding time per output token. No GPU, sleeps or global SDK needed.
        let accepted = Instant::now() - Duration::from_secs(2);
        let mut completed = metrics.start(&tracing::Span::none(), accepted, 12, 2);
        completed.token_generated();
        completed.token_generated();
        completed.cache_stats(8, 1);
        completed.succeeded(StopReason::MaxNewTokens, 2);

        let mut one_token = metrics.start(&tracing::Span::none(), accepted, 12, 2);
        one_token.token_generated();
        one_token.succeeded(StopReason::StopToken(99), 1);
        metrics
            .start(&tracing::Span::none(), accepted, 12, 2)
            .succeeded(StopReason::StopToken(99), 0);

        // A partial response is still a failed invocation: no successful token
        // timings, no raw error text, no inferred final output count.
        let mut failed = metrics.start(&tracing::Span::none(), accepted, 12, 2);
        failed.token_generated();
        failed.failed(&crate::ExecutorError::Execution(
            "sensitive error text".into(),
        ));
        metrics
            .start(&tracing::Span::none(), accepted, 12, 2)
            .panicked();
    });
    tracer_provider.force_flush().unwrap();
    meter_provider.force_flush().unwrap();
    let spans = span_exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 5);
    let attribute = |index: usize, key: &str| {
        spans[index]
            .attributes
            .iter()
            .find(|kv| kv.key.as_str() == key)
            .map(|kv| kv.value.clone())
    };
    for span in &spans {
        assert_eq!(span.name, "text_completion");
        assert_eq!(span.span_kind, SpanKind::Internal);
        assert!(span.events.is_empty());
        assert!(span.attributes.iter().all(|kv| {
            kv.key.as_str() != "gen_ai.request.model"
                && !kv.key.as_str().starts_with("hellas.reused")
                && !kv.value.to_string().contains("sensitive error text")
        }));
    }
    assert_eq!(
        attribute(0, "gen_ai.usage.input_tokens"),
        Some(Value::I64(12))
    );
    assert_eq!(
        attribute(0, "gen_ai.usage.cache_read.input_tokens"),
        Some(Value::I64(8))
    );
    assert_eq!(
        attribute(0, "gen_ai.usage.output_tokens"),
        Some(Value::I64(2))
    );
    for (index, reason) in ["length", "stop", "stop", "error", "error"]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            attribute(index, "gen_ai.response.finish_reasons"),
            Some(Value::Array(Array::String(vec![reason.into()])))
        );
    }
    assert_eq!(spans[0].status, Status::Unset);
    assert!(matches!(spans[3].status, Status::Error { .. }));
    assert!(matches!(spans[4].status, Status::Error { .. }));
    assert_eq!(
        attribute(3, "error.type"),
        Some(Value::from("execution_error"))
    );
    assert_eq!(attribute(4, "error.type"), Some(Value::from("panic")));
    assert!(attribute(3, "gen_ai.usage.output_tokens").is_none());
    assert!(attribute(3, "gen_ai.response.time_to_first_chunk").is_none());

    let exported = metric_exporter.get_finished_metrics().unwrap();
    let exported = exported
        .iter()
        .flat_map(|r| r.scope_metrics())
        .flat_map(|s| s.metrics())
        .collect::<Vec<_>>();
    assert_eq!(exported.len(), 3);
    for metric in exported {
        assert_eq!(metric.unit(), "s");
        let AggregatedMetrics::F64(MetricData::Histogram(histogram)) = metric.data() else {
            panic!("expected seconds histogram");
        };
        let points = histogram.data_points().collect::<Vec<_>>();
        let count = points.iter().map(|point| point.count()).sum::<u64>();
        match metric.name() {
            "gen_ai.server.request.duration" => {
                assert_eq!(count, 5);
                assert_eq!(points.len(), 3, "success, execution error, panic");
                assert!(
                    points
                        .iter()
                        .all(|point| point.sum() >= 2.0 * point.count() as f64)
                );
            }
            "gen_ai.server.time_to_first_token" => {
                assert_eq!(count, 2, "exclude zero-token and failed responses");
                assert_eq!(points.len(), 1);
                assert!(points[0].sum() >= 4.0);
            }
            "gen_ai.server.time_per_output_token" => {
                assert_eq!(count, 1, "require at least two successful output tokens");
                assert_eq!(points.len(), 1);
            }
            name => panic!("unexpected metric {name}"),
        }
        for point in points {
            assert!(
                point
                    .attributes()
                    .any(|kv| kv.key.as_str() == "gen_ai.operation.name"
                        && kv.value == Value::from("text_completion"))
            );
            assert!(
                point
                    .attributes()
                    .any(|kv| kv.key.as_str() == "gen_ai.provider.name"
                        && kv.value == Value::from("hellas"))
            );
        }
    }
    tracer_provider.shutdown().unwrap();
    meter_provider.shutdown().unwrap();
}
