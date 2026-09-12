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
    config
        .validate_invocation_resources(
            &Invocation {
                input_ids: vec![1, 2],
                max_new_tokens: 5,
                stop_token_ids: vec![],
            },
            &[4, 8],
            4,
        )
        .unwrap();
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
