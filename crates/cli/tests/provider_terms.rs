//! Provider terms must admit the client-rendered programs they are meant to
//! sell. Client model code lives here, outside the provider source tree.

#[tokio::test]
async fn faucet_upload_terms_admit_a_fresh_whisper_program_and_features() {
    use hellas_client::model::{ModelPackage, ModelRequest};
    use hellas_store::content::{
        ContentStore as _, DiskStore, IndexMode, JobId, PinName, PinPolicy, PinValue, Reservations,
        Scope, Target,
    };
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/src/model/whisper/mini");
    let model = ModelPackage::open(
        &fixture,
        &hellas_client::model::evaluator(hellas_client::model::GpuDialect::Hip),
    )
    .await
    .unwrap();
    let job = model
        .render_job(&ModelRequest::Transcription {
            samples: &[0.; 400],
            language: Some("en"),
            max_new_tokens: 4,
        })
        .await
        .unwrap();
    let example: toml::Value =
        toml::from_str(include_str!("../../../docs/examples/faucet-provider.toml")).unwrap();
    let limits: hellas_rpc::protocol::invocation::Limits =
        example["limits"].clone().try_into().unwrap();
    let inputs = job
        .inputs
        .iter()
        .map(|a| {
            (
                a.name.clone(),
                hellas_rpc::ContentRef::for_bytes(a.bytes.as_bytes()),
            )
        })
        .collect();
    let root = tempfile::tempdir().unwrap();
    let node = DiskStore::open(
        hellas_private::StoreLocation::for_test(&root.path().join("content")),
        vec![fixture],
        IndexMode::Resume,
        None,
        Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
        false,
    )
    .await
    .unwrap();
    node.finish_recovery().await.unwrap();
    for asset in &job.environment.assets {
        node.set_pin(
            &Scope::Owner,
            &PinName::new(format!("config/{}", asset.name)).unwrap(),
            None,
            Some(PinValue {
                target: Target::Object(asset.object),
                policy: PinPolicy::Jobs,
                expires: None,
            }),
        )
        .await
        .unwrap();
    }
    let mut closure = vec![hellas_rpc::ContentRef::for_bytes(
        &job.environment.canonical_bytes().unwrap(),
    )];
    closure.extend(job.environment.sources.iter().copied());
    closure.extend(job.environment.assets.iter().map(|asset| asset.object));
    let inputs: std::collections::BTreeMap<_, _> = inputs;
    closure.extend(inputs.values().copied());
    hellas_executor::catena::validate::preflight(&job.environment, &inputs, &job.plan, &limits)
        .unwrap();
    // The generic `compute` resource a plain `serve --program` offers admits it too.
    let compute = hellas_sdk::grant_config::GrantConfig::compute(
        &hellas_private::StoreLocation::for_test(root.path()),
        hellas_rpc::protocol::invocation::Admission::Compute {
            evaluator: hellas_client::model::evaluator(hellas_client::model::GpuDialect::Hip),
            programs: hellas_rpc::protocol::invocation::ComputePrograms::Any {},
        },
    )
    .unwrap();
    let generic = compute.configuration.resources()[0]
        .invocation_policy
        .limits;
    assert!(generic.max_upload_bytes >= limits.max_upload_bytes);
    hellas_executor::catena::validate::preflight(&job.environment, &inputs, &job.plan, &generic)
        .unwrap();
    let id = JobId {
        channel: hellas_auth::Digest::hash(b"faucet channel"),
        id: hellas_auth::Digest::hash(b"faucet job"),
    };
    // The real reservation charges fresh program/root/features, while a
    // readable Jobs pin supplies provider-held weights without charging uploads.
    let scope = node
        .open_work(id, closure.clone(), limits.max_upload_bytes)
        .await
        .unwrap();
    node.end_work(&scope).await.unwrap();
    assert!(matches!(
        node.open_work(id, closure, 1 << 20).await,
        Err(hellas_store::content::Error::Capacity)
    ));
    node.close().await;
}

/// Terms that admit any program are served only when the operator says
/// `--knowingly-unsafe`; the flag itself admits nothing.
#[test]
fn serve_refuses_terms_admitting_any_program_without_the_acknowledgement() {
    let home = tempfile::tempdir().unwrap();
    let example = include_str!("../../../docs/examples/faucet-provider.toml");
    let terms = home.path().join("terms.toml");
    let compute_only = example.split("# Caller-signed HTTPS Fetch").next().unwrap();
    std::fs::write(&terms, compute_only).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_hellas"))
        .env("HOME", home.path())
        .arg("--home")
        .arg(home.path().join("app"))
        .args([
            "serve",
            "--no-discovery",
            "--port",
            "0",
            "--paid-work-config",
        ])
        .arg(&terms)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("--knowingly-unsafe"), "{stderr}");
    assert!(stderr.contains("roughly root on this host"), "{stderr}");
}

/// A text request that names no token budget gets the command's default:
/// 256 for `hellas text`, 128 for the gateway. The example paid terms and a
/// plain `serve --program` grant must both admit it.
#[tokio::test]
async fn example_terms_and_the_generic_grant_admit_a_default_text_budget() {
    use hellas_client::model::{ModelPackage, ModelRequest};
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../client/src/model/package/mini-qwen3.gguf");
    let mut job = ModelPackage::open(
        &fixture,
        &hellas_client::model::evaluator(hellas_client::model::GpuDialect::Hip),
    )
    .await
    .unwrap()
    .render_job(&ModelRequest::Text {
        prompt_ids: &[1],
        max_new: 1,
        stops: &[],
    })
    .await
    .unwrap();
    // One step per new token; the fixture's context is shorter than 256.
    let stop = &mut job.plan.step.as_mut().unwrap().stop;
    assert_eq!(stop.max_steps, 1);
    stop.max_steps = 256;
    let example: toml::Value =
        toml::from_str(include_str!("../../../docs/examples/faucet-provider.toml")).unwrap();
    let paid: hellas_rpc::protocol::invocation::Limits =
        example["limits"].clone().try_into().unwrap();
    let root = tempfile::tempdir().unwrap();
    let grant = hellas_sdk::grant_config::GrantConfig::compute(
        &hellas_private::StoreLocation::for_test(root.path()),
        hellas_rpc::protocol::invocation::Admission::Compute {
            evaluator: hellas_client::model::evaluator(hellas_client::model::GpuDialect::Hip),
            programs: hellas_rpc::protocol::invocation::ComputePrograms::Any {},
        },
    )
    .unwrap();
    for limits in [
        paid,
        grant.configuration.resources()[0].invocation_policy.limits,
    ] {
        job.plan.validate_bounds(&limits).unwrap();
    }
}
