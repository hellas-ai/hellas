use super::*;
use clap::Parser as _;

#[tokio::test]
async fn fleet_paid_startup_requires_exact_owner_approval_without_owner_key() {
    use std::sync::Arc;
    struct NoBackend;
    impl hellas_channel::work::WorkBackend for NoBackend {
        fn try_admit(
            &self,
            domain: hellas_channel::work::admission::CapacityDomain,
        ) -> Result<hellas_channel::work::admission::WorkPermit, hellas_channel::work::BackendFault>
        {
            Err(hellas_channel::work::admission::AdmissionError::Unsupported(domain).into())
        }
    }
    let root = tempfile::tempdir().unwrap();
    let identity = crate::identity::load_or_create(Some(&root.path().join("identity"))).unwrap();
    let example =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/examples/faucet-provider.toml");
    let mut paid = PaidWork::load(&example, root.path().join("provider"), None, None).unwrap();
    let config = hellas_sdk::grant_config::GrantConfig::unconfigured(&paid.root);
    assert!(
        paid.prepare(
            &config,
            &identity.enrollment,
            &identity.node_key,
            Default::default()
        )
        .await
        .is_err()
    );
    assert!(!paid.root.join("bootstrap.json").exists());

    let cli = crate::Cli::try_parse_from(["hellas", "serve", "--faucet-account", "7"]).unwrap();
    paid.owner = cli.owner.load().unwrap();
    let credential = paid
        .prepare(
            &config,
            &identity.enrollment,
            &identity.node_key,
            Default::default(),
        )
        .await
        .unwrap()
        .unwrap();
    let owner = paid.owner.take();
    assert!(
        paid.prepare(
            &config,
            &identity.enrollment,
            &identity.node_key,
            Default::default()
        )
        .await
        .is_err()
    );
    let store = NodeStore::open(
        &config.journal_root,
        hellas_authority::model::grant::grant_network(),
        Some(identity.enrollment.clone()),
        UnixMillis::now().unwrap(),
        Default::default(),
    )
    .await
    .unwrap();
    let service = hellas_authority::grant_service::GrantService::new(
        store,
        Arc::new(identity.node_key.clone()),
        NoBackend,
        vec![],
        Arc::new(|| UnixMillis::now().unwrap()),
        hellas_authority::test_support::content_store(&config.journal_root).await,
    )
    .unwrap();
    let admin = WorkAdministration::new(
        service,
        Default::default(),
        std::num::NonZeroU64::new(90_000).unwrap(),
    );
    // A daemon with only its node identity cannot install or alter paid terms.
    assert!(paid.configure(&admin, Some(&credential)).await.is_err());
    assert!(admin.node().paid_policy().await.unwrap().is_none());
    paid.owner = owner;
    paid.configure(&admin, Some(&credential)).await.unwrap();
    paid.owner = None;
    let approved = admin.node().paid_policy().await.unwrap().unwrap();
    paid.configure(&admin, None).await.unwrap();
    paid.policy.offers.max_open_offers += 1;
    assert!(paid.configure(&admin, None).await.is_err());
    assert_eq!(admin.node().paid_policy().await.unwrap().unwrap(), approved);
    drop(admin);
    assert!(
        paid.prepare(
            &config,
            &identity.enrollment,
            &identity.node_key,
            Default::default()
        )
        .await
        .is_err()
    );
    paid.policy.offers.max_open_offers -= 1;
    assert!(
        paid.prepare(
            &config,
            &identity.enrollment,
            &identity.node_key,
            Default::default()
        )
        .await
        .unwrap()
        .is_none()
    );
}

#[test]
fn paid_compute_program_selection_survives_config_parsing() {
    let example = include_str!("../../../../../../docs/examples/faucet-provider.toml");
    let environment = hellas_rpc::protocol::invocation::compute::Environment {
        sources: vec![hellas_rpc::ContentRef::for_bytes(b"approved program")],
        assets: vec![],
    };
    let manifest = environment.manifest().unwrap();
    let selected = example.replace(
        "mode = \"any\"",
        &format!(
            "mode = \"only\"\nmanifests = [\"{}\"]",
            manifest.content_id()
        ),
    );
    let file: PaidWorkFile = toml::from_str(&selected).unwrap();
    let policy = file
        .policy(Some(hellas_rpc::FetchContract::http().unwrap()))
        .unwrap();
    policy
        .invocation_policy
        .classify_manifest(&manifest)
        .unwrap();
    let other = hellas_rpc::ProgramManifest::new(
        manifest.application().clone(),
        hellas_rpc::ContentId::hash(b"other"),
    );
    assert!(policy.invocation_policy.classify_manifest(&other).is_err());
    let empty = selected.replace(&format!("\"{}\"", manifest.content_id()), "");
    assert!(
        toml::from_str::<PaidWorkFile>(&empty)
            .unwrap()
            .policy(Some(hellas_rpc::FetchContract::http().unwrap()))
            .is_err()
    );
    let ambiguous = selected.replace("mode = \"only\"", "mode = \"any\"");
    assert!(toml::from_str::<PaidWorkFile>(&ambiguous).is_err());
}

#[tokio::test]
async fn interrupted_bootstrap_reuses_prepared_owner_approval_credential_and_tls() {
    let root = tempfile::tempdir().unwrap();
    let identity = crate::identity::load_or_create(Some(&root.path().join("identity"))).unwrap();
    let cli = crate::Cli::try_parse_from(["hellas", "serve", "--faucet-account", "7"]).unwrap();
    let owner = cli.owner.load().unwrap().unwrap();
    let example =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/examples/faucet-provider.toml");
    let paid = PaidWork::load(&example, root.path().join("provider"), Some(owner), None).unwrap();
    assert_eq!(paid.chain.chain.network.as_str(), "hellas-devnet-1");
    assert_eq!(paid.policy.payment_policy.fixed_price, 20);
    assert_eq!(paid.policy.expected_payment_values.value(), 401);
    let config = hellas_sdk::grant_config::GrantConfig::unconfigured(&paid.root);
    let first = paid
        .prepare(
            &config,
            &identity.enrollment,
            &identity.node_key,
            Default::default(),
        )
        .await
        .unwrap()
        .unwrap();
    let certificate = std::fs::read(&config.control_certificate).unwrap();
    let key = std::fs::read(&config.control_private_key).unwrap();
    let approval = std::fs::read(paid.root.join("bootstrap.json")).unwrap();
    // Reproduce the on-disk state before the authority rename, after only the
    // certificate publication. Initialization must finish the prepared key pair.
    std::fs::remove_dir_all(&config.journal_root).unwrap();
    std::fs::remove_file(&config.control_private_key).unwrap();
    let resumed = paid
        .prepare(
            &config,
            &identity.enrollment,
            &identity.node_key,
            Default::default(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resumed.id(), first.id());
    assert_eq!(resumed.expose_secret(), first.expose_secret());
    assert_eq!(
        std::fs::read(paid.root.join("bootstrap.json")).unwrap(),
        approval
    );
    assert_eq!(
        std::fs::read(&config.control_certificate).unwrap(),
        certificate
    );
    assert_eq!(std::fs::read(&config.control_private_key).unwrap(), key);
}

#[tokio::test]
async fn faucet_upload_terms_admit_a_fresh_whisper_program_and_features() {
    use hellas_client::model::{ModelPackage, ModelRequest};
    use hellas_store::content::{
        ContentStore as _, DiskStore, IndexMode, JobId, PinName, PinPolicy, PinValue, Reservations,
        Scope, Target,
    };
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/src/model/whisper/mini");
    let model = ModelPackage::open(&fixture).await.unwrap();
    let job = model
        .render_job(&ModelRequest::Transcription {
            samples: &[0.; 400],
            language: Some("en"),
            max_new_tokens: 4,
        })
        .await
        .unwrap();
    let example: toml::Value = toml::from_str(include_str!(
        "../../../../../../docs/examples/faucet-provider.toml"
    ))
    .unwrap();
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
        root.path().join("content"),
        vec![fixture],
        IndexMode::Resume,
        None,
        Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
        Default::default(),
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

#[test]
fn paid_fetch_admission_derives_the_configured_route_contract() {
    use hellas_executor::FetchAdaptorFactory as _;
    let root = tempfile::tempdir().unwrap();
    let cli = crate::Cli::try_parse_from(["hellas", "serve", "--faucet-account", "7"]).unwrap();
    let owner = cli.owner.load().unwrap().unwrap();
    let example =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/examples/faucet-provider.toml");
    let mut terms: toml::Value =
        toml::from_str(&std::fs::read_to_string(&example).unwrap()).unwrap();
    terms.as_table_mut().unwrap().remove("compute");
    terms["fetch"]["route"] =
        toml::from_str("[SealedRoute]\nservice = \"codex\"\nmethod = \"responses\"\n").unwrap();
    let terms_path = root.path().join("paid.toml");
    std::fs::write(&terms_path, toml::to_string(&terms).unwrap()).unwrap();
    let fetch_path = root.path().join("fetch.json");
    std::fs::write(
        &fetch_path,
        serde_json::json!({
            "routes": [{
                "service": "codex",
                "method": "responses",
                "destination": {
                    "type": "codex-responses",
                    "auth_path": "target/hellas-test-codex-auth.json"
                }
            }]
        })
        .to_string(),
    )
    .unwrap();

    let paid = PaidWork::load(
        &terms_path,
        root.path().join("provider"),
        Some(owner),
        Some(&fetch_path),
    )
    .unwrap();
    let admission = paid
        .policy
        .invocation_policy
        .admissions
        .iter()
        .find_map(|admission| match admission {
            Admission::Fetch { admission } => Some(admission),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        admission.contract,
        hellas_providers::codex_responses_contract().unwrap()
    );
    assert_eq!(
        admission.contract.manifest_id(),
        hellas_providers::CodexResponsesAdaptorFactory::new()
            .unwrap()
            .execution_environment()
    );

    // An HTTP destination derives the generic contract instead.
    let http_path = root.path().join("http.json");
    std::fs::write(
        &http_path,
        serde_json::json!({
            "routes": [{
                "service": "http",
                "method": "request",
                "destination": {"type": "http", "config": {}}
            }]
        })
        .to_string(),
    )
    .unwrap();
    let http = paid_fetch_contract(
        Some(&http_path),
        &hellas_rpc::protocol::invocation::fetch::FetchRoutePolicy::sealed_route("http", "request")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(http, hellas_rpc::FetchContract::http().unwrap());
}
