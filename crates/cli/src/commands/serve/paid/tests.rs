use super::*;
use clap::Parser as _;
use hellas_sdk::serve_config::{Destination, Route, ServeConfig};
fn example() -> ServeConfig {
    ServeConfig::from_bytes(include_bytes!(
        "../../../../../../docs/examples/faucet-provider.json"
    ))
    .unwrap()
}

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
    let mut paid = PaidWork::from_config(&example(), root.path().join("provider"), None).unwrap();
    let config = hellas_sdk::grant_config::GrantConfig::unconfigured(&paid.root);
    assert!(
        paid.prepare(&config, &identity.enrollment, &identity.node_key)
            .await
            .is_err()
    );
    assert!(!paid.root.join("bootstrap.json").exists());

    let cli = crate::Cli::try_parse_from(["hellas", "serve", "--faucet-account", "7"]).unwrap();
    paid.owner = cli.owner.load().unwrap();
    let credential = paid
        .prepare(&config, &identity.enrollment, &identity.node_key)
        .await
        .unwrap()
        .unwrap();
    let owner = paid.owner.take();
    assert!(
        paid.prepare(&config, &identity.enrollment, &identity.node_key)
            .await
            .is_err()
    );
    let store = NodeStore::open(
        &config.journal_root,
        hellas_authority::model::grant::grant_network(),
        Some(identity.enrollment.clone()),
        UnixMillis::now().unwrap(),
    )
    .await
    .unwrap();
    let service = hellas_authority::grant_service::GrantService::new(
        store,
        Arc::new(identity.node_key.clone()),
        NoBackend,
        vec![],
        Arc::new(|| UnixMillis::now().unwrap()),
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
        paid.prepare(&config, &identity.enrollment, &identity.node_key)
            .await
            .is_err()
    );
    paid.policy.offers.max_open_offers -= 1;
    assert!(
        paid.prepare(&config, &identity.enrollment, &identity.node_key)
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn paid_compute_program_selection_survives_config_parsing() {
    let environment = hellas_rpc::protocol::invocation::compute::Environment {
        sources: vec![hellas_rpc::ContentRef::for_bytes(b"approved program")],
        assets: vec![],
    };
    let manifest = environment.manifest().unwrap();
    let mut selected = serde_json::to_value(example()).unwrap();
    selected["paid"]["invocation_policy"]["admissions"][0]["programs"] =
        serde_json::json!({"mode":"only","manifests":[manifest.content_id().to_string()]});
    let config = ServeConfig::from_bytes(&serde_json::to_vec(&selected).unwrap()).unwrap();
    let policy = config.paid.as_ref().unwrap().policy().unwrap();
    policy
        .invocation_policy
        .classify_manifest(&manifest)
        .unwrap();
    let other = hellas_rpc::ProgramManifest::new(
        manifest.application().clone(),
        hellas_rpc::ContentId::hash(b"other"),
    );
    assert!(policy.invocation_policy.classify_manifest(&other).is_err());
    selected["paid"]["invocation_policy"]["admissions"][0]["programs"]["manifests"] =
        serde_json::json!([]);
    assert!(ServeConfig::from_bytes(&serde_json::to_vec(&selected).unwrap()).is_err());
    selected["paid"]["invocation_policy"]["admissions"][0]["programs"]["mode"] =
        serde_json::json!("any");
    assert!(ServeConfig::from_bytes(&serde_json::to_vec(&selected).unwrap()).is_err());
}

#[tokio::test]
async fn interrupted_bootstrap_reuses_prepared_owner_approval_credential_and_tls() {
    let root = tempfile::tempdir().unwrap();
    let identity = crate::identity::load_or_create(Some(&root.path().join("identity"))).unwrap();
    let cli = crate::Cli::try_parse_from(["hellas", "serve", "--faucet-account", "7"]).unwrap();
    let owner = cli.owner.load().unwrap().unwrap();
    let paid =
        PaidWork::from_config(&example(), root.path().join("provider"), Some(owner)).unwrap();
    assert_eq!(paid.chain.chain.network.as_str(), "hellas-devnet-1");
    assert_eq!(paid.policy.payment_policy.fixed_price, 20);
    assert_eq!(paid.policy.expected_payment_values.value(), 401);
    let config = hellas_sdk::grant_config::GrantConfig::unconfigured(&paid.root);
    let first = paid
        .prepare(&config, &identity.enrollment, &identity.node_key)
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
        .prepare(&config, &identity.enrollment, &identity.node_key)
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

#[test]
fn faucet_upload_terms_admit_a_fresh_whisper_program_and_features() {
    use hellas_channel::content::{EphemeralContent, InvocationContent};
    use hellas_client::model::{ModelPackage, ModelRequest};
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/src/model/whisper/mini");
    let model = ModelPackage::open(&fixture).unwrap();
    let job = model
        .render_job(&ModelRequest::Transcription {
            samples: &[0.; 400],
            language: Some("en"),
            max_new_tokens: 4,
        })
        .unwrap();
    let limits = example().paid.unwrap().invocation_policy.limits;
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
    let mut held = EphemeralContent::default();
    held.insert(std::fs::read(fixture.join("weights.bf16")).unwrap());
    let held = InvocationContent::Ephemeral(held);
    // Only ordinary weights are held. The source and all four inputs must fit
    // as newly uploaded objects, even on the first request to this provider.
    hellas_executor::catena::validate::preflight(
        &job.environment,
        &inputs,
        &job.plan,
        &limits,
        &held,
    )
    .unwrap();
    let too_small = hellas_rpc::protocol::invocation::Limits {
        max_upload_bytes: 1 << 20,
        ..limits
    };
    assert!(
        hellas_executor::catena::validate::preflight(
            &job.environment,
            &inputs,
            &job.plan,
            &too_small,
            &held
        )
        .is_err()
    );
}

#[test]
fn paid_fetch_admission_derives_the_configured_route_contract() {
    let root = tempfile::tempdir().unwrap();
    let mut doc = example();
    doc.paid
        .as_mut()
        .unwrap()
        .invocation_policy
        .admissions
        .retain(|a| matches!(a, Admission::Fetch { .. }));
    doc.routes = vec![Route {
        service: "codex".into(),
        method: "responses".into(),
        destination: Destination::CodexResponses {
            auth_path: Some("target/hellas-test-codex-auth.json".into()),
        },
        capabilities: Default::default(),
        credential_metadata: Default::default(),
    }];
    if let Admission::Fetch { admission } =
        &mut doc.paid.as_mut().unwrap().invocation_policy.admissions[0]
    {
        admission.route = hellas_rpc::protocol::invocation::fetch::FetchRoutePolicy::sealed_route(
            "codex",
            "responses",
        )
        .unwrap();
        // The old HTTP contract cannot be passed off as a Codex contract.
    }
    assert!(doc.validate().is_err());
    if let Admission::Fetch { admission } =
        &mut doc.paid.as_mut().unwrap().invocation_policy.admissions[0]
    {
        admission.contract = hellas_providers::codex_responses_contract().unwrap();
    }
    doc.validate().unwrap();
    let paid = PaidWork::from_config(&doc, root.path().join("provider"), None).unwrap();
    let Admission::Fetch { admission } = &paid.policy.invocation_policy.admissions[0] else {
        panic!("Fetch admission")
    };
    assert_eq!(
        admission.contract,
        hellas_providers::codex_responses_contract().unwrap()
    );
}
