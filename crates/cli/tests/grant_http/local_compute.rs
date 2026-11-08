//! Shared owner, grant and gateway for the manual model comparisons.
use super::*;
use hellas_authority::model::grant::{grant_network, owner_grant_id, records::*};
use hellas_private::StoreLocation;
use hellas_rpc::protocol::invocation::{Admission, InvocationPolicy, Limits, compute};

pub(super) struct LocalCompute {
    pub gateway: Process,
    pub http: reqwest::Client,
    pub address: String,
    pub provider: hellas_auth::PublicKey,
    _directory: tempfile::TempDir,
}

impl LocalCompute {
    pub async fn start(
        model: &Path,
        model_flag: &str,
        content: &Path,
        limits: Limits,
        job_millis: Option<std::num::NonZeroU64>,
        extra: &[&str],
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        hellas_private::restrict_directory(root).unwrap();
        let owner = Cli::new(root, "owner", AGENT_PASSKEY);
        owner.run(&["--software-root", "identity", "init"]).await;
        let export = owner.output(&["identity", "export-enrollment"]).await;
        assert!(export.status.success());
        let enrollment = decode_enrollment(&export.stdout).unwrap();
        let principal = owner.principal();
        let journal = owner.home.join("provider");
        let (store, secret) = common_node::bootstrap_node_with_credential(
            &journal,
            grant_network(),
            Some(enrollment.clone()),
            hellas_auth::authority::UnixMillis::now().unwrap_or_default(),
        )
        .await
        .unwrap();
        let policy = GrantPolicy {
            name: "local".into(),
            invocation_policy: InvocationPolicy {
                admissions: vec![Admission::Compute {
                    evaluator: compute::EVALUATOR.into(),
                    programs: hellas_rpc::protocol::invocation::ComputePrograms::Any {},
                }],
                limits,
            },
            https: None,
            responses: None,
            ..hellas_authority::test_support::policy()
        };
        let allowance = owner_grant_id(grant_network(), enrollment.content_id(), principal);
        // Read this fixture identity's node key to provision its own service.
        let identity_bytes = std::fs::read(&owner.identity).unwrap();
        let mut decoder = hellas_rpc::DagCborDecoder::new(&identity_bytes);
        decoder.array(6, "identity").unwrap();
        decoder
            .tag("hellas.provider.identity.persistence.v3")
            .unwrap();
        assert_eq!(decoder.u64("version").unwrap(), 3);
        decoder.array(2, "root").unwrap();
        assert_eq!(decoder.u64("root kind").unwrap(), 0);
        let _: [u8; 32] = decoder.fixed_bytes("root key").unwrap();
        let signer = hellas_auth::ProducerSigningKey::from_secret_bytes(
            decoder.fixed_bytes("node key").unwrap(),
        )
        .unwrap();
        let mut definition = common_node::allowance(allowance, principal, vec![policy]);
        if let Some(millis) = job_millis {
            definition.max_job_millis = millis;
        }
        let store = common_node::provision(
            &journal,
            store,
            &secret,
            signer,
            (1, vec![]),
            definition,
            (vec![], 256),
        )
        .await;
        let node = hellas_authority::node::NodeCoordinator::new(
            store,
            Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
        );
        let credential =
            execution_credential(&node, &secret, principal, allowance, owner.holder().await).await;
        let authority = hellas_authority::test_support::session(&node, &secret)
            .await
            .authority();
        let work_profile = work_profile(root, authority, &credential);
        drop(node);
        let (gateway_profile, gateway_token) = gateway_profile(root).await;
        let trust_root = approve(root, "local", enrollment.content_id());
        let configuration = prepare_content(root, &journal, content);
        let allowance = hex::encode(allowance.0);
        let mut args = vec![
            "gateway",
            "--trust-store",
            string(&trust_root),
            "--trust-policy",
            "local",
            "--local-grant",
            &allowance,
            "--work-profile",
            string(&work_profile),
            model_flag,
            string(model),
            "--content-config",
            string(&configuration),
            "--gpu-backend",
            "hip",
            "--port",
            "0",
            "--gateway-profile",
            string(&gateway_profile),
            "--zdr",
        ];
        args.extend_from_slice(extra);
        let mut gateway = owner.spawn(&args, "local-model-gateway.log");
        let address = gateway.wait_for("gateway listening on ").await;
        // Native compilation can outlast the shared fixture client's 10 s.
        let http = reqwest::Client::builder()
            .default_headers(
                [(
                    reqwest::header::AUTHORIZATION,
                    reqwest::header::HeaderValue::from_str(&format!("Bearer {gateway_token}"))
                        .unwrap(),
                )]
                .into_iter()
                .collect(),
            )
            .build()
            .unwrap();
        let provider =
            hellas_auth::PublicKey::Secp256k1(grant_producer(&enrollment).unwrap().to_bytes());
        Self {
            gateway,
            http,
            address,
            provider,
            _directory: directory,
        }
    }
}

fn prepare_content(root: &Path, journal: &Path, content: &Path) -> PathBuf {
    // Prepare the ordinary dedicated upper's derived index before startup.
    let upper = journal.join("content");
    let records = hellas_store::fastresume::Records::default();
    if let Some(index) = std::env::var_os("HELLAS_TEST_CONTENT_INDEX") {
        let _ = records.load(Path::new(&index));
    }
    let ram = hellas_store::content::Reservations::ram(1 << 20);
    let lower = if content.is_dir() {
        content
    } else {
        content.parent().unwrap()
    };
    let mut pending = vec![lower.to_owned()];
    let mut pins = toml::map::Map::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() || entry.file_type().unwrap().is_file() {
                    pending.push(entry.path());
                }
            }
        } else if !hellas_store::fastresume::is_cache_debris(&path) {
            let indexed = records.index_file(&path, &ram, false).unwrap();
            if content.is_dir() || path == content {
                pins.insert(
                    format!("config/model/{}", indexed.id),
                    toml::Value::Table(toml::map::Map::from_iter([
                        ("expect".into(), toml::Value::String(indexed.id.to_string())),
                        (
                            "bytes".into(),
                            toml::Value::Integer(indexed.len.try_into().unwrap()),
                        ),
                    ])),
                );
            }
        }
    }
    records.save(&upper.join("fastresume.bin")).unwrap();
    let configuration = root.join("content.toml");
    let value = toml::Value::Table(toml::map::Map::from_iter([(
        "content".into(),
        toml::Value::Table(toml::map::Map::from_iter([
            (
                "upper".into(),
                toml::Value::String(upper.to_string_lossy().into_owned()),
            ),
            (
                "lower".into(),
                toml::Value::Array(vec![toml::Value::String(
                    lower.to_string_lossy().into_owned(),
                )]),
            ),
            ("index".into(), toml::Value::String("require".into())),
            ("pins".into(), toml::Value::Table(pins)),
        ])),
    )]));
    std::fs::write(&configuration, toml::to_string(&value).unwrap()).unwrap();
    configuration
}

/// Require must accept sibling model metadata without exposing it to jobs.
#[tokio::test]
async fn local_model_fixture_indexes_the_whole_lower_and_declares_only_requested_weights() {
    use hellas_store::content::{
        ContentStore as _, Cursor, PinPolicy, Reservations, Scope,
        config::{Config, Reconciler},
    };
    let directory = tempfile::tempdir().unwrap();
    let model = directory.path().join("model");
    std::fs::create_dir(&model).unwrap();
    let weights = model.join("weights.bf16");
    std::fs::write(&weights, b"fixture weights").unwrap();
    std::fs::write(model.join("config.json"), b"{}").unwrap();
    std::fs::write(model.join("download.incomplete"), b"partial").unwrap();
    let path = prepare_content(
        directory.path(),
        &directory.path().join("provider"),
        &weights,
    );
    let value: toml::Value = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let config: Config = value.get("content").unwrap().clone().try_into().unwrap();
    let store = config
        .open(
            &StoreLocation::for_test(directory.path()),
            Reservations::ram(32 << 20),
            true,
        )
        .await
        .unwrap();
    store.finish_recovery().await.unwrap();
    Reconciler::new(config.clone())
        .unwrap()
        .apply(&store, config)
        .await
        .unwrap();
    let pins = store
        .pins(&Scope::Owner, "config/", Cursor::default())
        .await
        .unwrap()
        .pins;
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].1.policy, PinPolicy::Jobs);
    let object = hellas_rpc::ContentRef::for_bytes(b"fixture weights");
    assert_eq!(pins[0].1.target.object(), object);
    let metadata = hellas_rpc::ContentRef::for_bytes(b"{}");
    let private = hellas_store::content::PinName::new("owner-metadata".into()).unwrap();
    store
        .set_pin(
            &Scope::Owner,
            &private,
            None,
            Some(hellas_store::content::PinValue {
                target: hellas_store::content::Target::Object(metadata),
                policy: PinPolicy::Owner,
                expires: None,
            }),
        )
        .await
        .unwrap();
    let scope = store
        .open_work(
            hellas_store::content::JobId {
                channel: hellas_auth::Digest::hash(b"fixture channel"),
                id: hellas_auth::Digest::hash(b"fixture job"),
            },
            vec![object, metadata],
            object.bytes() + metadata.bytes(),
        )
        .await
        .unwrap();
    assert!(
        store
            .stat(
                &scope,
                &hellas_store::content::Path::new(private, String::new()).unwrap()
            )
            .await
            .unwrap()
            .is_none()
    );
    let mut read = store
        .read(
            &scope,
            &hellas_store::content::Path::new(pins[0].0.clone(), String::new()).unwrap(),
            0..object.bytes(),
        )
        .await
        .unwrap();
    let mut actual = Vec::new();
    while let Some(chunk) = read.bytes.next().await {
        actual.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(actual, b"fixture weights");
    drop(read);
    store.end_work(&scope).await.unwrap();
    store.close().await;
}
