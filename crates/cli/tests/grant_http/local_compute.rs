//! A local gateway for the manual model comparisons.
use super::*;
use hellas_private::StoreLocation;

pub(super) struct LocalCompute {
    pub gateway: Process,
    pub http: reqwest::Client,
    pub address: String,
    pub provider: hellas_auth::PublicKey,
    _directory: tempfile::TempDir,
}

impl LocalCompute {
    /// `content`, if any, is served through a content configuration; the
    /// gateway serves `model` to its jobs either way.
    pub async fn start(model: &Path, content: Option<&Path>, extra: &[&str]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        hellas_private::restrict_directory(root).unwrap();
        let owner = Cli::new(root, "owner", AGENT_PASSKEY);
        owner.run(&["identity", "init"]).await;
        let hellas_auth::authority::CredentialHolder::Node(holder) = owner.holder().await else {
            panic!("a device key")
        };
        let journal = owner.home.join("provider");
        let (gateway_profile, gateway_token) = gateway_profile(root).await;
        let configuration = content.map(|content| prepare_content(root, &journal, content));
        let mut args = vec!["gateway", "--local", "--model", string(model)];
        if let Some(configuration) = &configuration {
            args.extend(["--content-config", string(configuration)]);
        }
        args.extend([
            "--gpu-backend",
            "hip",
            "--port",
            "0",
            "--gateway-profile",
            string(&gateway_profile),
            "--zdr",
        ]);
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
        let provider = holder.public_key();
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
