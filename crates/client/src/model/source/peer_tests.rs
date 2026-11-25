use super::*;
use crate::model::{GpuDialect, ModelPackage, evaluator};
use hellas_rpc::{
    protocol::invocation::compute::NamedAsset,
    services::content::{Content, ContentServer},
};
use hellas_store::content::{
    ContentService, MemoryStore, PinPolicy, PinValue, Target, Tree, owner_pin,
};
use hellas_wire::{Dispatcher, StreamTransport};

#[tokio::test]
async fn catalog_visibility_and_verified_header_select_the_same_program_as_local() {
    let store = MemoryStore::new(Reservations::ram(16 << 20));
    let weights = include_bytes!("../package/mini-qwen3.gguf");
    let object = hellas_channel::content::upload_object(&store, weights)
        .await
        .unwrap();
    let model = Model::new(vec![NamedAsset {
        name: "weights".into(),
        object,
    }])
    .unwrap();
    publish_model(&store, &model).await.unwrap();

    let server = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .alpns(vec![Content::ALPN.as_bytes().to_vec()])
        .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let id = model.content_id().unwrap();
    let uri = std::path::PathBuf::from(format!(
        "hellas://{id}@{}@{}",
        server.id(),
        server.bound_sockets()[0]
    ));
    let service = ContentService::new(Arc::new(store.clone()), Scope::Public);
    let listener = server.clone();
    let serving = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        while let Some(incoming) = listener.accept().await {
            let service = service.clone();
            connections.spawn(async move {
                let transport = IrohTransport::new(incoming.await.unwrap());
                while let Ok(Some(call)) = transport.accept().await {
                    let _ = Dispatcher::<IrohTransport>::dispatch(
                        &ContentServer(service.clone()),
                        call,
                    )
                    .await;
                }
            });
        }
    });
    let evaluator = evaluator(GpuDialect::Hip, "gfx1151");
    assert!(ModelPackage::open(&uri, &evaluator).await.is_err());
    let name = model_pin(id).unwrap();
    let jobs = owner_pin(&store, &name).await.unwrap().unwrap();
    let public = PinValue {
        policy: PinPolicy::Public,
        ..jobs.clone()
    };
    store
        .set_pin(&Scope::Owner, &name, Some(&jobs), Some(public.clone()))
        .await
        .unwrap();
    publish_model(&store, &model).await.unwrap();
    assert_eq!(owner_pin(&store, &name).await.unwrap().unwrap(), public);
    let dir = tempfile::tempdir().unwrap();
    let local_store = hellas_store::content::DiskStore::open(
        hellas_private::StoreLocation::for_test(dir.path()),
        vec![],
        hellas_store::content::IndexMode::Resume,
        None,
        Reservations::ram(16 << 20),
        false,
    )
    .await
    .unwrap();
    local_store.finish_recovery().await.unwrap();
    acquire_peer_model(uri.to_str().unwrap(), &local_store)
        .await
        .unwrap();
    let stored = owner_pin(
        &local_store,
        &PinName::new(format!("models/{}", object.id())).unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(stored.target, Target::Object(object));
    assert_eq!(stored.policy, PinPolicy::Jobs);
    local_store.close().await;
    let peer = ModelPackage::open(&uri, &evaluator).await.unwrap();
    let local = ModelPackage::open(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/model/package/mini-qwen3.gguf"),
        &evaluator,
    )
    .await
    .unwrap();
    assert_eq!(peer.model(), local.model());
    assert_eq!(peer.programs().unwrap(), local.programs().unwrap());
    let model_object = ContentRef::for_bytes(&model.canonical_bytes().unwrap());
    let forged = Tree::new(vec![
        ("model".into(), Target::Object(model_object)),
        (object.id().to_string(), Target::Object(model_object)),
    ])
    .unwrap();
    let forged = hellas_channel::content::upload_object(&store, &forged.bytes())
        .await
        .unwrap();
    store
        .set_pin(
            &Scope::Owner,
            &name,
            Some(&public),
            Some(PinValue {
                target: Target::Tree(forged),
                ..public.clone()
            }),
        )
        .await
        .unwrap();
    let err = ModelPackage::open(&uri, &evaluator)
        .await
        .err()
        .expect("substituted asset accepted");
    assert!(format!("{err:#}").contains("peer asset differs"), "{err:#}");
    server.close().await;
    serving.abort();
}
