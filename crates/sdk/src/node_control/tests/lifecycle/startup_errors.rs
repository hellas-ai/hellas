use super::*;

#[cfg(target_os = "linux")]
#[test]
fn provider_start_with_unavailable_native_secret_store() {
    let directory = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "node_control::tests::lifecycle::startup_errors::native_secret_store_child",
            "--ignored",
            "--nocapture",
        ])
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/missing-bus", directory.path().display()),
        )
        .env("XDG_DATA_HOME", directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "invoked with an isolated unavailable Secret Service bus"]
async fn native_secret_store_child() {
    let factory = host::ProviderFactory {
        prepare: None,
        start: Arc::new(|_| {
            Box::pin(async {
                tokio::task::spawn_blocking(|| {
                    hellas_private::SecretStore::native("host-startup-test")?.get("key")
                })
                .await??;
                panic!("the isolated Secret Service bus does not exist")
            })
        }),
    };
    assert_provider_failure(fixture().await, factory, "secret store unavailable").await;
}

#[tokio::test]
async fn provider_start_projects_locked_store_failure_to_rpc_and_status() {
    let f = fixture().await;
    let root = f.directory.path().to_owned();
    let error = NodeStore::open(
        &root,
        hellas_channel::test_support::network(),
        None,
        UnixMillis(1000),
    )
    .await
    .err()
    .unwrap();
    let expected = error.to_string();
    let factory = host::ProviderFactory {
        prepare: None,
        start: Arc::new(move |_| {
            let root = root.clone();
            Box::pin(async move {
                NodeStore::open(
                    &root,
                    hellas_channel::test_support::network(),
                    None,
                    UnixMillis(1000),
                )
                .await?;
                panic!("the existing authority still owns its writer lock")
            })
        }),
    };
    assert_provider_failure(f, factory, &expected).await;
}

#[tokio::test]
async fn provider_start_projects_secret_store_failure_to_rpc_and_status() {
    let f = fixture().await;
    let path = f.directory.path().join("not-a-secret-directory");
    std::fs::write(&path, b"not a directory").unwrap();
    let store = hellas_private::SecretStore::headless_files(path, "startup-test").unwrap();
    let expected = store.get("key").unwrap_err().to_string();
    assert!(expected.contains("secret store"));
    let prepare_store = store.clone();
    let factory = host::ProviderFactory {
        prepare: Some(Arc::new(move |_| {
            prepare_store.get("key")?;
            panic!("a regular file cannot be a secret store directory")
        })),
        start: Arc::new(move |_| {
            let store = store.clone();
            Box::pin(async move {
                store.get("key")?;
                panic!("a regular file cannot be a secret store directory")
            })
        }),
    };
    assert_provider_failure(f, factory, &expected).await;
}

async fn assert_provider_failure(f: Fixture, factory: host::ProviderFactory, expected: &str) {
    let configurable = factory.prepare.is_some();
    let (host, client, _) = controlled_host(
        f.node.clone(),
        &f.secret,
        f.directory.path(),
        Some(factory),
        None,
    )
    .await;
    if configurable {
        use crate::node_control::configuration::*;
        let error = client
            .configure_provider(ConfigureProviderRequest {
                authorization: ROOT_GRANT.0.to_vec(),
                update: Some(ProviderUpdate {
                    expected_revision: 0,
                    change: Some(UpstreamChange::RemoveEndpoint(UpstreamRoute {
                        service: "api".into(),
                        method: "fetch".into(),
                    })),
                }),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), WireCode::InvalidArgument);
        assert!(
            error.message().contains(expected),
            "preparation hid {expected:?}: {error}"
        );
    }
    let error = client
        .set_provider_state(provider_state(true))
        .await
        .unwrap_err();
    assert_eq!(error.code(), WireCode::Unavailable);
    assert!(
        error.message().contains(expected),
        "RPC hid {expected:?}: {error}"
    );
    let status = client
        .get_host_status(read_request(ROOT_GRANT))
        .await
        .unwrap()
        .provider
        .unwrap();
    assert_eq!(status.state, RuntimeState::Failed as i32);
    assert_eq!(status.detail, error.message());
    host.shutdown().await.unwrap();
}

#[tokio::test]
async fn gateway_start_projects_bind_failure_to_rpc_and_status() {
    let world = crate::test_support::Host::builder().build().await;
    let remote = world.remote().await;
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut options = world.responses_options(remote.addresses()).await;
    options.port = Some(occupied.local_addr().unwrap().port());
    let (host, client, _) = controlled_host(
        world.world.service.node(),
        world.world.secret(ROOT),
        world.root.path(),
        None,
        Some((
            options.access.clone(),
            options.into_factory(SecretKey::from_bytes(&[3; 32])),
        )),
    )
    .await;
    let error = client
        .set_gateway_state(gateway_state(true))
        .await
        .unwrap_err();
    assert_eq!(error.code(), WireCode::Unavailable);
    assert!(
        error.message().contains("Address already in use"),
        "{error}"
    );
    let status = client
        .get_host_status(read_request(ROOT_GRANT))
        .await
        .unwrap()
        .gateway
        .unwrap();
    assert_eq!(status.state, RuntimeState::Failed as i32);
    assert_eq!(status.detail, error.message());
    host.shutdown().await.unwrap();
    remote.shutdown().await;
}
