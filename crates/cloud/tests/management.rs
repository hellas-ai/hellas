#![cfg(unix)]

mod common;

use hellas_cloud::{
    config::read_json,
    internal_rpc,
    management::{Request, Service},
};
use serde_json::json;
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

// Seed an existing inventory without reaching a cloud provider.
fn existing_machine(
    root: &std::path::Path,
    key: &iroh::SecretKey,
    address: Option<std::net::SocketAddr>,
) -> hellas_cloud::config::Credentials {
    use hellas_cloud::config::{Credentials, save_private};
    let mut credentials = Credentials::generate();
    credentials.owner = Some(key.public().to_string());
    credentials.owner_enrollment = Some(hex::encode(common::bundle(key).canonical_bytes()));
    save_private(
        &root.join(key.public().to_string()).join("metal.json"),
        &json!({
            "name": "metal", "owner": key.public().to_string(),
            "source": {"kind":"bare-metal", "credentials":credentials, "admin_addr":address},
            "enrollment":null, "last_seen_unix":null, "running":null,
        }),
        true,
    )
    .unwrap();
    credentials
}

#[tokio::test]
async fn missing_enrollment_fails_before_receipts_bootstrap_or_provider_access() {
    use hellas_cloud::config::{Credentials, ProviderConfig, Spec, Trust};
    let dir = tempfile::tempdir().unwrap();
    let key = iroh::SecretKey::generate();
    let service = Service::new(key.clone(), dir.path()).unwrap();
    let bootstrap = dir.path().join("bootstrap.json");
    let error = service
        .execute(Request::Prepare {
            name: "blocked".into(),
            bootstrap_file: bootstrap.clone(),
            admin_addr: None,
            serve_args: vec![],
        })
        .await
        .unwrap_err();
    assert!(error.to_string().contains("owner enrollment required"));
    let spec = Spec {
        name: "blocked".into(),
        image: format!("registry/image@sha256:{}", "a".repeat(64)),
        provider: ProviderConfig::Docker { gpus: false },
        trust: Trust::Token,
        serve_args: vec![],
    };
    let receipt = dir.path().join("receipt.json");
    assert!(
        service
            .create(spec.clone(), Some(receipt.clone()))
            .await
            .unwrap_err()
            .to_string()
            .contains("owner enrollment required")
    );
    let mut credentials = Credentials::generate();
    credentials.owner = Some(key.public().to_string());
    assert!(
        hellas_cloud::deployment::create_with_credentials(spec, &receipt, credentials)
            .await
            .unwrap_err()
            .to_string()
            .contains("owner enrollment required")
    );
    assert!(!bootstrap.exists());
    assert!(!receipt.exists());
    assert_eq!(
        std::fs::read_dir(dir.path().join(key.public().to_string()))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn inventory_is_scoped_to_identity_and_never_returns_bootstrap_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let key = iroh::SecretKey::generate();
    let a = Service::new(key.clone(), dir.path()).unwrap();
    let b = Service::new(iroh::SecretKey::generate(), dir.path()).unwrap();
    let bootstrap = dir.path().join("bootstrap.json");
    let credentials = existing_machine(dir.path(), &key, None);
    hellas_cloud::config::save_private(&bootstrap, &credentials.env_for_args(&[]).unwrap(), true)
        .unwrap();
    let env: serde_json::Value = read_json(&bootstrap).unwrap();
    assert_eq!(env["HELLAS_REMOTE_OWNER"], key.public().to_string());
    assert_eq!(std::fs::metadata(&bootstrap).unwrap().mode() & 0o777, 0o600);
    let visible = a.list().unwrap();
    assert_eq!(visible["machines"][0]["name"], "metal");
    assert_eq!(
        visible["machines"][0]["enrollment"],
        serde_json::Value::Null
    );
    assert!(
        !visible
            .to_string()
            .contains(env["HELLAS_REMOTE_TOKEN"].as_str().unwrap())
    );
    assert!(
        !visible
            .to_string()
            .contains(env["HELLAS_REMOTE_KEY"].as_str().unwrap())
    );
    assert!(b.list().unwrap()["machines"].as_array().unwrap().is_empty());
    assert!(b.resolve("metal").await.is_err());
    assert!(
        a.execute(Request::Destroy {
            name: "metal".into()
        })
        .await
        .is_err()
    );
    assert!(
        a.execute(Request::Prepare {
            name: "../escape".into(),
            bootstrap_file: dir.path().join("bad"),
            admin_addr: None,
            serve_args: vec![]
        })
        .await
        .is_err()
    );
    // Restarting the local service keeps inventory scoped to the same identity.
    assert_eq!(
        visible,
        Service::new(key, dir.path()).unwrap().list().unwrap()
    );
}

#[tokio::test]
async fn rpc_handles_real_frames_and_shares_the_cli_service() {
    let dir = tempfile::tempdir().unwrap();
    let key = iroh::SecretKey::generate();
    let service = Service::new(key.clone(), &dir.path().join("inventory")).unwrap();
    existing_machine(&dir.path().join("inventory"), &key, None);
    let socket = dir.path().join("rpc/control.sock");
    let server_socket = socket.clone();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        internal_rpc::serve_until(service, &server_socket, async {
            let _ = stopped.await;
        })
        .await
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(std::fs::metadata(&socket).unwrap().mode() & 0o777, 0o600);
    let bootstrap = dir.path().join("bootstrap.json");
    internal_rpc::call(
        &socket,
        Request::Prepare {
            name: "metal".into(),
            bootstrap_file: bootstrap.clone(),
            admin_addr: None,
            serve_args: vec![],
        },
    )
    .await
    .unwrap_err();
    assert!(!bootstrap.exists());
    let inventory = internal_rpc::call(&socket, Request::List).await.unwrap();
    assert_eq!(inventory["owner"], key.public().to_string());
    assert_eq!(inventory["machines"][0]["name"], "metal");
    let mut stream = BufReader::new(UnixStream::connect(&socket).await.unwrap());
    for (request, code) in [
        ("not-json\n".to_owned(), -32700),
        (
            format!(
                "{}\n",
                json!({"jsonrpc":"2.0","id":"test","method":"unknown"})
            ),
            -32601,
        ),
        (
            format!(
                "{}\n",
                json!({"jsonrpc":"2.0","id":"test","method":"machines.status","params":{"name":3}})
            ),
            -32602,
        ),
        (
            format!(
                "{}\n",
                json!({"jsonrpc":"2.0","id":"test","method":"machines.prepare","params":{"name":"metal","bootstrap_file":bootstrap}})
            ),
            -32000,
        ),
    ] {
        stream
            .get_mut()
            .write_all(request.as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_line(&mut response).await.unwrap();
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["error"]["code"], code);
        assert!(!response.to_string().contains("HELLAS_REMOTE_TOKEN"));
    }
    drop(stream);
    // A second server cannot steal an active socket.
    let duplicate = Service::new(key, &dir.path().join("inventory")).unwrap();
    assert!(
        internal_rpc::serve_until(duplicate, &socket, std::future::ready(()))
            .await
            .is_err()
    );
    assert!(internal_rpc::call(&socket, Request::List).await.is_ok());
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    assert!(!socket.exists());
}

#[tokio::test]
async fn rpc_refuses_a_shared_socket_directory_or_existing_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join("shared");
    std::fs::create_dir(&socket_dir).unwrap();
    std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let service = Service::new(iroh::SecretKey::generate(), &dir.path().join("inventory")).unwrap();
    assert!(
        internal_rpc::serve_until(
            service,
            &socket_dir.join("control.sock"),
            std::future::ready(())
        )
        .await
        .is_err()
    );
    std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = socket_dir.join("control.sock");
    std::fs::write(&socket, "keep me").unwrap();
    let service = Service::new(iroh::SecretKey::generate(), &dir.path().join("inventory")).unwrap();
    assert!(
        internal_rpc::serve_until(service, &socket, std::future::ready(()))
            .await
            .is_err()
    );
    assert_eq!(std::fs::read_to_string(&socket).unwrap(), "keep me");
}

#[tokio::test]
async fn enrollment_requires_owner_confirmation_and_cannot_be_silently_replaced() {
    use hellas_cloud::{
        config::{Credentials, Enrollment},
        wire::{self, Operation, Response},
    };
    use iroh::{Endpoint, endpoint::presets};
    let dir = tempfile::tempdir().unwrap();
    let key = iroh::SecretKey::generate();
    let owner = key.public().to_string();
    let service = Service::new(key.clone(), dir.path()).unwrap();
    let credentials = Credentials::generate();
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(credentials.secret_key().unwrap())
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![wire::ALPN.to_vec()])
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let address = endpoint
        .bound_sockets()
        .into_iter()
        .find(|addr| addr.is_ipv4())
        .unwrap();
    existing_machine(dir.path(), &key, Some(address));
    // Replace only the test server bootstrap key so this local mock is the pinned agent.
    let record = dir.path().join(&owner).join("metal.json");
    let mut state: serde_json::Value = read_json(&record).unwrap();
    state["source"]["credentials"]["admin_secret"] = json!(credentials.admin_secret);
    std::fs::write(&record, serde_json::to_vec(&state).unwrap()).unwrap();
    let first = Enrollment {
        node_id: iroh::SecretKey::generate().public().to_string(),
        enrollment_id: "a".repeat(64),
        bundle: None,
    };
    let changed = Enrollment {
        node_id: iroh::SecretKey::generate().public().to_string(),
        enrollment_id: "b".repeat(64),
        bundle: None,
    };
    let expected = first.clone();
    let task = tokio::spawn(async move {
        for (owner, enrollment) in [
            (None, first.clone()),
            (Some(owner.clone()), first),
            (Some(owner), changed),
        ] {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let request: wire::Request =
                serde_json::from_slice(&recv.read_to_end(wire::MAX_MESSAGE).await.unwrap())
                    .unwrap();
            assert!(matches!(request.operation, Operation::Status));
            let response = Response::Status {
                owner,
                enrollment,
                running: true,
            };
            send.write_all(&serde_json::to_vec(&response).unwrap())
                .await
                .unwrap();
            send.finish().unwrap();
            connection.closed().await;
        }
        endpoint.close().await;
    });
    assert!(
        service
            .execute(Request::Restart {
                name: "metal".into()
            })
            .await
            .unwrap_err()
            .to_string()
            .contains("owner binding")
    );
    assert!(service.list().unwrap()["machines"][0]["enrollment"].is_null());
    assert_eq!(service.resolve("metal").await.unwrap(), expected);
    assert!(
        service
            .resolve("metal")
            .await
            .unwrap_err()
            .to_string()
            .contains("enrollment changed")
    );
    assert_eq!(
        service.list().unwrap()["machines"][0]["enrollment"]["node_id"],
        expected.node_id
    );
    task.await.unwrap();
}

#[tokio::test]
async fn enrolled_owner_prepares_verified_bootstrap_and_rejects_another_transport() {
    let dir = tempfile::tempdir().unwrap();
    let key = iroh::SecretKey::generate();
    let bundle = common::bundle(&key);
    let service = Service::new(key.clone(), dir.path())
        .unwrap()
        .with_owner_enrollment(bundle.clone())
        .unwrap();
    let bootstrap = dir.path().join("bootstrap.json");
    service
        .execute(Request::Prepare {
            name: "worker".into(),
            bootstrap_file: bootstrap.clone(),
            admin_addr: None,
            serve_args: vec![],
        })
        .await
        .unwrap();
    let env: std::collections::BTreeMap<String, String> = read_json(&bootstrap).unwrap();
    let principal = hellas_rpc::protocol::work_grant::records::Principal::decode(
        &hex::decode(&env["HELLAS_REMOTE_OWNER_ENROLLMENT"]).unwrap(),
    )
    .unwrap();
    assert_eq!(principal.bundle(), &bundle);
    assert_eq!(principal.transport(), *key.public().as_bytes());
    assert!(
        Service::new(iroh::SecretKey::generate(), dir.path())
            .unwrap()
            .with_owner_enrollment(bundle)
            .is_err()
    );
}
