#![cfg(unix)]

use hellas_auth::authority::NodeKey;
use hellas_cloud::wire::Owner;
use hellas_cloud::{
    config::read_json,
    internal_rpc,
    management::{Request, Service},
};
use hellas_work::test_support::actors::{ROOT, STRANGER};
use serde_json::json;
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

/// An owner principal administering from its own node.
fn owner(actor: hellas_auth::test_support::Actor) -> Owner {
    Owner {
        principal: actor.principal(),
        transport: iroh::SecretKey::generate(),
        node: actor.node_key(),
    }
}
fn node_key(owner: &Owner) -> NodeKey {
    owner.node_key().unwrap()
}
fn inventory(root: &std::path::Path, owner: &Owner) -> std::path::PathBuf {
    root.join(format!("p256-{}", hex::encode(owner.principal.as_bytes())))
}

// Seed an existing inventory without reaching a cloud provider.
fn existing_machine(
    root: &std::path::Path,
    owner: &Owner,
    address: Option<std::net::SocketAddr>,
) -> hellas_cloud::config::Credentials {
    use hellas_cloud::config::{Credentials, save_private};
    let credentials = Credentials::generate().owned_by(owner.principal, node_key(owner));
    save_private(
        &inventory(root, owner).join("metal.json"),
        &json!({
            "name": "metal", "owner": hex::encode(owner.principal.as_bytes()),
            "source": {"kind":"bare-metal", "credentials":credentials, "admin_addr":address},
            "enrollment":null, "last_seen_unix":null, "running":null,
        }),
        true,
    )
    .unwrap();
    credentials
}

#[tokio::test]
async fn a_half_bound_owner_fails_before_receipts_bootstrap_or_provider_access() {
    use hellas_cloud::config::{Credentials, ProviderConfig, Spec, Trust};
    let dir = tempfile::tempdir().unwrap();
    let owner = owner(ROOT);
    let spec = Spec {
        name: "blocked".into(),
        image: format!("registry/image@sha256:{}", "a".repeat(64)),
        provider: ProviderConfig::Docker { gpus: false },
        trust: Trust::Token,
        serve_args: vec![],
    };
    let receipt = dir.path().join("receipt.json");
    let bound = Credentials::generate().owned_by(owner.principal, node_key(&owner));
    for (owner, node) in [
        (bound.owner.clone(), None),
        (None, bound.owner_node.clone()),
        // A node key is never an owner principal, nor the reverse.
        (bound.owner_node.clone(), bound.owner.clone()),
    ] {
        let mut credentials = Credentials::generate();
        credentials.owner = owner;
        credentials.owner_node = node;
        assert!(
            hellas_cloud::deployment::create_with_credentials(spec.clone(), &receipt, credentials)
                .await
                .unwrap_err()
                .to_string()
                .contains("both or neither")
        );
    }
    assert!(!receipt.exists());
}

#[tokio::test]
async fn inventory_is_scoped_to_identity_and_never_returns_bootstrap_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let owner = owner(ROOT);
    let a = Service::new(owner.clone(), dir.path()).unwrap();
    let b = Service::new(self::owner(STRANGER), dir.path()).unwrap();
    let bootstrap = dir.path().join("bootstrap.json");
    let credentials = existing_machine(dir.path(), &owner, None);
    hellas_cloud::config::save_private(&bootstrap, &credentials.env_for_args(&[]).unwrap(), true)
        .unwrap();
    let env: serde_json::Value = read_json(&bootstrap).unwrap();
    assert_eq!(env["HELLAS_REMOTE_OWNER"], a.owner());
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
        Service::new(owner, dir.path()).unwrap().list().unwrap()
    );
}

#[tokio::test]
async fn rpc_handles_real_frames_and_shares_the_cli_service() {
    let dir = tempfile::tempdir().unwrap();
    let owner = owner(ROOT);
    let service = Service::new(owner.clone(), &dir.path().join("inventory")).unwrap();
    let expected_owner = service.owner();
    existing_machine(&dir.path().join("inventory"), &owner, None);
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
    assert_eq!(inventory["owner"], expected_owner);
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
    let duplicate = Service::new(owner, &dir.path().join("inventory")).unwrap();
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
    let service = Service::new(owner(ROOT), &dir.path().join("inventory")).unwrap();
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
    let service = Service::new(owner(ROOT), &dir.path().join("inventory")).unwrap();
    assert!(
        internal_rpc::serve_until(service, &socket, std::future::ready(()))
            .await
            .is_err()
    );
    assert_eq!(std::fs::read_to_string(&socket).unwrap(), "keep me");
}

/// A worker enrollment whose transport key is `key`'s.
fn worker(key: &iroh::SecretKey) -> hellas_cloud::config::Enrollment {
    let bundle = hellas_work::test_support::software_enrollment(7, *key.public().as_bytes());
    hellas_cloud::config::Enrollment {
        node_id: key.public().to_string(),
        enrollment_id: bundle.content_id().to_string(),
        bundle: hex::encode(bundle.canonical_bytes()),
    }
}

#[tokio::test]
async fn enrollment_requires_owner_confirmation_and_cannot_be_silently_replaced() {
    use hellas_cloud::{
        config::Credentials,
        wire::{self, Operation, Response},
    };
    use iroh::{Endpoint, endpoint::presets};
    let dir = tempfile::tempdir().unwrap();
    let owner = owner(ROOT);
    let service = Service::new(owner.clone(), dir.path()).unwrap();
    let principal = service.owner();
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
    existing_machine(dir.path(), &owner, Some(address));
    // Replace only the test server bootstrap key so this local mock is the pinned agent.
    let record = inventory(dir.path(), &owner).join("metal.json");
    let mut state: serde_json::Value = read_json(&record).unwrap();
    state["source"]["credentials"]["admin_secret"] = json!(credentials.admin_secret);
    std::fs::write(&record, serde_json::to_vec(&state).unwrap()).unwrap();
    let first = worker(&iroh::SecretKey::generate());
    let changed = worker(&iroh::SecretKey::generate());
    let expected = first.clone();
    let node = node_key(&owner);
    let task = tokio::spawn(async move {
        for (owner, enrollment) in [
            (None, first.clone()),
            (Some(principal.clone()), first),
            (Some(principal), changed),
        ] {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let request: wire::Request =
                serde_json::from_slice(&recv.read_to_end(wire::MAX_MESSAGE).await.unwrap())
                    .unwrap();
            assert!(matches!(request.operation, Operation::Status));
            // The owner's node key proves this exact connection.
            let proof: [u8; 64] = hex::decode(request.proof.unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            hellas_auth::signature::verify_digest_signature(
                &node.public_key(),
                &hellas_auth::Signature::Secp256k1(proof),
                wire::session_digest(&connection).unwrap(),
            )
            .unwrap();
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
async fn an_owner_prepares_a_bootstrap_naming_its_principal_and_node() {
    use hellas_cloud::{config::Credentials, wire};
    let dir = tempfile::tempdir().unwrap();
    let owner = owner(ROOT);
    let service = Service::new(owner.clone(), dir.path()).unwrap();
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
    let credentials = Credentials {
        admin_secret: env["HELLAS_REMOTE_KEY"].clone(),
        token: env["HELLAS_REMOTE_TOKEN"].clone(),
        owner: Some(env["HELLAS_REMOTE_OWNER"].clone()),
        owner_node: Some(env["HELLAS_REMOTE_OWNER_NODE"].clone()),
    };
    let (principal, node) = credentials.owner().unwrap().unwrap();
    assert_eq!(principal, ROOT.principal());
    assert_eq!(
        principal.public_key().kind(),
        hellas_auth::SignatureKind::P256
    );
    assert_eq!(node, node_key(&owner));
    assert_eq!(
        node.public_key().kind(),
        hellas_auth::SignatureKind::Secp256k1
    );
    // Neither another principal nor another of the owner's nodes may
    // administer the machine; the call is refused before dialing.
    for other in [
        self::owner(STRANGER),
        Owner {
            node: STRANGER.node_key(),
            ..owner.clone()
        },
    ] {
        assert!(matches!(
            wire::call_as(&credentials, None, wire::Operation::Status, Some(&other)).await,
            Err(wire::AdminError::OwnerKey)
        ));
    }
    assert!(matches!(
        wire::call(&credentials, None, wire::Operation::Status).await,
        Err(wire::AdminError::OwnerKey)
    ));
}
