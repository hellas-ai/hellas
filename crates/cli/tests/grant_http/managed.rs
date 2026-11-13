//! Stateful verbs each send one Configure; a restart reads the same journal document.
use super::*;
use hellas_sdk::node_control::bootstrap::Invitation;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paired_owner_configures_routes_and_restart_preserves_them() {
    let occupied = std::net::TcpListener::bind("127.0.0.1:8080").unwrap();
    let root = tempfile::tempdir().unwrap();
    let owner = Cli::new(root.path(), "owner", AGENT_PASSKEY);
    owner.run(&["identity", "init"]).await;
    let worker = Cli::new(root.path(), "worker", ROOT_PASSKEY);
    let reserved = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = reserved.local_addr().unwrap().port().to_string();
    drop(reserved);
    let mut process = worker.spawn(&["serve", "--port", &port], "managed.log");
    let encoded = process.wait_for("hellas-invite:").await;
    let mut invitation = Invitation::decode(&format!("hellas-invite:{encoded}")).unwrap();
    // Remote owner control uses the pinned transport on loopback in this process fixture.
    for address in &mut invitation.addresses {
        if address.is_ipv4() {
            address.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
        }
    }
    let paired = owner
        .run(&["pair", &invitation.encode().unwrap(), "--name", "worker"])
        .await;
    let paired: Value = serde_json::from_str(&paired).unwrap();
    assert_eq!(paired["node_id"], invitation.node.to_string());
    process.wait_for("Daemon ready;").await;
    let profile_path = owner.home.join("nodes/worker/profile.json");
    let mut local: Value = serde_json::from_slice(&std::fs::read(&profile_path).unwrap()).unwrap();
    local.as_object_mut().unwrap().remove("remote_node");
    local.as_object_mut().unwrap().remove("remote_addresses");
    local["local"] = json!({"certificate": worker.home.join("provider/control.cert.der"), "server_name": "localhost"});
    let local_path = profile_path.with_file_name("local.json");
    hellas_private::write_atomically(&local_path, ".local", &serde_json::to_vec(&local).unwrap())
        .unwrap();
    owner
        .run(&[
            "routes",
            "--profile",
            string(&local_path),
            "--control-socket",
            string(&worker.home.join("provider/control.sock")),
        ])
        .await;
    drop(occupied);
    // Execute the paid-policy command exactly as the selling guide spells it.
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let guide = std::fs::read_to_string(repository.join("docs/paid-gateway.md")).unwrap();
    let recipe = guide
        .lines()
        .find(|line| line.starts_with("hellas admin "))
        .unwrap();
    let arguments: Vec<String> = recipe
        .split_whitespace()
        .skip(1)
        .map(|arg| {
            if arg.starts_with("docs/") {
                repository.join(arg).display().to_string()
            } else {
                arg.into()
            }
        })
        .collect();
    let arguments: Vec<_> = arguments.iter().map(String::as_str).collect();
    let applied: Value = serde_json::from_str(&owner.run(&arguments).await).unwrap();
    assert_eq!(applied["PaidPolicyChanged"]["revision"], 1);
    assert!(
        !owner.output(&arguments).await.status.success(),
        "stale policy revision must fail"
    );

    let key = root.path().join("api.key");
    std::fs::write(&key, "write-only-fixture-key").unwrap();
    owner
        .run(&[
            "backend",
            "add",
            "upstream",
            "https://example.com/v1",
            "--key-file",
            string(&key),
        ])
        .await;
    owner.run(&["route", "add", "model@upstream"]).await;
    owner.run(&["route", "listen", "127.0.0.1:0"]).await;
    let before = owner.run(&["routes"]).await;
    assert!(
        before.contains("model") && before.contains("upstream"),
        "{before}"
    );
    assert!(!before.contains("write-only-fixture-key"));
    let bad = owner
        .output(&[
            "backend",
            "add",
            "invalid",
            "http://example.com",
            "--key-file",
            string(&key),
        ])
        .await;
    assert!(!bad.status.success());
    assert_eq!(owner.run(&["routes"]).await, before);
    process.stop().await;
    let saved = saved_configuration(&worker).await;
    let reserved = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let next_port = reserved.local_addr().unwrap().port();
    drop(reserved);
    let mut restarted = worker.spawn(
        &["serve", "--port", &next_port.to_string()],
        "managed-restart.log",
    );
    restarted.wait_for("Daemon ready;").await;
    assert!(
        std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, next_port)).is_err(),
        "explicit startup port must be bound"
    );
    assert!(
        std::net::UdpSocket::bind(format!("127.0.0.1:{port}")).is_ok(),
        "old port must be released"
    );
    let mut remote: Value = serde_json::from_slice(&std::fs::read(&profile_path).unwrap()).unwrap();
    remote["remote_addresses"] = json!([format!("127.0.0.1:{next_port}")]);
    hellas_private::write_atomically(
        &profile_path,
        ".moved",
        &serde_json::to_vec(&remote).unwrap(),
    )
    .unwrap();
    assert_eq!(owner.run(&["routes"]).await, before);
    restarted.stop().await;
    let moved = saved_configuration(&worker).await;
    assert_eq!(moved.revision, saved.revision.next().unwrap());
    let mut expected: hellas_sdk::daemon_config::Document =
        serde_json::from_str(&saved.document).unwrap();
    let hellas_sdk::daemon_config::Listener::Iroh { port, .. } =
        expected.listeners.get_mut("work").unwrap()
    else {
        panic!("work listener")
    };
    *port = next_port;
    assert_eq!(
        serde_json::from_str::<Value>(&moved.document).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
    assert_eq!(moved.secrets, saved.secrets);
    // No flag on the next start: the journal itself must carry the edit.
    let mut restarted = worker.spawn(&["serve"], "managed-restored.log");
    restarted.wait_for("Daemon ready;").await;
    assert_eq!(owner.run(&["routes"]).await, before);
    owner.run(&["route", "rm", "model@upstream"]).await;
    assert!(!owner.run(&["routes"]).await.contains("model"));
    owner.run(&["backend", "rm", "upstream"]).await;
    restarted.stop().await;
}

async fn saved_configuration(
    cli: &Cli,
) -> hellas_authority::model::grant::configuration::ConfigurationDocument {
    let root = hellas_private::StoreLocation::from_home(
        &cli.home.join("provider/authority"),
        hellas_private::Durability::Crash,
    );
    let mut store = hellas_authority::work_store::grant::NodeStore::open(
        &root,
        hellas_authority::model::grant::grant_network(),
        None,
        hellas_auth::authority::UnixMillis::now().unwrap(),
    )
    .await
    .unwrap();
    let saved = store.state().configuration().unwrap().clone();
    store.close().await;
    saved
}
