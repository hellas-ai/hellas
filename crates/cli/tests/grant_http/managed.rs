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
    let mut restarted = worker.spawn(&["serve", "--port", &port], "managed-restart.log");
    restarted.wait_for("Daemon ready;").await;
    assert_eq!(owner.run(&["routes"]).await, before);
    owner.run(&["route", "rm", "model@upstream"]).await;
    assert!(!owner.run(&["routes"]).await.contains("model"));
    owner.run(&["backend", "rm", "upstream"]).await;
    restarted.stop().await;
}
