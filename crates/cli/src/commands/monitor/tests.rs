use super::*;
use hellas_wire::iroh::swarm::{Scope, SwarmEngine, peers::static_feed};
use hellas_wire::peers::PeerRegistryConfig;

fn endpoint_id(number: usize) -> EndpointId {
    let mut secret = [0; 32];
    secret[..8].copy_from_slice(&u64::try_from(number).unwrap().to_le_bytes());
    SecretKey::from(secret).public()
}

async fn discovered(number: usize) -> Peer {
    SwarmEngine::new(
        endpoint_id(0),
        Node::ALPN.as_bytes(),
        vec![static_feed(vec![endpoint_id(number)], 0, 0, Scope::Any)],
    )
    .next()
    .await
    .unwrap()
    .unwrap()
}

#[tokio::test]
async fn interrogation_admission_bounds_active_and_completed_tasks() {
    let endpoint = Endpoint::builder(presets::Minimal).bind().await.unwrap();
    let registry = ServiceRegistry::new(&endpoint);
    let peer_manager = PeerManager::default();
    let admission =
        ConnectionSlots::new(MAX_INTERROGATIONS, MAX_INTERROGATIONS, MAX_INTERROGATIONS);
    let mut interrogations = Interrogations::new();
    let mut interrogated = 0;
    let mut tasks = Vec::new();
    // Completed responses still occupy their slots until the monitor drains them.
    for number in 1..=MAX_INTERROGATIONS {
        let permit = admission.try_acquire(None).unwrap();
        tasks.push(
            interrogations
                .spawn(async move { (endpoint_id(number), Err(anyhow::anyhow!("done")), permit) }),
        );
    }
    while tasks.iter().any(|task| !task.is_finished()) {
        tokio::task::yield_now().await;
    }
    let peer = discovered(MAX_INTERROGATIONS + 1).await;
    handle_discovery_event::<Node>(
        "node",
        &peer,
        DiscoveryEventContext {
            registry: &registry,
            peer_manager: &peer_manager,
            interrogate: true,
            interrogated: &mut interrogated,
            interrogations: &mut interrogations,
            admission: &admission,
        },
    );
    assert_eq!(interrogations.len(), MAX_INTERROGATIONS);
    assert_eq!(interrogated, 0, "full admission must not start a dial");

    drop(interrogations.join_next().await.unwrap().unwrap());
    let peer = discovered(MAX_INTERROGATIONS + 2).await;
    handle_discovery_event::<Node>(
        "node",
        &peer,
        DiscoveryEventContext {
            registry: &registry,
            peer_manager: &peer_manager,
            interrogate: true,
            interrogated: &mut interrogated,
            interrogations: &mut interrogations,
            admission: &admission,
        },
    );
    assert_eq!(interrogations.len(), MAX_INTERROGATIONS);
    assert_eq!(interrogated, 1, "draining a result must release admission");
    interrogations.shutdown().await;
    endpoint.close().await;
}

#[tokio::test]
async fn unavailable_or_full_registry_does_not_schedule_interrogation() {
    let endpoint = Endpoint::builder(presets::Minimal).bind().await.unwrap();
    let registry = ServiceRegistry::new(&endpoint);
    let unavailable = PeerManager::default();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = unavailable.with_registry(|_| panic!("poison registry for regression test"));
    }));
    let full = PeerManager::with_config(PeerRegistryConfig {
        max_peers: 0,
        ..PeerRegistryConfig::default()
    });
    let admission =
        ConnectionSlots::new(MAX_INTERROGATIONS, MAX_INTERROGATIONS, MAX_INTERROGATIONS);
    let peer = discovered(1).await;
    for peer_manager in [&unavailable, &full] {
        let mut interrogations = Interrogations::new();
        let mut interrogated = 0;
        handle_discovery_event::<Node>(
            "node",
            &peer,
            DiscoveryEventContext {
                registry: &registry,
                peer_manager,
                interrogate: true,
                interrogated: &mut interrogated,
                interrogations: &mut interrogations,
                admission: &admission,
            },
        );
        assert!(interrogations.is_empty());
        assert_eq!(interrogated, 0);
    }
    endpoint.close().await;
}

#[test]
fn peer_hint_processing_is_bounded_including_invalid_ids() {
    let hints = (1..=MAX_KNOWN_PEERS + 1)
        .map(|number| endpoint_id(number).as_bytes().to_vec())
        .collect();
    let (peers, invalid) = decode_known_peers(endpoint_id(0), hints);
    assert_eq!(peers.len(), MAX_KNOWN_PEERS);
    assert_eq!(invalid, 0);
    let (peers, invalid) = decode_known_peers(endpoint_id(0), vec![vec![]; MAX_KNOWN_PEERS + 1]);
    assert!(peers.is_empty());
    assert_eq!(invalid, MAX_KNOWN_PEERS);
}

#[test]
fn node_info_record_escapes_peer_controlled_fields() {
    let text = "\nevent=monitor-summary forged=true\r\x1b[2J\u{9b}31m\t\"\\";
    let info = GetNodeInfoResponse {
        node_id: text.into(),
        version: text.into(),
        build: text.into(),
        os: text.into(),
        uptime_seconds: 1,
        graffiti: [text.as_bytes(), &[0xff]].concat(),
        ..Default::default()
    };
    let record = node_info_record(endpoint_id(1), &info);
    assert_eq!(record.lines().count(), 1);
    assert!(record.chars().all(|character| !character.is_control()));
    assert!(record.contains(r#"reported_node_id="\nevent=monitor-summary"#));
    assert!(record.contains(r#"\"\\"#));
}

#[test]
fn error_records_escape_peer_controlled_messages() {
    let text = "\"\nevent=monitor-stop reason=forged\r\x1b[2J\u{9b}31m";
    for event in [
        "discovery-error service=node",
        "known-peers-error",
        "interrogate-error",
    ] {
        for peer in [None, Some(endpoint_id(1))] {
            let record = error_record(event, peer, text);
            assert_eq!(record.lines().count(), 1);
            assert!(record.chars().all(|character| !character.is_control()));
            assert!(record.contains(r#"error="\"\nevent=monitor-stop"#));
        }
    }
}
