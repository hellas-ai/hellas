use super::*;
use crate::peers::test_markers::TestService as Node;

fn peer(byte: u8) -> PeerId {
    PeerId::from([byte; 32])
}

fn config() -> PeerRegistryConfig {
    PeerRegistryConfig {
        max_peers: 16,
        max_services_per_peer: 4,
        max_in_flight_per_peer: 2,
        max_in_flight_total: 4,
        bucket_capacity: 4.0,
        bucket_refill_per_sec: 1.0,
        ..PeerRegistryConfig::default()
    }
}

#[test]
fn successful_rpc_records_authenticated_service_and_releases_slot() {
    let manager = PeerManager::with_config(config());
    let id = peer(1);

    let mut permit = manager
        .acquire_rpc(
            id,
            RequestKind::for_method::<crate::peers::test_markers::GetNodeInfo>(),
            RpcObservation::authenticated_transport("iroh"),
        )
        .expect("request should be admitted");
    assert_eq!(
        manager
            .with_registry(PeerRegistry::total_in_flight)
            .expect("registry should be readable"),
        1
    );

    permit.finish_ok();

    let registry = manager.snapshot().expect("registry should be readable");
    let entry = registry.get(id).expect("peer should exist");
    assert_eq!(entry.transport_security, TransportSecurity::Authenticated);
    assert!(entry.has_service_key::<Node>());
    assert_eq!(entry.in_flight, 0);
    assert_eq!(registry.total_in_flight(), 0);
}

#[test]
fn connect_error_does_not_authenticate_or_observe_service() {
    let manager = PeerManager::with_config(config());
    let id = peer(2);

    let mut permit = manager
        .acquire_rpc(
            id,
            RequestKind::for_method::<crate::peers::test_markers::GetNodeInfo>(),
            RpcObservation::authenticated_transport("iroh"),
        )
        .expect("request should be admitted");
    permit.finish_connect_err("connect failed");

    let registry = manager.snapshot().expect("registry should be readable");
    let entry = registry.get(id).expect("peer should exist");
    assert_eq!(entry.transport_security, TransportSecurity::Untrusted);
    assert!(!entry.has_service_key::<Node>());
    assert_eq!(entry.in_flight, 0);
}

#[test]
fn dropped_guard_records_cancellation() {
    let manager = PeerManager::with_config(config());
    let id = peer(3);

    let permit = manager
        .acquire_rpc(
            id,
            RequestKind::for_method::<crate::peers::test_markers::GetNodeInfo>(),
            RpcObservation::authenticated_transport("iroh"),
        )
        .expect("request should be admitted");
    drop(permit);

    let registry = manager.snapshot().expect("registry should be readable");
    let entry = registry.get(id).expect("peer should exist");
    assert_eq!(entry.in_flight, 0);
    assert_eq!(registry.total_in_flight(), 0);
}

#[test]
fn finish_ok_after_forget_preserves_tombstone_and_purges_entry() {
    // Regression for the bug where finish_ok went through `apply` (not
    // `apply_completion`), so the Discovered/ServiceObserved events
    // emitted as part of completion would un-tombstone the peer. That
    // left the final `release` looking at a live entry, so an in-flight
    // RPC completing after `forget_peer` would re-enliven the peer.
    let manager = PeerManager::with_config(config());
    let id = peer(7);

    let mut permit = manager
        .acquire_rpc(
            id,
            RequestKind::for_method::<crate::peers::test_markers::GetNodeInfo>(),
            RpcObservation::authenticated_transport("iroh"),
        )
        .expect("request should be admitted");

    // Forget while a permit is in flight. The peer is tombstoned —
    // hidden from queries but still bookkept so release doesn't
    // double-count.
    let change = manager.forget_peer(id).expect("forget should succeed");
    assert!(change.removed, "forget reports removed even when deferred");
    assert!(
        manager
            .snapshot()
            .expect("registry readable")
            .get(id)
            .is_none(),
        "tombstoned peer hidden from snapshot"
    );

    // Completing the RPC must not revive the peer — the entry should
    // be purged after the final release.
    permit.finish_ok();

    let registry = manager.snapshot().expect("registry readable");
    assert!(
        registry.get(id).is_none(),
        "finish_ok must preserve tombstone so release purges the entry"
    );
    assert_eq!(registry.total_in_flight(), 0);
}

#[test]
#[should_panic(expected = "Permit for peer")]
fn dropping_armed_permit_panics_in_debug() {
    // Belt-and-braces — the only way to leak the in-flight slot is to
    // construct a Permit and drop it without going through
    // `PeerRegistry::release`. Higher-level guards always disarm via
    // release, so we exercise the raw Permit here.
    let mut registry = PeerRegistry::with_config(config());
    let id = peer(8);

    let permit = registry
        .try_acquire(
            0,
            id,
            RequestKind::for_method::<crate::peers::test_markers::GetNodeInfo>(),
        )
        .expect("permit should be admitted");
    // Dropping without release should fire the debug tripwire.
    drop(permit);
}
