use super::*;
use crate::peers::test_markers::TestService as Node;

const NODE: &str = "hellas.swarm.v1.Node";
const GET_NODE_INFO: RequestKind =
    RequestKind::for_method::<crate::peers::test_markers::GetNodeInfo>();

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
fn tracks_service_observations_without_security_downgrade() {
    let mut registry = PeerRegistry::with_config(config());
    let id = peer(1);

    let change = registry.apply(
        10,
        id,
        PeerEvent::Discovered {
            source: DiscoverySource::Manual,
            transport_security: TransportSecurity::Authenticated,
        },
    );
    assert!(change.inserted);

    registry.apply(
        20,
        id,
        PeerEvent::ServiceObserved {
            service: NODE,
            transport_security: TransportSecurity::Untrusted,
        },
    );

    let entry = registry.get(id).expect("peer should exist");
    assert_eq!(entry.transport_security, TransportSecurity::Authenticated);
    assert_eq!(entry.auth_level, AuthLevel::Authenticated);
    assert!(entry.has_service(NODE));
    assert!(entry.has_service_key::<Node>());
    assert!(entry.service::<Node>().is_some());
}

#[test]
fn observe_discovered_service_reports_new_service_once() {
    let mut registry = PeerRegistry::with_config(config());
    let id = peer(8);

    let first = registry.observe_discovered_service(
        10,
        id,
        DiscoverySource::Mdns,
        NODE,
        TransportSecurity::Untrusted,
    );
    assert!(first.peer_inserted);
    assert!(first.service_inserted);
    assert!(!first.dropped);

    let second = registry.observe_discovered_service(
        20,
        id,
        DiscoverySource::Mdns,
        NODE,
        TransportSecurity::Untrusted,
    );
    assert!(!second.peer_inserted);
    assert!(!second.service_inserted);

    let entry = registry.get(id).expect("peer should exist");
    assert!(entry.has_service(NODE));
    assert_eq!(registry.iter().filter(|p| p.has_service(NODE)).count(), 1);
}

#[test]
fn enforces_per_peer_in_flight_limit() {
    let mut registry = PeerRegistry::with_config(PeerRegistryConfig {
        max_in_flight_per_peer: 1,
        bucket_capacity: 10.0,
        ..config()
    });
    let id = peer(2);

    let permit = registry
        .try_acquire(0, id, GET_NODE_INFO)
        .expect("first request should be admitted");
    let denied = registry
        .try_acquire(1, id, GET_NODE_INFO)
        .expect_err("second request should exceed peer in-flight limit");
    assert_eq!(denied, AcquireDenied::InFlightPeer { peer: id, limit: 1 });

    registry.release(2, permit, Outcome::ok(5.0));
    let permit = registry
        .try_acquire(3, id, GET_NODE_INFO)
        .expect("slot should reopen after release");
    registry.release(4, permit, Outcome::ok(5.0));
}

#[test]
fn enforces_token_bucket_rate_limit() {
    let mut registry = PeerRegistry::with_config(PeerRegistryConfig {
        bucket_capacity: 1.0,
        bucket_refill_per_sec: 0.0,
        ..config()
    });
    let id = peer(3);

    let permit = registry
        .try_acquire(0, id, GET_NODE_INFO)
        .expect("first request should spend the only token");
    registry.release(1, permit, Outcome::ok(5.0));

    let denied = registry
        .try_acquire(2, id, GET_NODE_INFO)
        .expect_err("second request should be rate limited");
    assert_eq!(
        denied,
        AcquireDenied::RateLimited {
            peer: id,
            retry_after_ms: None
        }
    );
}

#[test]
fn records_latency_ema_and_success_counts() {
    let mut registry = PeerRegistry::with_config(config());
    let id = peer(4);

    let first = registry.try_acquire(0, id, GET_NODE_INFO).unwrap();
    registry.release(10, first, Outcome::ok(100.0));
    let second = registry.try_acquire(20, id, GET_NODE_INFO).unwrap();
    registry.release(30, second, Outcome::ok(200.0));

    let entry = registry.get(id).unwrap();
    assert_eq!(entry.success_count, 2);
    assert_eq!(entry.service_state(NODE).unwrap().success_count, 2);
    assert!((entry.latency_ms().unwrap() - 120.0).abs() < f64::EPSILON);
}

#[test]
fn evicts_oldest_idle_peer_when_full() {
    let mut registry = PeerRegistry::with_config(PeerRegistryConfig {
        max_peers: 2,
        ..config()
    });
    let first = peer(5);
    let second = peer(6);
    let third = peer(7);

    registry.apply(
        10,
        first,
        PeerEvent::Discovered {
            source: DiscoverySource::Manual,
            transport_security: TransportSecurity::Untrusted,
        },
    );
    registry.apply(
        20,
        second,
        PeerEvent::Discovered {
            source: DiscoverySource::Manual,
            transport_security: TransportSecurity::Untrusted,
        },
    );
    let change = registry.apply(
        30,
        third,
        PeerEvent::Discovered {
            source: DiscoverySource::Manual,
            transport_security: TransportSecurity::Untrusted,
        },
    );

    assert_eq!(change.evicted, Some(first));
    assert!(registry.get(first).is_none());
    assert!(registry.get(second).is_some());
    assert!(registry.get(third).is_some());
}

#[test]
fn normalizes_invalid_float_config() {
    let registry = PeerRegistry::with_config(PeerRegistryConfig {
        bucket_capacity: f64::NAN,
        bucket_refill_per_sec: -1.0,
        rtt_ema_alpha: 4.0,
        ..config()
    });

    assert_eq!(registry.config().bucket_capacity, 0.0);
    assert_eq!(registry.config().bucket_refill_per_sec, 0.0);
    assert_eq!(registry.config().rtt_ema_alpha, 1.0);
}

#[test]
fn validate_flags_sub_unit_bucket_capacity() {
    let reasons = PeerRegistryConfig {
        bucket_capacity: 0.5,
        bucket_refill_per_sec: 1.0,
        ..config()
    }
    .validate();
    assert_eq!(
        reasons.len(),
        1,
        "exactly one violation expected: {reasons:?}"
    );
    assert!(
        reasons[0].contains("bucket_capacity"),
        "violation should mention the failing knob: {}",
        reasons[0]
    );
}

#[test]
fn validate_accepts_capacity_zero_as_explicit_reject_all() {
    // capacity == 0.0 is the "reject everything" signal and is valid.
    let reasons = PeerRegistryConfig {
        bucket_capacity: 0.0,
        bucket_refill_per_sec: 0.0,
        ..config()
    }
    .validate();
    assert!(
        reasons.is_empty(),
        "capacity 0.0 must validate: {reasons:?}"
    );
}

#[test]
#[should_panic(expected = "PeerRegistryConfig is invalid")]
fn with_config_panics_on_unsatisfiable_bucket() {
    // Sub-unit capacity with positive refill: bucket can never hold a
    // full token. `with_config` should refuse to construct a registry
    // that would silently reject every rate-limited request.
    let _ = PeerRegistry::with_config(PeerRegistryConfig {
        bucket_capacity: 0.5,
        bucket_refill_per_sec: 1.0,
        ..config()
    });
}

#[test]
fn auth_level_ordering_matches_authority() {
    assert!(AuthLevel::Authenticated.allows_at_least(AuthLevel::Local));
    assert!(AuthLevel::Local.allows_at_least(AuthLevel::Untrusted));
    assert!(!AuthLevel::Local.allows_at_least(AuthLevel::Authenticated));
    assert!(!AuthLevel::Untrusted.allows_at_least(AuthLevel::Local));
    assert!(AuthLevel::Authenticated.allows_at_least(AuthLevel::Authenticated));
    assert!(AuthLevel::Untrusted.allows_at_least(AuthLevel::Untrusted));
}

#[test]
fn len_and_is_empty_hide_tombstoned_peers() {
    // `len`/`is_empty` must agree with `get`/`iter` visibility — a peer
    // forgotten while a permit is still in flight is hidden from queries,
    // so it must not be counted either. (The internal eviction path uses
    // the raw HashMap len directly; that's what enforces `max_peers`.)
    let mut registry = PeerRegistry::with_config(config());
    let id = peer(42);

    let permit = registry.try_acquire(0, id, GET_NODE_INFO).unwrap();
    assert_eq!(registry.len(), 1);
    assert!(!registry.is_empty());

    // Tombstone while in flight: visible queries say "no peer", but the
    // internal map still has the entry until release.
    let _ = registry.apply(5, id, PeerEvent::Forgotten);
    assert!(registry.get(id).is_none());
    assert_eq!(
        registry.len(),
        0,
        "len must match the visible view (no tombstoned entries)",
    );
    assert!(registry.is_empty());

    // Release drops the underlying entry too.
    let _ = registry.release(10, permit, Outcome::ok(5.0));
    assert_eq!(registry.len(), 0);
    assert!(registry.is_empty());
}

#[test]
fn forgotten_with_in_flight_defers_until_release() {
    let mut registry = PeerRegistry::with_config(config());
    let id = peer(11);

    let permit = registry.try_acquire(0, id, GET_NODE_INFO).unwrap();
    // Peer is in queries while in flight.
    assert!(registry.get(id).is_some());
    assert_eq!(registry.total_in_flight(), 1);

    // Forget while in flight: hidden from queries, but still alive
    // internally so the release path doesn't double-count.
    let change = registry.apply(5, id, PeerEvent::Forgotten);
    assert!(
        change.removed,
        "Forgotten reports removed even when deferred"
    );
    assert!(
        registry.get(id).is_none(),
        "tombstoned peer hidden from get"
    );
    assert_eq!(
        registry.iter().count(),
        0,
        "tombstoned peer hidden from iter"
    );
    assert_eq!(registry.total_in_flight(), 1);

    // Release the permit: now the entry is actually gone.
    let change = registry.release(10, permit, Outcome::ok(5.0));
    assert!(change.removed);
    assert_eq!(registry.total_in_flight(), 0);
}

#[test]
fn forgotten_immediate_when_idle() {
    let mut registry = PeerRegistry::with_config(config());
    let id = peer(12);

    registry.apply(
        0,
        id,
        PeerEvent::Discovered {
            source: DiscoverySource::Manual,
            transport_security: TransportSecurity::Untrusted,
        },
    );

    let change = registry.apply(5, id, PeerEvent::Forgotten);
    assert!(change.removed);
    assert!(registry.get(id).is_none());
}

#[test]
fn rediscovery_revives_tombstoned_peer() {
    let mut registry = PeerRegistry::with_config(config());
    let id = peer(13);

    let permit = registry.try_acquire(0, id, GET_NODE_INFO).unwrap();
    registry.apply(5, id, PeerEvent::Forgotten);
    assert!(registry.get(id).is_none());

    registry.apply(
        10,
        id,
        PeerEvent::Discovered {
            source: DiscoverySource::Mdns,
            transport_security: TransportSecurity::Authenticated,
        },
    );
    // Re-discovery un-tombstones; release doesn't purge a live entry.
    registry.release(15, permit, Outcome::ok(5.0));
    let entry = registry.get(id).expect("peer should be live again");
    assert_eq!(entry.transport_security, TransportSecurity::Authenticated);
}

#[test]
fn service_cap_evicts_lowest_value() {
    let mut registry = PeerRegistry::with_config(PeerRegistryConfig {
        max_services_per_peer: 2,
        ..config()
    });
    let id = peer(14);

    // Three services; the cap is two. The first observed should be
    // evicted (zero successes, oldest last_seen).
    for (i, name) in ["svc.A", "svc.B", "svc.C"].iter().enumerate() {
        registry.apply(
            (i as u64) * 10,
            id,
            PeerEvent::ServiceObserved {
                service: name,
                transport_security: TransportSecurity::Untrusted,
            },
        );
    }
    let entry = registry.get(id).expect("peer should exist");
    assert_eq!(entry.services.len(), 2);
    assert!(!entry.has_service("svc.A"), "lowest-value service evicted");
    assert!(entry.has_service("svc.B"));
    assert!(entry.has_service("svc.C"));
}

#[test]
fn eviction_tie_break_uses_peer_id_so_choice_is_deterministic() {
    // With max_peers=2, inserting a third peer must evict one of the
    // existing two. When every other eviction key is identical (same
    // discovery moment, same trust, same security, same services,
    // same success count), the only differentiator is PeerId. The
    // trailing PeerId in eviction_key turns randomized HashMap
    // iteration into a stable, lowest-id-evicts-first rule — repeated
    // runs against the same inputs must always evict the same peer.
    let lower = peer(1);
    let upper = peer(2);

    // Run a small number of trials with fresh registries; without the
    // PeerId tiebreaker, HashMap's iteration order would surface here
    // as a random pick.
    for _ in 0..16 {
        let mut registry = PeerRegistry::with_config(PeerRegistryConfig {
            max_peers: 2,
            ..config()
        });

        registry.apply(
            0,
            lower,
            PeerEvent::Discovered {
                source: DiscoverySource::Manual,
                transport_security: TransportSecurity::Untrusted,
            },
        );
        registry.apply(
            0,
            upper,
            PeerEvent::Discovered {
                source: DiscoverySource::Manual,
                transport_security: TransportSecurity::Untrusted,
            },
        );

        let third = peer(3);
        let change = registry.apply(
            0,
            third,
            PeerEvent::Discovered {
                source: DiscoverySource::Manual,
                transport_security: TransportSecurity::Untrusted,
            },
        );
        assert_eq!(
            change.evicted,
            Some(lower),
            "lowest PeerId should win the eviction tie-break every run"
        );
    }
}

#[test]
fn peer_id_display_alternate_emits_full_hex() {
    let id = peer(0xab);
    let short = format!("{id}");
    let full = format!("{id:#}");
    assert!(short.contains('…'), "default Display truncates");
    assert_eq!(full.len(), 64, "alternate emits 64 hex chars");
    assert!(full.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn quarantine_survives_discovery_completion_and_eviction_until_expiry() {
    let mut registry = PeerRegistry::with_config(PeerRegistryConfig {
        max_peers: 1,
        ..config()
    });
    let id = peer(1);
    let permit = registry.try_acquire(0, id, GET_NODE_INFO).unwrap();
    registry.apply(1, id, PeerEvent::Blocked { until_ms: 100 });
    registry.apply(
        2,
        id,
        PeerEvent::Discovered {
            source: DiscoverySource::Manual,
            transport_security: TransportSecurity::Authenticated,
        },
    );
    registry.release(3, permit, Outcome::ok(3.0));
    assert!(registry.try_acquire(4, id, GET_NODE_INFO).is_err());
    assert!(registry.try_acquire(4, peer(2), GET_NODE_INFO).is_err());
    assert_eq!(registry.get(id).unwrap().blocked_until_ms, 100);
    let permit = registry.try_acquire(100, id, GET_NODE_INFO).unwrap();
    registry.release(101, permit, Outcome::ok(1.0));
    let permit = registry.try_acquire(102, peer(2), GET_NODE_INFO).unwrap();
    registry.release(103, permit, Outcome::ok(1.0));
}
