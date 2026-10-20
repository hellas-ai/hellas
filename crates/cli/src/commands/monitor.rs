//! Discovery / peer-interrogation monitor.
//!
//! Races peer-discovery feeds (DHT + mDNS + peer-exchange) for the Node
//! service, optionally interrogates each peer with `get_node_info` +
//! `get_known_peers`, and prints the events as whitespace-separated
//! `key=value` records that downstream pipelines can grep.
//!
//! Uses `hellas_wire::iroh::swarm::ServiceRegistry` plus per-service
//! pools for peer discovery and interrogation.

use std::collections::HashSet;
use std::future;
use std::time::Duration;

use anyhow::Context;
use futures::StreamExt;
use hellas_client::iroh::build_client_registry;
use hellas_rpc::pb::swarm::{GetKnownPeersRequest, GetNodeInfoRequest, GetNodeInfoResponse};
use hellas_rpc::services::node::{Node, NodeClientImpl};
use hellas_wire::iroh::pool::PoolOptions;
use hellas_wire::iroh::swarm::{Peer, ServiceRegistry};
use hellas_wire::peers::{DiscoverySource, PeerId, PeerManager, RpcService, TransportSecurity};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointId, SecretKey};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::commands::CliResult;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const RPC_TIMEOUT: Duration = Duration::from_secs(3);

struct PeerInterrogationOutcome {
    node_info: GetNodeInfoResponse,
    known_peers: Vec<EndpointId>,
    invalid_known_peers: usize,
    known_peers_error: Option<String>,
}

struct DiscoveryEventContext<'a> {
    registry: &'a ServiceRegistry,
    peer_manager: &'a PeerManager,
    interrogate: bool,
    interrogated: &'a mut HashSet<EndpointId>,
    interrogations: &'a mut JoinSet<(EndpointId, anyhow::Result<PeerInterrogationOutcome>)>,
}

pub async fn run(
    timeout_secs: Option<u64>,
    interrogate: bool,
    secret_key: SecretKey,
) -> CliResult<()> {
    // Bind an iroh endpoint with the Node ALPN advertised (so peers can
    // route to us), then start an mDNS address-lookup keyed by the
    // endpoint id. The endpoint's address_lookup service isn't wired to
    // mDNS here because the discovery feed only needs subscribe()
    // semantics — peers in turn discover us via the endpoint's
    // default-preset N0 discovery path.
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![Node::ALPN.as_bytes().to_vec()])
        .bind()
        .await
        .context("failed to bind iroh endpoint")?;

    let discovery = build_client_registry(&endpoint)?;
    let mut registry = discovery.registry;
    registry.with_pool_options(PoolOptions {
        connect_timeout: CONNECT_TIMEOUT,
        ..PoolOptions::default()
    });
    let peer_exchange = discovery.peer_exchange;

    let peer_manager = PeerManager::default();
    let mut node_discovery = Box::pin(registry.discover::<Node>());

    let mut interrogations = JoinSet::new();
    let mut interrogated = HashSet::new();

    let mut interrogation_ok = 0usize;
    let mut interrogation_failed = 0usize;
    let mut hinted_peers = 0usize;
    let mut node_done = false;

    println!(
        "event=monitor-start local_peer={} interrogate={} timeout_secs={}",
        endpoint.id(),
        interrogate,
        timeout_secs
            .map(|secs| secs.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    println!("event=monitor-ready message=\"press Ctrl+C to stop\"");

    let monitor_timeout = async {
        if let Some(secs) = timeout_secs {
            tokio::time::sleep(Duration::from_secs(secs)).await;
        } else {
            future::pending::<()>().await;
        }
    };
    tokio::pin!(monitor_timeout);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("event=monitor-stop reason=signal");
                break;
            }
            _ = &mut monitor_timeout => {
                println!("event=monitor-stop reason=timeout");
                break;
            }
            peer = node_discovery.next(), if !node_done => {
                match peer {
                    Some(Ok(peer)) => {
                        handle_discovery_event::<Node>(
                            "node",
                            &peer,
                            DiscoveryEventContext {
                                registry: &registry,
                                peer_manager: &peer_manager,
                                interrogate,
                                interrogated: &mut interrogated,
                                interrogations: &mut interrogations,
                            },
                        );
                    }
                    Some(Err(err)) => {
                        println!("event=discovery-error service=node error=\"{err}\"");
                    }
                    None => {
                        node_done = true;
                        println!("event=discovery-complete service=node");
                    }
                }
            }
            joined = interrogations.join_next(), if !interrogations.is_empty() => {
                match joined {
                    Some(Ok((peer_id, Ok(outcome)))) => {
                        interrogation_ok += 1;
                        let info = &outcome.node_info;
                        println!(
                            "event=node-info peer={} reported_node_id={} version={} build={} os={} uptime_seconds={} graffiti={}",
                            peer_id,
                            info.node_id,
                            info.version,
                            info.build,
                            info.os,
                            info.uptime_seconds,
                            String::from_utf8_lossy(&info.graffiti),
                        );

                        if let Some(err) = outcome.known_peers_error.as_deref() {
                            println!("event=known-peers-error peer={} error=\"{}\"", peer_id, err);
                        }

                        if outcome.invalid_known_peers > 0 {
                            println!(
                                "event=known-peers-invalid peer={} invalid_count={}",
                                peer_id,
                                outcome.invalid_known_peers
                            );
                        }

                        println!(
                            "event=known-peers peer={} count={}",
                            peer_id,
                            outcome.known_peers.len()
                        );

                        if !outcome.known_peers.is_empty() {
                            hinted_peers += outcome.known_peers.len();
                            for hinted in &outcome.known_peers {
                                let _ = peer_manager
                                    .peer(PeerId::from(*hinted.as_bytes()))
                                    .observe_discovered(
                                        DiscoverySource::PeerExchange,
                                        TransportSecurity::Untrusted,
                                    );
                            }
                            for hinted in &outcome.known_peers {
                                println!("event=peer-hint from={} peer={}", peer_id, hinted);
                            }
                            peer_exchange.ingest_peers(outcome.known_peers.iter().copied());
                        }
                    }
                    Some(Ok((peer_id, Err(err)))) => {
                        interrogation_failed += 1;
                        println!("event=interrogate-error peer={} error=\"{err:#}\"", peer_id);
                    }
                    Some(Err(err)) => {
                        interrogation_failed += 1;
                        println!("event=interrogate-error error=\"task join failed: {err}\"");
                    }
                    None => {}
                }
            }
        }

        if node_done && interrogations.is_empty() {
            println!("event=monitor-stop reason=discovery-exhausted");
            break;
        }
    }

    let unique_peers = peer_manager
        .with_registry(|registry| registry.len())
        .unwrap_or(0);

    println!(
        "event=monitor-summary unique_peers={} interrogated={} interrogation_ok={} interrogation_failed={} hinted_peers={}",
        unique_peers,
        interrogated.len(),
        interrogation_ok,
        interrogation_failed,
        hinted_peers
    );

    endpoint.close().await;
    Ok(())
}

fn handle_discovery_event<S: RpcService>(
    service: &str,
    peer: &Peer,
    context: DiscoveryEventContext<'_>,
) {
    let peer_id = peer.id();
    let service_inserted = context
        .peer_manager
        .peer(PeerId::from(*peer_id.as_bytes()))
        .service::<S>()
        .observe_discovered(
            discovery_source(peer.source()),
            TransportSecurity::Untrusted,
        )
        .map_or(true, |observation| observation.service_inserted);
    if !service_inserted {
        return;
    }

    println!(
        "event=discovered service={} peer={} source={} trust={} remote_trust={} source_trust={}",
        service,
        peer_id,
        peer.source(),
        peer.trust(),
        peer.remote_trust(),
        peer.source_trust()
    );

    if context.interrogate && context.interrogated.insert(peer_id) {
        println!("event=interrogate-start peer={}", peer_id);
        let registry = context.registry.clone();
        context.interrogations.spawn(async move {
            let result = interrogate_peer(registry, peer_id).await;
            (peer_id, result)
        });
    }
}

fn discovery_source(source: &str) -> DiscoverySource {
    match source {
        "dht" => DiscoverySource::Dht,
        "peer-exchange" => DiscoverySource::PeerExchange,
        "mdns" => DiscoverySource::Mdns,
        _ => DiscoverySource::Transport("discovery"),
    }
}

async fn interrogate_peer(
    registry: ServiceRegistry,
    peer_id: EndpointId,
) -> anyhow::Result<PeerInterrogationOutcome> {
    let transport = match timeout(CONNECT_TIMEOUT, registry.pool::<Node>().transport(peer_id)).await
    {
        Ok(Ok(t)) => t,
        Ok(Err(err)) => return Err(anyhow::anyhow!("failed to dial Node service: {err}")),
        Err(_) => {
            return Err(anyhow::anyhow!(
                "Node dial timed out after {CONNECT_TIMEOUT:?}"
            ));
        }
    };

    let client = NodeClientImpl::new(transport);

    let node_info = match timeout(RPC_TIMEOUT, client.get_node_info(GetNodeInfoRequest {})).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(err)) => return Err(anyhow::anyhow!("get_node_info RPC failed: {err}")),
        Err(_) => {
            return Err(anyhow::anyhow!(
                "get_node_info timed out after {RPC_TIMEOUT:?}"
            ));
        }
    };

    let mut known_peers = Vec::new();
    let mut invalid_known_peers = 0usize;
    let mut known_peers_error = None;

    match timeout(
        RPC_TIMEOUT,
        client.get_known_peers(GetKnownPeersRequest {
            service_alpn: String::new(),
        }),
    )
    .await
    {
        Ok(Ok(resp)) => {
            let mut dedupe = HashSet::new();
            for raw_id in resp.peer_ids {
                match decode_endpoint_id(&raw_id) {
                    Ok(id) if id != peer_id => {
                        if dedupe.insert(id) {
                            known_peers.push(id);
                        }
                    }
                    Ok(_) => {}
                    Err(_) => invalid_known_peers += 1,
                }
            }
        }
        Ok(Err(err)) => {
            known_peers_error = Some(format!("get_known_peers RPC failed: {err}"));
        }
        Err(_) => {
            known_peers_error = Some(format!("get_known_peers timed out after {RPC_TIMEOUT:?}"));
        }
    }

    drop(client);
    Ok(PeerInterrogationOutcome {
        node_info,
        known_peers,
        invalid_known_peers,
        known_peers_error,
    })
}

fn decode_endpoint_id(raw_id: &[u8]) -> anyhow::Result<EndpointId> {
    let bytes: [u8; 32] = raw_id
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid endpoint id length: {}", raw_id.len()))?;
    EndpointId::from_bytes(&bytes).context("invalid endpoint id bytes")
}
