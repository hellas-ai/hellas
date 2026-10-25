//! `hellas rpc` subcommand — query node info from a remote peer.
//!
//! Dials the peer directly (no discovery / pool race) over the
//! Node service ALPN and prints the response.

use std::net::SocketAddr;

use anyhow::Context;
use hellas_rpc::pb::swarm::{GetNodeInfoRequest, GetNodeInfoResponse};
use hellas_rpc::services::node::NodeClientImpl;
use hellas_wire::ServiceMarker;
use hellas_wire::iroh::IrohTransport;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr};

use crate::commands::CliResult;

pub async fn run(
    node_id: EndpointId,
    node_addrs: Vec<SocketAddr>,
    secret_key: SecretKey,
) -> CliResult<()> {
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![
            hellas_rpc::services::node::Node::ALPN.as_bytes().to_vec(),
        ])
        .bind()
        .await
        .context("failed to bind iroh endpoint")?;

    let endpoint_addr =
        EndpointAddr::from_parts(node_id, node_addrs.into_iter().map(TransportAddr::Ip));

    let connection = endpoint
        .connect(
            endpoint_addr,
            hellas_rpc::services::node::Node::ALPN.as_bytes(),
        )
        .await
        .map_err(|err| anyhow::anyhow!("failed to connect to {node_id}: {:?}", err.to_string()))?;

    let transport = IrohTransport::new(connection);
    let client = NodeClientImpl::new(transport);

    let response = client
        .get_node_info(GetNodeInfoRequest {})
        .await
        .map_err(|err| anyhow::anyhow!("get_node_info: {:?}", err.to_string()))?;

    println!("{}", node_info_display(&response));

    Ok(())
}

fn node_info_display(response: &GetNodeInfoResponse) -> String {
    format!(
        "Node ID:  {:?}\nVersion:  {:?}\nBuild:    {:?}\nOS:       {:?}\nUptime:   {}s\nGraffiti: {:?}",
        response.node_id,
        response.version,
        response.build,
        response.os,
        response.uptime_seconds,
        String::from_utf8_lossy(&response.graffiti)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_info_display_escapes_peer_controlled_fields() {
        let text = "\nGraffiti: forged\r\x1b[2J\u{9b}31m\t\"\\";
        let response = GetNodeInfoResponse {
            node_id: text.into(),
            version: text.into(),
            build: text.into(),
            os: text.into(),
            uptime_seconds: 1,
            graffiti: text.as_bytes().to_vec(),
            ..Default::default()
        };
        let display = node_info_display(&response);
        assert_eq!(display.lines().count(), 6);
        assert!(
            display
                .chars()
                .all(|character| !character.is_control() || character == '\n')
        );
        assert_eq!(display.matches("\nGraffiti:").count(), 1);
    }
}
