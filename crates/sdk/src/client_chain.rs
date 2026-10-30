//! Verified remote chain access shared by requester commands and gateways.
use crate::work_config::{ChainCrossCheck, WorkConfig};
use futures::StreamExt as _;
use hellas_chain::genesis::{Genesis, TrustDocument};
use hellas_chain::{
    ConsensusInfo, ConsensusVerifier, LightClient as _, QueryError, client::RemoteLightClient,
};
use std::{path::Path, time::Duration};

fn invalid(error: impl std::fmt::Display) -> QueryError {
    QueryError::Remote(error.to_string())
}

pub fn pinned_consensus_verifier(
    trust: &TrustDocument,
    genesis_json: &[u8],
    reported: &ConsensusInfo,
) -> Result<ConsensusVerifier, QueryError> {
    hellas_chain::proof_verify::ProofVerifier::with_genesis(trust.clone(), genesis_json)
        .map_err(invalid)?;
    let [epoch] = trust.epochs.as_slice() else {
        return Err(invalid("one initial trusted epoch is required"));
    };
    if epoch.epoch != 0 || epoch.start_height != 0 || epoch.end_height.is_some() {
        return Err(invalid(
            "one open trusted epoch starting at zero is required",
        ));
    }
    let genesis: Genesis = serde_json::from_slice(genesis_json).map_err(invalid)?;
    let pinned = ConsensusInfo {
        network_id: trust.network_id.clone(),
        threshold_identity: hex::decode(&epoch.threshold_identity).map_err(invalid)?,
        validators: genesis
            .validators
            .iter()
            .map(|validator| validator.public_key.clone())
            .collect(),
    };
    if reported.network_id != pinned.network_id
        || reported.threshold_identity != pinned.threshold_identity
    {
        return Err(invalid(
            "endpoint consensus identity differs from the authenticated trust document",
        ));
    }
    ConsensusVerifier::new(&pinned, hellas_chain::genesis_digest(&genesis)).map_err(invalid)
}

pub fn devnet(root: &Path) -> Result<WorkConfig, crate::work_config::WorkConfigError> {
    use hellas_chain::genesis::*;
    let trust: TrustDocument =
        serde_json::from_str(HELLAS_DEVNET_1_TRUST_JSON).expect("embedded devnet trust is tested");
    let epoch = &trust.epochs[0];
    WorkConfig {
        chain: ChainCrossCheck {
            network: hellas_kernel::NetworkId::new(HELLAS_DEVNET_1_ID)
                .expect("embedded devnet network"),
            genesis_payload_digest: hellas_auth::Digest::from_bytes(
                hex::decode(HELLAS_DEVNET_1_GENESIS_PAYLOAD.trim())
                    .expect("embedded genesis payload is hexadecimal")
                    .try_into()
                    .expect("embedded genesis payload has 32 bytes"),
            ),
            threshold_identity: hex::decode(&epoch.threshold_identity)
                .expect("embedded threshold is hexadecimal"),
            genesis: None,
        },
        validators: (0..6)
            .map(|index| format!("wss://devnet.hellas.ai/ws/validator-{index}"))
            .collect(),
        journal_root: root.join("channels"),
        poll: Duration::from_millis(500),
        max_observation_age: hellas_chain::node::RECOVERY_TIMEOUT,
    }
    .validate()
}

pub async fn connect(
    config: &WorkConfig,
    timeout: Duration,
) -> Result<RemoteLightClient, QueryError> {
    let genesis = crate::work_config::chain_genesis(config.chain.network, &config.chain.genesis)
        .map_err(invalid)?;
    let pinned = ConsensusInfo {
        network_id: config.chain.network.as_str().into(),
        threshold_identity: config.chain.threshold_identity.clone(),
        validators: config.validators.clone(),
    };
    let verifier =
        ConsensusVerifier::new(&pinned, hellas_chain::genesis_digest(&genesis)).map_err(invalid)?;
    let mut reason = "no finalized remote snapshot is available".to_owned();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(QueryError::ReadUnavailableTimeout { timeout, reason });
        }
        let attempts = futures::stream::iter(config.validators.iter().cloned())
            .map(|url| {
                let pinned = pinned.clone();
                let verifier = verifier.clone();
                async move {
                    tokio::time::timeout(timeout.min(Duration::from_secs(5)), async {
                        let client = RemoteLightClient::connect(url).await?;
                        let reported = client.get_consensus_info().await?;
                        if reported.network_id != pinned.network_id
                            || reported.threshold_identity != pinned.threshold_identity
                        {
                            return Err(invalid(
                                "endpoint consensus identity differs from the configured chain",
                            ));
                        }
                        let client = client.with_consensus_verifier(verifier);
                        client.get_latest_block().await?.ok_or_else(|| {
                            QueryError::StateUnavailable("chain is catching up".into())
                        })?;
                        Ok(client)
                    })
                    .await
                }
            })
            .buffer_unordered(6);
        futures::pin_mut!(attempts);
        let mut transient = false;
        let mut invalid_source = None;
        loop {
            let attempt = match tokio::time::timeout_at(deadline, attempts.next()).await {
                Ok(Some(attempt)) => attempt,
                Ok(None) => break,
                Err(_) => {
                    transient = true;
                    break;
                }
            };
            match attempt {
                // A later reply can report a higher tip simply because it took
                // longer. Use the first authenticated source; channel reads
                // enforce their own advancing-height and freshness bounds.
                Ok(Ok(client)) => return Ok(client),
                Ok(Err(QueryError::Remote(error))) => {
                    reason = error.clone();
                    invalid_source = Some(error);
                }
                Ok(Err(error)) => {
                    reason = error.to_string();
                    transient = true;
                }
                Err(_) => {
                    reason = "remote connection did not answer".into();
                    transient = true;
                }
            }
        }
        if !transient && let Some(error) = invalid_source {
            return Err(invalid(error));
        }
        tokio::time::sleep_until(deadline.min(tokio::time::Instant::now() + config.poll)).await;
    }
}
