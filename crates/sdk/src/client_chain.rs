use crate::work_config::WorkConfig;
use futures::StreamExt as _;
use hellas_chain::{LightClient as _, QueryError, client::RemoteLightClient};
use std::{sync::Arc, time::Duration};

fn invalid(error: impl std::fmt::Display) -> QueryError {
    QueryError::Remote(error.to_string())
}

/// A known chain whose endpoint reports another network id means this binary
/// predates a devnet reset (G19 bumps the id); say so instead of a proof error.
fn stale_reason(config: &WorkConfig) -> String {
    match config.chain.known_chain() {
        Some(chain) => format!(
            "this binary is out of date for {}; please update",
            chain.name()
        ),
        None => "endpoint consensus identity differs from the configured chain".into(),
    }
}

pub async fn connect(
    config: &WorkConfig,
    timeout: Duration,
) -> Result<RemoteLightClient, QueryError> {
    connect_at(config, timeout, 0).await
}

/// Connects to a verified source that can serve state at or above `min_height`.
///
/// Authentication alone does not make a source usable. A peer that answers
/// fastest may be behind the caller's retained journal, and the caller's own
/// height guard then rejects its state — so a reconnect policy that keeps
/// choosing it never recovers while healthy peers sit configured beside it.
/// Requiring the height here makes the selection agree with that guard instead
/// of racing against it.
pub async fn connect_at(
    config: &WorkConfig,
    timeout: Duration,
    min_height: u64,
) -> Result<RemoteLightClient, QueryError> {
    let verifier = Arc::new(
        hellas_chain::proof_verify::ProofVerifier::for_profile(&config.chain).map_err(invalid)?,
    );
    let mut reason = "no finalized remote snapshot is available".to_owned();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(QueryError::ReadUnavailableTimeout { timeout, reason });
        }
        let attempts = futures::stream::iter(config.chain.validators().iter().cloned())
            .map(|url| {
                let verifier = Arc::clone(&verifier);
                async move {
                    tokio::time::timeout(timeout.min(Duration::from_secs(5)), async {
                        let client = RemoteLightClient::connect(url, verifier).await?;
                        // Unauthenticated, used only to explain a mismatch: proofs
                        // remain the sole source of accepted state.
                        if client.get_consensus_info().await?.network_id
                            != config.chain.network_id()
                        {
                            return Err(invalid(stale_reason(config)));
                        }
                        let latest = client.get_latest_block().await?.ok_or_else(|| {
                            QueryError::StateUnavailable("chain is catching up".into())
                        })?;
                        if latest.height < min_height {
                            return Err(QueryError::StateUnavailable(format!(
                                "chain is at height {} but the journal requires {min_height}",
                                latest.height
                            )));
                        }
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
        tokio::time::sleep_until(
            deadline.min(tokio::time::Instant::now() + hellas_channel::work::SETUP_POLL),
        )
        .await;
    }
}
