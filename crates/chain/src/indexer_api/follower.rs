//! The follower half of the indexer: pull finalized blocks from an upstream
//! validator and feed them to the index.
//!
//! Separated from `mod.rs`, which is the HTTP and RPC surface. The two were
//! one file because they ship in one process, not because they are one
//! concern: this half talks to a validator and writes, that half answers
//! untrusted readers.
use super::*;

pub(super) async fn index_transactions(state: OriginState) -> OriginResult<()> {
    // Replay::new recovered the durable checkpoint before the listener opened.
    // Never scan old archive heights merely to rebuild an ephemeral owner tree.
    let mut height = state.replay.lock().await.next_height()?;
    loop {
        match state
            .indexer
            .get_finalized_block(FinalizedBlockQuery::Height(height))
            .await?
        {
            Some(finalized) => {
                let verified = state.verifier.verify(
                    proof_bundle(&state, finalized),
                    ProofQuery::Block(FinalizedBlockQuery::Height(height)),
                )?;
                let block =
                    crate::HellasBlock::decode(verified.bundle().canonical_block.as_slice())?;
                state.replay.lock().await.apply(&block, verified).await?;
                height = height
                    .checked_add(1)
                    .ok_or("transaction index height exhausted")?;
                ::tokio::task::yield_now().await;
            }
            None => ::tokio::time::sleep(std::time::Duration::from_secs(1)).await,
        }
    }
}

// Bound both outstanding requests and completed responses waiting for an
// earlier height. Verification and archive ingestion remain serial below.
pub(super) const FINALIZED_FETCH_WINDOW: usize = 32;

pub(super) fn ordered_fetches<T, F, Fut>(first: u64, mut fetch: F) -> impl Stream<Item = (u64, T)>
where
    F: FnMut(u64) -> Fut,
    Fut: Future<Output = T>,
{
    stream::iter(std::iter::successors(Some(first), |height| {
        height.checked_add(1)
    }))
    .map(move |height| {
        let pending = fetch(height);
        async move { (height, pending.await) }
    })
    .buffered(FINALIZED_FETCH_WINDOW)
}

pub(super) async fn follow_trusted(
    state: OriginState,
    rpc: String,
    status: FollowerStatusSink,
) -> OriginResult<()> {
    loop {
        // The remote client is only a transport/codec here. The authenticated height-key
        // schedule below verifies every block before the native archive sees it.
        let client = match crate::client::RemoteLightClient::connect(rpc.clone()).await {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(%error,"indexer upstream connection failed");
                ::tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };
        'connection: loop {
            let next = state
                .indexer
                .get_latest_block()
                .await?
                .map_or(1, |latest| latest.height.saturating_add(1));
            let fetched = ordered_fetches(next, |height| {
                client.get_finalized_block(FinalizedBlockQuery::Height(height))
            });
            futures_util::pin_mut!(fetched);
            while let Some((height, result)) = fetched.next().await {
                let remote = match result {
                    Ok(Some(finalized)) => finalized,
                    Ok(None) => {
                        // Never skip a missing height, even if later responses
                        // already arrived. Retry from the committed archive head.
                        ::tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(%error,"indexer upstream disconnected");
                        ::tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        break 'connection;
                    }
                };
                state.verifier.verify(
                    proof_bundle(&state, remote.clone()),
                    ProofQuery::Block(FinalizedBlockQuery::Height(height)),
                )?;
                ingest_finalized_block(&state.indexer, remote, height, &status).await?;
                ::tokio::task::yield_now().await;
            }
        }
    }
}
