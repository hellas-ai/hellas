#[cfg(feature = "evaluate")]
pub mod local;

use super::CliResult;
use crate::identity::LocalIdentity;
use hellas_sdk::{
    grant_client::{GrantSessionOptions, GrantTransport, PinnedOffer},
    grant_gateway::GrantGateway,
};
use std::{sync::Arc, time::Duration};

pub async fn remote(
    target: PinnedOffer,
    identity: &LocalIdentity,
    policy: Option<String>,
) -> CliResult<Arc<GrantGateway>> {
    let client = super::contributions::principal(identity)?;
    let journal_root = super::contributions::client_journal_root(&client)?;
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(identity.transport_key.clone())
        .bind()
        .await?;
    Ok(GrantGateway::open(
        GrantSessionOptions {
            target,
            client,
            signer: Arc::new(identity.producer_key.clone()),
            journal_root,
            timeout: Duration::from_secs(90),
        },
        GrantTransport::Remote(endpoint),
        policy,
    )
    .await?)
}
