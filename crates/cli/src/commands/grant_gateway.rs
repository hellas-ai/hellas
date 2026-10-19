#[cfg(feature = "evaluate")]
pub mod local;

use super::CliResult;
use crate::identity::LocalIdentity;
use hellas_sdk::grant_client::{GrantSessionOptions, PinnedOffer};
use std::{sync::Arc, time::Duration};

pub fn session(
    target: PinnedOffer,
    identity: &LocalIdentity,
    application: Arc<hellas_sdk::node_control::profile::ClientProfile>,
) -> CliResult<GrantSessionOptions> {
    let client = super::contributions::principal(identity)?;
    Ok(GrantSessionOptions {
        target,
        principal: client,
        signer: Arc::new(identity.node_key.clone()),
        application,
        journal_root: super::contributions::client_journal_root(&client)?,
        timeout: Duration::from_secs(90),
    })
}
