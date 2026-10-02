use std::path::Path;

use crate::{
    config::{Credentials, Deployment, ProviderConfig, Spec, lock_state, read_json, save_state},
    provider,
};

pub type Result<T> = std::result::Result<T, DeploymentError>;

#[derive(Debug, thiserror::Error)]
pub enum DeploymentError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Provider(#[from] crate::provider::ProviderError),
    #[error("state already exists; allocation was not attempted")]
    StateExists,
    #[error("deployment was destroyed")]
    Destroyed,
    #[error("receipt provider/account changed; refusing termination")]
    ProviderMismatch,
    #[error("pod ID does not match receipt; refusing termination")]
    IdMismatch,
    #[error("pending allocation; reconcile by name and adopt before destroying")]
    PendingId,
    #[error("state already exists or cannot be saved; allocation was not attempted")]
    SaveBeforeAllocation(#[source] crate::config::ConfigError),
    #[error("pending receipt retained; reconcile by name before retrying allocation")]
    PendingAllocation(#[source] crate::provider::ProviderError),
    #[error("allocated pod retained in receipt; inspect or destroy it before retrying")]
    AllocatedVerification(#[source] crate::provider::ProviderError),
}

pub async fn create(spec: Spec, state: &Path) -> Result<String> {
    create_with_credentials(spec, state, Credentials::generate()).await
}

pub async fn create_with_credentials(
    mut spec: Spec,
    state: &Path,
    credentials: Credentials,
) -> Result<String> {
    credentials.require_owner_enrollment()?;
    credentials.secret_key()?;
    let _lock = lock_state(state)?;
    spec.validate()?;
    if state.exists() {
        return Err(DeploymentError::StateExists);
    }
    let provider = provider::adapter(&spec.provider)?;
    provider.prepare(&mut spec).await?;
    let mut deployment = Deployment {
        spec,
        credentials,
        resource_id: None,
        enrollment: None,
        destroyed: false,
    };
    save_state(state, &deployment, true).map_err(DeploymentError::SaveBeforeAllocation)?;
    let id = provider
        .create(&deployment.spec, &deployment.credentials)
        .await
        .map_err(DeploymentError::PendingAllocation)?;
    eprintln!("allocated resource: {id}");
    deployment.resource_id = Some(id.clone());
    save_state(state, &deployment, false)?;
    provider
        .verify(&deployment.spec, &id)
        .await
        .map_err(DeploymentError::AllocatedVerification)?;
    Ok(id)
}

pub async fn destroy(
    path: &Path,
    expected_provider: Option<&ProviderConfig>,
    expected_id: Option<&str>,
) -> Result<String> {
    let _lock = lock_state(path)?;
    let mut state: Deployment = read_json(path)?;
    state.spec.validate()?;
    if state.destroyed {
        return Err(DeploymentError::Destroyed);
    }
    if let Some(expected) = expected_provider
        && !(&state.spec.provider == expected)
    {
        return Err(DeploymentError::ProviderMismatch);
    }
    let id = state
        .resource_id
        .as_deref()
        .ok_or(DeploymentError::PendingId)?;
    if let Some(expected) = expected_id
        && (id != expected)
    {
        return Err(DeploymentError::IdMismatch);
    }
    provider::adapter(&state.spec.provider)?.destroy(id).await?;
    let id = id.to_owned();
    state.destroyed = true;
    save_state(path, &state, false)?;
    Ok(id)
}
