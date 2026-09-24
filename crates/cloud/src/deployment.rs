use std::path::Path;

use anyhow::{Context, Result, ensure};

use crate::{
    config::{Credentials, Deployment, ProviderConfig, Spec, lock_state, read_json, save_state},
    provider,
};

pub async fn create(spec: Spec, state: &Path) -> Result<String> {
    create_with_credentials(spec, state, Credentials::generate()).await
}

pub async fn create_with_credentials(
    spec: Spec,
    state: &Path,
    credentials: Credentials,
) -> Result<String> {
    credentials.secret_key()?;
    let _lock = lock_state(state)?;
    spec.validate()?;
    let provider = provider::adapter(&spec.provider)?;
    let mut deployment = Deployment {
        spec,
        credentials,
        resource_id: None,
        enrollment: None,
        destroyed: false,
    };
    save_state(state, &deployment, true)
        .context("state already exists or cannot be saved; allocation was not attempted")?;
    let id = provider
        .create(&deployment.spec, &deployment.credentials)
        .await
        .context("pending receipt retained; reconcile by name before retrying allocation")?;
    eprintln!("allocated resource: {id}");
    deployment.resource_id = Some(id.clone());
    save_state(state, &deployment, false)?;
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
    ensure!(!state.destroyed, "deployment was destroyed");
    if let Some(expected) = expected_provider {
        ensure!(
            &state.spec.provider == expected,
            "receipt provider/account changed; refusing termination"
        );
    }
    let id = state
        .resource_id
        .as_deref()
        .context("pending allocation; reconcile by name and adopt before destroying")?;
    if let Some(expected) = expected_id {
        ensure!(
            id == expected,
            "pod ID does not match receipt; refusing termination"
        );
    }
    provider::adapter(&state.spec.provider)?.destroy(id).await?;
    let id = id.to_owned();
    state.destroyed = true;
    save_state(path, &state, false)?;
    Ok(id)
}
