//! Normal node startup with one explicit owner-pairing interval.
use crate::identity::LocalIdentity;
use anyhow::{Context, Result};
use hellas_private::StoreLocation;
use hellas_sdk::{
    grant_config::GrantConfig,
    node_control::{RemoteControlAdmission, bootstrap},
};

pub async fn prepare(
    home: &StoreLocation,
    identity: &LocalIdentity,
    port: Option<u16>,
    configured: Option<GrantConfig>,
) -> Result<(GrantConfig, Option<iroh::Endpoint>)> {
    let root = GrantConfig::provider_dir(home);
    let mut config = configured.unwrap_or_else(|| GrantConfig::unconfigured(home));
    // --await-owner is the explicit opt-in to credential-gated remote ingress.
    // An existing allowlist remains a narrower operator-selected restriction.
    if !config.remote_control.enabled() {
        config.remote_control = RemoteControlAdmission::credential_gated();
    }
    let now = hellas_auth::authority::UnixMillis::now()?;
    match hellas_authority::work_store::grant::NodeStore::open(
        &config.journal_root(),
        hellas_authority::model::grant::grant_network(),
        Some(identity.enrollment.clone()),
        now,
    )
    .await
    {
        Ok(mut store) => {
            store.close().await;
            return Ok((config, None));
        }
        Err(hellas_authority::work_store::grant::NodeStoreError::Uninitialized) => {}
        Err(error) => return Err(error.into()),
    }
    hellas_private::create_dir_all_durable(&root)?;
    // No client trusts local TLS before initialization. Generate it before the
    // authority commit; after a crash, committed store state skips regeneration.
    let tls = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    hellas_private::write_atomically(&config.control_certificate(), ".writing", tls.cert.der())?;
    hellas_private::write_atomically(
        &config.control_private_key(),
        ".writing",
        &tls.signing_key.serialize_der(),
    )?;
    let endpoint = hellas_sdk::node_control::host::bind_transport(
        identity.transport_key.clone(),
        port,
        config.remote_control.clone(),
    )
    .await?;
    hellas_wire::iroh::close_on_error(&endpoint, pair(&endpoint, &config, identity, &root, now))
        .await?;
    Ok((config, Some(endpoint)))
}

async fn pair(
    endpoint: &iroh::Endpoint,
    config: &GrantConfig,
    identity: &LocalIdentity,
    root: &std::path::Path,
    now: hellas_auth::authority::UnixMillis,
) -> Result<()> {
    let invitation = bootstrap::Invitation::create(endpoint, now)?;
    let invitation_path = root.join("invitation.json");
    hellas_private::write_atomically(
        &invitation_path,
        ".pairing",
        &serde_json::to_vec(&invitation)?,
    )?;
    eprintln!("Private pairing invitation: {}", invitation_path.display());
    // Pairing exists only for this process. A restart cannot reset the attempt
    // counter for an old secret: it generates an independent invitation instead.
    eprintln!("Obtain this pairing document through the authenticated machine console:");
    println!("{}", serde_json::to_string(&invitation)?);
    let result = bootstrap::accept(
        endpoint,
        &invitation,
        &config.journal_root(),
        hellas_authority::model::grant::grant_network(),
        Some(identity.enrollment.clone()),
    )
    .await;
    result.context(
        "owner bootstrap refused or expired; restart explicitly to create a new pairing invitation",
    )
}
