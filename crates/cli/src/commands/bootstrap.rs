//! Normal node startup: an uninitialized node waits for its owner to pair.
use anyhow::{Context, Result};
use hellas_private::StoreLocation;
use hellas_sdk::node_control::{RemoteControlAdmission, bootstrap};

pub async fn prepare(
    home: &StoreLocation,
    transport_key: &iroh::SecretKey,
    enrollment: &hellas_rpc::ProviderEnrollmentBundle,
    port: Option<u16>,
) -> Result<Option<iroh::Endpoint>> {
    let root = home.child("provider");
    let journal = root.child("authority");
    let remote_control = RemoteControlAdmission::credential_gated();
    let now = hellas_auth::authority::UnixMillis::now()?;
    match hellas_authority::work_store::grant::NodeStore::open(
        &journal,
        hellas_authority::model::grant::grant_network(),
        Some(enrollment.clone()),
        now,
    )
    .await
    {
        Ok(mut store) => {
            store.close().await;
            return Ok(None);
        }
        Err(hellas_authority::work_store::grant::NodeStoreError::Uninitialized) => {}
        Err(error) => return Err(error.into()),
    }
    hellas_private::create_dir_all_durable(&root)?;
    // No client trusts local TLS before initialization. Generate it before the
    // authority commit; after a crash, committed store state skips regeneration.
    let tls = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    hellas_private::write_atomically(&root.child("control.cert.der"), ".writing", tls.cert.der())?;
    hellas_private::write_atomically(
        &root.child("control.key.der"),
        ".writing",
        &tls.signing_key.serialize_der(),
    )?;
    let endpoint = hellas_sdk::node_control::bootstrap::bind_transport(
        transport_key.clone(),
        port,
        remote_control,
    )
    .await?;
    hellas_wire::iroh::close_on_error(&endpoint, pair(&endpoint, &journal, enrollment, now))
        .await?;
    Ok(Some(endpoint))
}

async fn pair(
    endpoint: &iroh::Endpoint,
    journal: &StoreLocation,
    enrollment: &hellas_rpc::ProviderEnrollmentBundle,
    now: hellas_auth::authority::UnixMillis,
) -> Result<()> {
    let invitation = bootstrap::Invitation::create(endpoint, now)?;
    // Pairing exists only for this process. A restart cannot reset the attempt
    // counter for an old secret: it generates an independent invitation instead.
    eprintln!(
        "Waiting for the owner. Copy the invite below from this console, never an untrusted channel, and run `hellas pair INVITE`:"
    );
    println!("{}", invitation.encode()?);
    let result = bootstrap::accept(
        endpoint,
        &invitation,
        journal,
        hellas_authority::model::grant::grant_network(),
        Some(enrollment.clone()),
    )
    .await;
    result.context(
        "owner bootstrap refused or expired; restart explicitly to create a new pairing invitation",
    )
}
