use super::{AdminArgs, AdminCommand, OfflineArgs};
use crate::{
    commands::contributions::{data_root, offer_fingerprints, principal},
    identity::LocalIdentity,
};
use anyhow::{Context, Result, ensure};
use hellas_auth::authority::{
    AdministrationCommand, AdministrationRecord, CredentialCommand, CredentialId, GrantCommand,
    GrantId, GrantSpec, Revision,
};
use hellas_rpc::{
    pb::host::{
        GetHostStatusRequest, GrantControlRequest, IssueCredentialRequest, RevokeCredentialRequest,
        SetMachineCapacityRequest, WorkControlRequest,
    },
    protocol::value::{canonical_dag_cbor, decode_dag_cbor},
    services::host_control::HostControlClientImpl,
};
use hellas_sdk::{
    node_control::{self, profile},
    work::work_store::grant::NodeStore,
};
use hellas_wire::{ServiceMarker, StreamTransport};
use hellas_work::model::grant::admin::{MAX_ADMIN_BYTES, WorkControlCommand, WorkControlReply};
use hellas_work::model::grant::records::{decode_contact, grant_transport};
use std::{path::Path, time::Duration};

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(
        &hellas_private::read_bounded_regular_file(path, 64 * 1024)?,
    )?)
}

pub async fn run(args: AdminArgs, identity: &LocalIdentity) -> Result<()> {
    match &args.command {
        AdminCommand::Bootstrap { .. } | AdminCommand::Recover { .. } => {
            ensure!(
                args.profile.is_none()
                    && args.control_socket.is_none()
                    && args.node_contact.is_none()
                    && args.addresses.is_empty(),
                "offline initialization does not connect to a daemon"
            );
            return offline(args.command, identity).await;
        }
        _ => {}
    }
    let profile =
        profile::ClientProfile::load(args.profile.as_deref().context("--profile is required")?)?;
    if let Some(contact) = args.node_contact {
        let provider = decode_contact(&hellas_private::read_bounded_regular_file(
            &contact,
            hellas_work::model::grant::records::MAX_PRINCIPAL_BYTES,
        )?)?;
        // The application identity is proved inside the authenticated session.
        // A stable endpoint key permits explicit remote ingress admission; use
        // local control to administer a node using this same transport identity.
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(identity.transport_key.clone())
            .bind()
            .await?;
        let result = async {
            let address = iroh::EndpointAddr::from_parts(
                iroh::EndpointId::from_bytes(&grant_transport(&provider)?)?,
                args.addresses.into_iter().map(iroh::TransportAddr::Ip),
            );
            let connection = tokio::time::timeout(
                Duration::from_secs(15),
                endpoint.connect(
                    address,
                    hellas_rpc::services::host_control::HostControl::ALPN.as_bytes(),
                ),
            )
            .await??;
            let client = node_control::connect_iroh(
                connection,
                profile.authority,
                &profile.credential,
                &identity.producer_key,
            )
            .await?;
            command(args.command, client, profile.authorization).await
        }
        .await;
        endpoint.close().await;
        result
    } else {
        let (tls, server_name) = profile
            .local
            .context("profile requires local server trust")?;
        let socket = match args.control_socket {
            Some(path) => path,
            None => data_root(&principal(identity)?)?.join("control.sock"),
        };
        let client = node_control::connect_local(
            &socket,
            tls,
            server_name,
            profile.authority,
            &profile.credential,
            &identity.producer_key,
        )
        .await?;
        command(args.command, client, profile.authorization).await
    }
}

async fn command<T>(
    command: AdminCommand,
    client: HostControlClientImpl<T>,
    authorization: GrantId,
) -> Result<()>
where
    T: StreamTransport + Send + Sync,
    T::Stream: Send + 'static,
{
    match command {
        AdminCommand::Status => {
            let status = client
                .get_host_status(GetHostStatusRequest {
                    authorization: authorization.0.to_vec(),
                })
                .await?;
            let machine = status.machine.map(|m| -> Result<_> {
                let limits: Vec<hellas_work::model::grant::budget::Limit> = decode_dag_cbor(&m.limits)?;
                Ok(serde_json::json!({"revision": m.revision, "max_in_flight": m.max_in_flight, "limits": limits}))
            }).transpose()?;
            println!(
                "{}",
                serde_json::json!({
                    "authority": hex::encode(status.authority),
                    "revision": status.authority_revision,
                    "generation": status.generation,
                    "provider_configured": status.provider_configured,
                    "machine": machine,
                })
            );
        }
        AdminCommand::SetCapacity {
            expected_revision,
            max_in_flight,
            limits,
        } => {
            let limits: Vec<hellas_work::model::grant::budget::Limit> = read(&limits)?;
            let result = client
                .set_machine_capacity(SetMachineCapacityRequest {
                    authorization: authorization.0.to_vec(),
                    expected_revision,
                    max_in_flight: u32::from(max_in_flight),
                    limits: canonical_dag_cbor(&limits)?,
                })
                .await?;
            println!(
                "{}",
                serde_json::json!({"revision": result.revision, "max_in_flight": result.max_in_flight})
            );
        }
        AdminCommand::Grant { command } => {
            let value: GrantCommand = read(&command)?;
            let response = client
                .grant_control(GrantControlRequest {
                    command: canonical_dag_cbor(&value)?,
                })
                .await?;
            let record: AdministrationRecord = decode_dag_cbor(&response.reply)?;
            println!("{}", serde_json::to_string(&record)?);
        }
        AdminCommand::IssueCredential {
            scope,
            credential_out,
        } => {
            let scope: GrantSpec = read(&scope)?;
            let output = credential_output(&credential_out)?;
            let response = client
                .issue_credential(IssueCredentialRequest {
                    authorization: authorization.0.to_vec(),
                    scope: canonical_dag_cbor(&scope)?,
                })
                .await?;
            ensure!(
                response.record.len() <= MAX_ADMIN_BYTES,
                "credential reply exceeds limit"
            );
            let record: AdministrationRecord = decode_dag_cbor(&response.record)?;
            let secret = response.credential()?;
            let AdministrationCommand::Credential(CredentialCommand::Issue {
                authorization: returned_authorization,
                credential,
            }) = record.command()
            else {
                anyhow::bail!("invalid credential issuance reply");
            };
            ensure!(
                *returned_authorization == authorization
                    && credential.id() == secret.id()
                    && credential.scope() == &scope
                    && credential.revision() == Revision(1)
                    && !credential.revoked(),
                "credential issuance reply differs from request"
            );
            let id = hex::encode(secret.id().0);
            profile::save_credential(output, &credential_out, &secret).with_context(|| {
                format!(
                    "credential {id} was issued but could not be saved; revoke it before retrying"
                )
            })?;
            println!(
                "{}",
                serde_json::json!({
                    "credential_id": id, "revision": credential.revision().0,
                    "credential_file": credential_out,
                    "subject": hex::encode(scope.subject.as_bytes()),
                    "subject_fingerprint": scope.subject.fingerprint(),
                    "authority": hex::encode(scope.authority.0.as_bytes()),
                })
            );
        }
        AdminCommand::RevokeCredential {
            credential_id,
            expected_revision,
        } => {
            let id: CredentialId = credential_id
                .parse()
                .context("credential ID must be 16 bytes of hex")?;
            let response = client
                .revoke_credential(RevokeCredentialRequest {
                    authorization: authorization.0.to_vec(),
                    credential_id: id.0.to_vec(),
                    expected_revision,
                })
                .await?;
            ensure!(
                response.record.len() <= MAX_ADMIN_BYTES,
                "credential reply exceeds limit"
            );
            let record: AdministrationRecord = decode_dag_cbor(&response.record)?;
            println!("{}", serde_json::to_string(&record)?);
        }
        AdminCommand::Work { command, offer_out } => {
            let value: WorkControlCommand = read(&command)?;
            ensure!(
                offer_out.is_none() || matches!(value, WorkControlCommand::Offers { id: Some(_) }),
                "--offer-out requires Offers with one explicit allowance ID"
            );
            let response = client
                .work_control(WorkControlRequest {
                    authorization: authorization.0.to_vec(),
                    command: canonical_dag_cbor(&value)?,
                })
                .await?;
            ensure!(
                response.reply.len() <= MAX_ADMIN_BYTES,
                "Work reply exceeds limit"
            );
            let reply: WorkControlReply = decode_dag_cbor(&response.reply)?;
            if let Some(path) = offer_out {
                let WorkControlReply::Offers(offers) = &reply else {
                    anyhow::bail!("offer reply required")
                };
                let [offer] = offers.as_slice() else {
                    anyhow::bail!("one active offer required")
                };
                offer_fingerprints(offer)?;
                hellas_private::write_atomically(&path, ".writing", &offer.encode()?)?;
            }
            println!("{}", serde_json::to_string(&reply)?);
        }
        _ => anyhow::bail!("this command requires its offline or management entrypoint"),
    }
    Ok(())
}

async fn offline(command: AdminCommand, identity: &LocalIdentity) -> Result<()> {
    let (state, root, revision) = match command {
        AdminCommand::Bootstrap { root_grant, state } => {
            let id: GrantId = root_grant
                .parse()
                .context("root grant must be 16 bytes of hex")?;
            (state, Some(id), None)
        }
        AdminCommand::Recover {
            expected_revision,
            state,
        } => (state, None, Some(Revision(expected_revision))),
        _ => anyhow::bail!("offline command required"),
    };
    let OfflineArgs {
        journal,
        administrator,
        credential_scope,
        credential_out,
    } = state;
    let administrator: GrantSpec = read(&administrator)?;
    let scope: GrantSpec = read(&credential_scope)?;
    let subject = scope.subject;
    let authority = scope.authority;
    let output = credential_output(&credential_out)?;
    let now = hellas_auth::authority::UnixMillis::now().unwrap_or_default();
    let network = hellas_work::model::grant::grant_network();
    let secret = match (root, revision) {
        (Some(root), None) => {
            let (store, secret) = NodeStore::bootstrap(
                &journal,
                network,
                root,
                administrator,
                scope,
                Some(identity.enrollment.clone()),
                now,
            )
            .await?;
            drop(store);
            secret
        }
        (None, Some(revision)) => {
            NodeStore::recover_offline(&journal, network, revision, administrator, scope, now)
                .await?
                .1
        }
        _ => anyhow::bail!("invalid offline operation"),
    };
    profile::save_credential(output, &credential_out, &secret)
        .context("authority committed but credential publication failed; use explicit offline recovery before retrying")?;
    println!(
        "{}",
        serde_json::json!({
            "credential_id": hex::encode(secret.id().0), "credential_file": credential_out,
            "subject": hex::encode(subject.as_bytes()), "subject_fingerprint": subject.fingerprint(),
            "authority": hex::encode(authority.0.as_bytes()),
        })
    );
    Ok(())
}

fn credential_output(path: &Path) -> Result<tempfile::NamedTempFile> {
    ensure!(!path.try_exists()?, "credential output already exists");
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(hellas_private::private_tempfile(
        parent,
        ".credential-",
        ".issuing",
    )?)
}
