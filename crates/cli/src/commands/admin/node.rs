use super::{AdminArgs, AdminCommand, OfflineArgs};
use crate::{
    commands::contributions::{data_root, offer_fingerprints, principal},
    identity::LocalIdentity,
};
use anyhow::{Context, Result, ensure};
use hellas_auth::authority::{
    AdministrationCommand, AdministrationRecord, Credential, CredentialCommand, CredentialHolder,
    CredentialId, GrantCommand, GrantId, GrantSpec, Ownership, Revision, ownership_digest,
};
use hellas_rpc::{
    pb::host::{
        BindProviderRequest, GetHostStatusRequest, GrantControlRequest, InspectAuthorityRequest,
        IssueCredentialRequest, RevokeCredentialRequest, SetMachineCapacityRequest,
        WorkControlRequest,
    },
    protocol::value::{canonical_dag_cbor, decode_dag_cbor},
    services::host_control::HostControlClientImpl,
};
use hellas_sdk::{
    access_bundle::{AccessBundle, MAX_BUNDLE_OFFERS, MAX_LABEL_BYTES},
    node_control::{self, profile},
    work::{
        node::{SessionKey, passkey_assertion},
        work_store::grant::{NodeStore, OwnerApproval},
    },
};
use hellas_wire::{ServiceMarker, StreamTransport};
use hellas_work::model::grant::admin::{MAX_ADMIN_BYTES, WorkControlCommand, WorkControlReply};
use hellas_work::model::grant::records::{decode_enrollment, grant_transport};
use std::{path::Path, time::Duration};

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(
        &hellas_private::read_bounded_regular_file(path, 64 * 1024)?,
    )?)
}

/// Offline inspection neither loads nor creates a machine identity or passkey.
pub async fn inspect_offline(args: AdminArgs) -> Result<()> {
    if let AdminCommand::InspectOffline { journal, command } = &args.command {
        ensure!(
            args.profile.is_none()
                && args.control_socket.is_none()
                && args.node_enrollment.is_none()
                && args.addresses.is_empty(),
            "offline inspection does not connect to a daemon"
        );
        let query: hellas_auth::authority::InspectionQuery = read(command)?;
        let inspection =
            NodeStore::inspect_offline(journal, hellas_work::model::grant::grant_network(), &query)
                .await?;
        println!("{}", serde_json::to_string(&inspection)?);
        return Ok(());
    }
    anyhow::bail!("offline inspection command required")
}

/// With the principal's `passkey` the session is a passkey session, which
/// step-up operations require; without it this node's key proves a daily
/// session. Offline initialization and recovery require the passkey.
pub async fn run(
    args: AdminArgs,
    identity: &LocalIdentity,
    passkey: Option<&hellas_kernel::SoftPasskey>,
) -> Result<()> {
    if matches!(args.command, AdminCommand::BootstrapRemote { .. }) {
        ensure!(args.profile.is_none() && args.control_socket.is_none() && args.node_enrollment.is_none()
            && args.addresses.is_empty(), "bootstrap uses the invitation's pin and addresses");
        return bootstrap_remote(args.command, identity, passkey.context("bootstrap requires --passkey")?).await;
    }
    match &args.command {
        AdminCommand::Bootstrap { .. } | AdminCommand::Recover { .. } => {
            ensure!(
                args.profile.is_none()
                    && args.control_socket.is_none()
                        && args.node_enrollment.is_none()
                    && args.addresses.is_empty(),
                "offline initialization does not connect to a daemon"
            );
            let passkey = passkey.context("offline initialization requires --passkey")?;
            return offline(args.command, identity, passkey).await;
        }
        _ => {}
    }
    let key = passkey.map_or(SessionKey::Node(&identity.node_key), SessionKey::Passkey);
    let profile =
        profile::ClientProfile::load(args.profile.as_deref().context("--profile is required")?)?;
    let remote = args.node_enrollment.map(|target| -> Result<iroh::EndpointId> {
        if let Ok(pin) = target.parse() { return Ok(pin); }
        let provider = decode_enrollment(&hellas_private::read_bounded_regular_file(
            Path::new(&target), hellas_work::model::grant::records::MAX_ENROLLMENT_BYTES)?)?;
        Ok(iroh::EndpointId::from_bytes(&grant_transport(&provider)?)?)
    }).transpose()?;
    if let Some(node) = remote {
        // The application identity is proved inside the authenticated session.
        // A stable endpoint key permits explicit remote ingress admission; use
        // local control to administer a node using this same transport identity.
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(identity.transport_key.clone())
            .bind()
            .await?;
        let result = async {
            let address = iroh::EndpointAddr::from_parts(
                node,
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
            let (client, challenge) =
                node_control::connect_iroh(connection, profile.authority, &profile.credential, key)
                    .await?;
            command(
                args.command,
                client,
                profile.authorization,
                challenge.generation,
            )
            .await
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
            None => data_root(&principal(passkey.context(
                "the default control socket is the principal's; pass --passkey or --control-socket",
            )?)?)?
            .join("control.sock"),
        };
        let (client, challenge) = node_control::connect_local(
            &socket,
            tls,
            server_name,
            profile.authority,
            &profile.credential,
            key,
        )
        .await?;
        command(
            args.command,
            client,
            profile.authorization,
            challenge.generation,
        )
        .await
    }
}

async fn command<T>(
    command: AdminCommand,
    client: HostControlClientImpl<T>,
    authorization: GrantId,
    generation: u64,
) -> Result<()>
where
    T: StreamTransport + Send + Sync,
    T::Stream: Send + 'static,
{
    match command {
        AdminCommand::Inspect { command } => {
            let query: hellas_auth::authority::InspectionQuery = read(&command)?;
            let response = client
                .inspect_authority(InspectAuthorityRequest {
                    authorization: authorization.0.to_vec(),
                    query: canonical_dag_cbor(&query)?,
                })
                .await?;
            ensure!(
                response.reply.len() <= MAX_ADMIN_BYTES,
                "authority reply exceeds limit"
            );
            let inspection: hellas_auth::authority::AuthorityInspection =
                decode_dag_cbor(&response.reply)?;
            println!("{}", serde_json::to_string(&inspection)?);
        }
        AdminCommand::ConfigureProvider { command } => {
            let update: node_control::configuration::ProviderUpdate = read(&command)?;
            let status = client.configure_provider(hellas_rpc::pb::host::ConfigureProviderRequest {
                authorization:authorization.0.to_vec(), update:Some(update),
            }).await?;
            print_status(status)?;
        }
        AdminCommand::SetProviderState { enabled } => {
            let status = client.set_provider_state(hellas_rpc::pb::host::SetProviderStateRequest {
                authorization:authorization.0.to_vec(), enabled,
            }).await?;
            print_status(status)?;
        }
        AdminCommand::Status => {
            let status = client
                .get_host_status(GetHostStatusRequest {
                    authorization: authorization.0.to_vec(),
                })
                .await?;
            print_status(status)?;
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
        AdminCommand::BindProvider { enrollment } => {
            let response = client
                .bind_provider(BindProviderRequest {
                    authorization: authorization.0.to_vec(),
                    enrollment: hellas_private::read_bounded_regular_file(
                        &enrollment,
                        hellas_work::model::grant::records::MAX_ENROLLMENT_BYTES,
                    )?,
                })
                .await?;
            println!(
                "{}",
                serde_json::json!({"provider_genesis": hex::encode(response.provider_genesis)})
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
            holder,
            credential_out,
        } => {
            let scope: GrantSpec = read(&scope)?;
            let holder: CredentialHolder = read(&holder)?;
            let (credential, secret) = Credential::prepare(scope.clone(), holder, generation)?;
            let output = credential_output(&credential_out)?;
            let id = secret.id();
            profile::save_credential(output, &credential_out, &secret)?;
            issue(&client, authorization, &credential).await.with_context(|| format!(
                "credential {id} is retained at {} pending confirmation; inspect Credential {{ id }} before using it or retrying issuance",
                credential_out.display(),
            ))?;
            println!(
                "{}",
                serde_json::json!({
                    "credential_id": id.to_string(), "revision": 1,
                    "credential_file": credential_out,
                    "subject": hex::encode(scope.subject.as_bytes()),
                    "subject_fingerprint": scope.subject.fingerprint(),
                    "authority": hex::encode(scope.authority.0.as_bytes()),
                })
            );
        }
        AdminCommand::ExportBundle {
            allowances,
            grant_id,
            credential_scope,
            holder,
            label,
            out,
        } => {
            ensure!(!out.try_exists()?, "bundle output already exists");
            ensure!(
                label
                    .as_ref()
                    .is_none_or(|label| label.len() <= MAX_LABEL_BYTES),
                "label exceeds {MAX_LABEL_BYTES} bytes"
            );
            ensure!(
                allowances.len() <= MAX_BUNDLE_OFFERS,
                "a bundle shares at most {MAX_BUNDLE_OFFERS} allowances"
            );
            let grant: GrantId = grant_id
                .parse()
                .context("grant ID must be 16 bytes of hex")?;
            let scope: GrantSpec = read(&credential_scope)?;
            let CredentialHolder::Node(holder) = read(&holder)? else {
                anyhow::bail!("a contact's credential is held by the contact's device");
            };
            let mut offers = Vec::with_capacity(allowances.len());
            for allowance in &allowances {
                let allowance: GrantId = allowance
                    .parse()
                    .context("allowance must be 16 bytes of hex")?;
                ensure!(
                    scope.permissions.iter().any(|p| {
                        p.operation.as_str() == hellas_work::grant_service::WORK_EXECUTE
                            && p.resource
                                == hellas_work::grant_service::allowance_resource(
                                    scope.authority,
                                    allowance,
                                )
                    }),
                    "the credential scope must grant work.execute on allowance {allowance}"
                );
                let request = WorkControlCommand::Offers {
                    id: Some(allowance),
                };
                let WorkControlReply::Offers(found) =
                    work(&client, authorization, &request).await?
                else {
                    anyhow::bail!("offer reply required")
                };
                let Ok([offer]) = <[_; 1]>::try_from(found) else {
                    anyhow::bail!("allowance {allowance} needs one active offer")
                };
                offers.push(offer);
            }
            let (prepared, credential) =
                Credential::prepare(scope.clone(), CredentialHolder::Node(holder), generation)?;
            let id = hex::encode(credential.id().0);
            let bundle = AccessBundle {
                offers,
                authority: scope.authority,
                authorization: grant,
                subject: scope.subject,
                holder,
                credential,
                expires: scope.expires,
                label,
            };
            bundle.save(&out)?;
            issue(&client, authorization, &prepared).await.with_context(|| format!(
                "bundle credential {id} is retained at {} pending confirmation; inspect Credential {{ id }} before sharing it or retrying issuance",
                out.display(),
            ))?;
            for offer in &bundle.offers {
                offer_fingerprints(offer)?;
            }
            println!(
                "{}",
                serde_json::json!({
                    "credential_id": id, "revision": 1, "bundle_file": out,
                    "subject": hex::encode(scope.subject.as_bytes()),
                    "subject_fingerprint": scope.subject.fingerprint(),
                    "authority": hex::encode(scope.authority.0.as_bytes()),
                    "allowances": allowances,
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
            let reply = work(&client, authorization, &value).await?;
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

/// Submit only the retained credential's verifier and confirm the exact durable record.
async fn issue<T>(
    client: &HostControlClientImpl<T>,
    authorization: GrantId,
    prepared: &Credential,
) -> Result<()>
where
    T: StreamTransport + Send + Sync,
    T::Stream: Send + 'static,
{
    let response = client
        .issue_credential(IssueCredentialRequest {
            authorization: authorization.0.to_vec(),
            credential: canonical_dag_cbor(prepared)?,
        })
        .await?;
    ensure!(
        response.record.len() <= MAX_ADMIN_BYTES,
        "credential reply exceeds limit"
    );
    let record: AdministrationRecord = decode_dag_cbor(&response.record)?;
    let AdministrationCommand::Credential(CredentialCommand::Issue {
        authorization: returned_authorization,
        credential,
    }) = record.command()
    else {
        anyhow::bail!("invalid credential issuance reply");
    };
    ensure!(
        *returned_authorization == authorization && credential.as_ref() == prepared,
        "credential issuance reply differs from request"
    );
    Ok(())
}

async fn work<T>(
    client: &HostControlClientImpl<T>,
    authorization: GrantId,
    command: &WorkControlCommand,
) -> Result<WorkControlReply>
where
    T: StreamTransport + Send + Sync,
    T::Stream: Send + 'static,
{
    let response = client
        .work_control(WorkControlRequest {
            authorization: authorization.0.to_vec(),
            command: canonical_dag_cbor(command)?,
        })
        .await?;
    ensure!(
        response.reply.len() <= MAX_ADMIN_BYTES,
        "Work reply exceeds limit"
    );
    Ok(decode_dag_cbor(&response.reply)?)
}

async fn offline(
    command: AdminCommand,
    identity: &LocalIdentity,
    passkey: &hellas_kernel::SoftPasskey,
) -> Result<()> {
    let (state, root, revision, bearer) = match command {
        AdminCommand::Bootstrap {
            root_grant,
            state,
            bearer_scope,
            bearer_out,
        } => {
            let id: GrantId = root_grant
                .parse()
                .context("root grant must be 16 bytes of hex")?;
            let bearer = match (bearer_scope, bearer_out) {
                (Some(scope), Some(out)) => {
                    Some((read::<GrantSpec>(&scope)?, credential_output(&out)?, out))
                }
                _ => None,
            };
            (state, Some(id), None, bearer)
        }
        AdminCommand::Recover {
            expected_revision,
            state,
        } => (state, None, Some(Revision(expected_revision)), None),
        _ => anyhow::bail!("offline command required"),
    };
    let OfflineArgs {
        journal,
        administrator,
        credential_scope,
        holder,
        credential_out,
    } = state;
    let administrator: GrantSpec = read(&administrator)?;
    let scope: GrantSpec = read(&credential_scope)?;
    let CredentialHolder::Node(holder) = read(&holder)? else {
        anyhow::bail!("the initial credential must be held by a device");
    };
    let subject = scope.subject;
    let authority = scope.authority;
    let output = credential_output(&credential_out)?;
    let now = hellas_auth::authority::UnixMillis::now().unwrap_or_default();
    let network = hellas_work::model::grant::grant_network();
    let approve = |ownership| owner_approval(passkey, ownership, &administrator, &scope, holder);
    let (secret, revision) = match (root, revision) {
        (Some(root), None) => {
            let (store, secret) = NodeStore::bootstrap(
                &journal,
                network,
                root,
                approve(Ownership::Bootstrap { root })?,
                Some(identity.enrollment.clone()),
                now,
            )
            .await?;
            let mut revision = store.state().authority().revision();
            if let Some((scope, output, out)) = bearer {
                let node = hellas_sdk::work::node::NodeCoordinator::new(
                    store,
                    std::sync::Arc::new(|| {
                        hellas_auth::authority::UnixMillis::now().unwrap_or_default()
                    }),
                );
                let caller = node
                    .authenticate_session(&secret, SessionKey::Passkey(passkey))
                    .await?;
                let (credential, bearer) =
                    Credential::prepare(scope, CredentialHolder::Bearer, caller.generation())?;
                profile::save_credential(output, &out, &bearer)?;
                let record = node.issue_credential(&caller, root, credential).await.with_context(|| format!(
                    "bearer {} is retained at {} pending confirmation; inspect-offline before using it or retrying issuance",
                    bearer.id(), out.display(),
                ))?;
                revision = record.revision();
            }
            (secret, revision)
        }
        (None, Some(expected)) => {
            let (record, secret) = NodeStore::recover_offline(
                &journal,
                network,
                expected,
                approve(Ownership::Recover { expected })?,
                now,
            )
            .await?;
            (secret, record.revision)
        }
        _ => anyhow::bail!("invalid offline operation"),
    };
    profile::save_credential(output, &credential_out, &secret)
        .with_context(|| format!("authority committed at revision {}; credential publication failed; inspect-offline before recovery", revision.0))?;
    println!(
        "{}",
        serde_json::json!({
            "credential_id": hex::encode(secret.id().0), "credential_file": credential_out,
            "revision": revision.0,
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

fn owner_approval(
    passkey: &hellas_kernel::SoftPasskey,
    ownership: Ownership,
    administrator: &GrantSpec,
    scope: &GrantSpec,
    holder: hellas_auth::authority::NodeKey,
) -> Result<OwnerApproval> {
    let digest = ownership_digest(ownership, administrator, scope, holder);
    let envelope = passkey.sign(hellas_kernel::PayloadHash::from_bytes(*digest.as_bytes()))
        .map_err(|error| anyhow::anyhow!("passkey signing failed: {error:?}"))?;
    Ok(OwnerApproval { administrator: administrator.clone(), credential: scope.clone(), holder,
        assertion: passkey_assertion(&envelope)? })
}

async fn bootstrap_remote(
    command: AdminCommand,
    identity: &LocalIdentity,
    passkey: &hellas_kernel::SoftPasskey,
) -> Result<()> {
    let AdminCommand::BootstrapRemote { invitation, root_grant, administrator, credential_scope, profile_out } = command
        else { anyhow::bail!("remote bootstrap required") };
    let invitation: node_control::bootstrap::Invitation = read(&invitation)?;
    let root: GrantId = root_grant.parse()?;
    let administrator: GrantSpec = read(&administrator)?;
    let scope: GrantSpec = read(&credential_scope)?;
    let holder = hellas_auth::authority::NodeKey::from_public_key(identity.node_key.public_key())?;
    let approval = owner_approval(passkey, Ownership::Bootstrap { root }, &administrator, &scope, holder)?;
    let (credential, secret) = Credential::prepare(scope.clone(), CredentialHolder::Node(holder), 1)?;
    let profile = profile::install_remote(&profile_out, scope.authority, root, &secret)?;
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(identity.transport_key.clone()).bind().await?;
    let result = node_control::bootstrap::connect(&endpoint, &invitation, root,
        hellas_work::work_store::grant::PreparedBootstrap { administrator,
            credential, assertion: approval.assertion }).await;
    endpoint.close().await;
    result.with_context(|| format!("credential {} retained in {}; authenticate and inspect its exact ID after a lost reply", secret.id(), profile.display()))?;
    println!("{}", serde_json::json!({"profile":profile,"node_id":invitation.node,"credential_id":secret.id()}));
    Ok(())
}

fn print_status(status: hellas_rpc::pb::host::HostStatus) -> Result<()> {
    let configuration = status.provider_configuration;
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
                    "endpoint": status.endpoint,
                    "provider_state": status.provider.map(|provider| provider.state),
                    "configuration": configuration,
                })
            );
    Ok(())
}
