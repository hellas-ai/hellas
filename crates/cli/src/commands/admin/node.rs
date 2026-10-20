use super::{AdminArgs, AdminCommand, OfflineArgs};
use crate::{
    commands::contributions::{data_root, offer_fingerprints, principal},
    identity::LocalIdentity,
};
use anyhow::{Context, Result, ensure};
use hellas_auth::authority::{
    AdministrationCommand, AdministrationRecord, CredentialCommand, CredentialHolder, CredentialId,
    CredentialSecret, GrantCommand, GrantId, GrantSpec, Ownership, Revision, ownership_digest,
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
    if let Some(node) = args.node_enrollment {
        let provider = decode_enrollment(&hellas_private::read_bounded_regular_file(
            &node,
            hellas_work::model::grant::records::MAX_ENROLLMENT_BYTES,
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
            let client =
                node_control::connect_iroh(connection, profile.authority, &profile.credential, key)
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
            None => data_root(&principal(passkey.context(
                "the default control socket is the principal's; pass --passkey or --control-socket",
            )?)?)?
            .join("control.sock"),
        };
        let client = node_control::connect_local(
            &socket,
            tls,
            server_name,
            profile.authority,
            &profile.credential,
            key,
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
            let output = credential_output(&credential_out)?;
            let secret = issue(&client, authorization, &scope, holder).await?;
            let id = hex::encode(secret.id().0);
            profile::save_credential(output, &credential_out, &secret).with_context(|| {
                format!(
                    "credential {id} was issued but could not be saved; revoke it before retrying"
                )
            })?;
            println!(
                "{}",
                serde_json::json!({
                    "credential_id": id, "revision": 1,
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
            let credential = issue(
                &client,
                authorization,
                &scope,
                CredentialHolder::Node(holder),
            )
            .await?;
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
            bundle.save(&out).with_context(|| {
                format!(
                    "credential {id} was issued but the bundle could not be saved; revoke it before retrying"
                )
            })?;
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

/// Issue a credential and check the durable record matches the request.
async fn issue<T>(
    client: &HostControlClientImpl<T>,
    authorization: GrantId,
    scope: &GrantSpec,
    holder: CredentialHolder,
) -> Result<CredentialSecret>
where
    T: StreamTransport + Send + Sync,
    T::Stream: Send + 'static,
{
    let response = client
        .issue_credential(IssueCredentialRequest {
            authorization: authorization.0.to_vec(),
            scope: canonical_dag_cbor(scope)?,
            holder: canonical_dag_cbor(&holder)?,
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
            && credential.scope() == scope
            && credential.holder() == holder
            && credential.revision() == Revision(1)
            && !credential.revoked(),
        "credential issuance reply differs from request"
    );
    Ok(secret)
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
    let approve = |ownership| -> Result<OwnerApproval> {
        let digest = ownership_digest(ownership, &administrator, &scope, holder);
        let envelope = passkey
            .sign(hellas_kernel::PayloadHash::from_bytes(*digest.as_bytes()))
            .map_err(|error| anyhow::anyhow!("passkey signing failed: {error:?}"))?;
        Ok(OwnerApproval {
            administrator: administrator.clone(),
            credential: scope.clone(),
            holder,
            assertion: passkey_assertion(&envelope)?,
        })
    };
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
                let (record, bearer) = node
                    .issue_credential(&caller, root, scope, CredentialHolder::Bearer)
                    .await?;
                revision = record.revision();
                profile::save_credential(output, &out, &bearer).with_context(|| format!(
                    "authority committed at revision {}; bearer {} publication failed; inspect-offline before retrying",
                    revision.0, hex::encode(bearer.id().0),
                ))?;
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
