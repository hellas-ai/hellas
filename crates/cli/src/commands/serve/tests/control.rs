use super::super::*;
use crate::commands::admin::{AdminArgs, AdminCommand, OfflineArgs};
use crate::identity::LocalIdentity;
use hellas_auth::{Digest, authority as auth};
use hellas_authority::{
    node::{HOST_STATUS, WORK_CAPACITY_CONFIGURE, host_resource, machine_resource},
    test_support::{WAIT, common_node, ids},
};
use hellas_rpc::Assurance;
use hellas_sdk::{grant_config::GrantConfig, node_control};
use std::path::Path;
const ROOT_GRANT: auth::GrantId = ids::ROOT_GRANT;
const READER_GRANT: auth::GrantId = ids::FRIEND_GRANT;
type Control =
    hellas_rpc::services::host_control::HostControlClientImpl<hellas_sdk::wire::mux::MuxTransport>;

/// A software passkey file and the principal it controls.
fn passkey(root: &Path, name: &str, scalar: u8) -> (PathBuf, auth::PrincipalId) {
    let path = root.join(name);
    hellas_private::write_atomically(&path, ".writing", &[scalar; 32]).unwrap();
    let passkey = hellas_kernel::SoftPasskey::from_secret_scalar([scalar; 32]).unwrap();
    let principal = auth::PrincipalId::from_public_key(hellas_auth::PublicKey::P256(
        passkey.party_key().to_bytes(),
    ))
    .unwrap();
    (path, principal)
}
/// A JSON CredentialHolder naming `identity`'s node key.
fn holder(root: &Path, name: &str, identity: &LocalIdentity) -> PathBuf {
    let path = root.join(name);
    let holder = auth::CredentialHolder::Node(
        auth::NodeKey::from_public_key(identity.node_key.public_key()).unwrap(),
    );
    std::fs::write(&path, serde_json::to_vec(&holder).unwrap()).unwrap();
    path
}

struct Daemon {
    root: tempfile::TempDir,
    identity: LocalIdentity,
    passkey: PathBuf,
    admin_holder: PathBuf,
    provider_identity: LocalIdentity,
    wrong_identity: LocalIdentity,
    scope: auth::GrantSpec,
    scope_file: PathBuf,
    credential_file: PathBuf,
    profile_path: PathBuf,
    socket: PathBuf,
    journal: PathBuf,
    handle: Option<node_control::host::HostHandle>,
}
/// One admin invocation: its arguments and the global `--passkey` file.
struct Invocation(AdminArgs, Option<PathBuf>);
async fn run(
    Invocation(args, passkey): Invocation,
    identity: &LocalIdentity,
) -> anyhow::Result<()> {
    let passkey = passkey
        .as_deref()
        .map(crate::commands::chain::passkey)
        .transpose()?;
    crate::commands::admin::run(
        args,
        identity,
        passkey
            .as_ref()
            .map(|key| key as &dyn hellas_authority::authenticator::Authenticator),
    )
    .await
}
fn offline_args(command: AdminCommand, passkey: Option<&Path>) -> Invocation {
    Invocation(
        AdminArgs {
            profile: None,
            control_socket: None,
            node_enrollment: None,
            addresses: vec![],
            command,
        },
        passkey.map(Path::to_owned),
    )
}
impl Daemon {
    async fn start() -> Self {
        // Keep Unix socket paths below the platform length limit.
        let scratch = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/t");
        std::fs::create_dir_all(&scratch).unwrap();
        let root = tempfile::Builder::new()
            .prefix("ctl-")
            .tempdir_in(scratch.canonicalize().unwrap())
            .unwrap();
        hellas_private::restrict_directory(root.path()).unwrap();
        let identity =
            crate::identity::load_or_create(Some(&root.path().join("identity"))).unwrap();
        let provider_identity =
            crate::identity::load_or_create(Some(&root.path().join("provider-identity"))).unwrap();
        let wrong_identity =
            crate::identity::load_or_create(Some(&root.path().join("other-identity"))).unwrap();
        let authority = auth::AuthorityId(Digest::hash(b"daemon control fixture"));
        let root_grant = ROOT_GRANT;
        let now = hellas_auth::authority::UnixMillis::now().unwrap_or_default();
        let (passkey, owner) = self::passkey(root.path(), "admin.passkey", 0x31);
        let admin_holder = holder(root.path(), "admin-holder.json", &identity);
        let scope = common_node::admin_spec(
            authority,
            owner,
            &[
                (HOST_STATUS, host_resource(authority)),
                (WORK_CAPACITY_CONFIGURE, machine_resource(authority)),
            ],
            (now, auth::UnixMillis(now.0 + 3_600_000)),
            (3_600_000, 8),
            &[],
        );
        let mut grant_config = GrantConfig::unconfigured(&root.path().canonicalize().unwrap());
        grant_config.remote_control = node_control::RemoteControlAdmission::new(vec![
            identity.transport_key.public(),
            wrong_identity.transport_key.public(),
        ])
        .unwrap();
        let scope_file = root.path().join("scope.json");
        let credential_file = root.path().join("app.credential");
        hellas_private::write_atomically(
            &scope_file,
            ".writing",
            &serde_json::to_vec(&scope).unwrap(),
        )
        .unwrap();
        let offline = || OfflineArgs {
            journal: grant_config.journal_root.clone(),
            administrator: scope_file.clone(),
            credential_scope: scope_file.clone(),
            holder: admin_holder.clone(),
            credential_out: credential_file.clone(),
        };
        run(
            offline_args(
                AdminCommand::Bootstrap {
                    root_grant: hex::encode(root_grant.0),
                    state: offline(),
                    bearer_scope: None,
                    bearer_out: None,
                },
                Some(&passkey),
            ),
            &provider_identity,
        )
        .await
        .unwrap();
        let tls = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        hellas_private::write_atomically(
            &grant_config.control_certificate,
            ".writing",
            tls.cert.der(),
        )
        .unwrap();
        hellas_private::write_atomically(
            &grant_config.control_private_key,
            ".writing",
            &tls.signing_key.serialize_der(),
        )
        .unwrap();
        let profile_path = root.path().join("control-profile.json");
        let profile_json = serde_json::json!({
            "authority": authority, "authorization": root_grant,
            "credential": "app.credential",
            "local": {"certificate": "control.cert.der", "server_name": "localhost"},
        });
        hellas_private::write_atomically(
            &profile_path,
            ".writing",
            &serde_json::to_vec(&profile_json).unwrap(),
        )
        .unwrap();
        let socket = grant_config.control_socket.clone();
        let journal = grant_config.journal_root.clone();
        let mut executor = ExecutorSpawnConfig::fetch_only(
            Arc::new(provider_identity.node_key.clone()),
            Assurance::ProducerSigned,
            FetchRouteRegistry::default(),
        );
        executor.queue_capacity = 4;
        executor.fetch_max_in_flight = 1;
        executor.fetch_queue_capacity = 1;
        let daemon = super::super::configuration::start_host(
            hellas_sdk::ProviderOptions {
                executor,
                grants: None,
                discovery: false,
                port: Some(0),
                build: "control-test".into(),
                graffiti: vec![],
                work: None,
                secret_key: provider_identity.transport_key.clone(),
                open_identity: provider_identity.open_identity(),
            },
            Some(grant_config),
            None,
            None,
        )
        .await
        .unwrap();
        Self {
            root,
            identity,
            passkey,
            admin_holder,
            provider_identity,
            wrong_identity,
            scope,
            scope_file,
            credential_file,
            profile_path,
            socket,
            journal,
            handle: Some(daemon),
        }
    }
    /// The administrator's passkey session over the local socket.
    fn local(&self, command: AdminCommand) -> Invocation {
        let Invocation(args, passkey) = offline_args(command, Some(&self.passkey));
        Invocation(
            AdminArgs {
                profile: Some(self.profile_path.clone()),
                control_socket: Some(self.socket.clone()),
                ..args
            },
            passkey,
        )
    }
    /// A daily session over the local socket, by whichever identity runs it.
    fn local_daily(&self, command: AdminCommand) -> Invocation {
        Invocation(self.local(command).0, None)
    }
    fn remote(
        &self,
        profile: PathBuf,
        command: AdminCommand,
        passkey: Option<&Path>,
    ) -> Invocation {
        let contact = self.root.path().join("node.enrollment");
        std::fs::write(
            &contact,
            self.provider_identity.enrollment.canonical_bytes(),
        )
        .unwrap();
        let Invocation(args, passkey) = offline_args(command, passkey);
        Invocation(
            AdminArgs {
                profile: Some(profile),
                node_enrollment: Some(contact.to_str().unwrap().into()),
                addresses: self
                    .handle
                    .as_ref()
                    .unwrap()
                    .provider_endpoint()
                    .borrow()
                    .as_ref()
                    .unwrap()
                    .bound_sockets(),
                ..args
            },
            passkey,
        )
    }
    async fn client(&self) -> Control {
        let profile = node_control::profile::ClientProfile::load(&self.profile_path).unwrap();
        let (tls, name) = profile.local.unwrap();
        node_control::connect_local(
            &self.socket,
            tls,
            name,
            profile.authority,
            &profile.credential,
            hellas_authority::node::SessionKey::Node(&self.identity.node_key),
        )
        .await
        .unwrap()
        .0
    }
    fn reader_scope(&self) -> PathBuf {
        let mut scope = self.scope.clone();
        scope.subject = passkey(self.root.path(), "reader.passkey", 0x32).1;
        scope.issuance = None;
        scope
            .permissions
            .retain(|p| p.operation.as_str() == HOST_STATUS);
        let path = self.root.path().join("reader-scope.json");
        std::fs::write(&path, serde_json::to_vec(&scope).unwrap()).unwrap();
        path
    }
    fn issue_reader_command(&self) -> AdminCommand {
        AdminCommand::IssueCredential {
            scope: self.reader_scope(),
            holder: holder(self.root.path(), "reader-holder.json", &self.wrong_identity),
            credential_out: self.root.path().join("reader.credential"),
        }
    }
    async fn issue_reader(&self) -> Reader {
        let scope = serde_json::from_slice(&std::fs::read(self.reader_scope()).unwrap()).unwrap();
        let change = self.root.path().join("issue.json");
        std::fs::write(
            &change,
            serde_json::to_vec(&auth::GrantCommand::Issue {
                authorization: ROOT_GRANT,
                id: READER_GRANT,
                spec: scope,
            })
            .unwrap(),
        )
        .unwrap();
        run(
            self.local(AdminCommand::Grant { command: change }),
            &self.identity,
        )
        .await
        .unwrap();
        run(
            self.remote(
                self.profile_path.clone(),
                self.issue_reader_command(),
                Some(&self.passkey),
            ),
            &self.identity,
        )
        .await
        .unwrap();
        let credential_path = self.root.path().join("reader.credential");
        let credential = node_control::profile::read_credential(&credential_path).unwrap();
        let profile = self.root.path().join("reader-profile.json");
        hellas_private::write_atomically(&profile, ".writing", &serde_json::to_vec(&serde_json::json!({
            "authority": self.scope.authority, "authorization": READER_GRANT, "credential": credential_path,
        })).unwrap()).unwrap();
        Reader {
            credential_path,
            credential,
            profile,
        }
    }
    async fn stop(&mut self) {
        assert!(self.socket.exists());
        tokio::time::timeout(WAIT, self.handle.take().unwrap().shutdown())
            .await
            .unwrap()
            .unwrap();
        assert!(!self.socket.exists(), "shutdown removes the control socket");
    }
    async fn store(&self) -> hellas_authority::work_store::grant::NodeStore {
        hellas_authority::work_store::grant::NodeStore::open(
            &self.journal,
            hellas_authority::model::grant::grant_network(),
            Some(self.provider_identity.enrollment.clone()),
            auth::UnixMillis::now().unwrap_or_default(),
        )
        .await
        .unwrap()
    }
}
struct Reader {
    credential_path: PathBuf,
    credential: auth::CredentialSecret,
    profile: PathBuf,
}
fn status_request() -> hellas_rpc::pb::host::GetHostStatusRequest {
    hellas_rpc::pb::host::GetHostStatusRequest {
        authorization: ROOT_GRANT.0.to_vec(),
    }
}
fn assert_permission_denied(error: anyhow::Error) {
    assert_eq!(
        error
            .downcast_ref::<hellas_sdk::wire::WireStatus>()
            .expect("wire refusal")
            .code,
        hellas_sdk::wire::WireCode::PermissionDenied,
        "{error:#}"
    );
}

#[tokio::test]
async fn online_admin_requires_an_explicit_profile() {
    let mut daemon = Daemon::start().await;
    let error = run(offline_args(AdminCommand::Status, None), &daemon.identity)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "--profile is required");
    daemon.stop().await;
}

#[tokio::test]
async fn local_capacity_command_reaches_the_running_host() {
    let mut daemon = Daemon::start().await;
    let limits = daemon.root.path().join("machine-limits.json");
    let budget = vec![hellas_authority::model::grant::budget::Limit {
        meter: hellas_authority::model::grant::budget::Meter::Requests,
        window: hellas_authority::model::grant::budget::Window::Total,
        amount: 7,
    }];
    std::fs::write(&limits, serde_json::to_vec(&budget).unwrap()).unwrap();
    let client = daemon.client().await;
    let before = client.get_host_status(status_request()).await.unwrap();
    assert!(before.machine.is_none());
    run(
        daemon.local(AdminCommand::SetCapacity {
            limits,
            expected_revision: 0,
            max_in_flight: 3,
        }),
        &daemon.identity,
    )
    .await
    .unwrap();
    let machine = client
        .get_host_status(status_request())
        .await
        .unwrap()
        .machine
        .unwrap();
    assert_eq!(machine.max_in_flight, 3);
    assert_eq!(
        hellas_rpc::protocol::value::decode_dag_cbor::<
            Vec<hellas_authority::model::grant::budget::Limit>,
        >(&machine.limits)
        .unwrap(),
        budget
    );
    daemon.stop().await;
}

#[tokio::test]
async fn local_profile_requires_its_own_identity() {
    let mut daemon = Daemon::start().await;
    // A daily session needs the node key the credential is bound to.
    assert_permission_denied(
        run(
            daemon.local_daily(AdminCommand::Status),
            &daemon.wrong_identity,
        )
        .await
        .unwrap_err(),
    );
    run(daemon.local_daily(AdminCommand::Status), &daemon.identity)
        .await
        .unwrap();
    daemon.stop().await;
}

#[tokio::test]
async fn existing_credential_output_refuses_before_issuing_again() {
    let mut daemon = Daemon::start().await;
    let reader = daemon.issue_reader().await;
    let client = daemon.client().await;
    let original = std::fs::read(&reader.credential_path).unwrap();
    let before = client
        .get_host_status(status_request())
        .await
        .unwrap()
        .authority_revision;
    let error = run(
        daemon.local(daemon.issue_reader_command()),
        &daemon.identity,
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "credential output already exists");
    assert_eq!(std::fs::read(&reader.credential_path).unwrap(), original);
    assert_eq!(
        client
            .get_host_status(status_request())
            .await
            .unwrap()
            .authority_revision,
        before
    );
    daemon.stop().await;
}

#[tokio::test]
async fn refused_issuance_retains_an_exact_pending_credential_without_granting_access() {
    let mut daemon = Daemon::start().await;
    let command = daemon.issue_reader_command();
    let AdminCommand::IssueCredential {
        ref scope,
        ref credential_out,
        ..
    } = command
    else {
        panic!("issue")
    };
    let output = credential_out.clone();
    let mut invalid: auth::GrantSpec =
        serde_json::from_slice(&std::fs::read(scope).unwrap()).unwrap();
    invalid.permissions = [auth::Permission {
        operation: auth::OperationId::new(hellas_authority::node::HOST_STATUS).unwrap(),
        resource: auth::ResourceId(hellas_auth::Digest::hash(b"another host")),
    }]
    .into();
    std::fs::write(scope, serde_json::to_vec(&invalid).unwrap()).unwrap();
    let client = daemon.client().await;
    let before = client
        .get_host_status(status_request())
        .await
        .unwrap()
        .authority_revision;
    let error = run(daemon.local(command), &daemon.identity)
        .await
        .unwrap_err();
    let pending = node_control::profile::read_credential(&output).unwrap();
    assert!(error.to_string().contains("pending confirmation"));
    assert!(error.to_string().contains(&pending.id().to_string()));
    assert_permission_denied(error);
    assert_eq!(
        client
            .get_host_status(status_request())
            .await
            .unwrap()
            .authority_revision,
        before
    );
    let denied = client
        .inspect_authority(hellas_rpc::pb::host::InspectAuthorityRequest {
            authorization: ROOT_GRANT.0.to_vec(),
            query: hellas_rpc::protocol::value::canonical_dag_cbor(
                &auth::InspectionQuery::Credential { id: pending.id() },
            )
            .unwrap(),
        })
        .await
        .unwrap_err();
    assert_eq!(denied.code(), hellas_sdk::wire::WireCode::PermissionDenied);
    daemon.stop().await;
}

#[tokio::test]
async fn issued_credential_is_private_and_revocation_reaches_remote_authentication() {
    let mut daemon = Daemon::start().await;
    let reader = daemon.issue_reader().await;
    assert!(
        hellas_private::is_private(&std::fs::File::open(&reader.credential_path).unwrap()).unwrap()
    );
    run(
        daemon.remote(reader.profile.clone(), AdminCommand::Status, None),
        &daemon.wrong_identity,
    )
    .await
    .unwrap();
    run(
        daemon.local(AdminCommand::RevokeCredential {
            credential_id: reader.credential.id().to_string(),
            expected_revision: 1,
        }),
        &daemon.identity,
    )
    .await
    .unwrap();
    assert_permission_denied(
        run(
            daemon.remote(reader.profile, AdminCommand::Status, None),
            &daemon.wrong_identity,
        )
        .await
        .unwrap_err(),
    );
    daemon.stop().await;
}

#[tokio::test]
async fn offline_recovery_publishes_a_usable_replacement_credential() {
    let mut daemon = Daemon::start().await;
    daemon.stop().await;
    let store = daemon.store().await;
    let expected_revision = store.state().authority().revision().0;
    drop(store);
    let recovered_path = daemon.root.path().join("recovered.credential");
    run(
        offline_args(
            AdminCommand::Recover {
                expected_revision,
                state: OfflineArgs {
                    journal: daemon.journal.clone(),
                    administrator: daemon.scope_file.clone(),
                    credential_scope: daemon.scope_file.clone(),
                    holder: daemon.admin_holder.clone(),
                    credential_out: recovered_path.clone(),
                },
            },
            Some(&daemon.passkey),
        ),
        &daemon.identity,
    )
    .await
    .unwrap();
    let store = daemon.store().await;
    let authority = store.state().authority();
    let daily = |secret: &auth::CredentialSecret| {
        let now = auth::UnixMillis::now().unwrap_or_default();
        let binding = Digest::hash(b"recovery check");
        let pending = authority.begin_authentication(binding, now)?;
        let proof = pending.challenge().sign_daily(
            authority.authority(),
            binding,
            secret.id(),
            &daemon.identity.node_key,
        )?;
        pending
            .complete(authority, binding, secret, &proof, now)
            .map(auth::AuthenticatedSession::into_caller)
    };
    let original = node_control::profile::read_credential(&daemon.credential_file).unwrap();
    hellas_auth::assert_err!(daily(&original), auth::AuthorityError::Credential);
    let replacement = node_control::profile::read_credential(&recovered_path).unwrap();
    assert_eq!(daily(&replacement).unwrap().subject(), daemon.scope.subject);
}

#[tokio::test]
async fn offline_bootstrap_issues_a_separate_gateway_bearer() {
    let root = tempfile::tempdir().unwrap();
    let identity = crate::identity::load_or_create(Some(&root.path().join("identity"))).unwrap();
    let (passkey_file, owner) = passkey(root.path(), "operator.passkey", 0x33);
    let authority = auth::AuthorityId(Digest::hash(b"gateway bearer fixture"));
    let now = auth::UnixMillis::now().unwrap_or_default();
    let permission =
        hellas_authority::operations::Operation::named(hellas_authority::node::GATEWAY_INVOKE)
            .unwrap()
            .permission(authority, None)
            .unwrap();
    let administrator = common_node::admin_spec(
        authority,
        owner,
        &[(hellas_authority::node::GATEWAY_INVOKE, permission.resource)],
        (now, auth::UnixMillis(now.0 + 3_600_000)),
        (3_600_000, 0),
        &[],
    );
    let bearer_scope = auth::GrantSpec {
        authority,
        subject: owner,
        permissions: [permission].into(),
        issuance: None,
        delegation_depth: 0,
        not_before: now,
        expires: auth::UnixMillis(now.0 + 3_600_000),
    };
    let admin_file = root.path().join("admin.json");
    std::fs::write(&admin_file, serde_json::to_vec(&administrator).unwrap()).unwrap();
    let bearer_file = root.path().join("bearer-scope.json");
    std::fs::write(&bearer_file, serde_json::to_vec(&bearer_scope).unwrap()).unwrap();
    let journal = root.path().join("http-authority");
    let (admin_out, bearer_out) = (
        root.path().join("admin.credential"),
        root.path().join("http.credential"),
    );
    run(
        offline_args(
            AdminCommand::Bootstrap {
                root_grant: hex::encode([0; 16]),
                state: OfflineArgs {
                    journal: journal.clone(),
                    administrator: admin_file.clone(),
                    credential_scope: admin_file,
                    holder: holder(root.path(), "holder.json", &identity),
                    credential_out: admin_out.clone(),
                },
                bearer_scope: Some(bearer_file),
                bearer_out: Some(bearer_out.clone()),
            },
            Some(&passkey_file),
        ),
        &identity,
    )
    .await
    .unwrap();
    let admin = node_control::profile::read_credential(&admin_out).unwrap();
    let bearer = node_control::profile::read_credential(&bearer_out).unwrap();
    assert_ne!(admin.id(), bearer.id());
    let store = hellas_authority::work_store::grant::NodeStore::open(
        &journal,
        hellas_authority::model::grant::grant_network(),
        None,
        now,
    )
    .await
    .unwrap();
    assert_eq!(
        store
            .state()
            .authority()
            .credential(bearer.id())
            .unwrap()
            .holder(),
        auth::CredentialHolder::Bearer
    );
    let node = hellas_authority::node::NodeCoordinator::new(store, Arc::new(move || now));
    // The bearer authenticates by its secret alone, for gateway.invoke only;
    // the device-held bootstrap credential does not.
    let caller = node.authenticate(&bearer).await.unwrap();
    node.authorize_gateway(&caller, auth::GrantId([0; 16]))
        .await
        .unwrap();
    assert!(node.authenticate(&admin).await.is_err());
}
