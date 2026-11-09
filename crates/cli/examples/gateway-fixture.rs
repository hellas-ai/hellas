//! Test-only provisioner for the fresh-home NixOS gateway service.
//! Built as an example, never installed with the operator CLI.
use hellas_auth::{Digest, ProducerSigningKey, authority::*};
use hellas_authority::{
    model::grant::{grant_network, records::decode_enrollment},
    test_support::common_node,
};
use hellas_private::StoreLocation;
use serde_json::json;
use std::{path::Path, process::Command, sync::Arc};

const ALLOWANCE: GrantId = GrantId([7; 16]);
const ROOT_GRANT: GrantId = GrantId([0; 16]);
const PASSKEY: [u8; 32] = [0x14; 32];

fn private(path: &Path, bytes: &[u8]) {
    hellas_private::write_atomically(path, ".writing", bytes).unwrap();
}

#[tokio::main]
async fn main() {
    let root = std::env::var("HELLAS_GATEWAY_FIXTURE_ROOT").unwrap();
    let cli = std::env::var("HELLAS_CLI_BIN").unwrap();
    let root = Path::new(&root);
    let home = root.join(".hellas");
    std::fs::create_dir(&home).unwrap();
    let passkey = root.join("principal.passkey");
    private(&passkey, hex::encode(PASSKEY).as_bytes());
    let run = |args: &[&str]| {
        let output = Command::new(&cli)
            .arg("--home")
            .arg(&home)
            .arg("--passkey")
            .arg(&passkey)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };
    run(&["identity", "init"]);
    let enrollment = decode_enrollment(&run(&["identity", "export-enrollment"])).unwrap();
    let passkey = hellas_kernel::SoftPasskey::from_secret_scalar(PASSKEY).unwrap();
    let principal =
        PrincipalId::from_public_key(hellas_auth::PublicKey::P256(passkey.party_key().to_bytes()))
            .unwrap();

    // Use the node key from the identity that the actual gateway CLI opens.
    let identity = std::fs::read(home.join("identity")).unwrap();
    let mut decoder = hellas_rpc::DagCborDecoder::new(&identity);
    decoder.array(6, "identity").unwrap();
    decoder
        .tag("hellas.provider.identity.persistence.v3")
        .unwrap();
    assert_eq!(decoder.u64("version").unwrap(), 3);
    decoder.array(2, "root").unwrap();
    assert_eq!(decoder.u64("root kind").unwrap(), 0);
    let _: [u8; 32] = decoder.fixed_bytes("root key").unwrap();
    let signer =
        ProducerSigningKey::from_secret_bytes(decoder.fixed_bytes("node key").unwrap()).unwrap();
    let holder = CredentialHolder::Node(
        hellas_auth::authority::NodeKey::from_public_key(signer.public_key()).unwrap(),
    );
    let journal =
        hellas_sdk::grant_config::GrantConfig::journal_dir(&StoreLocation::for_test(&home));
    let now = UnixMillis::now().unwrap();
    let (store, admin) = common_node::bootstrap_node_with_credential(
        &journal,
        grant_network(),
        Some(enrollment.clone()),
        now,
    )
    .await
    .unwrap();
    let definition = common_node::allowance(
        ALLOWANCE,
        principal,
        vec![hellas_authority::test_support::policy()],
    );
    let store = common_node::provision(
        &journal,
        store,
        &admin,
        signer,
        (1, vec![]),
        definition,
        (vec![], 256),
    )
    .await;
    let node = hellas_authority::node::NodeCoordinator::new(
        store,
        Arc::new(|| UnixMillis::now().unwrap()),
    );
    let caller = hellas_authority::test_support::session(&node, &admin).await;
    let scope = GrantSpec {
        authority: caller.authority(),
        subject: principal,
        permissions: [Permission {
            operation: OperationId::new(hellas_authority::grant_service::WORK_EXECUTE).unwrap(),
            resource: hellas_authority::grant_service::allowance_resource(
                caller.authority(),
                ALLOWANCE,
            ),
        }]
        .into(),
        not_before: UnixMillis(1000),
        expires: UnixMillis(u64::MAX),
        delegation_depth: 0,
        issuance: None,
    };
    node.grant(
        &caller,
        GrantCommand::Issue {
            authorization: ROOT_GRANT,
            id: common_node::EXECUTION_AUTHORIZATION,
            spec: scope.clone(),
        },
    )
    .await
    .unwrap();
    let (_, credential) = hellas_authority::test_support::credentials::issue_one(
        &node, &caller, ROOT_GRANT, scope, holder,
    )
    .await
    .unwrap();
    drop(node);
    hellas_sdk::node_control::profile::save_credential(
        hellas_private::private_tempfile(root, ".work-", ".issuing").unwrap(),
        &root.join("work.credential"),
        &credential,
    )
    .unwrap();
    private(
        &root.join("work-profile.json"),
        &serde_json::to_vec(&json!({
            "authority": caller.authority(),
            "authorization": common_node::EXECUTION_AUTHORIZATION,
            "credential": "work.credential",
        }))
        .unwrap(),
    );
    hellas_sdk::trust_policy::TrustPolicyStore::new(root.join("local-trust"))
        .approve(
            "local",
            0,
            hellas_sdk::trust_policy::TrustPolicy {
                provider_genesis: enrollment.content_id(),
                assurance: hellas_rpc::Assurance::ProducerSigned,
                apple: None,
            },
            "VM fixture approval".into(),
        )
        .unwrap();

    // HTTP admission has its own authority and an issued bearer credential.
    let authority = AuthorityId(Digest::hash(b"gateway VM fixture authority"));
    let subject = hellas_channel::test_support::actors::ROOT.principal();
    let permission =
        hellas_authority::operations::Operation::named(hellas_authority::node::GATEWAY_INVOKE)
            .unwrap()
            .permission(authority, None)
            .unwrap();
    let administrator = common_node::admin_spec(
        authority,
        subject,
        &[(hellas_authority::node::GATEWAY_INVOKE, permission.resource)],
        (now, UnixMillis(now.0 + 600_000)),
        (600_000, 0),
        &[],
    );
    let bearer_scope = GrantSpec {
        authority,
        subject,
        permissions: [permission].into(),
        issuance: None,
        delegation_depth: 0,
        not_before: now,
        expires: UnixMillis(now.0 + 600_000),
    };
    let gateway_journal = root.join("gateway-authority");
    let location = StoreLocation::for_test(&gateway_journal);
    let (store, admin) = hellas_authority::work_store::grant::NodeStore::bootstrap(
        &location,
        grant_network(),
        ROOT_GRANT,
        common_node::approval(
            Ownership::Bootstrap {
                root: ROOT_GRANT,
                target: None,
            },
            administrator,
        ),
        None,
        now,
    )
    .await
    .unwrap();
    let node = hellas_authority::node::NodeCoordinator::new(
        store,
        Arc::new(|| UnixMillis::now().unwrap()),
    );
    let caller = hellas_authority::test_support::session(&node, &admin).await;
    let (_, bearer) = hellas_authority::test_support::credentials::issue_one(
        &node,
        &caller,
        ROOT_GRANT,
        bearer_scope,
        CredentialHolder::Bearer,
    )
    .await
    .unwrap();
    drop(node);
    let mut token = bearer.id().0.to_vec();
    token.extend_from_slice(bearer.expose_secret());
    private(&root.join("gateway.credential"), &token);
    private(&root.join("gateway.token"), hex::encode(&token).as_bytes());
    private(
        &root.join("gateway-profile.json"),
        &serde_json::to_vec(&json!({
            "journal": gateway_journal,
            "authority": authority,
            "authorization": ROOT_GRANT,
            "credential": root.join("gateway.credential"),
        }))
        .unwrap(),
    );
}
