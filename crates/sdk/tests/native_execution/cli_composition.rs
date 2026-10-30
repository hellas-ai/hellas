//! Run the real CLI gateway against the providers in the paid/grant fixture.
use super::*;
use hellas_auth::authority::{
    AuthorityId, CredentialHolder, CredentialSecret, GrantId, GrantSpec, NodeKey, Ownership,
};
use hellas_authority::test_support::common_node;
use hellas_sdk::grant_client::GrantSessionOptions;
use hellas_sdk::trust_policy::{TrustPolicy, TrustPolicyStore};
use std::path::Path;

pub(super) fn run_gateway<'a>(
    binary: &'a std::ffi::OsStr,
    root: &'a Path,
    first: &'a GrantSessionOptions,
    second: &'a super::pool::Provider,
    data_root: &'a Path,
) -> futures::future::BoxFuture<'a, ()> {
    Box::pin(async move {
        use hellas_rpc::services::work::Work;
        use hellas_wire::{Dispatcher, ServiceMarker, StreamTransport};
        let signer = hellas_channel::test_support::principal(3).1;
        let server = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(&[3; 32]))
            .alpns(vec![Work::ALPN.as_bytes().to_vec()])
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        assert_eq!(server.id(), second.endpoint);
        let second_enrollment = second.options.target.offer().provider.clone();
        let open = Arc::new(
            hellas_sdk::ProviderOpen::<ProducerSigningKey>::new(
                Arc::new(signer.clone()),
                second_enrollment,
                None,
            )
            .unwrap(),
        );
        let router = hellas_sdk::work_router::WorkRouter::grants(second.service.clone());
        let accepting = server.clone();
        let server_task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Some(incoming) = accepting.accept().await {
                let router = router.clone();
                let open = open.clone();
                connections.spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    let transport = hellas_wire::iroh::IrohTransport::new(connection);
                    let Ok(dispatcher) = router.accept_iroh(&transport, open).await else {
                        return;
                    };
                    while let Ok(Some(inbound)) = transport.accept().await {
                        if dispatcher.dispatch(inbound).await.is_err() {
                            break;
                        }
                    }
                });
            }
            while connections.join_next().await.is_some() {}
        });
        let mut second_offer = second.options.target.offer().clone();
        second_offer.addresses = server
            .bound_sockets()
            .iter()
            .map(ToString::to_string)
            .collect();
        let second_offer =
            hellas_authority::model::grant::records::SignedOffer::sign(second_offer, &signer)
                .unwrap();
        let holder = NodeKey::from_public_key(first.signer.public_key()).unwrap();
        let store = hellas_sdk::grant_store::GrantStore::new(data_root);
        let trust_root = root.join("composition-cli-trust");
        let mut channels = Vec::new();
        for (label, options, signed, resource) in [
            (
                "first",
                first,
                first.target.signed().clone(),
                first.target.offer().grant.policies[1].resource,
            ),
            ("second", &second.options, second_offer, second.resource),
        ] {
            let source = root.join(format!("composition-{label}.bundle"));
            let bundle = hellas_sdk::access_bundle::AccessBundle {
                offers: vec![signed.clone()],
                authority: options.application.authority,
                authorization: options.application.authorization,
                subject: first.principal,
                holder,
                credential: CredentialSecret::from_parts(
                    options.application.credential.id(),
                    *options.application.credential.expose_secret(),
                ),
                expires: UnixMillis(u64::MAX),
                label: None,
            };
            bundle.save(&source).unwrap();
            let imported = store
                .import_bundle(&source, label, &first.principal, &holder, false)
                .unwrap();
            TrustPolicyStore::new(&trust_root)
                .approve(
                    label,
                    0,
                    TrustPolicy {
                        provider_genesis: signed.offer().provider.content_id(),
                        assurance: Assurance::ProducerSigned,
                        apple: None,
                    },
                    "independent provider approval".into(),
                )
                .unwrap();
            channels.push(
                serde_json::json!({"offer": imported.offers[0].name, "work_profile":label,
            "trust_policy":label, "resources":[resource.0.to_string()]}),
            );
        }
        let config = root.join("composition-cli-pool.json");
        std::fs::write(
            &config,
            serde_json::to_vec(&serde_json::json!({"channels":channels})).unwrap(),
        )
        .unwrap();

        let identity_path = root.join("composition-cli-identity");
        let root_key = ProducerSigningKey::from_secret_bytes([0x41; 32]).unwrap();
        let node_key = ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
        let transport = iroh::SecretKey::from_bytes(&[0x42; 32]);
        let enrollment = enrollment(
            &root_key,
            &node_key,
            *transport.public().as_bytes(),
            [0x43; 32],
        );
        let mut identity = hellas_rpc::DagCborEncoder::new();
        identity.array(6);
        identity.str("hellas.provider.identity.persistence.v3");
        identity.u64(3);
        identity.array(2);
        identity.u64(0);
        identity.bytes(&[0x41; 32]);
        identity.bytes(&[1; 32]);
        identity.bytes(&[0x42; 32]);
        identity.bytes(&enrollment.canonical_bytes());
        hellas_private::write_atomically(&identity_path, ".writing", &identity.into_bytes())
            .unwrap();
        let passkey = root.join("composition-cli-passkey");
        hellas_private::write_atomically(&passkey, ".writing", &[0x81; 32]).unwrap();

        let authority = AuthorityId(Digest::hash(b"composition gateway authority"));
        let owner = hellas_auth::test_support::actors::OPERATOR.principal();
        let now = UnixMillis::now().unwrap();
        let permission =
            hellas_authority::operations::Operation::named(hellas_authority::node::GATEWAY_INVOKE)
                .unwrap()
                .permission(authority, None)
                .unwrap();
        let administrator = common_node::admin_spec(
            authority,
            owner,
            &[(hellas_authority::node::GATEWAY_INVOKE, permission.resource)],
            (now, UnixMillis(now.0 + 600_000)),
            (600_000, 0),
            &[],
        );
        let scope = GrantSpec {
            authority,
            subject: owner,
            permissions: [permission].into(),
            issuance: None,
            not_before: now,
            expires: UnixMillis(now.0 + 600_000),
            delegation_depth: 0,
        };
        let gateway_root = root.join("composition-http-authority");
        let root_grant = GrantId([0; 16]);
        let (node_store, administrator_secret) =
            hellas_authority::work_store::grant::NodeStore::bootstrap(
                &gateway_root,
                hellas_authority::model::grant::grant_network(),
                root_grant,
                common_node::approval(
                    Ownership::Bootstrap {
                        root: root_grant,
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
            node_store,
            Arc::new(|| UnixMillis::now().unwrap_or_default()),
        );
        let caller = hellas_authority::test_support::session(&node, &administrator_secret).await;
        let (_, bearer) = hellas_authority::test_support::credentials::issue_one(
            &node,
            &caller,
            root_grant,
            scope,
            CredentialHolder::Bearer,
        )
        .await
        .unwrap();
        drop(node);
        let mut token = bearer.id().0.to_vec();
        token.extend_from_slice(bearer.expose_secret());
        let credential_path = root.join("composition-http-credential");
        hellas_private::write_atomically(&credential_path, ".writing", &token).unwrap();
        let profile = root.join("composition-gateway-profile.json");
        hellas_private::write_atomically(&profile, ".writing", &serde_json::to_vec(&serde_json::json!({
        "journal": gateway_root, "authority": authority, "authorization": root_grant, "credential": credential_path,
    })).unwrap()).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let log_path = root.join("composition-cli.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let mut child = tokio::process::Command::new(binary)
            .env("HELLAS_GRANT_DATA_DIR", data_root.parent().unwrap())
            .arg("--identity")
            .arg(&identity_path)
            .arg("--passkey")
            .arg(&passkey)
            .arg("gateway")
            .arg("--grant-pool-config")
            .arg(&config)
            .arg("--trust-store")
            .arg(&trust_root)
            .arg("--port")
            .arg(address.port().to_string())
            .arg("--gateway-profile")
            .arg(&profile)
            .arg("--archive-dir")
            .arg(root.join("composition-cli-archive"))
            .arg("--zdr")
            .stdout(std::process::Stdio::from(log.try_clone().unwrap()))
            .stderr(std::process::Stdio::from(log))
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if tokio::net::TcpStream::connect(address).await.is_ok() {
                    break;
                }
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "gateway exited: {}",
                    std::fs::read_to_string(&log_path).unwrap_or_default()
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
        let response = reqwest::Client::new()
            .post(format!("http://{address}/v1/chat/completions"))
            .bearer_auth(hex::encode(token))
            .json(&serde_json::json!({"messages":[]}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert!(
            std::process::Command::new("kill")
                .args(["-INT", &child.id().unwrap().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let status = tokio::time::timeout(Duration::from_secs(30), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(
            status.success(),
            "gateway shutdown: {}",
            std::fs::read_to_string(&log_path).unwrap_or_default()
        );
        server.close().await;
        server_task.await.unwrap();
    })
}
