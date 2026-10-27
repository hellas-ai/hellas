use super::*;
use hellas_authority::model::grant::records::decode_enrollment;

struct LocalGateway {
    _root: tempfile::TempDir,
    process: Process,
    http: reqwest::Client,
    url: String,
}
impl LocalGateway {
    async fn start_with_exhausted_allowance() -> Self {
        use hellas_authority::model::grant::{budget::*, grant_network, owner_grant_id};
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        hellas_private::restrict_directory(root).unwrap();
        let owner = Cli::new(root, "owner", AGENT_PASSKEY);
        owner.run(&["--software-root", "identity", "init"]).await;
        let export = owner.output(&["identity", "export-enrollment"]).await;
        assert!(export.status.success());
        let enrollment = decode_enrollment(&export.stdout).unwrap();
        let principal = owner.principal();
        let journal = root
            .join("grants")
            .join(format!("p256-{}", hex::encode(principal.as_bytes())))
            .join("provider");
        let now = hellas_auth::authority::UnixMillis::now().unwrap_or_default();
        let (store, secret) = common_node::bootstrap_node_with_credential(
            &journal,
            grant_network(),
            Some(enrollment.clone()),
            now,
        )
        .await
        .unwrap();
        let (environment, policy, environment_file, tokenizer) =
            super::native_owner::native_model(root, "local", 1023, 1023);
        let allowance = owner_grant_id(grant_network(), enrollment.content_id(), principal);
        // Read only this freshly generated fixture identity to provision its native service.
        let identity_bytes = std::fs::read(&owner.identity).unwrap();
        let mut decoder = hellas_rpc::DagCborDecoder::new(&identity_bytes);
        decoder.array(6, "identity").unwrap();
        decoder
            .tag("hellas.provider.identity.persistence.v3")
            .unwrap();
        assert_eq!(decoder.u64("version").unwrap(), 3);
        decoder.array(2, "root").unwrap();
        assert_eq!(decoder.u64("root kind").unwrap(), 0);
        let _: [u8; 32] = decoder.fixed_bytes("root key").unwrap();
        let signer = hellas_auth::ProducerSigningKey::from_secret_bytes(
            decoder.fixed_bytes("node key").unwrap(),
        )
        .unwrap();
        let store = common_node::provision(
            &journal,
            store,
            &secret,
            signer,
            (
                1,
                vec![Limit {
                    meter: Meter::Requests,
                    window: Window::Total,
                    amount: 0,
                }],
            ),
            common_node::allowance(allowance, principal, vec![policy]),
            (vec![], 256),
        )
        .await;
        let node = hellas_authority::node::NodeCoordinator::new(
            store,
            Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
        );
        // The local gateway signs its jobs with this node's own key.
        let credential =
            execution_credential(&node, &secret, principal, allowance, owner.holder().await).await;
        let authority = hellas_authority::test_support::session(&node, &secret)
            .await
            .authority();
        let work_profile = work_profile(root, authority, &credential);
        drop(node);
        let (gateway_profile, gateway_token) = gateway_profile(root).await;
        let trust_root = approve(
            root,
            "local",
            enrollment.content_id(),
            vec![environment.manifest().content_id()],
        );
        let mut gateway = owner.spawn(
            &[
                "gateway",
                "--trust-store",
                string(&trust_root),
                "--trust-policy",
                "local",
                "--local",
                "--local-grant",
                &hex::encode(allowance.0),
                "--work-profile",
                string(&work_profile),
                "--environment",
                string(&environment_file),
                "--content",
                string(&environment_file),
                "--tokenizer",
                string(&tokenizer),
                "--model",
                "fixture",
                "--port",
                "0",
                "--gateway-profile",
                string(&gateway_profile),
                "--archive-dir",
                string(&root.join("archive")),
                "--zdr",
            ],
            "local-gateway.log",
        );
        let address = gateway.wait_for("gateway listening on ").await;
        Self {
            _root: directory,
            process: gateway,
            http: gateway_client(&gateway_token),
            url: format!("http://{address}/v1/completions"),
        }
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_gateway_consults_the_existing_machine_allowance() {
    let mut gateway = LocalGateway::start_with_exhausted_allowance().await;
    let response = post(
        &gateway.http,
        &gateway.url,
        json!({"model":"fixture","prompt":"hello","max_tokens":1}),
    )
    .await;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "{}",
        response.text().await.unwrap()
    );
    gateway.process.stop().await;
}
