//! Shared owner, grant and gateway for the manual model comparisons.
use super::*;
use hellas_authority::model::grant::{
    ChannelClient, ChannelId, grant_channel_id, grant_network, owner_grant_id, records::*,
};
use hellas_rpc::protocol::invocation::{
    Admission, InvocationPolicy, Limits, compute, output::InvocationOutput,
};

pub(super) struct LocalCompute {
    pub gateway: Process,
    pub http: reqwest::Client,
    pub address: String,
    pub provider: hellas_auth::PublicKey,
    journal: PathBuf,
    enrollment: hellas_rpc::ProviderEnrollmentBundle,
    channel: ChannelId,
    _directory: tempfile::TempDir,
}

impl LocalCompute {
    pub async fn start(
        model: &Path,
        model_flag: &str,
        content: &Path,
        limits: Limits,
        job_millis: Option<std::num::NonZeroU64>,
        extra: &[&str],
    ) -> Self {
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
        let (store, secret) = common_node::bootstrap_node_with_credential(
            &journal,
            grant_network(),
            Some(enrollment.clone()),
            hellas_auth::authority::UnixMillis::now().unwrap_or_default(),
        )
        .await
        .unwrap();
        let policy = GrantPolicy {
            name: "local".into(),
            invocation_policy: InvocationPolicy {
                admissions: vec![Admission::Compute {
                    evaluator: compute::EVALUATOR.into(),
                }],
                limits,
            },
            https: None,
            responses: None,
            ..hellas_authority::test_support::policy()
        };
        let allowance = owner_grant_id(grant_network(), enrollment.content_id(), principal);
        // Read this fixture identity's node key to provision its own service.
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
        let client = ChannelClient {
            principal,
            node: hellas_auth::authority::NodeKey::from_public_key(signer.public_key()).unwrap(),
        };
        let mut definition = common_node::allowance(allowance, principal, vec![policy]);
        if let Some(millis) = job_millis {
            definition.max_job_millis = millis;
        }
        let store = common_node::provision(
            &journal,
            store,
            &secret,
            signer,
            (1, vec![]),
            definition,
            (vec![], 256),
        )
        .await;
        let channel = grant_channel_id(
            grant_network(),
            enrollment.content_id(),
            allowance,
            client,
            store.state().generation(allowance).unwrap(),
        );
        let node = hellas_authority::node::NodeCoordinator::new(
            store,
            Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
        );
        let credential =
            execution_credential(&node, &secret, principal, allowance, owner.holder().await).await;
        let authority = hellas_authority::test_support::session(&node, &secret)
            .await
            .authority();
        let work_profile = work_profile(root, authority, &credential);
        drop(node);
        let (gateway_profile, gateway_token) = gateway_profile(root).await;
        let trust_root = approve(root, "local", enrollment.content_id());
        let index = std::env::var("HELLAS_TEST_CONTENT_INDEX")
            .map(PathBuf::from)
            .unwrap_or_else(|_| root.join("content-index.bin"));
        // Hash large checkpoints before the ordinary gateway startup check.
        let store = hellas_store::ContentStore::new();
        let _ = store.records().load(&index);
        let content_flag = if content.is_dir() {
            store.adopt(content).unwrap();
            "--content-root"
        } else {
            store.index(content).unwrap();
            "--content"
        };
        store.records().save(&index).unwrap();
        let allowance = hex::encode(allowance.0);
        let archive = root.join("archive");
        let mut args = vec![
            "gateway",
            "--trust-store",
            string(&trust_root),
            "--trust-policy",
            "local",
            "--local-grant",
            &allowance,
            "--work-profile",
            string(&work_profile),
            model_flag,
            string(model),
            content_flag,
            string(content),
            "--content-index",
            string(&index),
            "--gpu-backend",
            "hip",
            "--port",
            "0",
            "--gateway-profile",
            string(&gateway_profile),
            "--archive-dir",
            string(&archive),
            "--zdr",
        ];
        args.extend_from_slice(extra);
        let mut gateway = owner.spawn(&args, "local-model-gateway.log");
        let address = gateway.wait_for("gateway listening on ").await;
        // Native compilation can outlast the shared fixture client's 10 s.
        let http = reqwest::Client::builder()
            .default_headers(
                [(
                    reqwest::header::AUTHORIZATION,
                    reqwest::header::HeaderValue::from_str(&format!("Bearer {gateway_token}"))
                        .unwrap(),
                )]
                .into_iter()
                .collect(),
            )
            .build()
            .unwrap();
        let provider =
            hellas_auth::PublicKey::Secp256k1(grant_producer(&enrollment).unwrap().to_bytes());
        Self {
            gateway,
            http,
            address,
            provider,
            journal,
            enrollment,
            channel,
            _directory: directory,
        }
    }

    pub async fn verify_result(
        &self,
        commitment: &str,
        transcript: &[u8],
        expected: &InvocationOutput,
    ) {
        let store = hellas_authority::work_store::grant::NodeStore::open(
            &self.journal,
            grant_network(),
            Some(self.enrollment.clone()),
            hellas_auth::authority::UnixMillis::now().unwrap(),
        )
        .await
        .unwrap();
        let book = store.state().channel(self.channel).unwrap().job_book();
        let actual: Vec<_> = book
            .jobs()
            .filter_map(|job| job.result().map(|(result, _)| result))
            .chain(book.terminals().filter_map(|terminal| {
                terminal
                    .outcome
                    .result
                    .as_ref()
                    .map(|signed| &signed.result)
            }))
            .collect();
        assert_eq!(actual.len(), 1, "one signed model result");
        assert_eq!(hex::encode(actual[0].work_id.as_bytes()), commitment);
        assert_eq!(
            actual[0].transcript_content,
            hellas_rpc::ContentRef::for_bytes(transcript)
        );
        assert_eq!(
            actual[0].canonical_output_digest,
            expected.content_id().unwrap().digest()
        );
    }
}
