//! Shared real authority provisioning for native and process-loss SDK controls.
use hellas_auth::authority::{GrantId, UnixMillis};
use hellas_authority::{
    grant_service::GrantService,
    model::grant::records::{GrantDef, Offer, SignedOffer},
    test_support as common,
};
use hellas_channel::test_support::{
    backend::{Backend, Completion, Reply},
    network, principal,
};
use hellas_rpc::{Assurance, Retention, protocol::invocation::PreparedInvocation};
use hellas_sdk::{
    grant_client::{GrantSessionOptions, UnpinnedOffer},
    node_control::profile::ClientProfile,
};

use std::{
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};

pub(super) struct Fixture {
    pub(super) root: tempfile::TempDir,
    pub(super) service: GrantService,
    pub(super) node_content: hellas_store::content::DiskStore,
    pub(super) grant: GrantDef,
    pub(super) enrollment: hellas_rpc::ProviderEnrollmentBundle,
    pub(super) application: Arc<ClientProfile>,
    pub(super) calls: Arc<AtomicUsize>,
    pub(super) now: UnixMillis,
}
impl Fixture {
    pub(super) async fn with_reply(compute: bool, reply: Option<Reply>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let provider_root = root.path().join("provider");
        let enrollment = hellas_channel::test_support::software_enrollment(
            2,
            *iroh::SecretKey::from_bytes(&[2; 32]).public().as_bytes(),
        );
        let (store, secret) = common::common_node::bootstrap_node_with_credential(
            &provider_root,
            network(),
            Some(enrollment.clone()),
            UnixMillis(1000),
        )
        .await
        .unwrap();
        let mut grant = common::definition(GrantId([1; 16]), principal(1).0);
        if compute {
            grant.policies = vec![common::compute::Compute.policy()];
        }
        if reply.is_some() {
            let hellas_rpc::protocol::invocation::Admission::Fetch { admission } =
                &mut grant.policies[0].invocation_policy.admissions[0]
            else {
                unreachable!()
            };
            admission.limits.max_request_body_bytes = 1 << 20;
            admission.limits.max_spool_bytes = 1 << 20;
            admission.limits.max_output_events =
                (admission.limits.max_spool_bytes / 1024 + 1) as u32;
        }
        let store = common::common_node::provision(
            &provider_root,
            store,
            &secret,
            principal(2).1,
            (4, vec![]),
            grant.clone(),
            (vec![], 2),
        )
        .await;
        let now = UnixMillis::now().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = Backend {
            calls: calls.clone(),
            finish: Completion::Immediate,
            reply: reply.unwrap_or_else(|| Reply::text("sdk-private-output", 1)),
            ..Backend::default()
        };
        let node_content = common::content_store(&provider_root).await;
        let service = GrantService::new(
            store,
            Arc::new(principal(2).1),
            backend,
            vec![],
            Arc::new(move || now),
            node_content.clone(),
        )
        .unwrap();
        let credential = common::common_node::execution_credential(
            &service.node(),
            &secret,
            principal(1).0,
            grant.id,
        )
        .await;
        let caller = common::session(&service.node(), &secret).await;
        let application = Arc::new(ClientProfile {
            authority: caller.authority(),
            authorization: common::common_node::EXECUTION_AUTHORIZATION,
            credential,
            local: None,
        });
        Self {
            root,
            service,
            node_content,
            grant,
            enrollment,
            application,
            calls,
            now,
        }
    }
    pub(super) fn options(&self, addresses: Vec<String>) -> GrantSessionOptions {
        let signed = SignedOffer::sign(
            Offer {
                network: network(),
                provider: self.enrollment.clone(),
                grant: self.grant.clone(),
                generation: 0,
                sequence: 1,
                valid_until: UnixMillis(self.now.0 + 1_000_000),
                addresses,
            },
            &principal(2).1,
        )
        .unwrap();
        let target = UnpinnedOffer::decode(&signed.encode().unwrap(), self.now)
            .unwrap()
            .pin(&hellas_client::ProviderTrustAnchor {
                expected_genesis: self.enrollment.content_id(),
                required_assurance: Assurance::ProducerSigned,
                apple_app_attest: None,
            })
            .unwrap();
        GrantSessionOptions {
            target,
            principal: principal(1).0,
            signer: Arc::new(principal(1).1),
            application: self.application.clone(),
            journal_root: self.root.path().join("client"),
            control_timeout: Duration::from_secs(10),
        }
    }

    pub(super) fn input_from(&self, body: &[u8]) -> PreparedInvocation {
        let contract = hellas_channel::test_support::test_responses_contract();
        let events = hellas_rpc::fetch::build_input_events_with_retention(
            "openai",
            "responses",
            body,
            contract.manifest_id(),
            Assurance::ProducerSigned,
            &principal(1).1,
            Retention::Ephemeral,
        )
        .unwrap();
        hellas_rpc::protocol::invocation::fetch::prepare(
            &events,
            &contract,
            principal(2).1.public_key(),
            self.grant.policies[0]
                .invocation_policy
                .canonical_bytes()
                .unwrap(),
            [1; 32],
        )
        .unwrap()
    }
}
