//! Canonical native Evaluate input for CPU-only service tests.
use super::*;
use crate::model::prepared_input::PreparedPaidInputV1;
use crate::model::work::{EvaluatePolicyV2, generation_policy_digest, identity_source_digest};
use hellas_rpc::protocol::artifacts::*;

pub struct Evaluate {
    manifest: ProgramManifest,
    tokens: TokenIds,
    policy: TextPolicy,
    identity: TextArtifact,
}
impl Default for Evaluate {
    fn default() -> Self {
        let manifest = ProgramManifest::new(
            Application::new(CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR).unwrap(),
            ContentId::hash(b"service test model"),
        );
        let identity =
            TextArtifact::identity(BoundTermId::from_digest(manifest.content_id().digest()));
        Self {
            manifest,
            tokens: TokenIds::from([9, 8, 7]),
            policy: TextPolicy::from_u32_stop_tokens(5, []),
            identity,
        }
    }
}
impl Evaluate {
    pub fn policy(&self) -> GrantPolicy {
        GrantPolicy {
            responses: None,
            work: EvaluatePolicyV2 {
                allowed_environment: self.manifest.content_id(),
                generation_policy_digest: generation_policy_digest(&self.policy.canonical_bytes())
                    .unwrap(),
                identity_source_digest: identity_source_digest(&self.identity.canonical_bytes())
                    .unwrap(),
                max_prompt_tokens: 128,
                max_new_tokens: 5,
                max_stop_token_ids: 0,
                max_spool_bytes: 1 << 20,
                max_encoded_result_frame: 1 << 20,
                max_encoded_prepared_input: 1 << 20,
                max_upload_bytes: 1 << 20,
            }
            .into(),
            ..policy()
        }
    }
    pub fn allowance(&self, id: GrantId, actor: Actor) -> Allowance {
        let mut allowance = Allowance::responses(id, actor);
        allowance.definition.policies = vec![self.policy()];
        allowance
    }
    pub fn proposal(
        &self,
        node: &TestNode,
        actor: Actor,
        allowance: GrantId,
        nonce: u64,
    ) -> Proposal {
        let execution = TextExecution::new(
            SourceRef::output(self.identity.output_id()),
            self.tokens.output_id(),
            self.policy.output_id(),
        );
        let request = EvaluateRequest {
            text_execution: execution.input_id().digest(),
            runner_public_key: actor.node_key().public_key(),
            execution_environment: self.manifest.content_id(),
            nonce: [0; 32],
            assurance: Assurance::ProducerSigned,
            retain: true,
        };
        let input = PreparedWorkInput::from(PreparedPaidInputV1::new(
            &request,
            &self.manifest,
            &execution,
            &self.tokens,
            &self.policy,
            &self.identity,
        ));
        let store = &node.store;
        let def = store.state().grant(allowance).unwrap();
        let channel = store
            .state()
            .channel_id(allowance, super::channel_client(actor.principal()))
            .unwrap();
        let policy = &def.policies[0];
        let now = node.clock.now().0;
        let authorization = GrantJobAuthorizationV1 {
            channel_id: channel,
            generation: store.state().generation(allowance).unwrap(),
            grant_id: allowance,
            grant_revision: def.revision,
            resource_id: policy.resource,
            resource_revision: policy.revision,
            pricing_revision: policy.pricing.revision,
            work_policy_digest: policy.work.digest(network(), channel.0),
            prepared_input_digest: input.bound_digest(network(), channel.0).unwrap(),
            proposal_nonce: nonce,
            acceptance_deadline_ms: UnixMillis(now + 1000),
            request_commitment: RequestCommitment::from_digest(
                input.input_commitment().unwrap().digest(),
            ),
            environment_commitment: self.manifest.content_id(),
            terminal_deadline_ms: UnixMillis(now + 3000),
            delivery_deadline_ms: UnixMillis(now + 4000),
        };
        let signature = actor
            .node_key()
            .sign_digest(grant_work_id(network(), &authorization))
            .unwrap();
        Proposal {
            authorization,
            signature,
            input,
        }
    }
}
