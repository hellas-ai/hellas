//! CPU-only generic Compute invocation for service lifecycle tests.
use super::*;
use hellas_rpc::protocol::invocation::PreparedInvocation;

#[derive(Default)]
pub struct Compute;
impl Compute {
    pub fn policy(&self) -> GrantPolicy {
        GrantPolicy {
            name: "compute".into(),
            responses: None,
            https: None,
            invocation_policy: hellas_channel::test_support::channel::work_policy(),
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
        let store = &node.store;
        let def = store.state().grant(allowance).unwrap();
        let channel = store
            .state()
            .channel_id(allowance, super::channel_client(actor.principal()))
            .unwrap();
        let policy = &def.policies[0];
        let mut input: PreparedInvocation =
            hellas_channel::test_support::channel::bundle(nonce as u8);
        input.request.runner_public_key = hellas_auth::PublicKey::Secp256k1(
            grant_producer(store.state().provider().unwrap())
                .unwrap()
                .to_bytes(),
        );
        input.request.retain = false;
        input.request.nonce[..8].copy_from_slice(&nonce.to_be_bytes());
        input.application_policy = JsonBytes(policy.invocation_policy.canonical_bytes().unwrap());
        let now = node.clock.now().0;
        let authorization = GrantJobAuthorizationV1 {
            channel_id: channel,
            generation: store.state().generation(allowance).unwrap(),
            grant_id: allowance,
            grant_revision: def.revision,
            resource_id: policy.resource,
            resource_revision: policy.revision,
            pricing_revision: policy.pricing.revision,
            work_policy_digest: hellas_channel::job::policy_digest(
                network(),
                channel.0,
                &policy.invocation_policy,
            )
            .unwrap(),
            input_content: hellas_rpc::ContentRef::for_bytes(&input.canonical_bytes().unwrap()),
            prepared_input_digest: hellas_channel::job::bound_prepared_input_digest(
                network(),
                channel.0,
                &input,
            )
            .unwrap(),
            proposal_nonce: nonce,
            acceptance_deadline_ms: UnixMillis(now + 1000),
            request_commitment: input.request.commitment().unwrap(),
            environment_commitment: input.request.execution_environment,
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
