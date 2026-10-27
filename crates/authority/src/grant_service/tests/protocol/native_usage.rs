use super::*;
use crate::test_support::{actors::*, evaluate::Evaluate, ids};

struct NativeWork {
    world: TestService,
    backend: Backend,
    work: crate::grant_service::GrantWork,
    first: Proposal,
    second: Proposal,
}
impl NativeWork {
    async fn new(path: &std::path::Path) -> Self {
        let evaluate = Evaluate::default();
        let node = Node::bootstrap(path)
            .with_capacity(Capacity::new(4).with_limits(vec![Limit {
                meter: Meter::OutputTokens,
                window: Window::Total,
                amount: 5,
            }]))
            .with_allowance(evaluate.allowance(ids::ALLOWANCE, FRIEND))
            .with_grant(
                ids::FRIEND_GRANT,
                Rights::new(authority(), FRIEND)
                    .allow(
                        crate::grant_service::WORK_EXECUTE,
                        crate::grant_service::allowance_resource(authority(), ids::ALLOWANCE),
                    )
                    .valid_until(UnixMillis(100_000))
                    .build(),
            )
            .build()
            .await;
        let first = evaluate.proposal(&node, FRIEND, ids::ALLOWANCE, 1);
        let second = evaluate.proposal(&node, FRIEND, ids::ALLOWANCE, 2);
        let backend = Backend {
            signer: Arc::new(PROVIDER.node_key()),
            ..Backend::default()
        };
        let world = node.serve(backend.clone());
        let work = world.work(FRIEND, ids::FRIEND_GRANT).await;
        Self {
            world,
            backend,
            work,
            first,
            second,
        }
    }
    async fn finish_first(&self) {
        let id = accepted_id(
            crate::test_support::accept_grant(
                &self.work,
                &self.first.request(),
                &FRIEND.node_key(),
            )
            .await,
        );
        within(self.backend.started.notified()).await;
        self.backend.finish.release();
        let mut stream = self
            .work
            .stream(delivery::delivery_request(&self.first.authorization, id));
        loop {
            let event = within(stream.next())
                .await
                .expect("native work terminal")
                .unwrap();
            match event.outcome {
                Some(work_stream_event::Outcome::Prefix(_)) => {}
                Some(work_stream_event::Outcome::Terminal(_)) => break,
                other => panic!("native execution refused: {other:?}"),
            }
        }
    }
}

#[tokio::test]
async fn native_execution_settles_verified_tokens() {
    let directory = tempfile::tempdir().unwrap();
    let native = NativeWork::new(directory.path()).await;

    native.finish_first().await;

    assert_eq!(
        native
            .world
            .used(BudgetNode::Machine, Meter::InputTokens)
            .await,
        3
    );
    assert_eq!(
        native
            .world
            .used(BudgetNode::Machine, Meter::OutputTokens)
            .await,
        1
    );
    assert_eq!(native.backend.calls.load(Ordering::SeqCst), 1);
    within(native.world.service.drain()).await.unwrap();
}

#[tokio::test]
async fn an_exhausted_token_budget_refuses_before_native_execution() {
    let directory = tempfile::tempdir().unwrap();
    let native = NativeWork::new(directory.path()).await;
    native.finish_first().await;

    let response = crate::test_support::accept_grant(
        &native.work,
        &native.second.request(),
        &FRIEND.node_key(),
    )
    .await;

    assert_eq!(refusal(response), GrantRefusalCode::Budget);
    assert_eq!(native.backend.calls.load(Ordering::SeqCst), 1);
    within(native.world.service.drain()).await.unwrap();
}
