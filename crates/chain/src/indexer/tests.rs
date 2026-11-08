use super::fixtures::spawn_archive;
use super::*;
use crate::domain::PublicKey;
use crate::execution::test_support::{ConsensusFixture, consensus_fixture, finality_envelope};
use crate::{Application, ApplicationConfig};
use commonware_consensus::{
    simplex::types::Context,
    types::{Epoch, Round, View},
};
use commonware_runtime::Handle;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

async fn genesis(context: deterministic::Context, leader: PublicKey, prefix: &str) -> HellasBlock {
    Application::new(
        context,
        crate::domain::TEST_NETWORK,
        commonware_cryptography::sha256::Digest::from([0; 32]),
        leader,
        Vec::new(),
        prefix,
        ApplicationConfig {
            page_cache_size: 1024,
            page_cache_count: 8,
        },
    )
    .await
    .genesis_block()
}

fn block(parent: &HellasBlock, leader: PublicKey, view: u64, state: u8) -> HellasBlock {
    let parent_context = parent.context();
    HellasBlock::new(
        Context {
            round: Round::new(Epoch::zero(), View::new(view)),
            leader,
            parent: (parent_context.round.view(), parent.digest()),
        },
        parent.digest(),
        parent.height().next(),
        view,
        Digest::from([state; 32]),
        parent.sync_target(),
        Vec::new(),
    )
}

async fn setup(
    context: deterministic::Context,
    seed: u64,
) -> (
    fixtures::ArchiveSource,
    Handle<()>,
    ConsensusFixture,
    HellasBlock,
) {
    let fixture = consensus_fixture(seed);
    let genesis = genesis(
        context.child("app"),
        fixture.leaders[0].clone(),
        &format!("genesis-{seed}"),
    )
    .await;
    let config = Config {
        mailbox_size: 32,
        replay_buffer: 32,
        write_buffer: 32,
        page_cache_size: 1024,
        page_cache_count: 8,
        ..Config::default()
    };
    let (indexer, handle) = spawn_archive(
        context.child("indexer"),
        &format!("indexer-{seed}"),
        config,
        fixture.verifier.clone(),
        genesis.clone(),
    )
    .await
    .expect("indexer");
    (indexer, handle, fixture, genesis)
}

#[test]
fn pruning_reclaims_old_marshal_sections() {
    deterministic::Runner::default().start(|context| async move {
        let (indexer, _handle, fixture, mut parent) = setup(context, 97989).await;
        for height in 1..=260 {
            let next = block(&parent, fixture.leaders[0].clone(), height, 1);
            indexer
                .publish_proof(next.clone(), &finality_envelope(&fixture, &next))
                .await
                .unwrap();
            parent = next;
        }
        indexer.retain_from(259, 259);
        // This bypasses the public retention floor: the backing archive itself
        // must have removed the first section, not merely hidden its entries.
        assert!(indexer.marshal.get_block(Height::new(1)).await.is_none());
        assert!(indexer.marshal.get_block(Height::new(260)).await.is_some());
        assert!(
            indexer
                .get_finalized_block(FinalizedBlockQuery::Height(258))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            indexer
                .get_finalized_block(FinalizedBlockQuery::Height(259))
                .await
                .unwrap()
                .is_some()
        );
    });
}
