use super::*;

#[test]
fn inconsistent_persisted_edge_is_corruption_not_catch_up() {
    crate::execution::test_support::run_qmdb(|context| async move {
        let maker = hellas_kernel::Secp256k1Signer::from_secret_scalar([19; 32]).unwrap();
        let taker = hellas_kernel::Secp256k1Signer::from_secret_scalar([20; 32]).unwrap();
        let owner = crate::domain::SettlementKey::from(maker.party_key());
        let mut h =
            crate::edge_index::IndexedNodeHarness::new(context, vec![(owner, 100)], "corrupt-edge")
                .await;
        let (_, _, tx) = crate::edge_index::indexed_basic(h.network, 0, &maker, &taker);
        h.append(vec![Transaction::Kernel(tx)]).await;
        let page = h
            .index
            .list_edges(ListEdgesRequest {
                schema_version: crate::edge_index::SCHEMA_VERSION,
                ..Default::default()
            })
            .unwrap();
        let id = &page.data.unwrap().items[0].edge_id;
        let write = h.index.store.db.begin_write().unwrap();
        write
            .open_table(OBJECTS)
            .unwrap()
            .remove(hex::decode(id).unwrap().as_slice())
            .unwrap();
        write.commit().unwrap();
        let error = h
            .index
            .get_edge_detail(crate::edge_index::types::GetEdgeDetailRequest {
                schema_version: crate::edge_index::SCHEMA_VERSION,
                edge_id: id.clone(),
                payload: None,
            })
            .unwrap_err();
        assert_eq!((error.status, error.code), (500, "index_corrupt"));
        assert!(error.message.contains("history/object state mismatch"));
    });
}

#[test]
fn indexed_startup_rejects_corrupt_published_evidence() {
    for certificate in [false, true] {
        crate::execution::test_support::run_qmdb(|context| async move {
            let mut h =
                crate::edge_index::IndexedNodeHarness::new(context, Vec::new(), "corrupt-startup")
                    .await;
            let mut proof = h.append(Vec::new()).await;
            let config = h.node.config().clone();
            h.node.shutdown().await.unwrap();
            if certificate {
                proof.finalization[0] ^= 1;
            } else {
                proof.state_root = "ff".repeat(32);
            }
            let write = h.index.store.db.begin_write().unwrap();
            write
                .open_table(PROOFS)
                .unwrap()
                .insert(proof.height, proof.encode_to_vec().as_slice())
                .unwrap();
            write.commit().unwrap();
            drop(h.index);
            assert!(
                crate::node::FullNode::start_indexed(
                    config,
                    h.trust,
                    h.genesis_json,
                    "edge-test".into()
                )
                .await
                .is_err()
            );
        });
    }
}
