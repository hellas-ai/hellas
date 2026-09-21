//! Shared generated EdgeIndex transport models and validation.
pub use hellas_rpc::edge_index::*;

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    #[test]
    fn proof_routes_keep_schema_one_json_and_proto3_preserves_absence() {
        let proof = ProofBundle {
            schema_version: PROOF_SCHEMA_VERSION,
            height: 7,
            canonical_block: vec![0, 255],
            ..Default::default()
        };
        let json = serde_json::to_value(&proof).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["height"], 7);
        assert_eq!(json["canonical_block"], serde_json::json!([0, 255]));
        let missing = serde_json::from_str::<GetEdgeDetailResponse>("{}").unwrap();
        assert!(missing.envelope.is_none());
        assert!(
            super::super::projection::check_detail(
                &EdgeDetail::default(),
                &EdgeIndexMetadata::default(),
                &[],
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Snapshot>(r#"{"height":"1","payload":"","state_root":""}"#)
                .unwrap()
                .block_proof
                .is_none()
        );
    }
    #[test]
    fn json_preserves_u64_max_and_canonical_bytes() {
        let fees = CloseFees {
            base: u64::MAX,
            slot: 1,
            proof: 2,
            lifetime: 3,
        };
        let json = serde_json::to_value(fees).unwrap();
        assert_eq!(json["base"], u64::MAX.to_string());
        assert_eq!(serde_json::from_value::<CloseFees>(json).unwrap(), fees);
        for bad in [
            r#"{"base":1,"slot":"1","proof":"2","lifetime":"3"}"#,
            r#"{"base":"01","slot":"1","proof":"2","lifetime":"3"}"#,
        ] {
            assert!(serde_json::from_str::<CloseFees>(bad).is_err());
        }
        let slot = RegistrySlot {
            object_id: "ab".repeat(32),
            chunk: Some(vec![0, 255, 1]),
        };
        let json = serde_json::to_value(&slot).unwrap();
        assert_eq!(json["chunk"], "AP8B");
        assert_eq!(serde_json::from_value::<RegistrySlot>(json).unwrap(), slot);
        assert_ne!(
            RegistrySlot {
                object_id: slot.object_id.clone(),
                chunk: None
            }
            .encode_to_vec(),
            RegistrySlot {
                object_id: slot.object_id,
                chunk: Some(vec![])
            }
            .encode_to_vec()
        );
    }
    #[test]
    fn generated_proto_and_explicit_json_share_fields_and_presence() {
        let request = GetWorkChannelDetailRequest {
            payment_edge_id: "a1".repeat(32),
            payload: Some("b2".repeat(32)),
            funding: Some(FundingQuery { coins: vec![] }),
            schema_version: SCHEMA_VERSION,
        };
        let generated =
            GetWorkChannelDetailRequest::decode(request.encode_to_vec().as_slice()).unwrap();
        assert!(generated.funding.is_some());
        let response = ListEdgesResponse {
            envelope: Some(EdgeIndexMetadata {
                schema_version: SCHEMA_VERSION,
                network_id: "hellas-devnet-1".into(),
                genesis_sha256: "a1".repeat(32),
                trust_sha256: "b2".repeat(32),
                snapshot: Some(Snapshot {
                    height: u64::MAX,
                    payload: "c3".repeat(32),
                    state_root: "d4".repeat(32),
                    block_proof: Some(ProofBundle {
                        height: u64::MAX,
                        canonical_block: vec![0, 255],
                        ..Default::default()
                    }),
                }),
                index: Some(IndexCoverage {
                    indexed_through_height: u64::MAX,
                    ..Default::default()
                }),
                provenance: Some(Provenance::reported()),
                evidence: vec![],
            }),
            data: Some(ListEdgesPage {
                items: vec![],
                next_cursor: None,
            }),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("envelope").is_some());
        assert_eq!(json["envelope"]["schema_version"], SCHEMA_VERSION);
        assert_eq!(json["envelope"]["snapshot"]["height"], u64::MAX.to_string());
        assert_eq!(
            json["envelope"]["snapshot"]["block_proof"]["canonical_block"],
            serde_json::json!([0, 255])
        );
        assert_eq!(
            serde_json::from_value::<ListEdgesResponse>(json).unwrap(),
            response
        );
    }
    #[test]
    fn object_and_parser_absence_are_explicit() {
        let absent = ObjectAnswer {
            answer: Some(ObjectState::Absent(AbsentObject {
                provenance: "indexer-reported".into(),
            })),
        };
        let json = serde_json::to_value(&absent).unwrap();
        assert!(json["answer"].get("absent").is_some());
        assert_eq!(
            serde_json::from_value::<ObjectAnswer>(json).unwrap(),
            absent
        );
        let invalid = PendingAnswer {
            answer: Some(PendingState::Invalid(ParserInvalid {
                reason: "wrong edge".into(),
            })),
        };
        let json = serde_json::to_value(&invalid).unwrap();
        assert!(json["answer"].get("invalid").is_some());
        assert_eq!(
            serde_json::from_value::<PendingAnswer>(json).unwrap(),
            invalid
        );
    }
    #[test]
    fn invalid_filters_schema_and_noncanonical_ids_are_rejected() {
        let mut request = ListEdgesRequest {
            schema_version: SCHEMA_VERSION,
            ..Default::default()
        };
        assert!(request.validate().is_ok());
        request.limit = Some(0);
        assert!(request.validate().is_err());
        request.limit = None;
        request.kind = Some("unknown".into());
        assert!(request.validate().is_err());
        request.kind = None;
        request.role = Some("maker".into());
        assert!(request.validate().is_err());
        request.role = None;
        request.schema_version = 1;
        assert!(request.validate().is_err());
        for id in ["A1".repeat(32), "00".repeat(31), "0g".repeat(32)] {
            assert!(validate_id(&id).is_err());
        }
    }
}
