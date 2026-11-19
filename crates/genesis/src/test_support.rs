//! Synthetic documents for tests; no deployed network identity.
use crate::{ChainProfile, CustomChainFile, Genesis, TrustDocument, TrustEpoch};
use sha2::{Digest as _, Sha256};

pub const NETWORK_ID: &str = "test-network";
pub const GENESIS_JSON: &str = r#"{"schema_version":1,"network_id":"test-network","validators":[{"public_key":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","label":"validator"}],"allocations":[{"address":"jesTu2BpszP8DKSoi1R5G6ggjHrsrVnboLdx6V47vkoR","balance":1000}]}"#;

pub fn genesis() -> Genesis {
    serde_json::from_str(GENESIS_JSON).unwrap()
}

pub fn profile() -> ChainProfile {
    ChainProfile::custom(CustomChainFile {
        trust: TrustDocument {
            schema_version: crate::TRUST_SCHEMA_VERSION,
            network_id: NETWORK_ID.into(),
            genesis_sha256: hex::encode(Sha256::digest(GENESIS_JSON)),
            epochs: vec![TrustEpoch {
                epoch: 0,
                start_height: 0,
                end_height: None,
                // BLS12-381 G1 generator: the public key for secret scalar one.
                threshold_identity: "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb".into(),
            }],
        },
        validators: vec!["ws://unused.invalid".into()],
        genesis_json: GENESIS_JSON.into(),
    }).unwrap()
}
