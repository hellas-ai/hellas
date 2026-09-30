pub const HASH_TUPLE_V2: &str = "hellas.hash_tuple.v2";
pub const PRODUCER_ID_V2: &str = "hellas.producer_id.v2";

pub const STREAM_CANONICALIZATION_ID_V2: &str = "hellas.stream.canonicalization.id.v2";
pub const STREAM_INPUT_EVENT_V2: &str = "hellas.stream.input.event.v2";
pub const STREAM_OUTPUT_EVENT_V2: &str = "hellas.stream.output.event.v2";
pub const STREAM_EVENT_SIGNATURE_V2: &str = "hellas.stream.event.signature.v2";
pub const STREAM_INPUT_GENESIS_V2: &str = "hellas.stream.input.genesis.v2";
pub const STREAM_OUTPUT_GENESIS_V2: &str = "hellas.stream.output.genesis.v2";
pub const STREAM_ID_V2: &str = "hellas.stream.id.v2";
pub const STREAM_INPUT_COMMITMENT_V2: &str = "hellas.stream.input.commitment.v2";

// Canonical protocol tags. Producer-signed retains the existing scheme IDs.
pub const ASSURANCE_PRODUCER_SIGNED: u8 = 0x00;
pub const ASSURANCE_APPLE_APP_ATTEST: u8 = 0x01;
pub const SCHEME_EVALUATE_PRODUCER_SIGNED: u8 = 0x00;
pub const SCHEME_FETCH_PRODUCER_SIGNED: u8 = 0x01;
pub const SCHEME_EVALUATE_APPLE_APP_ATTEST: u8 = 0x02;
pub const SCHEME_FETCH_APPLE_APP_ATTEST: u8 = 0x03;

pub const SIGNATURE_SECP256K1: u8 = 1;
pub const SIGNATURE_ED25519: u8 = 2;
pub const SIGNATURE_P256: u8 = 3;
