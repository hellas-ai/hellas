#![allow(clippy::redundant_pub_crate)]

//! All chain-version constants in one place.
//!
//! Changing any value here is a **protocol-incompatible change**. Every
//! deployment must agree on these, and every Xet commitment computed
//! by the kernel depends on them — coin ids, edge ids, terms commitments,
//! and close hashes would all shift under a different choice of sizes
//! or domain separators.
//!
//! Group by area; document each constant's role; never inline a "magic
//! number" that lives here.

// ── Identifier and hash sizes (bytes) ─────────────────────────────────

/// Length of every kernel hash output. Xet produces a 32-byte
/// digest; every commitment ([`crate::TermsHash`], [`crate::PayloadHash`])
/// and every derived identifier ([`crate::CoinId`], [`crate::EdgeId`],
/// [`crate::BlockHash`]) is this size.
pub(crate) const HASH_LENGTH: usize = 32;

/// Length of a kernel object identifier. Equal to [`HASH_LENGTH`] because
/// every id is derived as a Xet commitment over canonical fields.
pub(crate) const ID_LENGTH: usize = HASH_LENGTH;

/// Length of a compressed settlement key. 33 bytes is the SEC1
/// compressed form (`02` / `03` prefix byte plus the 32-byte
/// x-coordinate) used by native secp256k1 keys and passkey P-256 keys.
pub(crate) const KEY_LENGTH: usize = 33;

/// Length of each P-256 affine coordinate and compact signature scalar.
pub(crate) const P256_COORDINATE_LENGTH: usize = 32;

/// Length of a compact ECDSA settlement signature: `r ‖ s`, 32 bytes
/// each, no DER framing.
pub(crate) const SIG_LENGTH: usize = 64;

/// Maximum bytes of `authenticatorData || clientDataJSON` carried by one
/// `WebAuthn` authorization assertion.
///
/// Mirrors Tempo's 2 KiB bound: large enough for browser-produced
/// assertion metadata, small enough to keep every kernel transaction
/// payload statically bounded.
pub const MAX_WEBAUTHN_DATA_LENGTH: usize = 2048;

// ── Operation bounds ──────────────────────────────────────────────────

/// Maximum coins that can fund one party in a v1 edge open.
///
/// Four inputs per party covers the expected one-or-two-coin channel
/// open while keeping validation fully bounded. Raising this changes
/// operation shape, resource costs, and model bounds, so it is a
/// chain-version change.
pub const MAX_PARTY_INPUTS: usize = 4;

/// Maximum coins that can fund one v1 edge open. Equals
/// `2 * MAX_PARTY_INPUTS`.
pub const MAX_EDGE_INPUTS: usize = MAX_PARTY_INPUTS * 2;

/// Maximum coins that can be produced by one v1 edge close.
///
/// Four outputs leaves room for maker, taker, and small protocol-defined
/// splits without making every close pay for an unbounded payout
/// fanout. Raising this is also a chain-version change.
pub const MAX_EDGE_OUTPUTS: usize = 4;

// ── Work-channel bounds ───────────────────────────────────────────────

/// Largest response window a work-payment channel may commit.
pub const MAX_OMIT_RESPONSE_BLOCKS: u64 = 4096;

// The response-window floor is a *derived* deployment bound, not a
// preference. The omission theorem pays the provider its greatest
// admitted certificate only if the provider can (a) observe the client's
// close start from a finalized view, (b) notice it within its own poll
// interval, (c) get its answer onto the wire, and (d) have that answer
// included. A window shorter than that sum leaves the client an
// understatement it can win by construction, so consensus refuses to
// open the channel at all rather than opening one whose safety argument
// cannot hold.
//
// Each term below is a measurement of *this* deployment, taken at the
// upper end of its observed range. A deployment with slower finality,
// lazier endpoints, or a longer censorship tail does not get a shorter
// window by leaving these alone: it must re-measure and raise them,
// which moves `MIN_OMIT_RESPONSE_BLOCKS` and is therefore a
// chain-version change. If inclusion delay is unbounded — a censoring
// proposer majority — no finite floor restores the theorem, and this
// bound does not pretend otherwise.

/// `F`: blocks between inclusion and a finalized view.
///
/// Threshold-simplex finalizes the block it notarizes, so this is the
/// notarize/finalize round trip plus one block of slack.
pub const RESPONSE_FINALIZATION_BLOCKS: u64 = 2;

/// `POLL`: longest interval an endpoint may leave between finalized-view
/// reads.
///
/// Endpoints poll for the terminal window rather than performing a
/// finalized read before every off-chain acknowledgement.
pub const RESPONSE_POLL_BLOCKS: u64 = 4;

/// `G`: blocks a submitted response may spend propagating to a proposer.
pub const RESPONSE_PROPAGATION_BLOCKS: u64 = 1;

/// `I`: blocks a fee-paying response may wait for inclusion.
///
/// At the deployment's measured censorship quantile.
pub const RESPONSE_INCLUSION_BLOCKS: u64 = 8;

/// Smallest response window a work-payment channel may commit.
///
/// `F + POLL + G + I + 1`. The trailing block is the response's own
/// inclusion block: the deadline is exclusive, so a response landing
/// exactly at it is too late.
pub const MIN_OMIT_RESPONSE_BLOCKS: u64 = RESPONSE_FINALIZATION_BLOCKS
    + RESPONSE_POLL_BLOCKS
    + RESPONSE_PROPAGATION_BLOCKS
    + RESPONSE_INCLUSION_BLOCKS
    + 1;

// A floor above the ceiling would admit no window at all, which reads at
// the call site as "every payment open is rejected" rather than as the
// constant mistake it is.
const _: () = assert!(
    MIN_OMIT_RESPONSE_BLOCKS <= MAX_OMIT_RESPONSE_BLOCKS,
    "the derived response-window floor must leave a committable range"
);

/// Largest inclusion window a signed work-payment close start may claim.
///
/// A start authorization is replayable for exactly this many blocks, so
/// it bounds how stale a signed close attempt may be when it lands.
pub const MAX_START_VALIDITY_BLOCKS: u64 = 64;

/// Largest inclusion window a signed cooperative freeze may claim.
///
/// Same role as [`MAX_START_VALIDITY_BLOCKS`] for the other terminal
/// authorization: signing a freeze is terminal for an honest endpoint, so
/// the signed height interval bounds how long that commitment stays
/// spendable.
pub const MAX_FREEZE_AUTH_BLOCKS: u64 = 64;

// ── Registry bounds ───────────────────────────────────────────────────

/// Value bytes one registry chunk carries.
///
/// Chosen so a whole encoded chunk stays inside the payload area the
/// chain's stored object already reserves for an edge: widening it past
/// that would grow every stored object, coins and edges included, for
/// state only the registry uses.
pub const REGISTRY_CHUNK_DATA_CAPACITY: usize = 120;

/// Chunks one registry value may be split into.
///
/// `chunk_index` and `chunk_count` are single bytes, so this is the
/// representable limit rather than a policy choice.
pub const MAX_REGISTRY_CHUNKS: usize = u8::MAX as usize;

/// Registry chunk slots one applied operation may write.
///
/// This one *is* a policy choice: it is the width of the
/// [`crate::RegistryDiff`] every apply returns, so it bounds the host's
/// per-operation replay work and the memory an operation's result costs.
/// A transition that needs a third slot is a chain-version change, not a
/// wider array — the point of a fixed bound is that no operation can
/// make the host do unpriced work.
///
/// Two is what the widest transition in this kernel actually writes: a
/// payment open creates both chunks of a [`crate::BondLease`], and a
/// leased bond's timeout deletes both. `lease.rs` asserts that
/// correspondence at compile time, so the bound cannot quietly become
/// smaller than the record it is bounding. A bound above the widest
/// reachable write is not headroom, it is an array every applied
/// operation carries and no transition can fill.
pub const MAX_REGISTRY_MUTATIONS: usize = 2;

// ── Domain separators (Xet binding prefixes) ─────────────────────────
//
// Every kernel hash is the Xet file hash of `domain ‖ canonical_bytes`
// where `domain` is one of the byte strings below. Changing any of
// these strings breaks compatibility with every previously-committed
// hash.

/// Prefix for genesis coin id derivation. Input: allocation index (u32).
pub(crate) const COIN_GENESIS: &[u8] = b"hellas.edge.genesis.v1";

/// Prefix for payout coin id derivation. Inputs: edge id, output index,
/// owner key.
pub(crate) const COIN_PAYOUT: &[u8] = b"hellas.edge.coin.v1";

/// Prefix for edge id derivation. Inputs: terms hash, maker funding ids,
/// taker funding ids.
pub(crate) const EDGE_OPEN: &[u8] = b"hellas.edge.edge.v1";

/// Prefix for open payload hash. Inputs: edge id (which already binds
/// funding ids and terms hash via [`Self::EDGE_OPEN`] domain separation).
/// Maker and taker both sign this hash to authorize one open.
pub(crate) const OPEN: &[u8] = b"hellas.edge.open.v1";

/// Prefix for close payload hash. Inputs: edge id, close kind tag,
/// terms hash, payouts.
pub(crate) const CLOSE: &[u8] = b"hellas.edge.close.v1";

/// Prefix for the basic-terms commitment. Inputs: protocol code,
/// parties (each `{ owner, signer, payout_delegate }`), timeout height,
/// timeout payouts.
pub(crate) const TERMS_BASIC: &[u8] = b"hellas.terms.basic.v2";

/// Prefix for the work-payment terms commitment. Inputs: the complete
/// canonical tag-2 terms body.
pub(crate) const TERMS_WORK_PAYMENT: &[u8] = b"hellas.terms.work-payment.v4";

/// Prefix for the work-stake-bond terms commitment. Inputs: the
/// complete canonical tag-4 terms bytes, envelope and variant included,
/// so an embedded bond witness and a standalone bond commit to the same
/// hash.
pub(crate) const TERMS_WORK_STAKE_BOND: &[u8] = b"hellas.terms.work-stake-bond.v4";

/// Prefix for the earned-certificate digest the client signs. Inputs:
/// network id, payment edge, payment terms hash, and the complete
/// canonical certificate body.
pub(crate) const WORK_EARNED_CERTIFICATE: &[u8] = b"hellas.work.earned-cumulative.v2";

/// Prefix for the constant that stands in for an absent certificate in a
/// close start. Inputs: payment edge, payment terms hash.
///
/// A distinct constant rather than a zero-valued certificate: zero is the
/// implicit certificate, and encoding it as a body would give the same
/// state two spellings.
pub(crate) const WORK_NO_EARNED_CERTIFICATE: &[u8] = b"hellas.work.no-earned-certificate.v2";

/// Prefix for the 32-byte canonical settlement state. Inputs: network id,
/// payment edge, payment terms hash, cumulative amount.
pub(crate) const WORK_SETTLEMENT_STATE: &[u8] = b"hellas.work.settlement-state.v2";

/// Prefix for the close-start digest the opener signs. Inputs: network
/// id, payment edge, payment terms hash, opener role, validity bounds,
/// and the earned digest or its absent constant.
pub(crate) const WORK_START_PAYMENT_CLOSE: &[u8] = b"hellas.work.start-payment-close.v2";

/// Prefix for the accepted start's identifier. Inputs: start digest,
/// inclusion height.
///
/// The inclusion height is in the preimage so a start signature that is
/// replayable across its validity window still names exactly one accepted
/// contest.
pub(crate) const WORK_START_PAYMENT_CLOSE_ID: &[u8] = b"hellas.work.start-payment-close-id.v2";

/// Prefix for the close-response digest the provider signs. Inputs:
/// network id, payment edge, payment terms hash, start id, responder
/// role, earned digest.
pub(crate) const WORK_RESPOND_PAYMENT_CLOSE: &[u8] = b"hellas.work.respond-payment-close.v2";

/// Prefix for the adjudicated-close contest commitment. Inputs: network
/// id, payment edge, payment terms hash, and the complete pending record
/// the contest ended in.
pub(crate) const WORK_ADJUDICATED_PAYMENT_CLOSE: &[u8] =
    b"hellas.work.adjudicated-payment-close.v3";

/// Prefix for the cooperative freeze digest both parties sign. Inputs:
/// network id, payment edge, payment terms hash, settlement commitment,
/// validity bounds.
pub(crate) const WORK_FREEZE_CLOSE: &[u8] = b"hellas.work.freeze-close.v2";

/// Prefix for the payload hash an owner signs to reshape its coins.
/// Inputs: network id, then the canonical reshape body — its input ids
/// and its output payouts.
pub(crate) const OWNER_RESHAPE: &[u8] = b"hellas.owner.reshape.v2";

/// Prefix for reshape output coin id derivation. Inputs: network id, the
/// complete input id list, output index, output owner.
///
/// The inputs are what make the ids fresh: every input is consumed by the
/// reshape, so no later reshape can name the same list, and a replayed
/// one fails on its first missing input before it could collide.
pub(crate) const COIN_RESHAPE: &[u8] = b"hellas.owner.coin.v2";

/// Prefix for registry chunk id derivation. Inputs: network id,
/// namespace tag, logical key, chunk index.
///
/// Registry ids are the one derived identifier that commits to the
/// network. The rule in [`crate::NetworkId`] exempts ids because an id
/// only has meaning inside one network's state; that still holds, and
/// the network here buys nothing against replay. It is in the preimage
/// because the design fixes this derivation, and changing it later would
/// move every stored chunk.
pub(crate) const REGISTRY_CHUNK_ID: &[u8] = b"hellas.registry.chunk-id.v2";

/// Prefix for the deterministic signature placeholder used by tests and
/// modelling. Inputs: half index (0 or 1), key, close hash.
#[cfg(any(test, feature = "placeholders"))]
pub(crate) const SIG_PLACEHOLDER: &[u8] = b"hellas.sig.placeholder.v1";
