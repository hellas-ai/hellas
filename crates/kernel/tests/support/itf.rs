#![allow(clippy::enum_variant_names)]
#![allow(clippy::expect_used)]

//! Shared ITF (Informal Trace Format) schema and op conversion.
//!
//! Quint emits each abstract trace under `models/traces/` as an ITF JSON
//! file. The schema mirrors the state vars in `models/l1.qnt` exactly —
//! the `itf` crate validates the trace's variable list against this
//! struct's fields at parse time.
//!
//! The conversion functions turn abstract ITF state into the concrete
//! `(Context, Op)` the kernel consumes. Both `tests/itf.rs` (validation
//! replay) and `benches/apply.rs` (throughput) drive the kernel through the
//! same conversion, so a fixture replayed in either place exercises the same
//! kernel paths.

use std::collections::{BTreeMap, BTreeSet};

use itf::de::{As, Integer, Same};
use serde::Deserialize;

use hellas_kernel::{BlockHash, BlockHeight, Context, Parties, PartyKeys, Proof, Terms, Tx};

use super::l1;

// -- Abstract types mirrored from models/l1.qnt -----------------------------

/// Abstract state mirrored from `models/l1.qnt`. Field order and names
/// must match the Quint declarations exactly; the `itf` crate verifies
/// the trace's variable list against the struct's fields at parse time.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct State {
    #[serde(with = "As::<BTreeMap<Same, Integer>>")]
    pub(crate) coins: BTreeMap<CoinTag, i64>,
    #[serde(with = "As::<BTreeMap<Same, Integer>>")]
    pub(crate) edges: BTreeMap<EdgeTag, i64>,
    #[serde(with = "As::<Integer>")]
    pub(crate) height: i64,
    pub(crate) last_event: Event,
    pub(crate) last_input: Input,
    pub(crate) live_coins: BTreeSet<CoinTag>,
    pub(crate) live_edges: BTreeSet<EdgeTag>,
    pub(crate) open_auth: BTreeMap<EdgeTag, OpenAuthBody>,
}

/// Quint `Coin` enum.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum CoinTag {
    MakerCoin,
    TakerCoin,
    MakerOut1,
    TakerOut1,
    MakerOut2,
    TakerOut2,
}

/// Quint `Edge` enum.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum EdgeTag {
    Edge1,
    Edge2,
}

/// Quint `Proof` enum, mirrored from the collapsed kernel proof surface.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum ProofTag {
    Mutual,
    Timeout,
}

/// Quint `Party` enum.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum PartyTag {
    Maker,
    Taker,
    Adversary,
}

/// Quint `OpenAuth` record.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize)]
pub(crate) struct OpenAuthBody {
    pub(crate) maker: PartyTag,
    pub(crate) taker: PartyTag,
}

/// Quint `Input` ADT.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum Input {
    NoInput,
    OpenInput(EdgeTag),
    CloseInput(CloseInputBody),
    RejectedOpenInput(RejectedOpenBody),
    RejectedCloseInput(CloseInputBody),
    TickInput,
    IdleInput,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CloseInputBody {
    pub(crate) edge: EdgeTag,
    pub(crate) proof: ProofTag,
    #[serde(with = "As::<Integer>")]
    pub(crate) maker_pay: i64,
    #[serde(with = "As::<Integer>")]
    pub(crate) taker_pay: i64,
}

/// Body of a `RejectedOpenInput`: the edge whose open was attempted plus
/// the party identities the submitter claimed.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RejectedOpenBody {
    pub(crate) edge: EdgeTag,
    pub(crate) as_maker: PartyTag,
    pub(crate) as_taker: PartyTag,
}

/// Quint `Event` ADT (abstract event emitted by the action that produced
/// the state).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum Event {
    NoEvent,
    EdgeOpenedEvent(EdgeTag),
    EdgeClosedEvent(EdgeTag),
}

// -- Conversion -------------------------------------------------------------

/// Maps `EdgeTag` to the corresponding model edge key.
pub(crate) const fn edge_key(tag: EdgeTag) -> l1::EdgeKey {
    match tag {
        EdgeTag::Edge1 => l1::EdgeKey::First,
        EdgeTag::Edge2 => l1::EdgeKey::Second,
    }
}

/// Synthesizes the kernel `Context` from the height carried by an ITF state.
pub(crate) fn context_for_height(height: i64) -> Result<Context, String> {
    let height = u64::try_from(height).map_err(|_| format!("negative l1 height: {height}"))?;
    Ok(Context::new(
        // The trace is network-agnostic: the model describes the game,
        // not the deployment. Any single network reproduces it, so long
        // as the trace and the kernel agree on one. Network separation
        // itself is pinned by tests/network.rs.
        super::NETWORK,
        BlockHeight::new(height),
        BlockHash::from_bytes([0; BlockHash::LENGTH]),
    ))
}

/// Concrete `Tx` (when the input maps to accepted kernel work). `NoInput`,
/// `TickInput`, and `IdleInput` produce none; rejected inputs are handled
/// separately by [`rejected_op_for`] so the throughput bench (which shares
/// this conversion) measures only accepted applies.
pub(crate) fn op_for(input: &Input) -> Option<Tx> {
    match input {
        Input::OpenInput(tag) => Some(l1::open(edge_key(*tag))),
        Input::CloseInput(body) => Some(close_op(body)),
        Input::NoInput
        | Input::TickInput
        | Input::IdleInput
        | Input::RejectedOpenInput(_)
        | Input::RejectedCloseInput(_) => None,
    }
}

/// Concrete `Tx` for a rejected input; the kernel must refuse it.
pub(crate) fn rejected_op_for(input: &Input) -> Option<Tx> {
    match input {
        Input::RejectedOpenInput(body) => Some(rejected_open_op(*body)),
        Input::RejectedCloseInput(body) => Some(rejected_close_op(body)),
        _ => None,
    }
}

/// Maps a model party to its concrete settlement key.
pub(crate) const fn party_key(tag: PartyTag) -> hellas_kernel::Key {
    match tag {
        PartyTag::Maker => l1::MAKER,
        PartyTag::Taker => l1::TAKER,
        PartyTag::Adversary => l1::ADVERSARY,
    }
}

/// Builds the open the model rejected: canonical funding for the edge,
/// terms naming the *claimed* parties, signed by the claimed keys. When a
/// claimed party does not own the matching funding coins the kernel must
/// reject (ownership check); when the funding coins are simply absent it
/// must reject on lookup.
fn rejected_open_op(body: RejectedOpenBody) -> Tx {
    let maker_key = party_key(body.as_maker);
    let taker_key = party_key(body.as_taker);
    let terms = Terms::basic(
        l1::PROTOCOL,
        Parties::new(PartyKeys::sole(maker_key), PartyKeys::sole(taker_key)),
        l1::TIMEOUT,
        l1::payouts_owned(maker_key, taker_key),
    );
    super::open_tx(
        l1::funding_for(edge_key(body.edge)),
        terms,
        maker_key,
        taker_key,
    )
}

/// Builds the close the model rejected. Witnesses bind to the *canonical*
/// split — the only payload the parties abstractly authorized — so a
/// canonical-split rejection carries valid witnesses (the kernel must
/// reject on its height guards), while a non-canonical split carries
/// witnesses that do not match the submitted payouts (the kernel must
/// reject the witness).
fn rejected_close_op(body: &CloseInputBody) -> Tx {
    let edge = edge_key(body.edge);
    let input = l1::edge_id(edge);
    let terms = l1::terms();
    let outputs = l1::payouts_with(
        u64::try_from(body.maker_pay).expect("negative rejected maker payout"),
        u64::try_from(body.taker_pay).expect("negative rejected taker payout"),
    );
    let canonical = l1::payouts();
    let proof = match body.proof {
        ProofTag::Mutual => {
            super::placeholder_mutual(input, terms.hash(), &canonical, l1::MAKER, l1::TAKER)
        }
        ProofTag::Timeout => Proof::timeout(terms),
    };
    Tx::close(input, proof, outputs)
}

/// Builds a close `Tx` from a model `CloseInput`. Payouts are taken
/// from the model body, not the support helper, so adversarial-payout
/// traces drive the kernel correctly.
pub(crate) fn close_op(body: &CloseInputBody) -> Tx {
    let edge = edge_key(body.edge);
    let outputs = l1::payouts_with(
        u64::try_from(body.maker_pay).expect("negative maker payout"),
        u64::try_from(body.taker_pay).expect("negative taker payout"),
    );
    let input = l1::edge_id(edge);
    let terms = l1::terms();
    let proof = match body.proof {
        ProofTag::Mutual => {
            super::placeholder_mutual(input, terms.hash(), &outputs, l1::MAKER, l1::TAKER)
        }
        ProofTag::Timeout => Proof::timeout(terms),
    };
    Tx::close(input, proof, outputs)
}
