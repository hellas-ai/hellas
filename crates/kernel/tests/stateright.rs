//! Stateright model checks for the current kernel operation surface.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

mod support;

use support::{
    CANARY_REGISTRY_SLOTS, FAKE_VERIFIER, FixedStore, canary_registry_slots,
    l1::{self, EdgeKey, OpenKey, ProofKey},
};

use hellas_kernel::{
    ApplyError, Coin, CoinId, Context, Edge, EdgeId, EventKind, Funding, InvalidCloseReason,
    InvalidProofReason, List, MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, Parties, Payout, Proof, State, Tx,
    View,
};
use stateright::{Checker, Model, Property};

type ModelView = View<4, 4, CANARY_REGISTRY_SLOTS>;
type ChannelStore = FixedStore<4, 4, CANARY_REGISTRY_SLOTS>;

#[derive(Clone, Copy)]
struct ChannelModel;

impl Model for ChannelModel {
    type Action = Action;
    type State = State<ChannelStore>;

    fn init_states(&self) -> Vec<Self::State> {
        vec![channel_state()]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        let view: ModelView = state.view();

        if view.edge_len() == 0
            && view.coin(l1::MAKER_ID).is_some()
            && view.coin(l1::TAKER_ID).is_some()
        {
            actions.push(Action::Open(OpenKey::Full));
            actions.push(Action::Open(OpenKey::MakerOnly));
            actions.push(Action::Open(OpenKey::TakerOnly));
            actions.push(Action::Open(OpenKey::Empty));
        }

        if view.edge(l1::open_case_id(OpenKey::Full)).is_some() {
            actions.push(Action::Close(ProofKey::Mutual));
            actions.push(Action::Close(ProofKey::Timeout));
            actions.push(Action::Close(ProofKey::EarlyTimeout));
            actions.push(Action::InvalidClose);
            actions.push(Action::InvalidProof);
            actions.push(Action::AdversarialTimeout);
        }
    }

    fn next_state(&self, last_state: &Self::State, action: Self::Action) -> Option<Self::State> {
        let mut state = *last_state;
        let context = action.context();
        let op = action.op();

        if matches!(action, Action::AdversarialTimeout) {
            // Soft application: ignore Ok/Err distinction. If the kernel
            // correctly rejects, atomic rollback leaves state == last_state
            // and the model adds no new state. If the kernel ever started
            // accepting adversarial timeouts, the new state would have
            // non-canonical payouts and `channel_shape` would fail — the
            // bug surfaces as a property violation rather than a silently
            // disabled action.
            let _ = state.apply(context, &FAKE_VERIFIER, &op);
            return Some(state);
        }

        if let Some(expected) = action.error() {
            // Expected-error actions must reject with exactly this error
            // and leave state untouched. Panic rather than return `None`:
            // a `None` would silently prune the branch, hiding a kernel
            // that started accepting (or mis-classifying) invalid input.
            // This matters for actions like `EarlyTimeout` whose wrongful
            // acceptance yields a canonical-looking state no shape or
            // value property can distinguish from a legitimate close.
            match state.apply(context, &FAKE_VERIFIER, &op) {
                Ok(outcome) => panic!("kernel accepted {action:?}: {outcome:?}"),
                Err(error) => {
                    assert_eq!(error, expected, "wrong rejection for {action:?}");
                    assert_eq!(state, *last_state, "rejection of {action:?} mutated state");
                }
            }
            return Some(state);
        }

        let outcome = state.apply(context, &FAKE_VERIFIER, &op).ok()?;
        // Every action this model offers moves an edge, so a silent
        // outcome or a registry write is a transition bug, not a state
        // to explore.
        assert!(
            outcome.registry().is_empty(),
            "{action:?} wrote registry state: {:?}",
            outcome.registry(),
        );
        let event = outcome
            .public_event()
            .unwrap_or_else(|| panic!("{action:?} applied without announcing itself"));
        Self::valid_state(&state, action, context, &op, event.kind())
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always(
                "channel value is conserved",
                |_, state: &State<ChannelStore>| l1::live_value(&state.view()) == l1::EDGE_VALUE,
            ),
            Property::always(
                "channel objects have one live shape",
                |_, state: &State<ChannelStore>| channel_shape(&state.view()),
            ),
            // Registry state is reachable in this model — the store
            // declares two slots — so "no chunk is ever live" is a
            // property the checker can violate, not a type-level
            // tautology. Opens and closes are edge transitions; the
            // moment one starts staging a record, every explored state
            // here reports it.
            Property::always(
                "no channel transition writes registry state",
                |_, state: &State<ChannelStore>| {
                    let view: ModelView = state.view();
                    view.registry_len() == 0
                },
            ),
        ]
    }
}

impl ChannelModel {
    fn valid_state(
        state: &State<ChannelStore>,
        action: Action,
        context: Context,
        op: &Tx,
        event: &EventKind,
    ) -> Option<State<ChannelStore>> {
        match (action, op, event) {
            (
                Action::Open(key),
                Tx::Open {
                    funding,
                    terms,
                    maker_auth: _,
                    taker_auth: _,
                },
                EventKind::EdgeOpened {
                    inputs: event_inputs,
                    output,
                },
            ) => Self::valid_open(state, key, op, funding, terms, event_inputs, *output),
            (
                Action::Close(proof),
                Tx::Close {
                    input,
                    proof: tx_proof,
                    outputs,
                },
                EventKind::EdgeClosed {
                    input: event_input,
                    outputs: event_outputs,
                },
            ) => Self::valid_close(
                state,
                proof,
                context,
                op,
                *input,
                tx_proof,
                outputs,
                *event_input,
                event_outputs,
            ),
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn valid_open(
        state: &State<ChannelStore>,
        key: OpenKey,
        op: &Tx,
        _funding: &Funding,
        _terms: &hellas_kernel::Terms,
        inputs: &List<CoinId, MAX_EDGE_INPUTS>,
        output: EdgeId,
    ) -> Option<State<ChannelStore>> {
        let ok = *op == l1::open_case(key)
            && *inputs == l1::open_case_inputs(key)
            && output == l1::open_case_id(key);

        ok.then_some(*state)
    }

    #[allow(clippy::too_many_arguments)]
    fn valid_close(
        state: &State<ChannelStore>,
        proof: ProofKey,
        context: Context,
        op: &Tx,
        _input: EdgeId,
        _tx_proof: &Proof,
        _outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
        event_input: EdgeId,
        event_outputs: &List<CoinId, MAX_EDGE_OUTPUTS>,
    ) -> Option<State<ChannelStore>> {
        let ok = event_input == l1::edge_id(EdgeKey::First)
            && *event_outputs == l1::output_ids(EdgeKey::First)
            && *op == l1::close(EdgeKey::First, proof)
            && (proof != ProofKey::Timeout || context == l1::TIMEOUT_CONTEXT);

        ok.then_some(*state)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Action {
    Open(OpenKey),
    Close(ProofKey),
    /// Submit a Mutual proof with non-canonical (value-mismatched) payouts;
    /// the kernel rejects on `InvalidClose::ValueMismatch`.
    InvalidClose,
    /// Submit a proof whose terms commitment does not match the edge's.
    InvalidProof,
    /// Submit a Timeout close with a value-conserving but non-canonical
    /// payout split. The kernel must reject because the edge's terms commit a
    /// specific `timeout_outputs` shape; any divergence is `InvalidProof`.
    AdversarialTimeout,
}

impl Action {
    const fn context(self) -> Context {
        match self {
            Self::Close(ProofKey::Timeout) | Self::AdversarialTimeout => l1::TIMEOUT_CONTEXT,
            _ => l1::CONTEXT,
        }
    }

    fn op(self) -> Tx {
        match self {
            Self::Open(key) => l1::open_case_op(key),
            Self::Close(proof) => l1::close(EdgeKey::First, proof),
            Self::InvalidClose => {
                l1::close_with(EdgeKey::First, ProofKey::Mutual, l1::bad_payouts())
            }
            Self::InvalidProof => l1::close(EdgeKey::First, ProofKey::WrongTerms),
            Self::AdversarialTimeout => {
                l1::close_with(EdgeKey::First, ProofKey::Timeout, l1::maker_grab_payouts())
            }
        }
    }

    fn error(self) -> Option<ApplyError> {
        match self {
            Self::InvalidClose => Some(ApplyError::InvalidClose {
                input: l1::edge_id(EdgeKey::First),
                reason: InvalidCloseReason::ValueMismatch,
            }),
            Self::InvalidProof => Some(ApplyError::InvalidProof {
                input: l1::edge_id(EdgeKey::First),
                reason: InvalidProofReason::TermsMismatch,
            }),
            Self::Close(ProofKey::EarlyTimeout) => Some(ApplyError::InvalidProof {
                input: l1::edge_id(EdgeKey::First),
                reason: InvalidProofReason::TimeoutNotReached,
            }),
            Self::Open(_) | Self::Close(_) | Self::AdversarialTimeout => None,
        }
    }
}

#[test]
fn open_close_model_checks() {
    let checker = ChannelModel.checker().spawn_dfs().join();

    assert!(checker.discoveries().is_empty());
    assert_eq!(checker.unique_state_count(), 6);
}

fn channel_state() -> State<ChannelStore> {
    l1::genesis(empty_channel())
}

fn empty_channel() -> ChannelStore {
    FixedStore::empty_with_registry(
        [
            l1::MAKER_ID,
            l1::TAKER_ID,
            l1::maker_out(EdgeKey::First),
            l1::taker_out(EdgeKey::First),
        ],
        [
            l1::open_case_id(OpenKey::Full),
            l1::open_case_id(OpenKey::MakerOnly),
            l1::open_case_id(OpenKey::TakerOnly),
            l1::open_case_id(OpenKey::Empty),
        ],
        canary_registry_slots(),
    )
}

fn channel_shape(view: &ModelView) -> bool {
    funding_shape(view)
        || full_open_shape(view)
        || maker_open_shape(view)
        || taker_open_shape(view)
        || empty_open_shape(view)
        || resolved_shape(view)
}

fn funding_shape(view: &ModelView) -> bool {
    view.coin(l1::MAKER_ID).is_some()
        && view.coin(l1::TAKER_ID).is_some()
        && view.coin(l1::maker_out(EdgeKey::First)).is_none()
        && view.coin(l1::taker_out(EdgeKey::First)).is_none()
        && view.edge_len() == 0
}

fn full_open_shape(view: &ModelView) -> bool {
    view.coin(l1::MAKER_ID).is_none()
        && view.coin(l1::TAKER_ID).is_none()
        && view.coin(l1::maker_out(EdgeKey::First)).is_none()
        && view.coin(l1::taker_out(EdgeKey::First)).is_none()
        && view
            .edge(l1::open_case_id(OpenKey::Full))
            .as_ref()
            .map(edge_view)
            == Some((l1::EDGE_VALUE, l1::PARTIES))
}

fn maker_open_shape(view: &ModelView) -> bool {
    view.coin(l1::MAKER_ID).is_none()
        && view.coin(l1::TAKER_ID).map(Coin::value) == Some(l1::TAKER_VALUE)
        && view.coin(l1::maker_out(EdgeKey::First)).is_none()
        && view.coin(l1::taker_out(EdgeKey::First)).is_none()
        && view
            .edge(l1::open_case_id(OpenKey::MakerOnly))
            .as_ref()
            .map(edge_view)
            == Some((l1::MAKER_VALUE, l1::PARTIES))
}

fn taker_open_shape(view: &ModelView) -> bool {
    view.coin(l1::MAKER_ID).map(Coin::value) == Some(l1::MAKER_VALUE)
        && view.coin(l1::TAKER_ID).is_none()
        && view.coin(l1::maker_out(EdgeKey::First)).is_none()
        && view.coin(l1::taker_out(EdgeKey::First)).is_none()
        && view
            .edge(l1::open_case_id(OpenKey::TakerOnly))
            .as_ref()
            .map(edge_view)
            == Some((l1::TAKER_VALUE, l1::PARTIES))
}

fn empty_open_shape(view: &ModelView) -> bool {
    view.coin(l1::MAKER_ID).map(Coin::value) == Some(l1::MAKER_VALUE)
        && view.coin(l1::TAKER_ID).map(Coin::value) == Some(l1::TAKER_VALUE)
        && view.coin(l1::maker_out(EdgeKey::First)).is_none()
        && view.coin(l1::taker_out(EdgeKey::First)).is_none()
        && view
            .edge(l1::open_case_id(OpenKey::Empty))
            .as_ref()
            .map(edge_view)
            == Some((0, l1::PARTIES))
}

fn resolved_shape(view: &ModelView) -> bool {
    view.coin(l1::MAKER_ID).is_none()
        && view.coin(l1::TAKER_ID).is_none()
        && view.edge_len() == 0
        && view.coin(l1::maker_out(EdgeKey::First)).map(Coin::value) == Some(l1::MAKER_PAYOUT)
        && view.coin(l1::taker_out(EdgeKey::First)).map(Coin::value) == Some(l1::TAKER_PAYOUT)
}

const fn edge_view(edge: &Edge) -> (u64, Parties) {
    (edge.value(), edge.parties())
}
