#![no_std]
#![forbid(unsafe_code)]
//! Deterministic settlement kernel for Hellas.
//!
//! # Work payment channels
//!
//! A work payment channel is one edge between two parties: the client is
//! the maker and funds capacity, the provider is the taker and earns
//! against it off-chain. Everything the chain will ever adjudicate about
//! it is **one monotone scalar** — the greatest valid client-signed
//! cumulative earned amount the provider durably admitted before its own
//! terminal cutoff. Not a set of jobs, not a lane tip, not a membership
//! root, and not a balance pair. [`EarnedCertificate`] is the client's
//! signature over that number; the `work` module says why it is
//! cumulative rather than incremental, and what the cutoff obliges an
//! endpoint to do before it signs.
//!
//! The channel is insured as well as funded. [`WorkPaymentTerms`] names a
//! tag-4 [`WorkStakeBondTerms`] bond the provider staked earlier, and the
//! payment open takes an exclusive [`BondLease`] over that bond in the
//! same atomic change that creates the edge. Exclusivity is the point: a
//! bond names no channel, so without the lease one stake could back
//! several channels at once, each priced as if it could cover the whole
//! of it. A second payment open naming a leased bond finds the slots
//! occupied and is refused.
//!
//! A channel has two exits and no third.
//!
//! * **Freeze** — cooperative. Both parties sign one settlement amount
//!   and the edge closes at it in a single transaction.
//! * **Start / Response / Adjudicated** — unilateral, three
//!   transactions. Either party submits [`Move::StartPaymentClose`]
//!   with the greatest certificate it holds (or with none), which opens a
//!   bounded response window; the certificate's beneficiary may answer at
//!   most once, with [`Move::RespondPaymentClose`] carrying a strictly
//!   greater client-signed amount; then `Proof::Adjudicated` pays out
//!   whatever the contest ended on, with no fresh counterparty signature.
//!   The window is not a courtesy — an immediate close cannot tell a
//!   world where no greater certificate exists from one where the
//!   counterparty is sitting on it, so the holder gets exactly one chance
//!   to speak, and a client caught understating its own signature
//!   forfeits the omission bond its terms funded.
//!
//! There is deliberately **no [`Proof::Timeout`]** on a payment edge; see
//! [`CloseKindSet`] and [`WorkPaymentTerms::admission_horizon`]. The
//! horizon that shape derives from its bond is an admission
//! and rent deadline, not a refund deadline: a fixed refund payable after
//! the provider has already earned against the channel would pay the
//! wrong party. An abandoned payment edge is therefore settled by
//! `Freeze` or by `Adjudicated` and by nothing else.
//!
//! Where the pieces live: the `work` module owns the close vocabulary —
//! the certificate, the two [`Move`] bodies, the [`PendingPaymentClose`]
//! record and every digest that binds them; `tx::work` owns the four
//! transitions that read and write it; `lease` owns [`BondLease`] and the
//! absence-versus-fault rule over its two slots; `registry` owns the
//! chunk substrate all of that consensus state is stored in; and `terms`
//! owns the two work shapes and the close-kind set each one fixes.
//!
//! ## What this slice does not implement
//!
//! **Payment close only.** The correctness dispute game is not here.
//! No transition opens a game, no transition slashes a bond, and there
//! is no Catena execution verifier. Nothing is *reserved* for one
//! either: there is no dormant game policy in the tag-4 body, no
//! challenge bitmap or live-game pointer in [`BondLease`], no
//! unreachable close kind, and no external seal verifier. A tag-4
//! bond's only exit is its `Timeout` — immediate while unleased, at the
//! horizon while leased. Do not read the landed payment close as
//! evidence that fraud proofs work end to end: nothing in this crate
//! proves a job was computed wrongly, and the stake is leased capital
//! that returns on time rather than working insurance. The game slice
//! adds its own transitions, its own state, and its own tags, together.
//!
//! # Abstract model
//!
//! Many kernel modules have a counterpart under `models/`; the table below
//! is the authoritative mapping. Modules absent from it (e.g. `terms`,
//! `canonical`, `list`, `secp256k1`, `webauthn`) have no abstract
//! counterpart by design. Reading the abstract Quint module first is often
//! the fastest way to understand a Rust module's shape.
//!
//! | Concern              | Rust                       | Quint                                |
//! |----------------------|----------------------------|--------------------------------------|
//! | Apply driver         | [`State`]                       | `models/l1.qnt`                      |
//! | Tx vocabulary + step | [`Tx`]                          | `models/l1.qnt` (`step` action)      |
//! | Proof witnesses      | [`Proof`]                       | `models/verifier.qnt`                |
//! | Verification policy  | [`SigVerifier`]                 | `models/verifier.qnt`                |
//! | Live objects         | [`Coin`] / [`Edge`] / ids       | `models/types.qnt`                   |
//! | Block context        | [`Context`]                     | `models/l1.qnt` (`height` var)       |
//! | Established rules    | [`Diff`], [`View`]              | `models/rules/invariants.qnt`        |
//! | Fees / reserve        | [`Fees`], [`Cost`]             | `models/l1_fees.qnt`                 |
//!
//! Every module named there is typechecked, run, symbolically verified,
//! and — for `l1` and `l1_fees` — replayed against this kernel by
//! `tests/itf.rs`. There is deliberately no row for the premises the
//! kernel takes on faith. `models/deps/assumptions.qnt` used to hold
//! them and used to occupy a row here, which read as though a Quint
//! module checked them; nothing imported it, so nothing typechecked or
//! ran it. Each premise now sits with the code that relies on it —
//! monotone height and network separation on [`Context`], deterministic
//! block order on [`Block`], atomicity and read isolation on [`Store`],
//! operator-trusted seeding on [`Genesis`] — and verifier soundness and
//! determinism at the top of `models/verifier.qnt`.
//!
//! Two standalone models were deleted with their subjects, not folded
//! in. `models/proof_lifetime.qnt` admitted a *self-contained
//! latest-state proof*, a violation proof, and bare/stale receipts: no
//! kernel ever had any of them, and it forced a close at the horizon
//! that this one does not force either. `models/lifetime.qnt` explored
//! permanent, budgeted and bonded lifetime policies against a
//! per-block rent bucket and a third-party collector reward; the kernel
//! charges one prepaid lifetime fee at open and has no rent, no state
//! bond, and no collector. Both replayed green while modelling a system
//! that does not exist. Every assertion of theirs that *was* about this
//! kernel — value accounting, the close reserve, no marginal close fee,
//! close pricing at the schedule committed at open, `Mutual` expiry,
//! `Timeout` liveness, and the timeout payout binding — is in
//! `models/l1.qnt` or `models/l1_fees.qnt`, over the same buckets, and
//! is asserted against this kernel by the ITF replay rather than only
//! inside Quint.
//!
//! The table is authoritative for the coin and edge state above and for
//! nothing else. Registry state — [`RegistryChunk`], [`RegistryDiff`],
//! [`BondLease`], and the registry half of [`ApplyOutcome`] — has **no**
//! abstract counterpart: no Quint var holds a chunk and no trace carries
//! one.
//! `models/registry.md` states exactly which properties that leaves
//! unproven and which kernel tests stand in for them meanwhile. Do not
//! read "the kernel is model-checked" as covering registry state.
//!
//! The work-channel terms shapes — [`WorkPaymentTerms`] and
//! [`WorkStakeBondTerms`] — have **no** abstract counterpart, and no
//! longer inherit one. The tag-1 bond model that used to stand in for
//! the tag-4 bond through a shared base was deleted with its subject,
//! so stake conservation, provider-only funding, the immediate and
//! horizon timeouts, and lease deletion are Rust-side properties only
//! until a tag-4 model lands. `models/registry.md` lists them.
//!
//! The correspondence claim above is likewise **retracted for the
//! payment-close actions and for the bond lease**. [`Tx::Move`],
//! `Proof::Freeze`, `Proof::Adjudicated`, the work-payment open that
//! leases its bond, and the tag-4 timeout that reads that lease have no
//! Quint action, no ITF trace, and no abstract invariant: the settlement
//! scalar's monotonicity, the omission bond's conservation, the
//! one-contest and one-response rules, the one-channel-per-bond rule,
//! and the absence-versus-fault rule are Rust-side properties only.
//! `models/registry.md` lists them individually. Do not read "the kernel
//! is model-checked" as covering a payment close.
//!
//! # Verifier boundary
//!
//! The transition core delegates cryptography to one caller-wired
//! trait: [`SigVerifier`] decides open authorizations, cooperative-close
//! signatures, and the payment `Freeze`. [`Proof::Timeout`] and
//! `Proof::Adjudicated` need none — their admissibility is structural
//! and the kernel checks it inline against committed terms and staged
//! registry state. There is no seal trait and no external verifier
//! seam. Test verifiers accept the deterministic placeholders built by
//! `Sig::placeholder` (available only under the `placeholders` feature —
//! production builds cannot construct forgeable witnesses); production
//! verifiers wire real cryptography.
//! Optional feature-gated helpers provide
//! concrete native/`WebAuthn` verification without changing the apply path.
//! [`Auth`] is only a witness format: it proves consent from the same
//! party key used for coin ownership, terms, and payouts — over the open
//! hash when opening, over the close payload hash when closing mutually.
//!
//! State objects and events are not directly constructible outside the crate.
//!
//! ```compile_fail
//! use hellas_kernel::{Coin, Key};
//!
//! let owner = Key::from_bytes([0; Key::LENGTH]);
//! let _coin = Coin::new(owner, 1);
//! ```
//!
//! ```compile_fail
//! use hellas_kernel::{CoinId, EdgeId, Event, EventKind, List, MAX_EDGE_INPUTS};
//!
//! let id = CoinId::from_bytes([0; CoinId::LENGTH]);
//! let edge = EdgeId::from_bytes([0; EdgeId::LENGTH]);
//! let _event = Event {
//!     kind: EventKind::EdgeOpened {
//!         inputs: List::all([id; MAX_EDGE_INPUTS]),
//!         output: edge,
//!     },
//! };
//! ```

mod block;
mod canonical;
pub(crate) mod consts;
mod context;
mod error;
mod event;
mod lease;
mod list;
mod network;
mod object;
mod primitive;
mod registry;
#[cfg(feature = "secp256k1")]
mod secp256k1;
mod state;
mod store;
mod terms;
mod tx;
mod verifier;
mod view;
#[cfg(feature = "webauthn")]
mod webauthn;
mod work;

pub use block::Block;
pub use canonical::{BufferWriter, Cursor, Decode, DecodeError, Encode, Writer};
pub use consts::{
    MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, MAX_FREEZE_AUTH_BLOCKS, MAX_OMIT_RESPONSE_BLOCKS,
    MAX_PARTY_INPUTS, MAX_REGISTRY_CHUNKS, MAX_REGISTRY_MUTATIONS, MAX_START_VALIDITY_BLOCKS,
    MAX_WEBAUTHN_DATA_LENGTH, MIN_OMIT_RESPONSE_BLOCKS, REGISTRY_CHUNK_DATA_CAPACITY,
    RESPONSE_FINALIZATION_BLOCKS, RESPONSE_INCLUSION_BLOCKS, RESPONSE_POLL_BLOCKS,
    RESPONSE_PROPAGATION_BLOCKS,
};
pub use context::{BlockHash, BlockHeight, Context, Cost, Fees};
pub use error::{
    ApplyError, BatchError, BondLeaseFault, InsertError, InvalidCloseReason, InvalidMoveReason,
    InvalidOpenReason, InvalidProofReason, KernelResult, PendingCloseFault,
};
pub use event::{ApplyOutcome, Diff, Event, EventKind};
pub use lease::{
    BOND_LEASE_CHUNKS, BondLease, LeaseSlots, bond_lease_slot, bond_lease_slots, parse_bond_lease,
};
pub use list::List;
pub use network::{MAX_NETWORK_ID_LENGTH, NetworkId};
pub use object::{Coin, Edge, EdgeValues, Genesis, Parties};
pub use primitive::{CoinId, EdgeId, Key, Party, PayloadHash, ProtocolCode, Sig, TermsHash};
pub use registry::{
    MAX_REGISTRY_VALUE_LEN, RegistryChunk, RegistryChunkId, RegistryDiff, RegistryDiffError,
    RegistryMutation, RegistryNamespace, RegistryRecordTag,
};
#[cfg(feature = "secp256k1")]
pub use secp256k1::{Secp256k1Signer, Secp256k1SignerError, Secp256k1Verifier};
pub use state::State;
pub use store::{Batch, Store};
pub use terms::{Terms, TermsProfile, WorkPaymentTerms, WorkStakeBondTerms};
pub use tx::{
    Auth, CloseKind, CloseKindSet, Funding, Move, OpenFunding, OpenProjection,
    PaymentContestCommitment, Payout, Proof, Tx, WebAuthnAssertion, WebAuthnData, check_response,
    open_projection,
};
pub use verifier::SigVerifier;
pub use view::{Snapshot, View};
#[cfg(feature = "test-support")]
pub use webauthn::test_support;
#[cfg(feature = "webauthn")]
pub use webauthn::{
    SoftPasskey, SoftPasskeyError, WebAuthnError, p256_key, verify_webauthn_assertion,
};
pub use work::{
    EarnedCertificate, PaymentCloseResponse, PaymentCloseStart, PendingPaymentClose, PendingSlot,
    StartId, WorkPaymentSettlement, adjudicated_payouts, freeze_digest, freeze_payouts,
    no_earned_digest, parse_pending_close, pending_payment_close_slot, response_digest,
    settlement_commitment, start_digest, start_id, work_payment_settlement,
};
