# Registry state is not modelled

Every `.qnt` module in this directory models coins and edges. None of
them models the kernel's third live object kind, the registry chunk.
This file records that gap deliberately, because the alternative — a
reader assuming "the kernel is model-checked" covers all of its state —
is how a false correspondence claim gets made.

## What exists in Rust and not here

| Rust | What it holds | Quint counterpart |
|---|---|---|
| `RegistryChunk` | one fixed 120-byte slice of a consensus record | none |
| `RegistryChunkId` | derived slot name, domain-separated from coin/edge ids | none |
| `RegistryDiff` / `RegistryMutation` | the bounded slot writes one operation makes | none |
| `ApplyOutcome::registry` | that diff, returned to the host for durable replay | none |
| `ApplyOutcome::public_event` being `Option` | an operation may commit state and announce nothing | `lastEvent = NoEvent`, which the models emit only for `init` / `tick` / rejected input |
| `View::registry_chunks` / `registry_value` | the live chunk set and its reassembly | none |
| `BondLease` | the two-chunk exclusive lease one payment channel holds over one tag-4 bond | none |

## Why it is not modelled yet

The substrate landed before any transition used it, and at that point
there was nothing to model: a Quint var holding a chunk set would have
been a var every action left empty. That is no longer the situation.
**The payment-close slice writes registry state**, and it is unmodelled.

`Tx::Move` (`StartPaymentClose`, `RespondPaymentClose`), `Proof::Freeze`,
and `Proof::Adjudicated` create, advance, read, and delete one
`PendingPaymentClose` record per payment edge. No `.qnt` module has an
action for any of them, no trace carries one, and no invariant covers
the amounts they move. Section 10.3 item 16 of the design requires
`types.qnt`, `l1.qnt`, `verifier.qnt`, and the ITF schemas to gain those
actions before activation; until they do, the correspondence claim in
`lib.rs` is retracted for them there, and this file is where the cost is
written down.

**The bond lease is unmodelled too.** A work-payment open now creates a
two-chunk `BondLease` over the tag-4 bond it names, and a tag-4 timeout
reads it and — at the horizon — deletes it. No `.qnt` action opens a
payment edge, so nothing abstract says a bond backs at most one channel,
and nothing abstract distinguishes an unleased bond from a leased one.

**The tag-4 bond itself is unmodelled.** `l1_stake.qnt` modelled the
legacy tag-1 bond and was deleted with it. The tag-4 bond used to
inherit its checked properties through a shared body; it no longer
shares one, so stake conservation, provider-only funding, the immediate
unleased timeout, the horizon leased timeout, and lease deletion are
Rust-side properties only. A tag-4 lease/timeout model with ITF replay
is owed before a paid release.

There are no other registry records. The challenge bitmap, the
live-game pointer and the winner record were deleted with the rest of
the unbuilt game surface: a record kind nothing writes is not coverage
owed, it is a promise. The game slice adds its records, its
transitions, and their model together.

## What that costs, precisely

These properties are **not** established by any abstract model today:

1. **No cross-chunk record invariant is proved abstractly.** That a
   value's chunks are all present, all in their own slots, and all agree
   on one length and record kind is enforced only by
   `View::registry_value` and tested only in `tests/view.rs`.
2. **No abstract atomicity claim covers a registry write.** The models
   capture atomicity by updating primed vars in one `action` block, and
   `src/store.rs` records that as a premise the implementation must
   honour. A registry write is outside that block, so
   "the chunk write and the edge effect commit together" is a Rust-side
   property, checked in `crates/chain/src/execution/kernel.rs` where
   both halves are replayed into one QMDB batch.
3. **`public_event = None` has no modelled meaning.** The models' `NoEvent`
   means "no operation ran". The kernel's `None` will also mean "an
   operation ran, committed consensus state, and announced nothing".
   Nothing abstract distinguishes them.
4. **A chunk swapped between two same-shaped values is undetectable.**
   A chunk body carries its namespace, record kind, index, count, and
   length, but not the logical key its slot id was derived from, so
   reassembly cannot tell one value's chunk from another's of identical
   shape in the same namespace. `tests/view.rs` pins this blind spot
   explicitly. Binding it is a record-body concern, not a substrate one.

## What that costs for the payment close, precisely

These properties of the landed payment close are **not** established by
any abstract model:

5. **The settlement scalar's monotonicity is Rust-side only.** That a
   contest's `final_cumulative` never decreases — a start sets it, one
   response may only raise it, and a freeze may not settle below it — is
   checked in `tests/channel/work.rs` and nowhere abstract.
6. **The omission bond's conservation is Rust-side only.** That
   `provider + client` equals exactly what the close distributes, and
   that the bond moves only on a proved understatement, rests on
   `Edge::closes` plus the derived split in `tx/work.rs`.
7. **The one-contest and one-response rules are Rust-side only.** No
   abstract state says a payment edge has at most one live contest or
   that a contest admits at most one response.
8. **Absence-versus-fault has no abstract counterpart.** The rule that a
   present-but-unreadable pending slot is an invalid transaction rather
   than "no contest is live" is a Rust-side property of
   `parse_pending_close`, mutation-tested in `tests/channel/work.rs` on
   the apply path and in `src/work.rs` on the classification itself. The
   same rule over the lease's *two* slots — where absence additionally
   means "this bond may be timed out at once" — is a Rust-side property
   of `parse_bond_lease`, mutation-tested in the same two places. Both
   parsers are public, and the endpoint readiness gate calls them rather
   than restating the shape rules, so an endpoint and a close cannot
   disagree about what a slot holds.
9. **Bond exclusivity is Rust-side only.** That a live tag-4 bond backs
   at most one payment channel, that a payment open refuses an absent,
   spent, or already-leased bond, and that the edge and its lease commit
   as one change, rest on `tx/work.rs::open_bond_lease` and on the chain
   replaying one `ApplyOutcome` into one batch. No abstract state holds
   a lease.

## What stands in for a model meanwhile

Not silence. Every harness that replays or explores the transitions the
models *do* cover — opens and closes of basic, stake-bond, and
work-stake-bond edges — asserts that they write **no** registry state at
all:

- `tests/itf.rs` — every ITF replay checks `view.registry_len() == 0`
  after each step, in all three runners.
- `tests/stateright.rs` — an always-property over the explored state
  space, on a store that *declares* registry slots so the write would
  succeed and be caught rather than be refused by the store.
- `tests/sequence.rs` and `tests/channel.rs` — every applied operation's
  `ApplyOutcome` must announce itself and carry an empty registry diff.
- `tests/state_machine.rs` — the map-backed store accepts any slot id, so
  the count check catches a write to a derived id too.

These are falsifiable: making a *modelled* open stage one mutation fails
all of them. They are also exactly as strong as they claim — they prove
that the modelled transitions are registry-free, and say nothing about
the registry-writing transitions no harness in this list replays: the
payment-close moves and proofs, and the work-payment open, which leases
its bond in the same change as its edge. `Change::open` is no longer
registry-free for every profile, and the assertion above has moved with
it: `tests/channel.rs` fails any *ordinary* open or close that writes a
chunk, while a payment open is applied through a helper that requires
exactly the two lease writes.

## What the directory holds now, and what it dropped

Three executable roots and their shared vocabulary. `l1.qnt`,
`l1_fees.qnt` and `delegation.qnt` are the roots: typechecked, `quint test`ed, `quint run`
with named invariants, `quint verify`ed by Apalache, and — this is the
part that makes them evidence rather than decoration — exported as ITF
traces and replayed against the kernel by `tests/itf.rs`, which compares
coin owners and values, edge value, reserve, committed close fee,
timeout, parties and terms hash, the emitted event, and the rejection of
every input the model refused. `types.qnt`, `verifier.qnt`,
`accounting.qnt`, `terms.qnt`, `bounds.qnt` and `rules/invariants.qnt`
are the L1 models’ vocabulary and are reached through them.

`delegation.qnt` tracks coin owner and delegate separately and checks consuming
reshapes, signer admission, committed destinations and owner-signed recovery.
Its eight ITF traces replay the same decisions against `State::apply`, including
rejected transactions and the full live coin set. It covers Basic edges and
unleased work-stake bonds; payment contests and leased-bond recovery remain
covered by the concrete `tests/delegation.rs` transaction tests, not this model.

Three things were removed because they modelled a system that does not
exist, and the removal is recorded here rather than only in a commit
message:

- **`proof_lifetime.qnt`.** Its close vocabulary was
  `SelfContainedLatestProof`, `ViolationProof`, `BareSignedReceipt`,
  `StaleReceipt`. No kernel has ever had a self-contained latest-state
  proof; `Violation` was deleted with the seal apparatus; and a receipt
  is not a `Proof` variant at all, so "a stale receipt is not
  admissible" was a statement about a type the kernel cannot even
  decode. Its `liveWithinPaidLifetime` invariant forced a close at the
  horizon, which the kernel does not do — an edge stays live past its
  timeout until somebody submits a close.
- **`lifetime.qnt`.** It compared permanent, budgeted and bonded
  lifetime policies, a per-block rent bucket that a `tick` drained, a
  state bond, and a third-party collector paid out of the expired
  slot's value. The kernel charges one prepaid lifetime fee at open,
  priced from the committed timeout height, and has no rent, no state
  bond, and no collector.
- **`deps/assumptions.qnt`.** Not stale in content — every premise in it
  is real — but it was imported by no module, so it was never
  typechecked and never run, while `lib.rs` listed it in the
  correspondence table beside modules that are. Its premises now live
  with their consumers: `src/context.rs` (monotone height, network
  separation), `src/block.rs` (deterministic block order), `src/store.rs`
  (transaction atomicity, read isolation), `src/object.rs`
  (operator-trusted genesis), and the head of `verifier.qnt` (verifier
  soundness and determinism).

Nothing real was dropped with them. Value accounting, the close
reserve, the absence of a marginal close fee, close pricing at the
schedule committed at open, `Mutual` expiry, `Timeout` liveness, and the
timeout payout binding all live in `l1.qnt` / `l1_fees.qnt` over the same
buckets, and each one has been shown to fail under a kernel mutation
that should break it. The one assertion the deleted pair held that
`l1_fees.qnt` did not is now in `feeRaiseDoesNotStrandCloseTest`: after a
fee raise the current fee genuinely exceeds the whole reserve and the
close is still available.

Two value domains went with them and are worth naming, because their
absence is now a claim. `EconomicTerms` used to carry a
`stateBudgetRefund`, a `stateBondRefund` and a `slashExposure`; after
`lifetime.qnt` and the seal apparatus went, every caller passed zero for
all three. They are deleted rather than zeroed: a value domain nothing
can make nonzero is a domain a reader will believe the kernel has.

## When this file should be deleted

When the v2 transitions land, this note is replaced by real modules and
real fixtures: registry state in `types.qnt`, the record-mutating
actions in `l1.qnt`, and ITF traces carrying the record fields, with
every field asserted against the kernel in `tests/itf.rs`. A trace field
that is deserialized and never compared is worse than an unmodelled
one; it has already happened here once, on a bond-terms field the
replay read and never asserted.
