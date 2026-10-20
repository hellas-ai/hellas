// -*- mode: Bluespec; -*-
//
// Coin delegation: the owner reshape, the authority-classified open, and
// the destination rules every close pays by.
//
// One owner `O` holds one genesis coin and runs two node keys, `N` and
// `N2`. A counterparty `T` is the zero-funded taker of every edge. The
// owner reshapes its coin to delegate it to a node, clears a delegation
// by reshaping it back, and opens at most one edge of each shape:
//
//   * `Basic` — a basic edge, which a delegate may never open;
//   * `Bond`  — a tag-4 work-stake bond, which a delegate may fund from a
//     coin delegated to it. Unleased, its timeout is immediate.
//
// Each edge pays its whole value to the maker's committed destination
// `{ O, payoutDelegate }` in one payout.
//
// What this model establishes, and what the Rust replay asserts against
// the kernel at every step (`tests/itf.rs`, `delegation_*` fixtures):
//
//   * a reshape consumes its input, so its replay is refused;
//   * only the owner reshapes, and value is conserved through it;
//   * a delegate-signed basic open is refused;
//   * a delegate funds only from a coin delegated to it, and commits only
//     itself or nobody as the payout delegate;
//   * every close pays exactly the committed destination, and an
//     owner-signed close pays it undelegated.
//
// What it does not model, deliberately and precisely:
//
//   * the work-payment channel: its open, its lease over the bond, its
//     contest moves, `Freeze` and `Adjudicated`. Those write registry
//     state, which no model here holds (`registry.md`). Their delegation
//     rules — signer-funded payment opens, party witnesses on every move,
//     the owner-signed contest's undelegated payouts, the omission penalty
//     keyed to role, and a bond released once its payment edge is gone —
//     are established by `tests/delegation.rs` through the apply path,
//     not here;
//   * fees, reserves and multi-coin funding (`l1_fees.qnt` owns fees);
//   * a second party with delegated coins: `T` is always its own sole key.

module delegation {
  // ---------------------------------------------------------------------
  // Vocabulary
  // ---------------------------------------------------------------------

  // `NoKey` is the absent delegate. Every other value is a settlement key.
  type Key =
    | O
    | N
    | N2
    | T
    | NoKey

  type Authority =
    | Owner
    | Signer

  // The closed coin universe. `DelN` / `DelN2` are the outputs of the two
  // delegating reshapes of `GenO`; `Swept` is `DelN` reshaped back to the
  // owner undelegated; `BasicOut` / `BondOut` are the payouts of the one
  // edge of each shape.
  type Coin =
    | GenO
    | DelN
    | DelN2
    | Swept
    | BasicOut
    | BondOut

  type Shape =
    | Basic
    | Bond

  type Reshape =
    | DelegateToN
    | DelegateToN2
    | SweepN

  type Proof =
    | Mutual
    | Timeout

  type CoinState = { owner: Key, delegate: Key, value: int }

  // One edge: its shape, the coin that funded it, the maker's committed
  // payout delegate, which of the maker's keys authorized the open, and
  // the delegate the funding coin carried.
  type EdgeState = {
    shape: Shape,
    coin: Coin,
    payoutDelegate: Key,
    makerAuth: Authority,
    fundedDelegate: Key,
    value: int,
  }

  type Input =
    | NoInput
    | ReshapeInput({ reshape: Reshape, signer: Key })
    | RejectedReshapeInput({ reshape: Reshape, signer: Key })
    | OpenInput({ shape: Shape, coin: Coin, payoutDelegate: Key, makerAuth: Authority })
    | RejectedOpenInput({ shape: Shape, coin: Coin, payoutDelegate: Key, makerAuth: Authority })
    | CloseInput({ proof: Proof, makerAuth: Authority, payOwner: Key, payDelegate: Key })
    | RejectedCloseInput({ proof: Proof, makerAuth: Authority, payOwner: Key, payDelegate: Key })
    | TickInput

  type Event =
    | NoEvent
    | CoinsReshapedEvent(Reshape)
    | EdgeOpenedEvent(Shape)
    | EdgeClosedEvent(Shape)

  pure val AllKeys = Set(O, N, N2, T, NoKey)
  pure val AllCoins = Set(GenO, DelN, DelN2, Swept, BasicOut, BondOut)
  pure val AllShapes = Set(Basic, Bond)
  pure val AllReshapes = Set(DelegateToN, DelegateToN2, SweepN)
  pure val AllProofs = Set(Mutual, Timeout)
  pure val AllAuthorities = Set(Owner, Signer)
  // The payout delegates a maker may commit in this model.
  pure val PayoutDelegates = Set(NoKey, N, N2)
  pure val Owners = Set(O, T)

  pure val Total = 10
  pure val TimeoutHeight = 2

  pure val NoEdge: EdgeState = {
    shape: Basic,
    coin: GenO,
    payoutDelegate: NoKey,
    makerAuth: Owner,
    fundedDelegate: NoKey,
    value: 0,
  }

  pure val Dead: CoinState = { owner: NoKey, delegate: NoKey, value: 0 }

  pure def reshapeInput(r: Reshape): Coin =
    match r {
      | DelegateToN => GenO
      | DelegateToN2 => GenO
      | SweepN => DelN
    }

  pure def reshapeOutput(r: Reshape): Coin =
    match r {
      | DelegateToN => DelN
      | DelegateToN2 => DelN2
      | SweepN => Swept
    }

  // Every reshape here keeps the value with the owner and moves only the
  // delegate.
  pure def reshapeDelegate(r: Reshape): Key =
    match r {
      | DelegateToN => N
      | DelegateToN2 => N2
      | SweepN => NoKey
    }

  pure def output(s: Shape): Coin =
    match s {
      | Basic => BasicOut
      | Bond => BondOut
    }

  // The payout delegate a close issues: none when the owner signed it,
  // the committed one otherwise.
  pure def issuedDelegate(e: EdgeState, ownerSigned: bool): Key =
    if (ownerSigned) NoKey else e.payoutDelegate

  // ---------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------

  var coins: Coin -> CoinState
  var liveCoins: Set[Coin]
  var edge: EdgeState
  var edgeLive: bool
  var opened: Set[Shape]
  // The record of each shape's closed edge, and whether its close was
  // owner-signed: the payout it issued is derived from both.
  var closedEdge: Shape -> EdgeState
  var closedOwnerSigned: Shape -> bool
  var height: int
  var lastInput: Input
  var lastEvent: Event

  // ---------------------------------------------------------------------
  // Preconditions: the kernel's rules, abstracted
  // ---------------------------------------------------------------------

  // O2: the input exists, the owner signs, the output is fresh.
  def canReshape(r: Reshape, signer: Key): bool =
    liveCoins.contains(reshapeInput(r))
      and signer == coins.get(reshapeInput(r)).owner
      and not(liveCoins.contains(reshapeOutput(r)))

  // F1–F3 for the maker; the taker is `T`, zero-funded and owner-signed.
  def canOpen(s: Shape, c: Coin, pd: Key, auth: Authority): bool =
    not(edgeLive)
      and not(opened.contains(s))
      and height < TimeoutHeight
      and liveCoins.contains(c)
      // F1: the funding coin is the maker's owner's.
      and coins.get(c).owner == O
      // F3: a basic open is owner-signed on both sides.
      and (s == Basic implies auth == Owner)
      // F2: a delegate funds only from its own coin and pays only itself
      // or nobody.
      and (auth == Signer implies
        (coins.get(c).delegate == N and (pd == NoKey or pd == N)))

  // C2 and C3′: the one payout lands exactly at the committed
  // destination, undelegated when the owner signed the close.
  def canClose(p: Proof, auth: Authority, payOwner: Key, payDelegate: Key): bool =
    val ownerSigned = p == Mutual and auth == Owner
    edgeLive
      and (match edge.shape {
        | Basic =>
          (p == Mutual and height < TimeoutHeight)
            or (p == Timeout and height >= TimeoutHeight)
        // An unleased bond's timeout is immediate; a bond has no other
        // exit.
        | Bond => p == Timeout
      })
      and payOwner == O
      and payDelegate == issuedDelegate(edge, ownerSigned)
      and not(liveCoins.contains(output(edge.shape)))

  // ---------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------

  action init = all {
    coins' = AllCoins.mapBy(c =>
      if (c == GenO) { owner: O, delegate: NoKey, value: Total } else Dead
    ),
    liveCoins' = Set(GenO),
    edge' = NoEdge,
    edgeLive' = false,
    opened' = Set(),
    closedEdge' = AllShapes.mapBy(_ => NoEdge),
    closedOwnerSigned' = AllShapes.mapBy(_ => false),
    height' = 1,
    lastInput' = NoInput,
    lastEvent' = NoEvent,
  }

  action reshape(r: Reshape, signer: Key): bool = all {
    canReshape(r, signer),
    coins' = coins.set(
      reshapeOutput(r),
      {
        owner: coins.get(reshapeInput(r)).owner,
        delegate: reshapeDelegate(r),
        value: coins.get(reshapeInput(r)).value,
      }
    ),
    liveCoins' = liveCoins.exclude(Set(reshapeInput(r))).union(Set(reshapeOutput(r))),
    edge' = edge,
    edgeLive' = edgeLive,
    opened' = opened,
    closedEdge' = closedEdge,
    closedOwnerSigned' = closedOwnerSigned,
    height' = height,
    lastInput' = ReshapeInput({ reshape: r, signer: signer }),
    lastEvent' = CoinsReshapedEvent(r),
  }

  action rejectReshape(r: Reshape, signer: Key): bool = all {
    not(canReshape(r, signer)),
    coins' = coins,
    liveCoins' = liveCoins,
    edge' = edge,
    edgeLive' = edgeLive,
    opened' = opened,
    closedEdge' = closedEdge,
    closedOwnerSigned' = closedOwnerSigned,
    height' = height,
    lastInput' = RejectedReshapeInput({ reshape: r, signer: signer }),
    lastEvent' = NoEvent,
  }

  action openEdge(s: Shape, c: Coin, pd: Key, auth: Authority): bool = all {
    canOpen(s, c, pd, auth),
    coins' = coins,
    liveCoins' = liveCoins.exclude(Set(c)),
    edge' = {
      shape: s,
      coin: c,
      payoutDelegate: pd,
      makerAuth: auth,
      fundedDelegate: coins.get(c).delegate,
      value: coins.get(c).value,
    },
    edgeLive' = true,
    opened' = opened.union(Set(s)),
    closedEdge' = closedEdge,
    closedOwnerSigned' = closedOwnerSigned,
    height' = height,
    lastInput' = OpenInput({ shape: s, coin: c, payoutDelegate: pd, makerAuth: auth }),
    lastEvent' = EdgeOpenedEvent(s),
  }

  action rejectOpen(s: Shape, c: Coin, pd: Key, auth: Authority): bool = all {
    not(canOpen(s, c, pd, auth)),
    coins' = coins,
    liveCoins' = liveCoins,
    edge' = edge,
    edgeLive' = edgeLive,
    opened' = opened,
    closedEdge' = closedEdge,
    closedOwnerSigned' = closedOwnerSigned,
    height' = height,
    lastInput' = RejectedOpenInput({ shape: s, coin: c, payoutDelegate: pd, makerAuth: auth }),
    lastEvent' = NoEvent,
  }

  action closeEdge(p: Proof, auth: Authority, payOwner: Key, payDelegate: Key): bool = all {
    canClose(p, auth, payOwner, payDelegate),
    coins' = coins.set(
      output(edge.shape),
      { owner: payOwner, delegate: payDelegate, value: edge.value }
    ),
    liveCoins' = liveCoins.union(Set(output(edge.shape))),
    edge' = NoEdge,
    edgeLive' = false,
    opened' = opened,
    closedEdge' = closedEdge.set(edge.shape, edge),
    closedOwnerSigned' = closedOwnerSigned.set(edge.shape, p == Mutual and auth == Owner),
    height' = height,
    lastInput' = CloseInput({ proof: p, makerAuth: auth, payOwner: payOwner, payDelegate: payDelegate }),
    lastEvent' = EdgeClosedEvent(edge.shape),
  }

  action rejectClose(p: Proof, auth: Authority, payOwner: Key, payDelegate: Key): bool = all {
    edgeLive,
    not(canClose(p, auth, payOwner, payDelegate)),
    coins' = coins,
    liveCoins' = liveCoins,
    edge' = edge,
    edgeLive' = edgeLive,
    opened' = opened,
    closedEdge' = closedEdge,
    closedOwnerSigned' = closedOwnerSigned,
    height' = height,
    lastInput' = RejectedCloseInput({ proof: p, makerAuth: auth, payOwner: payOwner, payDelegate: payDelegate }),
    lastEvent' = NoEvent,
  }

  action tick = all {
    coins' = coins,
    liveCoins' = liveCoins,
    edge' = edge,
    edgeLive' = edgeLive,
    opened' = opened,
    closedEdge' = closedEdge,
    closedOwnerSigned' = closedOwnerSigned,
    height' = height + 1,
    lastInput' = TickInput,
    lastEvent' = NoEvent,
  }

  // Every accepting transition, over every parameter the model knows.
  // Parameters a rule refuses are drawn as freely as the ones it admits:
  // the preconditions, not the parameter sets, are what keep them out.
  action step = any {
    nondet r = AllReshapes.oneOf()
    nondet signer = Set(O, N).oneOf()
    reshape(r, signer),
    nondet s = AllShapes.oneOf()
    nondet c = AllCoins.oneOf()
    nondet pd = PayoutDelegates.oneOf()
    nondet auth = AllAuthorities.oneOf()
    openEdge(s, c, pd, auth),
    nondet p = AllProofs.oneOf()
    nondet closeAuth = AllAuthorities.oneOf()
    nondet payOwner = Owners.oneOf()
    nondet payDelegate = PayoutDelegates.oneOf()
    closeEdge(p, closeAuth, payOwner, payDelegate),
    tick,
  }

  // ---------------------------------------------------------------------
  // Invariants
  // ---------------------------------------------------------------------

  def liveValue: int =
    liveCoins.fold(0, (sum, c) => sum + coins.get(c).value)
      + (if (edgeLive) edge.value else 0)

  // Reshapes and closes create no value and destroy none.
  val valueConserved = liveValue == Total

  // A node key never owns a coin: every coin is an owner's, delegated or
  // not.
  val nodeNeverOwns = liveCoins.forall(c => Owners.contains(coins.get(c).owner))

  // A reshape consumes its input: no coin and its reshape output are
  // ever live together.
  val reshapeConsumesItsInput =
    AllReshapes.forall(r =>
      not(liveCoins.contains(reshapeInput(r)) and liveCoins.contains(reshapeOutput(r)))
    )

  // F3: a live basic edge was opened by the maker's owner.
  val basicIsOwnerOpened = edgeLive and edge.shape == Basic implies edge.makerAuth == Owner

  // F2: a signer-opened edge was funded from a coin delegated to that
  // signer, and commits only the signer or nobody as payout delegate.
  val signerReachIsItsDelegation =
    edgeLive and edge.makerAuth == Signer implies
      (edge.fundedDelegate == N and (edge.payoutDelegate == NoKey or edge.payoutDelegate == N))

  // C2 and C3′: every payout coin is the maker's owner's, carrying the
  // committed delegate unless the close was owner-signed.
  val payoutsAtCommittedDestinations =
    AllShapes.forall(s =>
      liveCoins.contains(output(s)) implies
        coins.get(output(s)).owner == O
          and coins.get(output(s)).delegate
            == issuedDelegate(closedEdge.get(s), closedOwnerSigned.get(s))
    )

  val heightAtLeastGenesis = height >= 1

  // ---------------------------------------------------------------------
  // Traces, exported as ITF fixtures and replayed against the kernel
  // ---------------------------------------------------------------------

  // The owner delegates to N, fires N by sweeping the coin back, and the
  // public bytes of both reshapes are resubmitted: neither lands, because
  // each one's input is gone. N cannot reshape the coin delegated to it
  // either.
  run reshapeReplayRejectedTest =
    init
      .then(reshape(DelegateToN, O))
      .then(rejectReshape(SweepN, N))
      .then(reshape(SweepN, O))
      .then(rejectReshape(DelegateToN, O))
      .then(rejectReshape(SweepN, O))
      .expect(liveCoins == Set(Swept)
        and coins.get(Swept).delegate == NoKey
        and not(canReshape(DelegateToN, O))
        and not(canReshape(SweepN, O)))

  // A delegate-signed basic open is refused, though the coin is its own
  // and the destination its own; the owner may open the same edge.
  run delegateSignedBasicOpenRejectedTest =
    init
      .then(reshape(DelegateToN, O))
      .then(rejectOpen(Basic, DelN, N, Signer))
      .then(openEdge(Basic, DelN, N, Owner))
      .expect(edgeLive and edge.makerAuth == Owner)

  // A delegate may name only itself or nobody as the payout delegate.
  run foreignDestinationRejectedTest =
    init
      .then(reshape(DelegateToN, O))
      .then(rejectOpen(Bond, DelN, N2, Signer))
      .then(openEdge(Bond, DelN, N, Signer))
      .expect(edgeLive and edge.payoutDelegate == N)

  // N cannot fund with a coin delegated to N2, nor with the owner's
  // undelegated coin.
  run otherDelegationRejectedTest =
    init
      .then(rejectOpen(Bond, GenO, NoKey, Signer))
      .then(reshape(DelegateToN2, O))
      .then(rejectOpen(Bond, DelN2, N, Signer))
      .expect(not(edgeLive) and liveCoins == Set(DelN2))

  // A close pays exactly the committed destination: not a third party,
  // and not the owner under another delegate. Bond, signer-opened.
  run closePaysOnlyCommittedTest =
    init
      .then(reshape(DelegateToN, O))
      .then(openEdge(Bond, DelN, N, Signer))
      .then(rejectClose(Timeout, Signer, T, N))
      .then(rejectClose(Timeout, Signer, O, NoKey))
      .then(rejectClose(Timeout, Signer, O, N2))
      .then(closeEdge(Timeout, Signer, O, N))
      .expect(liveCoins == Set(BondOut) and coins.get(BondOut).delegate == N)

  // An owner-signed close pays undelegated whatever the terms committed;
  // the committed delegate is refused for it. Basic, owner-opened with a
  // payout delegate the owner was free to commit.
  run ownerSignedClosePaysUndelegatedTest =
    init
      .then(reshape(DelegateToN, O))
      .then(openEdge(Basic, DelN, N2, Owner))
      .then(rejectClose(Mutual, Owner, O, N2))
      .then(closeEdge(Mutual, Owner, O, NoKey))
      .expect(coins.get(BasicOut).delegate == NoKey and closedOwnerSigned.get(Basic))

  // The same edge closed by the maker's signer pays the committed
  // delegate, and the timeout — which nobody signs — does too.
  run signerSignedClosePaysCommittedTest =
    init
      .then(openEdge(Basic, GenO, N, Owner))
      .then(rejectClose(Mutual, Signer, O, NoKey))
      .then(closeEdge(Mutual, Signer, O, N))
      .expect(coins.get(BasicOut).delegate == N and not(closedOwnerSigned.get(Basic)))

  run timeoutPaysCommittedTest =
    init
      .then(openEdge(Basic, GenO, N2, Owner))
      .then(tick)
      .then(rejectClose(Timeout, Owner, O, NoKey))
      .then(closeEdge(Timeout, Owner, O, N2))
      .expect(coins.get(BasicOut).delegate == N2)
}
