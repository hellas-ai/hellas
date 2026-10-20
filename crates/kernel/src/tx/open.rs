//! The arithmetic an open performs, and the projection that lets a
//! non-kernel caller perform it without a store.
//!
//! An endpoint that wants to open a channel has to know, before it signs
//! anything, what the chain will charge it, what the edge will be worth,
//! and what id that edge will have. It cannot ask a node: the open does
//! not exist yet. Its only alternatives are to copy the formulas or to
//! guess, and a wrong guess is a rejected transaction with funding
//! already committed to a signature.
//!
//! So the formulas live here once. `apply_open` reaches them through
//! `open_debits` and `check_work_profile_open`; an endpoint reaches the
//! same functions through [`open_projection`]. There is no second copy
//! that agrees today.
//!
//! # What the projection does not answer
//!
//! Everything that needs the chain's state or a signature: duplicate
//! funding ids, whether the coins exist and who owns them, whether the
//! derived edge is already live, whether the authorizations verify,
//! whether the named bond is live and unleased. Those checks live around
//! this arithmetic in `apply_open` and cannot be inferred from values. A
//! caller that projects an open has computed what the chain would
//! compute; it has not been told the chain will accept it.
//!
//! One arithmetic rule is also deliberately outside the projection: the
//! comparison of the terms' committed timeout payouts against the total
//! this edge requires. The requirement is *returned* — see
//! [`OpenProjection::timeout_payout`] — because a caller building terms
//! needs that number before it can write payouts that satisfy it, and a
//! function that could only grade finished terms could not be used to
//! finish them. The comparison itself remains `apply_open`'s, and both
//! sides read the requirement from `timeout_payout`.

use super::{Funding, is_work_bond, timeout_close_cost, units};
use crate::{
    consts::{MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS},
    context::{BlockHeight, Cost, Fees},
    error::InvalidOpenReason,
    list::List,
    object::{Edge, EdgeValues, PartyKeys},
    primitive::{CoinId, EdgeId},
    terms::{Terms, TermsProfile, WorkPaymentTerms, WorkStakeBondTerms},
    tx::{CloseKind, Payout, Tx, work},
};

/// The funding an open would consume: one id and one value per coin,
/// split by party exactly as [`Funding`] splits it.
///
/// Carries each value beside its own id rather than in a second list
/// alongside, because the two would have to describe the same coins in
/// the same order and nothing could check that they did. A caller reads these pairs
/// off a finalized light-client answer and hands the whole thing to
/// [`open_projection`]; [`Self::funding`] then returns the ids alone, so
/// the transaction it signs cannot name coins the projection did not
/// price.
///
/// No owner. The projection does not check funding ownership — that read
/// belongs to the chain — and carrying a key it ignores would promise a
/// check it does not perform.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct OpenFunding {
    maker: List<(CoinId, u64), MAX_PARTY_INPUTS>,
    taker: List<(CoinId, u64), MAX_PARTY_INPUTS>,
}

impl OpenFunding {
    /// Creates the priced funding of a prospective open.
    #[must_use]
    pub const fn new(
        maker: List<(CoinId, u64), MAX_PARTY_INPUTS>,
        taker: List<(CoinId, u64), MAX_PARTY_INPUTS>,
    ) -> Self {
        Self { maker, taker }
    }

    /// Returns the funding the transaction carries: these coins' ids,
    /// in this order.
    #[must_use]
    pub fn funding(&self) -> Funding {
        Funding::new(ids(&self.maker), ids(&self.taker))
    }

    const fn len(&self) -> usize {
        self.maker.len() + self.taker.len()
    }

    const fn shape(&self) -> FundingShape {
        FundingShape {
            maker: !self.maker.is_empty(),
            taker: !self.taker.is_empty(),
        }
    }

    /// Sums both parties' contributions, `None` on overflow.
    ///
    /// Per party then together, which is the same total and the same
    /// overflow as one sum over all of them: every term is a `u64` value
    /// and none is negative.
    fn total(&self) -> Option<u64> {
        self.maker
            .checked_sum(|(_, value)| *value)?
            .checked_add(self.taker.checked_sum(|(_, value)| *value)?)
    }
}

fn ids(coins: &List<(CoinId, u64), MAX_PARTY_INPUTS>) -> List<CoinId, MAX_PARTY_INPUTS> {
    coins.clone().map(CoinId::ZERO, |(id, _)| id)
}

/// What the kernel would compute for a prospective [`Tx::Open`].
///
/// Deliberately not an [`Edge`]: an endpoint has no store and no
/// business forming one. It gets the three debits, the two numbers the
/// edge will carry, the schedule that prices its closes, the payout its
/// terms must commit, and the id it will have.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct OpenProjection {
    edge: EdgeId,
    open_fee: u64,
    lifetime_fee: u64,
    values: EdgeValues,
    timeout_payout: Option<u64>,
}

impl OpenProjection {
    /// Returns the id the produced edge will have.
    ///
    /// The same derivation [`Tx::edge_id_of`] performs, repeated here so
    /// one call answers every question about the open a caller is about
    /// to sign.
    #[must_use]
    pub const fn edge(&self) -> EdgeId {
        self.edge
    }

    /// Returns the fee charged for executing the open itself.
    #[must_use]
    pub const fn open_fee(&self) -> u64 {
        self.open_fee
    }

    /// Returns the prepaid rent for every block from the open to the
    /// committed timeout height.
    #[must_use]
    pub const fn lifetime_fee(&self) -> u64 {
        self.lifetime_fee
    }

    /// Returns the principal, the close reserve, and the fee schedule
    /// the edge will commit.
    ///
    /// One value rather than three accessors because these three
    /// numbers are what every close distributes from: hand them to
    /// [`crate::work_payment_settlement`] to learn a payment channel's
    /// capacity, or compare them against a finalized edge's
    /// [`Edge::values`] to confirm the chain opened what was projected.
    ///
    /// The committed close-fee schedule is the schedule passed to
    /// [`open_projection`], unchanged — an open commits the fees of its
    /// own block so a later schedule cannot strand a live edge. It is
    /// carried here because a caller comparing against a finalized edge
    /// needs all three in one value, not because the projection
    /// discovered it.
    #[must_use]
    pub const fn values(&self) -> EdgeValues {
        self.values
    }

    /// Returns the total the terms' committed timeout payouts must sum
    /// to, or `None` for a shape that commits none.
    ///
    /// This is a requirement, not an observation: [`Tx::Open`] is
    /// rejected with [`InvalidOpenReason::TermsValueMismatch`] if the
    /// terms commit any other total. Build the payouts to sum to
    /// exactly this and the rule cannot be failed.
    #[must_use]
    pub const fn timeout_payout(&self) -> Option<u64> {
        self.timeout_payout
    }
}

/// Returns what the kernel would compute for the open of `terms` funded
/// by `funding` at `height` under `fees`.
///
/// # Errors
///
/// The same [`InvalidOpenReason`] `apply_open` would return for the same
/// inputs, for every rule that reads only values and terms. See the module documentation for the rules that
/// read state, signatures, or the terms' own payout list, and that this
/// therefore does not apply.
pub fn open_projection(
    height: BlockHeight,
    fees: Fees,
    funding: &OpenFunding,
    terms: &Terms,
) -> Result<OpenProjection, InvalidOpenReason> {
    let debits = open_debits(height, fees, funding.len(), funding.total(), terms)?;
    check_work_profile_open(&debits.edge, funding.shape(), terms)?;
    Ok(OpenProjection {
        edge: Tx::edge_id_of(&funding.funding(), terms),
        open_fee: debits.open_fee,
        lifetime_fee: debits.lifetime_fee,
        values: debits.edge.values(),
        timeout_payout: debits.timeout_payout,
    })
}

/// The three debits an open charges, the edge they leave behind, and the
/// timeout payout that edge requires.
pub(super) struct OpenDebits {
    pub(super) open_fee: u64,
    pub(super) lifetime_fee: u64,
    pub(super) edge: Edge,
    pub(super) timeout_payout: Option<u64>,
}

/// Charges an open and builds the edge it produces.
///
/// `coins` is how many funding coins it spends and `total` what they are
/// worth — `None` for a sum that overflowed, which is a rejection here
/// rather than at the summing site so the reason is named once.
pub(super) fn open_debits(
    height: BlockHeight,
    fees: Fees,
    coins: usize,
    total: Option<u64>,
    terms: &Terms,
) -> Result<OpenDebits, InvalidOpenReason> {
    let open_fee = fees
        .charge(open_cost(coins, terms))
        .ok_or(InvalidOpenReason::FeeOverflow)?;
    let lifetime_fee = open_lifetime_fee(height, fees, terms)?;
    let reserve = fees
        .charge(open_reserve_cost(terms))
        .ok_or(InvalidOpenReason::ReserveOverflow)?;
    let total = total.ok_or(InvalidOpenReason::FundingOverflow)?;
    let edge = Edge::open(
        total,
        terms.parties(),
        terms.hash(),
        (open_fee, lifetime_fee, reserve, fees),
        terms.timeout(),
        terms.allowed_closes(),
    )?;
    let timeout_payout = timeout_payout(edge.values(), terms)?;
    Ok(OpenDebits {
        open_fee,
        lifetime_fee,
        edge,
        timeout_payout,
    })
}

/// Physical slots an open touches, by profile.
///
/// The generic open touches its funding coins and the edge it produces.
/// A work payment touches three more, all of them consequences of the
/// bond it names: the bond edge it reads, and the two chunks of the
/// lease it takes out. `Cost.slots` counts every slot the transition
/// reaches for, read-only ones included, because the host has to fetch
/// them whether or not the answer changes anything.
///
/// Every profile verifies one witness per party, and is charged one
/// proof unit for each.
pub(super) fn open_cost(coins: usize, terms: &Terms) -> Cost {
    let inputs = units(coins);
    match terms.profile() {
        TermsProfile::WorkPayment(_) => Cost::new(1, inputs.saturating_add(4), OPEN_WITNESSES),
        TermsProfile::WorkStakeBond(_) | TermsProfile::Basic => {
            Cost::new(1, inputs.saturating_add(1), OPEN_WITNESSES)
        }
    }
}

/// Witnesses an open verifies: one per party, funded or not.
const OPEN_WITNESSES: u64 = 2;

/// Reserve locked at open, by profile.
///
/// Every profile reserves the worst case *its own* close set can reach.
/// Work payment is the shape whose set makes that cheaper rather than
/// dearer: its two exits touch a fixed four slots between them, so
/// reserving the generic maximum fanout would lock value the channel can
/// never spend and shrink the capacity its parties negotiated.
pub(super) fn open_reserve_cost(terms: &Terms) -> Cost {
    match terms.profile() {
        TermsProfile::WorkPayment(_) => crate::work::work_payment_reserve_cost(),
        // A tag-4 bond's only exit is its timeout, which reads both
        // lease chunks on top of the maximum payout fanout. The proof
        // axis is still charged at the dearest kind so a bond that
        // later admits a two-signature exit cannot be stranded by a
        // reserve fixed here.
        TermsProfile::WorkStakeBond(_) => Cost::new(
            1,
            units(MAX_EDGE_OUTPUTS).saturating_add(super::WORK_BOND_TIMEOUT_EXTRA_SLOTS),
            CloseKind::Mutual.proofs(),
        ),
        // The close kind with the most proof units, at the maximum
        // payout fanout.
        TermsProfile::Basic => super::kind_close_cost(MAX_EDGE_OUTPUTS, CloseKind::Mutual),
    }
}

fn open_lifetime_fee(
    height: BlockHeight,
    fees: Fees,
    terms: &Terms,
) -> Result<u64, InvalidOpenReason> {
    let Some(blocks) = terms.timeout().get().checked_sub(height.get()) else {
        return Err(InvalidOpenReason::TimeoutNotFuture);
    };
    if blocks == 0 {
        return Err(InvalidOpenReason::TimeoutNotFuture);
    }
    fees.lifetime()
        .checked_mul(blocks)
        .ok_or(InvalidOpenReason::LifetimeFeeOverflow)
}

/// Returns the total a shape's committed timeout payouts must sum to, or
/// `None` for a shape that commits none.
///
/// The same price the timeout close will actually be charged. A profile
/// whose timeout touches extra slots requires a smaller payout, and
/// reading that price from anywhere but the one function that computes
/// it would let an open commit a payout its own close could never
/// satisfy.
///
/// A shape with no committed timeout payout has nothing to require: its
/// value is settled by the close paths its own set admits, not by a
/// payout fixed at open. It still pays lifetime rent to its horizon.
fn timeout_payout(values: EdgeValues, terms: &Terms) -> Result<Option<u64>, InvalidOpenReason> {
    let Some(outputs) = terms.timeout_outputs() else {
        return Ok(None);
    };
    let cost = timeout_close_cost(outputs.len(), is_work_bond(terms));
    values
        .close_value(cost)
        .map(Some)
        .ok_or(InvalidOpenReason::ReserveOverflow)
}

/// Checks the terms' committed timeout payouts against the total this
/// open requires, and against the two destinations the terms commit.
///
/// A timeout close needs no signature, so whatever these payouts name is
/// paid to whoever it names. Every one of them must therefore land
/// exactly at one party's committed destination — owner and delegate
/// both — or the timeout becomes a way to pay a key the parties never
/// committed.
///
/// Timeout-vs-height rejection happens earlier, in `open_lifetime_fee`:
/// a non-future timeout cannot price a lifetime fee. By the time this
/// runs, `terms.timeout() > height` already holds.
pub(super) fn check_timeout_payout(
    debits: &OpenDebits,
    terms: &Terms,
) -> Result<(), InvalidOpenReason> {
    let (Some(required), Some(outputs)) = (debits.timeout_payout, terms.timeout_outputs()) else {
        return Ok(());
    };
    let committed = payout_total(outputs).ok_or(InvalidOpenReason::TermsPayoutOverflow)?;
    if committed != required {
        return Err(InvalidOpenReason::TermsValueMismatch);
    }
    let parties = terms.parties();
    if outputs
        .iter()
        .all(|payout| parties.is_destination(*payout, false))
    {
        Ok(())
    } else {
        Err(InvalidOpenReason::TimeoutPayoutNotCommitted)
    }
}

fn payout_total<const N: usize>(outputs: &List<Payout, N>) -> Option<u64> {
    outputs.checked_sum(|output| output.value())
}

/// Which sides of an open carry funding.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) struct FundingShape {
    maker: bool,
    taker: bool,
}

impl FundingShape {
    pub(super) const fn of(funding: &Funding) -> Self {
        Self {
            maker: !funding.maker().is_empty(),
            taker: !funding.taker().is_empty(),
        }
    }
}

/// Rules the work profiles add to an open, by profile.
///
/// Matching on the profile rather than probing for one shape keeps a
/// newly added shape from defaulting into "no extra rules".
///
/// Each work shape is funded by its maker and by its maker alone. That
/// is a rule, not a habit, because it is what proves each party's owner:
/// the provider's by the bond it funds, the client's by the payment it
/// funds — and the payment inherits the bond's parties, so every party
/// that can act on a work edge has had its owner proved by funding on
/// some edge.
///
/// The rules of a work open that are not here read the authorization
/// witnesses, which an open being constructed does not have yet.
pub(super) fn check_work_profile_open(
    edge: &Edge,
    funding: FundingShape,
    terms: &Terms,
) -> Result<(), InvalidOpenReason> {
    match terms.profile() {
        TermsProfile::Basic => Ok(()),
        TermsProfile::WorkStakeBond(bond) => {
            check_work_bond_policy(bond)?;
            if !funding.maker {
                return Err(InvalidOpenReason::WorkStakeMakerUnfunded);
            }
            // The stake is the edge's own locked value, and a zero-value
            // object is not a stake bond. There is no second `stake`
            // scalar to compare it against, so this is the whole rule.
            if edge.value() == 0 {
                return Err(InvalidOpenReason::WorkStakeValueZero);
            }
            // The stake is the provider's alone. Any client
            // contribution would be handed to the provider by the
            // permissionless timeout an unleased bond admits.
            if funding.taker {
                Err(InvalidOpenReason::WorkStakeTakerFunded)
            } else {
                Ok(())
            }
        }
        TermsProfile::WorkPayment(payment) => {
            check_work_payment_terms(payment)?;
            if funding.taker {
                return Err(InvalidOpenReason::WorkPaymentTakerFunded);
            }
            if !funding.maker {
                return Err(InvalidOpenReason::WorkPaymentMakerUnfunded);
            }
            work::check_payment_capacity(edge, payment)
        }
    }
}

/// Policy a work bond commits at open.
///
/// Also checked on the bond witness a work-payment body embeds: that
/// witness is the bond's own terms, so it answers to the bond's rules
/// wherever it appears. The embedded case has no edge, so the
/// value rule is checked only where there is one.
fn check_work_bond_policy(bond: &WorkStakeBondTerms) -> Result<(), InvalidOpenReason> {
    // A bond whose price cap covers no job (p_j >= 1) insures nothing.
    if bond.max_job_price == 0 {
        return Err(InvalidOpenReason::JobPriceCapZero);
    }
    // Unleased, this bond times out permissionlessly, so its committed
    // payout is the only thing deciding who receives the stake back.
    // The generic open path pins the payout *sum* alone.
    //
    // `paid_solely_to` also rejects an empty list, and that half is not
    // independently reachable: `check_timeout_payout` runs first and
    // pins the payout sum to the edge's close value, and
    // `WorkStakeValueZero` above refuses a zero-value bond, so an empty
    // list is refused as a value mismatch or as a zero stake before it
    // is ever refused as routing. It stays because "pays nobody
    // everything" and "pays the wrong party" are one rule about who
    // receives the stake.
    if paid_solely_to(&bond.timeout_outputs, bond.parties.maker()) {
        Ok(())
    } else {
        Err(InvalidOpenReason::WorkStakeReturnRouting)
    }
}

/// A payment edge is only as good as the bond behind it: it embeds that
/// bond's complete terms, and those terms must describe the same two
/// parties in mirrored roles over the same horizon.
fn check_work_payment_terms(payment: &WorkPaymentTerms) -> Result<(), InvalidOpenReason> {
    // The mirrored roles and the shared horizon are derivations, not
    // checks: `parties()` reverses the bond's and `admission_horizon()`
    // is the bond's timeout, so there is no second spelling to disagree
    // with. What remains is the bond's own policy and this body's.
    check_work_bond_policy(&payment.bond_terms)?;
    // The floor is derived, not chosen: below it the provider has no
    // measured opportunity to observe the start, sign an answer, and get
    // it included, so the omission theorem the channel is priced on does
    // not hold. Consensus refuses the channel rather than opening one
    // whose safety argument it knows to be false.
    if payment.omit_response_blocks < crate::consts::MIN_OMIT_RESPONSE_BLOCKS
        || payment.omit_response_blocks > crate::consts::MAX_OMIT_RESPONSE_BLOCKS
    {
        return Err(InvalidOpenReason::WorkResponseWindowOutOfRange);
    }
    if payment.start_validity_blocks == 0
        || payment.start_validity_blocks > crate::consts::MAX_START_VALIDITY_BLOCKS
    {
        return Err(InvalidOpenReason::WorkStartValidityOutOfRange);
    }
    Ok(())
}

/// True when `outputs` is non-empty and pays nobody but `party`'s
/// committed destination, owner and delegate both.
fn paid_solely_to<const N: usize>(outputs: &List<Payout, N>, party: PartyKeys) -> bool {
    !outputs.is_empty()
        && outputs
            .iter()
            .all(|payout| party.is_destination(*payout, false))
}
