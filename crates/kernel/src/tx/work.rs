//! The work-payment close transitions.
//!
//! Two moves and two proofs, in the order they run:
//!
//! 1. [`apply_start`] stakes the opener's amount and opens a bounded
//!    response window, writing the one pending record.
//! 2. [`apply_response`] lets the certificate's beneficiary raise that
//!    amount exactly once, and marks the omission bond forfeit when the
//!    raise is the client's own contradiction of its own start.
//! 3. [`check_adjudicated`] pays out whatever the contest ended on.
//! 4. [`check_freeze`] is the cooperative alternative and can join at any
//!    point — but it can never settle below a contest already reached,
//!    and it can never erase a penalty the contest proved.
//!
//! Every one of them reads the same single registry slot through
//! [`read_pending_close`], and every one of them treats a present but
//! unreadable value as an invalid transaction rather than as absence.
//! That asymmetry is the whole point: absence is a *permission* here —
//! it lets a start open a contest and lets a freeze skip the pending
//! rules — so anything that could be mistaken for it has to be refused.

use crate::{
    consts::MAX_FREEZE_AUTH_BLOCKS,
    context::Context,
    error::{
        ApplyError, BondLeaseFault, InvalidMoveReason, InvalidOpenReason, InvalidProofReason,
        KernelResult, PendingCloseFault,
    },
    event::Change,
    lease::{BondLease, create_mutations as create_lease, read_bond_lease},
    object::{Edge, Parties},
    primitive::{EdgeId, Party, TermsHash},
    registry::{RegistryDiff, RegistryMutation},
    store::Batch,
    terms::{Terms, TermsProfile, WorkPaymentTerms},
    tx::{CloseKind, PartyAuth, PaymentContestCommitment, verify_party},
    verifier::SigVerifier,
    work::{
        EarnedCertificate, PaymentCloseResponse, PaymentCloseStart, PendingPaymentClose,
        close_route_minimum, payment_capacity, pending_payment_close_slot, read_pending_close,
        split_payouts,
    },
};

use super::Payouts;

/// Why a signed height interval does not admit this inclusion height.
#[derive(Clone, Copy)]
enum WindowFault {
    /// The inclusion height is outside the interval.
    Outside,
    /// The interval is wider than the bound that governs it.
    TooWide,
}

/// Applies a [`PaymentCloseStart`].
pub(super) fn apply_start<B, V>(
    start: &PaymentCloseStart,
    context: Context,
    verifier: &V,
    batch: &B,
) -> KernelResult<Change>
where
    B: Batch,
    V: SigVerifier + ?Sized,
{
    let input = start.payment_edge();
    let reject = |reason| ApplyError::InvalidMove { input, reason };
    let edge = batch
        .edge(input)
        .ok_or(ApplyError::MissingEdge { id: input })?;

    // The revealed terms are the edge's own, and they are a payment
    // channel. The kernel needs the two window widths and the omission
    // bond, none of which the edge stores.
    if start.terms().hash() != edge.terms() {
        return Err(reject(InvalidMoveReason::TermsMismatch));
    }
    let TermsProfile::WorkPayment(payment) = start.terms().profile() else {
        return Err(reject(InvalidMoveReason::NotAPaymentChannel));
    };

    let height = context.block_height().get();
    check_validity_window(
        height,
        (start.valid_from_height(), start.valid_through_height()),
        payment.start_validity_blocks,
    )
    .map_err(|fault| reject(move_window_fault(fault)))?;

    // One contest per edge. A second start by the opener would extend
    // its own deadline; a start by the other role would replace the
    // deadline the response is bound to. Both are refused without
    // mutation, and a racing party's remedy is the explicit response.
    if read_pending(batch, context, input)
        .map_err(|fault| reject(pending_move_fault(fault)))?
        .is_some()
    {
        return Err(reject(InvalidMoveReason::ClosePending));
    }

    // Checked, not saturating: a deadline that wrapped would be a
    // response window already shut. This is what disables the work
    // profile within one committed window of the height ceiling.
    let response_deadline = height
        .checked_add(payment.omit_response_blocks)
        .ok_or_else(|| reject(InvalidMoveReason::DeadlineOverflow))?;

    let claimed = match start.certificate() {
        None => 0,
        Some((certificate, _)) => {
            check_certificate(certificate, input, edge.terms()).map_err(reject)?;
            // Zero has exactly one encoding, the absent one. Admitting a
            // present zero would give one claim two spellings and two
            // start digests.
            if certificate.earned_cumulative() == 0 {
                return Err(reject(InvalidMoveReason::CertificateNotPositive));
            }
            check_capacity(
                &edge,
                payment.omission_bond,
                certificate.earned_cumulative(),
            )
            .map_err(reject)?;
            certificate.earned_cumulative()
        }
    };

    // Cryptography last: a start that fails a structural check must not
    // also pay for signature verification.
    let earned_digest = match start.certificate() {
        None => crate::work::no_earned_digest(input, edge.terms()),
        Some((certificate, auth)) => {
            let digest = certificate.digest(context.network());
            // Only the client signs a certificate. A provider-signed one
            // would be the provider paying itself.
            if !verify_party(verifier, auth, edge.parties().maker(), digest) {
                return Err(reject(InvalidMoveReason::BadCertificateSignature));
            }
            digest
        }
    };
    let start_digest = crate::work::start_digest(
        context.network(),
        input,
        edge.terms(),
        start.opener_role(),
        (start.valid_from_height(), start.valid_through_height()),
        earned_digest,
    );
    if !verify_party(
        verifier,
        start.action(),
        start.opener_role().keys_of(edge.parties()),
        start_digest,
    ) {
        return Err(reject(InvalidMoveReason::BadSignature));
    }

    let record = PendingPaymentClose::opened(
        input,
        start.opener_role(),
        crate::work::start_id(start_digest, height),
        response_deadline,
        (claimed, payment.omission_bond),
        start.action().is_owner(),
    );
    let chunk = record.to_chunk().ok_or_else(|| {
        reject(InvalidMoveReason::ClosePendingFault {
            fault: PendingCloseFault::Body,
        })
    })?;
    let diff = one_mutation(RegistryMutation::write(
        pending_payment_close_slot(context.network(), input),
        chunk,
    ))?;
    Ok(Change::private(&diff))
}

/// Checks a [`PaymentCloseResponse`] without changing the batch.
///
/// # Errors
///
/// Returns the same [`ApplyError`] [`apply_response`] would return before
/// writing the advanced contest record.
pub fn check_response<B, V>(
    response: &PaymentCloseResponse,
    context: Context,
    verifier: &V,
    batch: &B,
) -> KernelResult<PendingPaymentClose>
where
    B: Batch,
    V: SigVerifier + ?Sized,
{
    let input = response.payment_edge();
    let reject = |reason| ApplyError::InvalidMove { input, reason };
    let edge = batch
        .edge(input)
        .ok_or(ApplyError::MissingEdge { id: input })?;

    // A response reveals no terms, so the close-kind set is what
    // identifies the profile. It is structural: only a work payment
    // commits these exits.
    if !edge.allows(CloseKind::Adjudicated) {
        return Err(reject(InvalidMoveReason::NotAPaymentChannel));
    }
    let record = read_pending(batch, context, input)
        .map_err(|fault| reject(pending_move_fault(fault)))?
        .ok_or_else(|| reject(InvalidMoveReason::ClosePendingMissing))?;

    // Bound to the contest that won, not to the one the responder may
    // have submitted itself.
    if record.start_id() != response.start_id() {
        return Err(reject(InvalidMoveReason::StartIdMismatch));
    }
    // Only the provider — the certificate's beneficiary — may answer. A
    // client "response" would be the client raising its own claim, which
    // the start already let it do.
    if response.responder_role() != Party::Taker {
        return Err(reject(InvalidMoveReason::ResponderNotBeneficiary));
    }
    if record.responded() {
        return Err(reject(InvalidMoveReason::AlreadyResponded));
    }
    // Strictly below: a response landing exactly at the deadline is late,
    // which is what makes the adjudicated close's own guard the exact
    // complement of this one.
    if context.block_height().get() >= record.response_deadline() {
        return Err(reject(InvalidMoveReason::ResponseWindowClosed));
    }

    let certificate = response.certificate();
    check_certificate(certificate, input, edge.terms()).map_err(reject)?;
    // The one response has to advance the contest. Equal is not an
    // advance: it would consume the window and change nothing.
    if certificate.earned_cumulative() <= record.final_cumulative() {
        return Err(reject(InvalidMoveReason::CertificateNotIncreasing));
    }
    // The record carries the funded bond, so capacity is derivable here
    // without the terms being revealed a second time.
    check_capacity(
        &edge,
        record.penalty_amount(),
        certificate.earned_cumulative(),
    )
    .map_err(reject)?;

    let earned_digest = certificate.digest(context.network());
    let digest = crate::work::response_digest(
        context.network(),
        input,
        edge.terms(),
        record.start_id(),
        response.responder_role(),
        earned_digest,
    );
    if !verify_party(
        verifier,
        response.action(),
        response.responder_role().keys_of(edge.parties()),
        digest,
    ) {
        return Err(reject(InvalidMoveReason::BadSignature));
    }
    if !verify_party(
        verifier,
        response.certificate_auth(),
        edge.parties().maker(),
        earned_digest,
    ) {
        return Err(reject(InvalidMoveReason::BadCertificateSignature));
    }

    Ok(record.responded_at(
        certificate.earned_cumulative(),
        response.action().is_owner(),
    ))
}

/// Applies a [`PaymentCloseResponse`].
pub(super) fn apply_response<B, V>(
    response: &PaymentCloseResponse,
    context: Context,
    verifier: &V,
    batch: &B,
) -> KernelResult<Change>
where
    B: Batch,
    V: SigVerifier + ?Sized,
{
    let input = response.payment_edge();
    let reject = |reason| ApplyError::InvalidMove { input, reason };
    let advanced = check_response(response, context, verifier, batch)?;
    let chunk = advanced.to_chunk().ok_or_else(|| {
        reject(InvalidMoveReason::ClosePendingFault {
            fault: PendingCloseFault::Body,
        })
    })?;
    let diff = one_mutation(RegistryMutation::write(
        pending_payment_close_slot(context.network(), input),
        chunk,
    ))?;
    Ok(Change::private(&diff))
}

/// The close a work-payment proof is being checked against.
///
/// Carried as one value because all four parts are the same close: the
/// edge it consumes, the value conservation already pinned, and the
/// payouts that value has to land in.
#[derive(Debug, Clone, Copy)]
pub(super) struct CloseSubject<'a> {
    /// Edge being closed.
    pub(super) input: EdgeId,
    /// The live edge itself.
    pub(super) edge: &'a Edge,
    /// Value this close distributes, from the conservation check.
    pub(super) total: u64,
    /// Payouts the transaction carries.
    pub(super) outputs: &'a Payouts,
}

/// Checks a `Proof::Adjudicated` and returns the registry write it makes.
///
/// The contest is the proof. There is no signature here at all: the
/// amounts were authorized when the certificates behind them were signed,
/// and the window has closed on any further evidence.
pub(super) fn check_adjudicated<B: Batch>(
    close: CloseSubject<'_>,
    contest_commitment: PaymentContestCommitment,
    context: Context,
    batch: &B,
) -> Result<Option<RegistryMutation>, InvalidProofReason> {
    let CloseSubject {
        input,
        edge,
        total,
        outputs,
    } = close;
    let record = read_pending(batch, context, input)
        .map_err(pending_proof_fault)?
        .ok_or(InvalidProofReason::ClosePendingMissing)?;

    // Either the provider has spoken, or its window has run out. This is
    // the exact complement of the response guard: at the deadline the
    // response is refused and the close is admitted, so there is no
    // height at which both or neither is legal.
    if !record.responded() && context.block_height().get() < record.response_deadline() {
        return Err(InvalidProofReason::ResponseWindowOpen);
    }

    let provider = record
        .final_cumulative()
        .checked_add(record.penalty())
        .ok_or(InvalidProofReason::PayoutOverCapacity)?;
    // No signature here, so the contest's own actions decide the
    // delegates: an owner that started or answered it is exiting.
    check_split(
        edge.parties(),
        (total, provider),
        record.owner_signed(),
        outputs,
    )?;

    // Recomputed and byte-compared rather than verified: it names
    // the contest state this transaction expects to settle, so a close
    // racing a response pays out the state it was built for or nothing.
    if contest_commitment != record.contest_commitment(context.network(), input, edge.terms()) {
        return Err(InvalidProofReason::ContestMismatch);
    }

    Ok(Some(RegistryMutation::delete(pending_payment_close_slot(
        context.network(),
        input,
    ))))
}

/// Checks a `Proof::Freeze` and returns the registry write it makes.
pub(super) fn check_freeze<B, V>(
    close: CloseSubject<'_>,
    freeze: (u64, (u64, u64), &PartyAuth, &PartyAuth),
    context: Context,
    verifier: &V,
    batch: &B,
) -> Result<Option<RegistryMutation>, InvalidProofReason>
where
    B: Batch,
    V: SigVerifier + ?Sized,
{
    let CloseSubject {
        input,
        edge,
        total,
        outputs,
    } = close;
    let (earned, validity, maker_auth, taker_auth) = freeze;
    let height = context.block_height().get();
    // Consensus bounds the freeze window itself: the terms bound the
    // start's, and a cooperative close carries no terms to bound its own.
    // Both failures are one rejection here — a freeze reveals no policy,
    // so "outside" and "too wide" are the same statement about the same
    // consensus constant.
    check_validity_window(height, validity, MAX_FREEZE_AUTH_BLOCKS)
        .map_err(|_| InvalidProofReason::FreezeOutsideValidityWindow)?;

    // §4.6 describes this branch as carrying "the capacity check from
    // section 4.3". It does not, and deliberately: conservation is the
    // right bound for a close both parties signed. `check_split` already
    // refuses anything the edge cannot fund, and the capacity rule exists
    // to bound what *one* party can extract on the other's certificate —
    // a client that co-signs a freeze is not being charged on evidence,
    // it is agreeing. Imposing capacity here would only refuse a
    // settlement both parties chose, stranding a channel whose parties
    // had already agreed how to end it.
    //
    // The penalty branch coincides with the §4.3 bound anyway, since
    // `Adjudicated` verifies fewer proofs at the same slot count and so
    // fixes the minimum route; the no-penalty branch admits at most one
    // further bond, which no certificate could have claimed but which
    // both signatures cover.
    let pending = read_pending(batch, context, input).map_err(pending_proof_fault)?;
    let provider = match pending {
        // Exact absence is the no-contest route. Nothing that could be
        // mistaken for it reaches here: `read_pending` has already
        // refused every present-but-unreadable value.
        None => earned,
        Some(record) => {
            // A freeze may end a contest but not walk it back.
            if earned < record.final_cumulative() {
                return Err(InvalidProofReason::FreezeBelowSettled);
            }
            earned
                .checked_add(record.freeze_penalty(earned))
                .ok_or(InvalidProofReason::PayoutOverCapacity)?
        }
    };
    // An owner signing the freeze, or an owner that acted on the contest
    // it ends, is exiting the delegation: the payouts are undelegated.
    let owner_signed = maker_auth.is_owner()
        || taker_auth.is_owner()
        || pending.is_some_and(|record| record.owner_signed());
    check_split(edge.parties(), (total, provider), owner_signed, outputs)?;

    let digest =
        crate::work::freeze_digest(context.network(), input, edge.terms(), earned, validity);
    let parties = edge.parties();
    if !verify_party(verifier, maker_auth, parties.maker(), digest)
        || !verify_party(verifier, taker_auth, parties.taker(), digest)
    {
        return Err(InvalidProofReason::BadSignature);
    }

    Ok(pending
        .map(|_| RegistryMutation::delete(pending_payment_close_slot(context.network(), input))))
}

/// Loads the bond a work-payment open names and returns the registry
/// writes that lease it.
///
/// This is the open half of the bond's exclusivity rule, and it is the
/// reason a payment channel means anything: the terms a payment commits
/// name a bond and embed its complete witness, but a witness is only a
/// statement about a bond that might not exist. Without this, a client
/// signature over a payment open would be spendable by the provider
/// against a bond it never posted, closed already, or had committed to
/// some other channel — and the earned certificates settled under it
/// would have no stake behind them at all.
///
/// Non-payment profiles write nothing. The empty diff is returned rather
/// than skipped by the caller so that adding a profile is a decision
/// here rather than a silent omission there.
pub(super) fn open_bond_lease<B: Batch>(
    output: EdgeId,
    terms: &Terms,
    context: Context,
    batch: &B,
) -> KernelResult<RegistryDiff> {
    let TermsProfile::WorkPayment(payment) = terms.profile() else {
        return Ok(RegistryDiff::empty());
    };
    let reject = |reason| ApplyError::InvalidOpen { output, reason };

    // The bond has to be live *now*, in this block. A bond that has not
    // landed yet and a bond that has already been closed are the same
    // absent edge, and both are reported as the missing object they
    // are: an open whose bond arrives in a later block is early, not
    // wrong, and the host distinguishes those two for its mempool.
    let bond = batch
        .edge(payment.bond_edge)
        .ok_or(ApplyError::MissingEdge {
            id: payment.bond_edge,
        })?;
    // The embedded witness is the bond's own canonical `Terms` bytes,
    // so this single comparison decides everything the payment claims
    // about the bond: its profile, its stake and award, its horizon,
    // and its two parties. §2.1's mirrored-parties requirement is
    // enforced by `check_work_payment_terms` against that witness and
    // reaches the live edge through this equality — an edge carries the
    // parties of the terms that opened it, so a second comparison here
    // could not fail without a hash collision.
    if bond.terms() != payment.bond_terms_hash() {
        return Err(reject(InvalidOpenReason::WorkBondTermsMismatch));
    }
    // §2.1 also requires the open height to be strictly below the
    // admission horizon. It is not rechecked here: a payment's
    // `Terms::timeout()` *is* its admission horizon, and
    // `open_lifetime_fee` has already refused every open whose horizon
    // is not strictly in the future. A copy of that rule at this site
    // would be a branch no input could reach.
    if read_bond_lease(batch, context.network(), payment.bond_edge)
        .map_err(|fault| reject(InvalidOpenReason::WorkBondLeaseFault { fault }))?
        .is_some()
    {
        return Err(reject(InvalidOpenReason::WorkBondAlreadyLeased));
    }

    let lease = BondLease::opened(
        payment.bond_edge,
        output,
        terms.hash(),
        payment.private_policy_commitment,
        payment.admission_horizon().get(),
    );
    // `None` is unreachable for this fixed-width record; it is a
    // rejection rather than a panic because this runs on the apply path.
    let mutations = create_lease(context.network(), lease).ok_or_else(|| {
        reject(InvalidOpenReason::WorkBondLeaseFault {
            fault: BondLeaseFault::Body,
        })
    })?;
    let mut diff = RegistryDiff::empty();
    for mutation in mutations {
        diff.push(mutation)
            .map_err(|reason| ApplyError::RegistryDiffRejected { reason })?;
    }
    Ok(diff)
}

/// Rules a work-payment open adds once its edge exists.
///
/// The capacity arithmetic needs the locked value, so it cannot run
/// beside the rest of the terms checks: it runs here, against the edge
/// the open is about to produce.
pub(super) fn check_payment_capacity(
    edge: &Edge,
    payment: &WorkPaymentTerms,
) -> Result<(), InvalidOpenReason> {
    // Both exits have to be affordable from one reserve. An edge that
    // could take only the cheaper one would be a channel whose
    // cooperative close its own parties could not sign.
    let route = close_route_minimum(edge).ok_or(InvalidOpenReason::WorkPaymentReserveTooSmall)?;
    // A bond at or above everything the close distributes leaves no
    // capacity at all: no certificate could ever be admitted, so the
    // channel would be a channel in name only.
    let capacity = route
        .checked_sub(payment.omission_bond)
        .ok_or(InvalidOpenReason::WorkPaymentCapacityUnfunded)?;
    if capacity == 0 {
        return Err(InvalidOpenReason::WorkPaymentCapacityUnfunded);
    }
    Ok(())
}

// ── Shared checks ─────────────────────────────────────────────────────

fn read_pending<B: Batch>(
    batch: &B,
    context: Context,
    input: EdgeId,
) -> Result<Option<PendingPaymentClose>, PendingCloseFault> {
    read_pending_close(batch, context.network(), input)
}

const fn pending_proof_fault(fault: PendingCloseFault) -> InvalidProofReason {
    InvalidProofReason::ClosePendingFault { fault }
}

const fn pending_move_fault(fault: PendingCloseFault) -> InvalidMoveReason {
    InvalidMoveReason::ClosePendingFault { fault }
}

const fn move_window_fault(fault: WindowFault) -> InvalidMoveReason {
    match fault {
        WindowFault::Outside => InvalidMoveReason::OutsideValidityWindow,
        WindowFault::TooWide => InvalidMoveReason::ValiditySpanTooWide,
    }
}

/// The inclusion height must lie inside the signed window, and that
/// window must be no wider than `max_span` blocks.
///
/// Inclusive at both ends, so the span of a single-block window is one.
/// The width bound is what stops a signature from staying spendable
/// indefinitely; the containment check is what stops it from being
/// spent outside the interval its signer agreed to.
const fn check_validity_window(
    height: u64,
    validity: (u64, u64),
    max_span: u64,
) -> Result<(), WindowFault> {
    let (from, through) = validity;
    if height < from || height > through {
        return Err(WindowFault::Outside);
    }
    // Containment already implies `from <= through`, so the subtraction
    // cannot underflow; the addition is checked because a window through
    // `u64::MAX` would otherwise wrap its own width to zero.
    let Some(gap) = through.checked_sub(from) else {
        return Err(WindowFault::TooWide);
    };
    let Some(span) = gap.checked_add(1) else {
        return Err(WindowFault::TooWide);
    };
    if span > max_span {
        return Err(WindowFault::TooWide);
    }
    Ok(())
}

/// A certificate is evidence about one channel, so it has to name the
/// one it is being spent on.
///
/// Both fields also enter the signed digest, but the kernel builds that
/// digest from the *edge*: without this check a certificate for another
/// channel would simply produce a digest nobody signed, which rejects
/// for the wrong reason and reads as a signature failure.
fn check_certificate(
    certificate: &EarnedCertificate,
    input: EdgeId,
    terms: TermsHash,
) -> Result<(), InvalidMoveReason> {
    if certificate.payment_edge() == input && certificate.payment_terms_hash() == terms {
        Ok(())
    } else {
        Err(InvalidMoveReason::CertificateNotBound)
    }
}

fn check_capacity(edge: &Edge, omission_bond: u64, amount: u64) -> Result<(), InvalidMoveReason> {
    let capacity =
        payment_capacity(edge, omission_bond).ok_or(InvalidMoveReason::ReserveTooSmall)?;
    if amount > capacity {
        return Err(InvalidMoveReason::CertificateOverCapacity);
    }
    Ok(())
}

/// A work-payment close pays exactly two coins, provider first, each at
/// its party's committed destination.
///
/// The shape is fixed rather than carried because the cost is: the open
/// reserved four slots for two payouts, so a close with a different
/// fanout would be a close the edge did not pay for. `total` comes from
/// the conservation check that already ran, so the client's share is a
/// subtraction and not a second opinion.
fn check_split(
    parties: Parties,
    amounts: (u64, u64),
    owner_signed: bool,
    outputs: &Payouts,
) -> Result<(), InvalidProofReason> {
    let (total, provider_total) = amounts;
    let expected = split_payouts(parties, total, provider_total, owner_signed)?;
    if outputs.as_slice() == expected.as_slice() {
        Ok(())
    } else {
        Err(InvalidProofReason::PayoutMismatch)
    }
}

fn one_mutation(mutation: RegistryMutation) -> KernelResult<RegistryDiff> {
    let mut diff = RegistryDiff::empty();
    diff.push(mutation)
        .map_err(|reason| ApplyError::RegistryDiffRejected { reason })?;
    Ok(diff)
}
