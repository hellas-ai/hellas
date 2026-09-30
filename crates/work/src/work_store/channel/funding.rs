//! Funding types bind a job's authorization, clock and terminal obligations.

use super::{PaymentState, TerminalOutcome};
use hellas_kernel::Sig;
use hellas_rpc::protocol::work::{CreditLedger, PaidJobAuthorizationV2, PaidJobResultV1};
use std::fmt::{self, Debug};

mod sealed {
    pub trait Funding {}
    pub trait Authorization {}
    pub trait Clock {}
}

/// A clock value whose unit cannot be confused with another funding clock.
pub trait Clock: sealed::Clock + Copy + Debug + Eq + Ord {
    /// Unit displayed in diagnostics, fixed by this sealed clock type.
    const UNIT: &'static str;
    /// Scalar value for diagnostics, never for choosing another clock's deadline.
    fn value(self) -> u64;
    /// A diagnostic reading retaining this clock's unit.
    fn diagnostic(self) -> ClockReading {
        ClockReading {
            value: self.value(),
            unit: Self::UNIT,
        }
    }
}

/// A diagnostic reading constructed only from a typed funding clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockReading {
    value: u64,
    unit: &'static str,
}
impl fmt::Display for ClockReading {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.unit, self.value)
    }
}

/// A finalized block height, distinct from wall-clock milliseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FinalizedHeight(pub u64);
impl sealed::Clock for FinalizedHeight {}
impl Clock for FinalizedHeight {
    const UNIT: &'static str = "finalized height";
    fn value(self) -> u64 {
        self.0
    }
}

/// The lifecycle fields common to signed job authorizations.
pub trait JobAuthorization: sealed::Authorization + Clone + Debug + Eq {
    /// Deadline unit fixed by the funding model.
    type Clock: Clock;
    /// Monotone proposal sequence within its channel.
    fn proposal_nonce(&self) -> u64;
    /// Last instant at which a provider may accept new work.
    fn acceptance_deadline(&self) -> Self::Clock;
    /// Last instant at which a terminal result is owed.
    fn terminal_deadline(&self) -> Self::Clock;
}
impl sealed::Authorization for PaidJobAuthorizationV2 {}
impl JobAuthorization for PaidJobAuthorizationV2 {
    type Clock = FinalizedHeight;
    fn proposal_nonce(&self) -> u64 {
        self.proposal_nonce
    }
    fn acceptance_deadline(&self) -> FinalizedHeight {
        FinalizedHeight(self.acceptance_deadline)
    }
    fn terminal_deadline(&self) -> FinalizedHeight {
        FinalizedHeight(self.terminal_deadline)
    }
}

/// A terminal is funding-specific; a paid certificate is not a grant settlement.
pub trait JobOutcome: Clone + Debug + Eq {
    /// Stable diagnostic spelling, without payload or payment details.
    fn name(&self) -> &'static str;
}
impl JobOutcome for TerminalOutcome {
    fn name(&self) -> &'static str {
        self.name()
    }
}

/// Closed set of funding models, with obligations fixed by the funding type.
pub trait Funding: sealed::Funding + Copy + Debug + Eq {
    /// Signed proposal carrying this funding model's authority.
    type Authorization: JobAuthorization<Clock = Self::Clock>;
    /// Deadline unit associated with the authorization.
    type Clock: Clock;
    /// Funding-specific channel identity, observation and close state.
    type State: Clone + Debug + Eq;
    /// Funding-specific credit or reservation ledger.
    type Ledger: Clone + Debug + Eq;
    /// Canonical result bound to the accepted work.
    type Result: Clone + Debug + Eq;
    /// Signature evidence retained at each durable boundary.
    type Signature: Copy + Debug + Eq;
    /// Terminal obligations discharged by this funding model.
    type Terminal: JobOutcome;
}

/// Uninhabited marker for channels insured and settled by payment edges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentFunding {}
impl sealed::Funding for PaymentFunding {}
impl Funding for PaymentFunding {
    type Authorization = PaidJobAuthorizationV2;
    type Clock = FinalizedHeight;
    type State = PaymentState;
    type Ledger = CreditLedger;
    type Result = PaidJobResultV1;
    type Signature = Sig;
    type Terminal = TerminalOutcome;
}
