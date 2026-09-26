//! Paid-channel configuration and readiness checks.
//!
//! [`WorkChannelDescriptor::check_ready`] checks the configured terms against
//! live edges, their parties, the bond lease, contest state, collateral, and
//! admission horizon. Terms are hashed locally and compared with on-chain
//! commitments; a terms hash alone does not describe the channel.
//!
//! The caller must authenticate one coherent finalized [`ObservedChannel`]
//! snapshot. Readiness neither authorizes a particular job signature (see
//! [`ReadyChannel::check_signable`]) nor establishes computation correctness.
//! [`check_collateral`] checks the payment-omission bond, not fraud insurance.

use hellas_kernel::{
    BlockHeight, Decode, DecodeError, Edge, EdgeId, EdgeValues, Encode, Fees, LeaseSlots,
    MAX_START_VALIDITY_BLOCKS, NetworkId, PendingSlot, Terms, TermsHash, TermsProfile,
    WorkPaymentSettlement, WorkPaymentTerms, work_payment_settlement,
};

use crate::protocol::work::{
    PaidChannel, PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidWorkError, PrivateRecord,
};
use crate::protocol::work_profile::PaidWorkPolicy;

/// Why a configured channel is not one this endpoint may work over.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WorkSetupError {
    /// A record, policy, or price rule of the private protocol failed.
    #[error(transparent)]
    Record(#[from] PaidWorkError),
    /// An object the channel is made of was not present at the
    /// finalized block that was read.
    #[error("{object} is not live at the finalized state that was read")]
    NotLive {
        /// Which object was missing.
        object: &'static str,
    },
    /// A live object does not commit to the configured terms.
    #[error("{object} commits to other terms than the ones configured for this channel")]
    TermsMismatch {
        /// Which object disagreed.
        object: &'static str,
    },
    /// A live edge names other parties than its terms fix.
    #[error("{object} names other parties than its terms fix")]
    PartiesMismatch {
        /// Which object disagreed.
        object: &'static str,
    },
    /// The bond is not leased to this channel.
    #[error("the bond's lease is {found}, not this channel's lease")]
    Lease {
        /// What the lease slots held.
        found: LeaseState,
    },
    /// A contest is open, or the slot that would say so is unreadable.
    /// Either way the channel admits no new work.
    #[error("the payment edge's pending-close slot is {found}, so no new work is admitted")]
    PendingClose {
        /// What the pending slot held.
        found: PendingState,
    },
    /// The payment edge's reserve does not price both of its exits, so
    /// nothing it could settle is bounded.
    #[error("the payment edge's reserve does not price both of its close routes")]
    Unsettleable,
    /// The omission bond does not exceed the capacity it insures, so
    /// omitting a response could pay more than it forfeits.
    #[error(
        "omission bond {bond} does not exceed the payment capacity {capacity}, \
         so omitting a response could pay"
    )]
    Undercollateralised {
        /// Bond the payment terms fund.
        bond: u64,
        /// Largest cumulative amount a certificate on this channel may name.
        capacity: u64,
    },
    /// The finalized height is at or past the admission horizon.
    #[error("finalized height {height} is at or past the admission horizon {horizon}")]
    HorizonPassed {
        /// Finalized height the refusal is anchored at: the height the
        /// snapshot was read at, or the height a signature is being
        /// asked for at.
        height: u64,
        /// Height at and after which no work is admitted.
        horizon: u64,
    },
    /// The endpoint's finalized cursor has not reached the snapshot the
    /// decision is being made from.
    #[error("cursor is at height {cursor}, behind the snapshot at {height}")]
    CursorBehind {
        /// Height the endpoint has processed blocks through.
        cursor: u64,
        /// Height the snapshot was read at.
        height: u64,
    },
    /// The deadlines a job would carry do not fit the margins the
    /// policy measured.
    #[error(
        "height {height} plus dispatch {dispatch} and delivery {delivery} margins \
         exceeds the terminal deadline {terminal}"
    )]
    TerminalUnreachable {
        /// Finalized height the job would be signed at.
        height: u64,
        /// Blocks the policy allows to dispatch.
        dispatch: u64,
        /// Blocks the policy allows to deliver.
        delivery: u64,
        /// Deadline the authorization carries.
        terminal: u64,
    },
    /// The measured delivery margin no longer fits before the terminal
    /// deadline, so plaintext released now would not arrive in time.
    #[error(
        "height {height} plus the delivery margin {delivery} exceeds \
         the terminal deadline {terminal}"
    )]
    DeliveryUnreachable {
        /// Finalized height the release would begin at.
        height: u64,
        /// Blocks the policy allows to deliver.
        delivery: u64,
        /// Deadline the authorization carries.
        terminal: u64,
    },
    /// The gap between terminal and payment deadlines is under the
    /// oracle grace the policy measured.
    #[error(
        "terminal {terminal} to payment {payment} leaves {actual} blocks, \
         under the measured oracle grace {grace}"
    )]
    OracleGraceTooShort {
        /// Deadline a terminal result is owed by.
        terminal: u64,
        /// Deadline payment is owed by.
        payment: u64,
        /// Blocks the two deadlines actually leave.
        actual: u64,
        /// Blocks the policy measured as necessary.
        grace: u64,
    },
    /// A persisted close descriptor was not its one canonical encoding.
    #[error("the close descriptor is not canonical")]
    DescriptorMalformed,
    /// The signed terms do not carry the fixed start span this profile
    /// admits.
    #[error("the terms' start span is {span} blocks, not the fixed {fixed}")]
    StartSpanNotFixed {
        /// `start_validity_blocks`, as the signed terms fix it.
        span: u64,
        /// [`MAX_START_VALIDITY_BLOCKS`], the profile's fixed span.
        fixed: u64,
    },
    /// The proposed terms give the watcher fewer blocks to answer a
    /// contest in than this provider is configured to accept.
    #[error("the terms admit {window} blocks to answer a contest, under the configured {minimum}")]
    ResponseWindowBelowMinimum {
        /// `omit_response_blocks`, as the terms fix it.
        window: u64,
        /// The provider's configured minimum.
        minimum: u64,
    },
}

/// What the bond's two lease slots held, without the record itself.
///
/// The lease body is not carried into the error: what a refusal needs to
/// say is which of the three answers came back, and a `Faulty` lease has
/// no body to report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseState {
    /// Both slots were empty.
    Absent,
    /// A readable lease, over another payment channel.
    AnotherChannel,
    /// The slots held something that is not a whole lease.
    Faulty,
}

impl core::fmt::Display for LeaseState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Absent => "absent",
            Self::AnotherChannel => "held by another payment channel",
            Self::Faulty => "not a readable lease",
        })
    }
}

/// What the payment edge's pending-close slot held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingState {
    /// A readable live contest.
    Live,
    /// Something that is not this edge's readable record.
    Faulty,
}

impl core::fmt::Display for PendingState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Live => "a live contest",
            Self::Faulty => "not a readable record",
        })
    }
}

/// What an operator configured for one paid channel, before anything
/// has been checked.
///
/// A plain record with public fields: this is the shape a CLI or a
/// config file fills in. It is also why [`WorkChannelDescriptor::open`]
/// takes one argument — nine positional arguments, four of them `u64`,
/// is a signature whose mistakes compile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkChannelConfig {
    /// The network every signature on this channel is bound to.
    pub network: NetworkId,
    /// The tag-2 payment edge work is paid from.
    pub payment_edge: EdgeId,
    /// The complete payment terms, which embed the complete bond.
    pub payment_terms: WorkPaymentTerms,
    /// Salt of the private credit-policy commitment.
    pub policy_salt: [u8; 32],
    /// The credit policy those terms commit to.
    pub channel_policy: PaidChannelPolicyV1,
    /// The execution policy in force on this channel.
    pub execution_policy: PaidWorkPolicy,
    /// The payment edge's value, reserve, and close fees as the
    /// operator expects them to be funded.
    pub expected_payment_values: EdgeValues,
}

/// Everything a provider fixes about a channel before a client names the
/// two things it does not.
///
/// A [`WorkChannelConfig`] is this plus the client's own two choices —
/// the payment terms and the edge they derive — which is exactly the
/// split the handshake has: the provider proposes a bond, and the client
/// answers by naming the channel it wants over it. Holding the
/// provider's half as its own value is what lets
/// [`Self::admit`] run the same gates on proposed terms that
/// [`WorkChannelDescriptor::open`] runs on configured ones, before the
/// countersignature that makes those terms executable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderChannelPolicy {
    /// The network every signature on this channel is bound to.
    pub network: NetworkId,
    /// Salt of the private credit-policy commitment.
    pub policy_salt: [u8; 32],
    /// The credit policy this provider will work under.
    pub channel_policy: PaidChannelPolicyV1,
    /// The execution policy this provider will run jobs under.
    pub execution_policy: PaidWorkPolicy,
    /// The payment edge's value, reserve, and close fees as the provider
    /// requires them to be funded.
    pub expected_payment_values: EdgeValues,
    /// The shortest response window this provider will sign terms over.
    ///
    /// Here and not in [`WorkChannelConfig`] because it is a statement
    /// about the *node*, not about the channel: how many blocks this
    /// deployment needs to notice a contest and answer it is the
    /// operator's to say, and the same number governs every channel this
    /// provider admits. The kernel enforces its own floor,
    /// [`MIN_OMIT_RESPONSE_BLOCKS`], at every payment open; this is the
    /// provider's, and it is checked at admission.
    ///
    /// [`MIN_OMIT_RESPONSE_BLOCKS`]: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS
    pub min_omit_response_blocks: u64,
}

impl ProviderChannelPolicy {
    /// Builds the close-only descriptor a client must arm before exporting
    /// revision 2.
    ///
    /// This checks the committed policy body, execution-policy shape, and
    /// expected settleability because recovery needs those values to be
    /// coherent. It deliberately does not run omission economics: those are
    /// the provider's new-work admission judgement, made before revision 3,
    /// and a client must retain recovery data even when the provider later
    /// refuses its proposed terms.
    pub fn describe_close(
        &self,
        payment_edge: EdgeId,
        payment_terms: WorkPaymentTerms,
    ) -> Result<CloseDescriptor, WorkSetupError> {
        let bond_edge = payment_terms.bond_edge;
        let channel = PaidChannel::new(
            self.network,
            payment_edge,
            payment_terms,
            &self.policy_salt,
            self.channel_policy,
        )?;
        self.execution_policy.check()?;
        if work_payment_settlement(
            self.expected_payment_values,
            channel.payment_terms().omission_bond,
        )
        .is_none()
        {
            return Err(WorkSetupError::Unsettleable);
        }
        Ok(CloseDescriptor {
            channel,
            bond_edge,
            policy_salt: self.policy_salt,
            execution_policy: self.execution_policy.clone(),
            expected_payment_values: self.expected_payment_values,
        })
    }

    /// Opens the descriptor for terms a client has proposed, or says why
    /// this provider will not work over them.
    ///
    /// Every gate is [`WorkChannelDescriptor::open`]'s, reached by
    /// filling in the two fields the client chose and the six this
    /// provider fixed. In particular `private_policy_commitment` stops
    /// being the client's free choice here: [`PaidChannel::new`] opens it
    /// against *this* provider's salt and credit policy, so terms
    /// committing to any other policy are refused rather than signed.
    ///
    /// Two of the terms are the provider's judgement about its own
    /// deployment and are checked here and nowhere below: the signed
    /// `start_validity_blocks` must be exactly the profile's fixed 64,
    /// and the proposed `omit_response_blocks` must reach the configured
    /// [`Self::min_omit_response_blocks`].
    ///
    /// # Errors
    ///
    /// [`WorkSetupError::StartSpanNotFixed`] when the signed terms do
    /// not carry the fixed span, [`WorkSetupError::ResponseWindowBelowMinimum`]
    /// when the terms leave less time to answer than this provider
    /// accepts, and then whatever [`WorkChannelDescriptor::open`] raises:
    /// the commitment, the execution policy, the settleability of the
    /// expected funding, and the collateral rule.
    pub fn admit(
        &self,
        payment_edge: EdgeId,
        payment_terms: WorkPaymentTerms,
    ) -> Result<WorkChannelDescriptor, WorkSetupError> {
        // The kernel supplies only an upper bound. This profile fixes the
        // span at that bound, so a smaller value is a different term from
        // the one the profile offers, not a tighter one.
        if payment_terms.start_validity_blocks != MAX_START_VALIDITY_BLOCKS {
            return Err(WorkSetupError::StartSpanNotFixed {
                span: payment_terms.start_validity_blocks,
                fixed: MAX_START_VALIDITY_BLOCKS,
            });
        }
        if payment_terms.omit_response_blocks < self.min_omit_response_blocks {
            return Err(WorkSetupError::ResponseWindowBelowMinimum {
                window: payment_terms.omit_response_blocks,
                minimum: self.min_omit_response_blocks,
            });
        }
        WorkChannelDescriptor::open(WorkChannelConfig {
            network: self.network,
            payment_edge,
            payment_terms,
            policy_salt: self.policy_salt,
            channel_policy: self.channel_policy,
            execution_policy: self.execution_policy.clone(),
            expected_payment_values: self.expected_payment_values,
        })
    }
}

/// A configured channel whose static gates have passed.
///
/// Constructed only through [`Self::open`], which is where the policy
/// commitment is opened and those gates run. A descriptor in hand is
/// therefore a channel whose policy body matches its terms and whose
/// bond covers the capacity it insures — none of which says anything
/// yet about what is on chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkChannelDescriptor {
    channel: PaidChannel,
    bond_edge: EdgeId,
    bond_terms_hash: TermsHash,
    policy_salt: [u8; 32],
    execution_policy: PaidWorkPolicy,
    expected_payment_values: EdgeValues,
}

impl WorkChannelDescriptor {
    /// Opens a configured channel: checks its policy commitment, its
    /// execution policy, and that its bond covers its capacity.
    ///
    /// The bond edge and its terms hash are read out of the payment
    /// terms rather than configured separately, for the same reason
    /// [`PaidChannel::new`] reads them there: the payment body already
    /// embeds the complete bond, so a separately configured bond could
    /// only ever be the wrong one.
    ///
    /// The capacity the omission inequality is checked against here is
    /// the *configured* capacity, derived from the edge values the
    /// operator expects. It is checked again against the finalized edge
    /// in [`Self::check_ready`], because a configured expectation is not
    /// a funded edge.
    ///
    /// # Errors
    ///
    /// [`WorkSetupError::Record`] when the policy commitment or the
    /// execution policy is refused, [`WorkSetupError::Unsettleable`]
    /// when the expected edge values do not price both close routes, and
    /// [`WorkSetupError::Undercollateralised`] when the bond does not
    /// exceed the capacity it insures.
    pub fn open(config: WorkChannelConfig) -> Result<Self, WorkSetupError> {
        let bond_edge = config.payment_terms.bond_edge;
        let bond_terms_hash = config.payment_terms.bond_terms_hash();
        let omission_bond = config.payment_terms.omission_bond;
        let channel = PaidChannel::new(
            config.network,
            config.payment_edge,
            config.payment_terms,
            &config.policy_salt,
            config.channel_policy,
        )?;
        config.execution_policy.check()?;

        let settlement = work_payment_settlement(config.expected_payment_values, omission_bond)
            .ok_or(WorkSetupError::Unsettleable)?;
        check_collateral(omission_bond, settlement.capacity())?;

        Ok(Self {
            channel,
            bond_edge,
            bond_terms_hash,
            policy_salt: config.policy_salt,
            execution_policy: config.execution_policy,
            expected_payment_values: config.expected_payment_values,
        })
    }

    /// Returns the channel these records are bound to.
    pub const fn channel(&self) -> &PaidChannel {
        &self.channel
    }

    /// Returns the bond edge insuring this channel.
    pub const fn bond_edge(&self) -> EdgeId {
        self.bond_edge
    }

    /// Returns the execution policy in force on this channel.
    pub const fn execution_policy(&self) -> &PaidWorkPolicy {
        &self.execution_policy
    }

    /// Returns the height at and after which the channel admits no work.
    pub const fn admission_horizon(&self) -> BlockHeight {
        self.channel.payment_terms().admission_horizon()
    }

    /// Returns the self-contained descriptor recovery needs after an
    /// executable setup revision has escaped this process.
    #[must_use]
    pub fn close_descriptor(&self) -> CloseDescriptor {
        CloseDescriptor {
            channel: self.channel.clone(),
            bond_edge: self.bond_edge,
            policy_salt: self.policy_salt,
            execution_policy: self.execution_policy.clone(),
            expected_payment_values: self.expected_payment_values,
        }
    }

    /// Decides whether this configured channel is the channel on chain.
    ///
    /// Every check is against the one read it is handed, and every one
    /// of them can refuse: a live payment edge whose bond is gone is not
    /// a channel, a live pair under other terms is not this channel, and
    /// a live pair with an open contest is a channel that admits no new
    /// work even though both edges are perfectly healthy.
    ///
    /// Whether that read is *coherent* is not established here and
    /// cannot be: five fields assembled from five point queries satisfy
    /// [`ObservedChannel`] exactly as well as one database snapshot
    /// does, and the difference is the caller's to owe.
    ///
    /// # Errors
    ///
    /// One [`WorkSetupError`] naming the first fact that failed.
    pub fn check_ready(
        &self,
        observed: &ObservedChannel<'_>,
    ) -> Result<ReadyChannel, WorkSetupError> {
        let terms = self.channel.payment_terms();

        let bond = observed.bond.ok_or(WorkSetupError::NotLive {
            object: "the bond edge",
        })?;
        let payment = observed.payment.ok_or(WorkSetupError::NotLive {
            object: "the payment edge",
        })?;

        // The terms body is what says who the parties are and what the
        // bond covers, and the edge carries only a hash of it. Locally
        // hashing the configured body is the only thing that makes the
        // rest of these checks about this channel.
        if bond.terms() != self.bond_terms_hash {
            return Err(WorkSetupError::TermsMismatch {
                object: "the bond edge",
            });
        }
        if payment.terms() != self.channel.payment_terms_hash() {
            return Err(WorkSetupError::TermsMismatch {
                object: "the payment edge",
            });
        }
        // The kernel fixes both pairings at open, so a disagreement here
        // is a hash collision or a wrongly assembled snapshot rather
        // than a channel in an unexpected state. It is checked because a
        // wrongly assembled snapshot is the reachable one: these two
        // edges arrive as two `Option`s of the same type.
        if bond.parties() != terms.bond_terms.parties {
            return Err(WorkSetupError::PartiesMismatch {
                object: "the bond edge",
            });
        }
        if payment.parties() != terms.parties() {
            return Err(WorkSetupError::PartiesMismatch {
                object: "the payment edge",
            });
        }

        match observed.lease {
            LeaseSlots::Present(lease) if lease.payment_edge() == self.channel.payment_edge() => {}
            LeaseSlots::Present(_) => {
                return Err(WorkSetupError::Lease {
                    found: LeaseState::AnotherChannel,
                });
            }
            LeaseSlots::Absent => {
                return Err(WorkSetupError::Lease {
                    found: LeaseState::Absent,
                });
            }
            LeaseSlots::Faulty(_) => {
                return Err(WorkSetupError::Lease {
                    found: LeaseState::Faulty,
                });
            }
        }

        match observed.pending {
            PendingSlot::Absent => {}
            PendingSlot::Present(_) => {
                return Err(WorkSetupError::PendingClose {
                    found: PendingState::Live,
                });
            }
            PendingSlot::Faulty(_) => {
                return Err(WorkSetupError::PendingClose {
                    found: PendingState::Faulty,
                });
            }
        }

        // The capacity every later amount is bounded by, taken from the
        // edge that will pay rather than from the operator's
        // expectation. The collateral rule is re-checked against it for
        // the same reason: a channel funded above what was configured
        // has more to steal than the bond that was approved insures.
        let settlement = work_payment_settlement(payment.values(), terms.omission_bond)
            .ok_or(WorkSetupError::Unsettleable)?;
        check_collateral(terms.omission_bond, settlement.capacity())?;

        let horizon = terms.admission_horizon().get();
        if observed.height >= horizon {
            return Err(WorkSetupError::HorizonPassed {
                height: observed.height,
                horizon,
            });
        }

        Ok(ReadyChannel {
            channel: self.channel.clone(),
            execution_policy: self.execution_policy.clone(),
            settlement,
            finalized_height: observed.height,
            admission_horizon: horizon,
        })
    }
}

/// Everything close-only recovery cannot reconstruct after configuration
/// loss.
///
/// The complete payment terms inside [`PaidChannel`] also carry the complete
/// bond terms and the private-policy commitment.  The opened policy body and
/// its salt travel beside them, as do the execution policy and expected
/// payment funding.  The latter has one interpretation, exposed by
/// [`Self::expected_settlement`].
///
/// The provider's revision-3 value comes from a [`WorkChannelDescriptor`]
/// whose new-work admission gates passed. The client's revision-2 value is
/// armed earlier, after its policy commitment, execution-policy shape, and
/// expected settleability have been checked but before the provider decides
/// omission economics. Funded recovery deliberately does not run those gates
/// again: [`Self::funded_settlement`] checks the coherent payment edge and
/// derives the settlement consensus will use directly from that edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseDescriptor {
    channel: PaidChannel,
    bond_edge: EdgeId,
    policy_salt: [u8; 32],
    execution_policy: PaidWorkPolicy,
    expected_payment_values: EdgeValues,
}

/// First byte of the close descriptor stored in an armed setup record.
const CLOSE_DESCRIPTOR_VERSION: u8 = 1;
/// Version 2 length-prefixes the execution policy so the Fetch profile can
/// extend it; v1 is the fixed-size Evaluate policy exactly.
const CLOSE_DESCRIPTOR_VERSION_V2: u8 = 2;

impl CloseDescriptor {
    /// Returns the payment channel, including both complete terms bodies and
    /// the opened private credit-policy body.
    #[must_use]
    pub const fn channel(&self) -> &PaidChannel {
        &self.channel
    }

    /// Returns the bond edge the payment terms insure through.
    #[must_use]
    pub const fn bond_edge(&self) -> EdgeId {
        self.bond_edge
    }

    /// Returns the execution policy the armed endpoint accepted.
    #[must_use]
    pub const fn execution_policy(&self) -> &PaidWorkPolicy {
        &self.execution_policy
    }

    /// Returns what the provider expected the configured payment funding to
    /// settle when it admitted the setup.
    pub fn expected_settlement(&self) -> Result<WorkPaymentSettlement, WorkSetupError> {
        work_payment_settlement(
            self.expected_payment_values,
            self.channel.payment_terms().omission_bond,
        )
        .ok_or(WorkSetupError::Unsettleable)
    }

    /// Derives the actual close settlement from one funded payment edge.
    ///
    /// This is the recovery path.  It checks only that the coherent edge is
    /// this descriptor's edge under these terms and parties, then runs the
    /// kernel's settlement arithmetic over the edge values.  It does not
    /// rerun policy commitment, execution-envelope, horizon, or omission
    /// admission gates: those decide new work, not whether already-exported
    /// Opens must be closed.
    pub fn funded_settlement(
        &self,
        payment: &Edge,
    ) -> Result<WorkPaymentSettlement, WorkSetupError> {
        if payment.terms() != self.channel.payment_terms_hash() {
            return Err(WorkSetupError::TermsMismatch {
                object: "the armed payment edge",
            });
        }
        if payment.parties() != self.channel.payment_terms().parties() {
            return Err(WorkSetupError::PartiesMismatch {
                object: "the armed payment edge",
            });
        }
        work_payment_settlement(payment.values(), self.channel.payment_terms().omission_bond)
            .ok_or(WorkSetupError::Unsettleable)
    }

    /// Returns the descriptor's canonical journal bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let version = if matches!(self.execution_policy, PaidWorkPolicy::Evaluate(_)) {
            CLOSE_DESCRIPTOR_VERSION
        } else {
            CLOSE_DESCRIPTOR_VERSION_V2
        };
        let mut out = vec![version];
        push_kernel(&mut out, &self.channel.network());
        push_kernel(&mut out, &self.channel.payment_edge());
        push_kernel(
            &mut out,
            &Terms::work_payment(self.channel.payment_terms().clone()),
        );
        out.extend_from_slice(&self.policy_salt);
        out.extend_from_slice(&self.channel.channel_policy().encode());
        let policy_bytes = self.execution_policy.encode();
        if version == CLOSE_DESCRIPTOR_VERSION_V2 {
            out.extend_from_slice(&(policy_bytes.len() as u64).to_be_bytes());
        }
        out.extend_from_slice(&policy_bytes);
        out.extend_from_slice(&self.expected_payment_values.value().to_be_bytes());
        out.extend_from_slice(&self.expected_payment_values.reserve().to_be_bytes());
        push_kernel(&mut out, &self.expected_payment_values.close_fees());
        out
    }

    /// Reads one descriptor from exactly its canonical journal bytes.
    ///
    /// The policy commitment and execution policy are checked while the
    /// value is rebuilt.  Omission economics and readiness are intentionally
    /// absent: they are new-work decisions and funded recovery must not
    /// rerun them.
    pub fn decode(bytes: &[u8]) -> Result<Self, WorkSetupError> {
        let mut cursor = CloseCursor { bytes };
        let version = cursor.byte()?;
        if version != CLOSE_DESCRIPTOR_VERSION && version != CLOSE_DESCRIPTOR_VERSION_V2 {
            return Err(WorkSetupError::DescriptorMalformed);
        }
        let network = cursor.network()?;
        let payment_edge: EdgeId = cursor.field()?;
        let payment_terms = match cursor.field::<Terms>()?.profile() {
            TermsProfile::WorkPayment(terms) => terms.clone(),
            _ => return Err(WorkSetupError::DescriptorMalformed),
        };
        let policy_salt = cursor.array::<32>()?;
        let channel_policy =
            PaidChannelPolicyV1::decode(cursor.take(PaidChannelPolicyV1::ENCODED_SIZE)?)
                .map_err(|_| WorkSetupError::DescriptorMalformed)?;
        let policy_len = if version == CLOSE_DESCRIPTOR_VERSION {
            PaidExecutionPolicyV1::ENCODED_SIZE
        } else {
            usize::try_from(cursor.u64()?).map_err(|_| WorkSetupError::DescriptorMalformed)?
        };
        let execution_policy = PaidWorkPolicy::decode(cursor.take(policy_len)?)
            .map_err(|_| WorkSetupError::DescriptorMalformed)?;
        if (version == CLOSE_DESCRIPTOR_VERSION)
            != matches!(execution_policy, PaidWorkPolicy::Evaluate(_))
        {
            return Err(WorkSetupError::DescriptorMalformed);
        }
        let expected_payment_values =
            EdgeValues::new(cursor.u64()?, cursor.u64()?, cursor.field::<Fees>()?);
        if !cursor.bytes.is_empty() {
            return Err(WorkSetupError::DescriptorMalformed);
        }

        let channel = PaidChannel::new(
            network,
            payment_edge,
            payment_terms,
            &policy_salt,
            channel_policy,
        )?;
        execution_policy.check()?;
        if work_payment_settlement(
            expected_payment_values,
            channel.payment_terms().omission_bond,
        )
        .is_none()
        {
            return Err(WorkSetupError::Unsettleable);
        }
        Ok(Self {
            bond_edge: channel.payment_terms().bond_edge,
            channel,
            policy_salt,
            execution_policy,
            expected_payment_values,
        })
    }
}

fn push_kernel<E: Encode>(out: &mut Vec<u8>, value: &E) {
    let mut bytes = vec![0_u8; E::MAX_ENCODED_SIZE];
    let written = value.write_to(&mut bytes);
    out.extend_from_slice(&bytes[..written]);
}

struct CloseCursor<'a> {
    bytes: &'a [u8],
}

impl CloseCursor<'_> {
    fn byte(&mut self) -> Result<u8, WorkSetupError> {
        let (byte, rest) = self
            .bytes
            .split_first()
            .ok_or(WorkSetupError::DescriptorMalformed)?;
        self.bytes = rest;
        Ok(*byte)
    }

    fn take(&mut self, len: usize) -> Result<&[u8], WorkSetupError> {
        let (value, rest) = self
            .bytes
            .split_at_checked(len)
            .ok_or(WorkSetupError::DescriptorMalformed)?;
        self.bytes = rest;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WorkSetupError> {
        self.take(N)?
            .try_into()
            .map_err(|_| WorkSetupError::DescriptorMalformed)
    }

    fn u64(&mut self) -> Result<u64, WorkSetupError> {
        self.array::<8>().map(u64::from_be_bytes)
    }

    fn network(&mut self) -> Result<NetworkId, WorkSetupError> {
        let len = usize::from(self.byte()?);
        let bytes = self.take(len)?;
        let id = core::str::from_utf8(bytes).map_err(|_| WorkSetupError::DescriptorMalformed)?;
        NetworkId::new(id).ok_or(WorkSetupError::DescriptorMalformed)
    }

    fn field<T: Decode>(&mut self) -> Result<T, WorkSetupError> {
        let (value, consumed) =
            T::decode(self.bytes).map_err(|_: DecodeError| WorkSetupError::DescriptorMalformed)?;
        self.bytes = self
            .bytes
            .get(consumed..)
            .ok_or(WorkSetupError::DescriptorMalformed)?;
        Ok(value)
    }
}

/// One finalized read of a channel's four objects.
///
/// A struct rather than five arguments because two of the five are
/// `Option<&Edge>` and would otherwise be silently swappable. Every
/// field is named at the call site that builds it, so a bond passed as a
/// payment edge is a visible mistake rather than a subtle one.
///
/// Nothing here proves the five fields came from one block, and nothing
/// downstream can: whoever fills this in owes the coherence.
/// `hellas_chain::WorkChannelSnapshot` is what supplies it in this
/// milestone, by reading every object under one database snapshot at one
/// finalized block; five separate point queries would satisfy the type
/// and not the requirement.
#[derive(Clone, Copy, Debug)]
pub struct ObservedChannel<'a> {
    /// Finalized height every field below was read at.
    pub height: u64,
    /// The bond edge, or its absence.
    pub bond: Option<&'a Edge>,
    /// The payment edge, or its absence.
    pub payment: Option<&'a Edge>,
    /// What the bond's lease slots held.
    pub lease: LeaseSlots,
    /// What the payment edge's pending-close slot held.
    pub pending: PendingSlot,
}

/// A channel this endpoint has established is live, leased, uncontested,
/// and inside its horizon at one finalized height.
///
/// It can only be built by [`WorkChannelDescriptor::check_ready`], so
/// holding one is holding that decision — and holding it *only at*
/// [`Self::finalized_height`]. Liveness, the lease, and the absence of a
/// contest are facts about that one block, and nothing on this type
/// refreshes them: a close opened one block later is invisible to every
/// method here, because the objects it would have to re-read are not
/// carried.
///
/// A live channel observer must apply finalized history and refresh this
/// decision independently of requests. Admission, delivery and new certificates
/// check local observer freshness and the journal's close cutoff under the same
/// state lock. An expired observer must suspend those operations; cached
/// arithmetic alone cannot establish that the channel remains open.
/// [`Self::check_signable`] checks deadline margins against the applied cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadyChannel {
    channel: PaidChannel,
    execution_policy: PaidWorkPolicy,
    settlement: WorkPaymentSettlement,
    finalized_height: u64,
    admission_horizon: u64,
}

impl ReadyChannel {
    /// Returns the channel every private record is bound to.
    pub const fn channel(&self) -> &PaidChannel {
        &self.channel
    }

    /// Returns what this edge can settle, at the funding it actually
    /// has.
    pub const fn settlement(&self) -> WorkPaymentSettlement {
        self.settlement
    }

    /// Returns the execution policy this readiness was decided under.
    ///
    /// The policy an endpoint checks a proposal against must be the one
    /// whose margins [`Self::check_signable`] measures against and whose
    /// digest the authorization names. Carrying it here is what stops
    /// those three from being three copies.
    pub const fn execution_policy(&self) -> &PaidWorkPolicy {
        &self.execution_policy
    }

    /// Returns the finalized height this readiness was decided at.
    pub const fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    /// Checks that a job with these deadlines may be signed now.
    ///
    /// Readiness was decided at a height; this is decided at a
    /// signature, which is a different moment and a different question.
    /// `cursor_height` is that moment: how far the endpoint has actually
    /// processed finalized blocks. An endpoint that has read a snapshot
    /// it has not caught up to has seen a state it cannot yet act on,
    /// because the blocks between are where a contest it must not sign
    /// over would appear.
    ///
    /// Every bound below is therefore anchored at `cursor_height` and
    /// not at [`Self::finalized_height`]. The readiness height is the
    /// past; the chain has moved since, and a horizon or a deadline
    /// measured from the past is measured from a moment the signature
    /// will not be made at. Anchored at the readiness height, the whole
    /// interval `[finalized_height + margins, cursor_height + margins)`
    /// passes — and that interval is exactly the deadlines already
    /// missed by the time the signature is made.
    ///
    /// The two margins are the policy's measured ones, so this refuses a
    /// deadline that is legal, ordered, and unreachable — which is the
    /// only kind of deadline an honest provider signs and then misses.
    ///
    /// The ordering of the four deadlines is not re-derived here:
    /// [`crate::protocol::work::check_authorization`] fixes
    /// `acceptance < terminal < payment < horizon` against the same
    /// terms, and a second spelling of that chain is a second chance to
    /// spell it differently.
    ///
    /// # Errors
    ///
    /// [`WorkSetupError::CursorBehind`] when the endpoint has not
    /// processed blocks through the height this was decided at,
    /// [`WorkSetupError::HorizonPassed`] when the channel admits no more
    /// work, [`WorkSetupError::TerminalUnreachable`] when the measured
    /// margins do not fit before the terminal deadline, and
    /// [`WorkSetupError::OracleGraceTooShort`] when the payment deadline
    /// leaves less than the measured oracle grace.
    pub fn check_signable(
        &self,
        cursor_height: u64,
        terminal_deadline: u64,
        payment_deadline: u64,
    ) -> Result<(), WorkSetupError> {
        self.check_caught_up(cursor_height)?;
        if cursor_height >= self.admission_horizon {
            return Err(WorkSetupError::HorizonPassed {
                height: cursor_height,
                horizon: self.admission_horizon,
            });
        }

        let (dispatch, delivery, oracle_grace) = self.execution_policy.margins();
        let reachable = cursor_height
            .checked_add(dispatch)
            .and_then(|sum| sum.checked_add(delivery))
            .ok_or(PaidWorkError::Overflow {
                field: "dispatch and delivery margins",
            })?;
        if reachable > terminal_deadline {
            return Err(WorkSetupError::TerminalUnreachable {
                height: cursor_height,
                dispatch,
                delivery,
                terminal: terminal_deadline,
            });
        }

        let grace =
            payment_deadline
                .checked_sub(terminal_deadline)
                .ok_or(PaidWorkError::Overflow {
                    field: "oracle grace interval",
                })?;
        if grace < oracle_grace {
            return Err(WorkSetupError::OracleGraceTooShort {
                terminal: terminal_deadline,
                payment: payment_deadline,
                actual: grace,
                grace: oracle_grace,
            });
        }
        Ok(())
    }

    /// Checks that this endpoint has processed finalized blocks through
    /// the height this readiness was decided at.
    ///
    /// Every decision taken against a `ReadyChannel` needs this and
    /// only this in common: a snapshot the endpoint has not caught up
    /// to is a state it cannot yet act on, because the blocks between
    /// are where the fact that would change the decision would appear.
    /// It is written once here and called by each of them.
    ///
    /// # Errors
    ///
    /// [`WorkSetupError::CursorBehind`] when the cursor is behind.
    pub const fn check_caught_up(&self, cursor_height: u64) -> Result<(), WorkSetupError> {
        if cursor_height < self.finalized_height {
            return Err(WorkSetupError::CursorBehind {
                cursor: cursor_height,
                height: self.finalized_height,
            });
        }
        Ok(())
    }

    /// Checks that plaintext released now can still reach the client
    /// before the deadline it was promised by.
    ///
    /// The dispatch margin is deliberately absent: by the time there is
    /// plaintext to release it has already been spent, and charging it
    /// again would refuse a delivery that is in fact on time. What
    /// remains is the transfer the policy measured for the largest
    /// legal result.
    ///
    /// The admission horizon is likewise absent, and does not need to be
    /// here: `check_authorization` fixes `terminal < payment < horizon`
    /// for every signed job, so a height inside the terminal deadline is
    /// inside the horizon.
    ///
    /// # Errors
    ///
    /// [`WorkSetupError::CursorBehind`] when the endpoint has not
    /// processed blocks through the height this was decided at,
    /// [`WorkSetupError::DeliveryUnreachable`] when the measured margin
    /// no longer fits, and [`WorkSetupError::Record`] when that
    /// arithmetic would overflow.
    pub fn check_releasable(
        &self,
        cursor_height: u64,
        terminal_deadline: u64,
    ) -> Result<(), WorkSetupError> {
        self.check_caught_up(cursor_height)?;
        let delivery = self.execution_policy.margins().1;
        let arrives = cursor_height
            .checked_add(delivery)
            .ok_or(PaidWorkError::Overflow {
                field: "delivery margin",
            })?;
        if arrives > terminal_deadline {
            return Err(WorkSetupError::DeliveryUnreachable {
                height: cursor_height,
                delivery,
                terminal: terminal_deadline,
            });
        }
        Ok(())
    }
}

/// Checks that the omission bond exceeds the capacity it insures.
///
/// This is the whole of the omission contest's economics. A provider that
/// omits a response forfeits `omission_bond`; the most it could gain by
/// doing so is the channel's `payment_capacity`. With the bond strictly
/// larger, omission is loss-making at *every* response probability, so
/// no measurement of the provider's availability is needed to price the
/// channel and none is taken.
///
/// This is a bilateral policy gate, not a kernel fact. The kernel checks
/// that the bond is funded and that a proved understatement forfeits it.
/// Nothing on chain checks that a provider is actually online, and no
/// hash can make one respond.
///
/// # Errors
///
/// [`WorkSetupError::Undercollateralised`] naming both numbers.
pub const fn check_collateral(
    omission_bond: u64,
    payment_capacity: u64,
) -> Result<(), WorkSetupError> {
    if omission_bond > payment_capacity {
        return Ok(());
    }
    Err(WorkSetupError::Undercollateralised {
        bond: omission_bond,
        capacity: payment_capacity,
    })
}

/// Returns the terms hash of one payment body, as the edge commits to
/// it.
///
/// One line, and it exists so no caller writes
/// `Terms::work_payment(..).hash()` for itself: the edge's commitment is
/// over the tagged `Terms` envelope, not over the body, and a caller
/// that hashed the body would compare a value no edge carries.
#[must_use]
pub fn payment_terms_hash(terms: WorkPaymentTerms) -> TermsHash {
    Terms::work_payment(terms).hash()
}
