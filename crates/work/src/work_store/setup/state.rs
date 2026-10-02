use super::*;

impl SetupState {
    pub(super) fn new(network: NetworkId, bond_edge: EdgeId, role: Role) -> Self {
        Self {
            network,
            bond_edge,
            role,
            bundle: None,
            bundle_bytes: Vec::new(),
            scan_armed: None,
            close_descriptor: None,
            unresolved_bond_open: false,
            unresolved_payment_open: false,
            scan_cursor: None,
            bond_finalized: false,
            payment_finalized: false,
            bond_closed: false,
            payment_closed: false,
            bond_timeout_submitted: false,
            origin: None,
            end: None,
        }
    }

    /// Reopens a checkpoint under its journal identity, checking the retained
    /// signed bundle and the cursor/outcome invariants.
    pub(super) fn from_checkpoint<V: SigVerifier>(
        bytes: &[u8],
        network: NetworkId,
        bond_edge: EdgeId,
        role: Role,
        verifier: &V,
    ) -> Result<Self, SetupStateError> {
        let state = Self::decode_checkpoint(bytes)?;
        if state.network != network {
            return Err(SetupStateError::WrongChannel { field: "network" });
        }
        if state.bond_edge != bond_edge {
            return Err(SetupStateError::WrongChannel { field: "bond edge" });
        }
        if state.role != role {
            return Err(SetupStateError::WrongRole {
                step: "replaying a checkpoint",
            });
        }
        check_bundle_signatures(state.bundle_bytes(), verifier)?;
        state.revalidate()?;
        Ok(state)
    }

    /// Checks signed-handshake structure and the compact finalized outcomes.
    fn revalidate(&self) -> Result<(), SetupStateError> {
        if let Some(bundle) = &self.bundle {
            if bundle.network() != self.network {
                return Err(SetupStateError::WrongChannel { field: "network" });
            }
            if bundle.bond_edge() != self.bond_edge {
                return Err(SetupStateError::WrongChannel { field: "bond edge" });
            }
            let executable = matches!(
                (self.role, bundle.revision()),
                (Role::Client, 2 | 3) | (Role::Provider, 3)
            );
            match (&self.close_descriptor, executable) {
                (Some(descriptor), true) => describes_bundle(bundle, descriptor)?,
                (None, false) => {}
                _ => return Err(SetupStateError::DescriptorMismatch),
            }
            let armed_stage = executable || (self.role == Role::Provider && bundle.revision() == 1);
            if armed_stage && self.scan_armed.is_none() {
                return Err(SetupStateError::WrongStage {
                    step: "holding a revision this endpoint armed",
                    revision: self.revision(),
                });
            }
        } else if self.close_descriptor.is_some() {
            return Err(SetupStateError::DescriptorMismatch);
        }

        match (self.scan_armed, self.scan_cursor) {
            (None, None) if !self.bond_finalized && !self.payment_finalized => {}
            (Some(floor), Some(cursor))
                if cursor.height >= floor.height
                    && (cursor.height != floor.height || cursor.payload == floor.payload) => {}
            _ => return Err(SetupStateError::Malformed),
        }
        if (self.bond_closed && (!self.bond_finalized || self.role != Role::Provider))
            || (self.payment_closed && !self.payment_finalized)
            || (self.payment_finalized != self.origin.is_some())
            || (self.role == Role::Client
                && (self.unresolved_bond_open
                    || self.unresolved_payment_open
                    || self.bond_timeout_submitted))
        {
            return Err(SetupStateError::Malformed);
        }
        if let Some(origin) = self.origin {
            let floor = self.scan_armed.ok_or(SetupStateError::Malformed)?;
            let cursor = self.scan_cursor.ok_or(SetupStateError::Malformed)?;
            if Some(origin.payment_edge) != self.payment_edge()
                || origin.height <= floor.height
                || (self.end != Some(SetupEnd::Complete) && origin.height > cursor.height)
                || (origin.height == cursor.height && origin.payload != cursor.payload)
            {
                return Err(SetupStateError::Malformed);
            }
        }
        Ok(())
    }

    /// Returns the revision this endpoint has durably retained.
    #[must_use]
    pub fn revision(&self) -> Option<u8> {
        self.bundle.as_ref().map(WorkChannelSetupBundleV1::revision)
    }

    /// Returns the retained revision itself.
    ///
    /// Beside [`Self::bundle_bytes`] rather than instead of it, and the
    /// two are for different things. An endpoint that is *re-exporting*
    /// what it already exported wants the bytes, verbatim. An endpoint
    /// that is about to add its own signature wants the value, because
    /// re-decoding bytes this journal has already decoded and checked
    /// would be a second parse whose failure would have no meaning.
    #[must_use]
    pub const fn bundle(&self) -> Option<&WorkChannelSetupBundleV1> {
        self.bundle.as_ref()
    }

    /// Returns the exact bytes of the retained revision.
    ///
    /// The bytes that were handed in, kept verbatim rather than
    /// re-encoded from the decoded value: a recovered endpoint
    /// re-exports the artifact it exported before, and "the encoding of
    /// what those bytes decode to" would be that artifact only as long
    /// as the codec is a fixed point. This does not need it to be.
    #[must_use]
    pub fn bundle_bytes(&self) -> Option<&[u8]> {
        self.bundle.as_ref().map(|_| self.bundle_bytes.as_slice())
    }

    /// Returns the immutable observation floor once this endpoint is armed.
    #[must_use]
    pub const fn scan_armed(&self) -> Option<SetupScan> {
        self.scan_armed
    }

    /// Returns the close-only descriptor retained beside this role's
    /// executable setup revision.
    #[must_use]
    pub const fn close_descriptor(&self) -> Option<&CloseDescriptor> {
        self.close_descriptor.as_ref()
    }

    /// Returns the bond edge this journal is keyed to.
    #[must_use]
    pub const fn bond_edge(&self) -> EdgeId {
        self.bond_edge
    }

    /// Returns the payment edge, once the client's revision has named
    /// its funding and terms.
    #[must_use]
    pub fn payment_edge(&self) -> Option<EdgeId> {
        self.bundle
            .as_ref()
            .and_then(WorkChannelSetupBundleV1::payment_edge)
    }

    /// Returns whether the bond Open has been journaled as submitted.
    #[must_use]
    pub const fn bond_submitted(&self) -> bool {
        self.unresolved_bond_open
    }

    /// Returns whether the payment Open has been journaled as
    /// submitted.
    #[must_use]
    pub const fn payment_submitted(&self) -> bool {
        self.unresolved_payment_open
    }

    /// Returns the last contiguous finalized setup header held.
    #[must_use]
    pub const fn scan_cursor(&self) -> Option<SetupScan> {
        self.scan_cursor
    }

    /// Returns whether finalized history proves that a once-funded payment
    /// channel can no longer be admitted as a live leased channel but still
    /// needs its close history mounted.
    #[must_use]
    pub const fn close_only_recovery(&self) -> bool {
        self.origin.is_some() && (self.bond_closed || self.payment_closed)
    }

    /// Returns whether any submitted Open remains unresolved.
    #[must_use]
    pub const fn submitted_open_unresolved(&self) -> bool {
        self.unresolved_bond_open || self.unresolved_payment_open
    }

    /// Returns where the channel was finalized, once setup completed.
    #[must_use]
    pub const fn origin(&self) -> Option<SetupOrigin> {
        self.origin
    }

    /// Returns how setup ended, if it has.
    #[must_use]
    pub const fn end(&self) -> Option<SetupEnd> {
        self.end
    }

    /// Returns the coins the two retained Opens spend.
    ///
    /// This is what a caller reads liveness for before calling
    /// [`Self::decide`]. It is derived from the retained transactions,
    /// so a caller cannot check a coin set the signed bytes do not
    /// actually name.
    #[must_use]
    pub fn funding_coins(&self) -> BTreeSet<CoinId> {
        let mut coins = BTreeSet::new();
        for tx in [self.bond_open(), self.payment_open()]
            .into_iter()
            .flatten()
        {
            if let Tx::Open { funding, .. } = tx {
                coins.extend(funding.maker().iter().copied());
                coins.extend(funding.taker().iter().copied());
            }
        }
        coins
    }

    /// Returns the executable bond Open, once both parties have signed
    /// it.
    #[must_use]
    pub fn bond_open(&self) -> Option<Tx> {
        self.bundle
            .as_ref()
            .and_then(WorkChannelSetupBundleV1::bond_open)
    }

    /// Returns the executable payment Open, once both parties have
    /// signed it.
    #[must_use]
    pub fn payment_open(&self) -> Option<Tx> {
        self.bundle
            .as_ref()
            .and_then(WorkChannelSetupBundleV1::payment_open)
    }

    /// Returns the height at and after which the retained bond Open can
    /// no longer be included, and the channel admits no work.
    ///
    /// One value, not two: the tag-4 timeout is the bond's own expiry
    /// and, through the tag-2 body that derives its admission horizon
    /// from it, the channel's.
    #[must_use]
    pub fn horizon(&self) -> Option<u64> {
        let Some(Tx::Open { terms, .. }) = self.bond_open() else {
            return None;
        };
        Some(terms.timeout().get())
    }

    /// Decides what this endpoint should do next, from one finalized
    /// read.
    ///
    /// This is §6's recovery machine and the first submission both. The
    /// branch that submits the bond has the payment-funding preflight
    /// as a premise, so stake cannot be locked while a coin funding the
    /// client's already-signed payment Open is gone — on the first
    /// attempt or on the tenth.
    ///
    /// It never proposes a step whose subject is absent: no Timeout of
    /// an edge that does not exist, no resubmission of an Open whose
    /// own timeout has passed, and no reconstruction of a transaction
    /// from anything but the retained bytes.
    #[must_use]
    pub fn decide(&self, observed: &ObservedSetup<'_>) -> SetupDecision {
        if let Some(end) = self.end {
            return match end {
                SetupEnd::Complete => SetupDecision::Complete,
                SetupEnd::Aborted(abort) => SetupDecision::Abort(abort),
                SetupEnd::Faulted(fault) => SetupDecision::Fault(fault),
            };
        }
        let Some(payment_edge) = self.payment_edge() else {
            // Revision 1: no payment leg exists yet, so nothing on
            // chain can be about this channel.
            return SetupDecision::AwaitingCounterparty;
        };

        let leased_here = match observed.lease {
            LeaseSlots::Present(lease) => {
                if lease.payment_edge() == payment_edge && lease.bond_edge() == self.bond_edge {
                    Leased::Here
                } else {
                    Leased::Elsewhere
                }
            }
            LeaseSlots::Absent => Leased::Absent,
            LeaseSlots::Faulty(_) => Leased::Faulty,
        };

        match (observed.bond.is_some(), observed.payment.is_some()) {
            (true, true) => match leased_here {
                Leased::Here => SetupDecision::Complete,
                Leased::Elsewhere => SetupDecision::Fault(SetupFault::LeasedElsewhere),
                Leased::Faulty => SetupDecision::Fault(SetupFault::LeaseMalformed),
                // A live payment edge exists only because a payment
                // Open took this bond's lease. An absent slot beside it
                // is not an unleased channel, it is a state the kernel
                // does not produce.
                Leased::Absent => SetupDecision::Fault(SetupFault::UnexplainedState),
            },
            (true, false) => match leased_here {
                Leased::Absent => self.decide_unleased_bond(observed),
                Leased::Elsewhere => SetupDecision::Fault(SetupFault::LeasedElsewhere),
                Leased::Faulty => SetupDecision::Fault(SetupFault::LeaseMalformed),
                Leased::Here => SetupDecision::Fault(SetupFault::UnexplainedState),
            },
            // A leased bond may be permissionlessly timed out at its
            // horizon while the payment edge survives. Admission is over,
            // but the payment edge still carries a close duty.
            (false, true) => SetupDecision::CloseOnly,
            (false, false) => self.decide_absent_bond(observed),
        }
    }

    /// The bond is live and unleased: post the payment, or take the
    /// stake back.
    fn decide_unleased_bond(&self, observed: &ObservedSetup<'_>) -> SetupDecision {
        let Some(payment) = self.payment_open() else {
            // The client holds no countersigned payment Open, so it has
            // nothing to submit and nothing to time out; the provider
            // is the party that acts here.
            return SetupDecision::AwaitingCounterparty;
        };
        if self.role != Role::Provider {
            return SetupDecision::AwaitingCounterparty;
        }
        let horizon = self.horizon().unwrap_or(0);
        if !funding_live(&payment, observed.live_funding) || observed.height >= horizon {
            // Either the capacity funding is gone or the channel would
            // be born past its own horizon. The unleased bond has an
            // immediate Timeout, so the stake comes back now rather
            // than at the horizon.
            return SetupDecision::TimeoutBond;
        }
        SetupDecision::SubmitPayment
    }

    /// Neither edge exists: submit, abort, or reconcile.
    fn decide_absent_bond(&self, observed: &ObservedSetup<'_>) -> SetupDecision {
        let (Some(bond), Some(payment)) = (self.bond_open(), self.payment_open()) else {
            return SetupDecision::AwaitingCounterparty;
        };
        if self.role != Role::Provider {
            return SetupDecision::AwaitingCounterparty;
        }
        if !funding_live(&bond, observed.live_funding) {
            if self.bond_closed {
                // The bond finalized and contiguous history holds the
                // Close that spent it. For a provider that is the only
                // party to record bond Close evidence, that Close is its
                // own Timeout: the stake input is gone because the stake
                // came back, and the reclaim is clean rather than a fault.
                return SetupDecision::Abort(SetupAbort::BondReclaimed);
            }
            if self.bond_timeout_submitted {
                // This endpoint submitted the deterministic Timeout that
                // is spending the stake. History has not yet caught the
                // finalized Close, so its own reclaim in flight must not
                // be journaled as a theft: it waits for the Close.
                return SetupDecision::AwaitingCounterparty;
            }
            // The stake input is gone and no bond exists to explain it.
            // Nothing here can tell a duplicate submission from a theft,
            // so this stops rather than guessing.
            return SetupDecision::Fault(SetupFault::BondFundingSpent);
        }
        let horizon = self.horizon().unwrap_or(0);
        if observed.height >= horizon {
            return SetupDecision::Abort(SetupAbort::BondOpenExpired);
        }
        // The preflight. It is here, in the premise of the only branch
        // that locks stake, rather than in a caller that could forget
        // it on the second attempt.
        if !funding_live(&payment, observed.live_funding) {
            return SetupDecision::Abort(SetupAbort::PaymentFundingSpent);
        }
        SetupDecision::SubmitBond
    }

    /// Applies one record, or says why it may not be applied.
    pub(super) fn apply(&mut self, record: &SetupRecord) -> Result<Applied, SetupStateError> {
        if let Some(end) = self.end {
            // Completion is idempotent, so a retried completion is not
            // an error — but only the *same* completion is a retry. One
            // naming another origin is this caller's finalized read
            // disagreeing with the journal's, and an `Ok` would say the
            // block it computed is durable when the journal holds a
            // different one. Every other retried record here is compared
            // against what it repeats; this one is too.
            if let (
                SetupEnd::Complete,
                SetupRecord::Complete {
                    payment_edge,
                    origin_height,
                    origin_payload,
                    origin_parent,
                },
            ) = (end, record)
            {
                let same = self.origin.as_ref().is_some_and(|origin| {
                    origin.payment_edge == *payment_edge
                        && origin.height == *origin_height
                        && origin.payload == *origin_payload
                        && origin.parent == *origin_parent
                });
                return if same {
                    Ok(Applied::Redundant)
                } else {
                    Err(SetupStateError::Ended(end))
                };
            }
            if matches!(record, SetupRecord::Ended { outcome } if *outcome == end) {
                return Ok(Applied::Redundant);
            }
            return Err(SetupStateError::Ended(end));
        }
        match record {
            SetupRecord::Bundle { bundle } => self.apply_bundle(bundle),
            SetupRecord::ScanArmed { height, payload } => {
                let scan = SetupScan {
                    height: *height,
                    payload: *payload,
                };
                if self.scan_armed == Some(scan) {
                    return Ok(Applied::Redundant);
                }
                if self.scan_armed.is_some() {
                    return Err(SetupStateError::WrongStage {
                        step: "arming a second scan floor",
                        revision: self.revision(),
                    });
                }
                let stage_is_right = match self.role {
                    Role::Provider => self.revision().is_none(),
                    Role::Client => self.revision() == Some(1),
                };
                if !stage_is_right {
                    return Err(SetupStateError::WrongStage {
                        step: "arming the history scan",
                        revision: self.revision(),
                    });
                }
                self.scan_armed = Some(scan);
                self.scan_cursor = Some(scan);
                Ok(Applied::Changed)
            }
            SetupRecord::ArmedBundle {
                bundle,
                close_descriptor,
            } => self.apply_armed_bundle(bundle, close_descriptor),
            SetupRecord::Observed(observed) => self.apply_observation(observed),
            SetupRecord::BondTimeoutSubmitted => {
                self.require_provider("bond Timeout submission")?;
                self.require_executable("bond Timeout submission")?;
                if self.bond_timeout_submitted {
                    return Ok(Applied::Redundant);
                }
                self.bond_timeout_submitted = true;
                Ok(Applied::Changed)
            }
            SetupRecord::BondSubmitted => {
                self.require_provider("bond submission")?;
                self.require_executable("bond submission")?;
                if self.unresolved_bond_open {
                    return Ok(Applied::Redundant);
                }
                self.unresolved_bond_open = true;
                Ok(Applied::Changed)
            }
            SetupRecord::PaymentSubmitted => {
                self.require_provider("payment submission")?;
                self.require_executable("payment submission")?;
                if !self.bond_finalized && !self.unresolved_bond_open {
                    return Err(SetupStateError::WrongStage {
                        step: "payment submission before the bond was submitted",
                        revision: self.revision(),
                    });
                }
                if self.unresolved_payment_open {
                    return Ok(Applied::Redundant);
                }
                self.unresolved_payment_open = true;
                Ok(Applied::Changed)
            }
            SetupRecord::Complete {
                payment_edge,
                origin_height,
                origin_payload,
                origin_parent,
            } => {
                let retained = self.payment_edge();
                if retained != Some(*payment_edge) {
                    return Err(SetupStateError::WrongPaymentEdge {
                        named: *payment_edge,
                        retained,
                    });
                }
                let origin = SetupOrigin {
                    payment_edge: *payment_edge,
                    height: *origin_height,
                    payload: *origin_payload,
                    parent: *origin_parent,
                };
                if self.origin.is_some_and(|retained| retained != origin) {
                    return Err(SetupStateError::Malformed);
                }
                self.payment_finalized = true;
                self.origin = Some(origin);
                self.end = Some(SetupEnd::Complete);
                Ok(Applied::Changed)
            }
            SetupRecord::Ended { outcome } => {
                if *outcome == SetupEnd::Complete {
                    // Completion carries the channel's origin, and a
                    // bare end byte does not. Recording it this way
                    // would leave a watcher with no cursor.
                    return Err(SetupStateError::Malformed);
                }
                if self.submitted_open_unresolved() {
                    return Err(SetupStateError::SubmittedOpenUnresolved);
                }
                self.end = Some(*outcome);
                Ok(Applied::Changed)
            }
        }
    }

    fn apply_bundle(&mut self, bytes: &[u8]) -> Result<Applied, SetupStateError> {
        let bundle = WorkChannelSetupBundleV1::decode(bytes)?;
        if self.bundle.as_ref() == Some(&bundle) {
            return Ok(Applied::Redundant);
        }
        if bundle.network() != self.network {
            return Err(SetupStateError::WrongChannel { field: "network" });
        }
        if bundle.bond_edge() != self.bond_edge {
            return Err(SetupStateError::WrongChannel { field: "bond edge" });
        }
        if let Some(held) = &self.bundle {
            bundle.check_extends(held)?;
        }
        if matches!(
            (self.role, bundle.revision()),
            (Role::Client, 2) | (Role::Provider, 3)
        ) {
            return Err(SetupStateError::WrongStage {
                step: "recording an executable revision without its close descriptor",
                revision: self.revision(),
            });
        }
        if self.role == Role::Provider && bundle.revision() == 1 && self.scan_armed.is_none() {
            return Err(SetupStateError::WrongStage {
                step: "recording revision 1 before arming its scan floor",
                revision: self.revision(),
            });
        }
        self.apply_decoded_bundle(bytes, bundle)
    }

    fn apply_armed_bundle(
        &mut self,
        bytes: &[u8],
        close_descriptor: &CloseDescriptor,
    ) -> Result<Applied, SetupStateError> {
        let bundle = WorkChannelSetupBundleV1::decode(bytes)?;
        let expected_revision = match self.role {
            Role::Client => 2,
            Role::Provider => 3,
        };
        if bundle.revision() != expected_revision || self.scan_armed.is_none() {
            return Err(SetupStateError::WrongStage {
                step: "arming an executable setup bundle",
                revision: self.revision(),
            });
        }
        if self.bundle.as_ref() == Some(&bundle) {
            if self.close_descriptor.as_ref() == Some(close_descriptor) {
                return Ok(Applied::Redundant);
            }
            return Err(SetupStateError::DescriptorMismatch);
        }
        describes_bundle(&bundle, close_descriptor)?;
        let applied = self.apply_decoded_bundle(bytes, bundle)?;
        debug_assert_eq!(applied, Applied::Changed);
        self.close_descriptor = Some(close_descriptor.clone());
        Ok(Applied::Changed)
    }

    fn apply_decoded_bundle(
        &mut self,
        bytes: &[u8],
        bundle: WorkChannelSetupBundleV1,
    ) -> Result<Applied, SetupStateError> {
        if bundle.network() != self.network {
            return Err(SetupStateError::WrongChannel { field: "network" });
        }
        if bundle.bond_edge() != self.bond_edge {
            return Err(SetupStateError::WrongChannel { field: "bond edge" });
        }
        match &self.bundle {
            None => {
                if bundle.revision() != 1 {
                    return Err(SetupStateError::WrongStage {
                        step: "importing a revision that skips the proposal",
                        revision: None,
                    });
                }
            }
            Some(held) if held == &bundle => return Ok(Applied::Redundant),
            Some(held) => bundle.check_extends(held)?,
        }
        self.bundle = Some(bundle);
        self.bundle_bytes = bytes.to_vec();
        Ok(Applied::Changed)
    }

    /// Summarizes up to 256 contiguous, executed finalized blocks. The caller
    /// obtains these from `FinalizedBlocks`; no peer-supplied transaction is
    /// accepted as an observation without that verified source boundary.
    pub fn observe(
        &self,
        blocks: &[crate::work_close::FinalizedWork],
    ) -> Result<SetupObservation, SetupStateError> {
        if blocks.is_empty() || blocks.len() > 256 {
            return Err(SetupStateError::Malformed);
        }
        let from = self.scan_cursor.ok_or(SetupStateError::WrongStage {
            step: "observing before arming the scan floor",
            revision: self.revision(),
        })?;
        let payment_edge = self.payment_edge().ok_or(SetupStateError::WrongStage {
            step: "observing before the payment edge is named",
            revision: self.revision(),
        })?;
        let mut observed = SetupObservation {
            from,
            through: from,
            bond_finalized: self.bond_finalized,
            payment_finalized: self.payment_finalized,
            bond_closed: self.bond_closed,
            payment_closed: self.payment_closed,
            origin: self.origin,
        };
        for block in blocks {
            if Some(block.height) != observed.through.height.checked_add(1)
                || block.parent != observed.through.payload
            {
                return Err(SetupStateError::Malformed);
            }
            for tx in &block.txs {
                match tx {
                    Tx::Open { funding, terms, .. } => {
                        let edge = Tx::edge_id_of(funding, terms);
                        if edge == self.bond_edge {
                            observed.bond_finalized = true;
                        } else if edge == payment_edge {
                            observed.payment_finalized = true;
                            observed.origin.get_or_insert(SetupOrigin {
                                payment_edge,
                                height: block.height,
                                payload: block.payload,
                                parent: block.parent,
                            });
                        }
                    }
                    Tx::Close { input, .. }
                        if *input == self.bond_edge && self.role == Role::Provider =>
                    {
                        observed.bond_finalized = true;
                        observed.bond_closed = true;
                    }
                    Tx::Close { input, .. } if *input == payment_edge => {
                        observed.payment_closed = true;
                    }
                    _ => {}
                }
            }
            observed.through = SetupScan {
                height: block.height,
                payload: block.payload,
            };
        }
        Ok(observed)
    }

    fn apply_observation(
        &mut self,
        observed: &SetupObservation,
    ) -> Result<Applied, SetupStateError> {
        if self.scan_cursor != Some(observed.from)
            || observed.through.height <= observed.from.height
            || observed.through.height - observed.from.height > 256
            || (self.bond_finalized && !observed.bond_finalized)
            || (self.payment_finalized && !observed.payment_finalized)
            || (self.bond_closed && !observed.bond_closed)
            || (self.payment_closed && !observed.payment_closed)
            || (self.origin.is_some() && self.origin != observed.origin)
        {
            return Err(SetupStateError::Malformed);
        }
        self.scan_cursor = Some(observed.through);
        self.bond_finalized = observed.bond_finalized;
        self.payment_finalized = observed.payment_finalized;
        self.bond_closed = observed.bond_closed;
        self.payment_closed = observed.payment_closed;
        self.origin = observed.origin;
        if self.bond_finalized
            || observed.through.height > self.open_horizon(true).unwrap_or(u64::MAX)
        {
            self.unresolved_bond_open = false;
        }
        if self.payment_finalized
            || observed.through.height > self.open_horizon(false).unwrap_or(u64::MAX)
        {
            self.unresolved_payment_open = false;
        }
        self.revalidate()?;
        Ok(Applied::Changed)
    }

    fn open_horizon(&self, bond: bool) -> Option<u64> {
        let tx = if bond {
            self.bond_open()
        } else {
            self.payment_open()
        }?;
        let Tx::Open { terms, .. } = tx else {
            return None;
        };
        Some(terms.timeout().get())
    }

    fn require_provider(&self, step: &'static str) -> Result<(), SetupStateError> {
        if self.role == Role::Provider {
            Ok(())
        } else {
            Err(SetupStateError::WrongRole { step })
        }
    }

    fn require_executable(&self, step: &'static str) -> Result<(), SetupStateError> {
        if self.bond_open().is_some() && self.payment_open().is_some() {
            Ok(())
        } else {
            Err(SetupStateError::WrongStage {
                step,
                revision: self.revision(),
            })
        }
    }
}

/// Whether the bond's lease is this channel's, another's, or neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Leased {
    Here,
    Elsewhere,
    Absent,
    Faulty,
}

fn funding_live(tx: &Tx, live: &BTreeSet<CoinId>) -> bool {
    let Tx::Open { funding, .. } = tx else {
        return false;
    };
    funding
        .maker()
        .iter()
        .chain(funding.taker().iter())
        .all(|coin| live.contains(coin))
}
