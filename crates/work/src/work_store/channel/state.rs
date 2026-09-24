use super::*;

impl ChannelState {
    fn check_result_payload(
        &self,
        job: &JobState,
        result: &PaidJobResultV1,
        transcript: &[u8],
        metadata_only: bool,
    ) -> Result<(), ChannelStateError> {
        if result.work_id != job.work_id {
            return Err(ChannelStateError::WrongChannel {
                field: "result work_id",
            });
        }
        if metadata_only {
            return if transcript.is_empty() {
                Ok(())
            } else {
                Err(ChannelStateError::Malformed)
            };
        }
        let input = PreparedPaidWorkInput::decode(&job.prepared_input, MAX_RECORD_BYTES)
            .map_err(PaidWorkError::from)?;
        let budget = match &input {
            PreparedPaidWorkInput::Fetch(_) => {
                hellas_rpc::protocol::work_fetch::MAX_FETCH_TRANSCRIPT_BYTES
            }
            PreparedPaidWorkInput::Evaluate(_) => MAX_RECORD_BYTES,
        };
        let events = decode_transcript(transcript, budget)?;
        if input.terminal_result(&self.channel, &job.authorization, &events)? != *result {
            return Err(ChannelStateError::WrongChannel {
                field: "result against its transcript",
            });
        }
        Ok(())
    }

    pub(super) fn new(
        channel: PaidChannel,
        settlement: WorkPaymentSettlement,
        role: Role,
        origin: SetupOrigin,
    ) -> Self {
        Self {
            channel,
            settlement,
            role,
            ledger: CreditLedger::new(),
            jobs: BTreeMap::new(),
            terminals: BTreeMap::new(),
            proposal_nonce_high_water: 0,
            cursor: (origin.height, origin.payload),
            indeterminate: BTreeMap::new(),
            close_prepared: None,
            close_opened: None,
            close_responded: None,
            close_settled: None,
        }
    }

    /// Reads a checkpoint and reruns every rule replay would have run to
    /// reach it.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::decode_checkpoint`] refuses about the bytes, and
    /// whatever [`Self::revalidate`] refuses about the state.
    pub(super) fn from_checkpoint<V: SigVerifier>(
        bytes: &[u8],
        channel: PaidChannel,
        settlement: WorkPaymentSettlement,
        role: Role,
        verifier: &V,
        metadata_only: bool,
    ) -> Result<Self, ChannelStateError> {
        let state = Self::decode_checkpoint(bytes, channel, settlement, role)?;
        state.revalidate(verifier, metadata_only)?;
        Ok(state)
    }

    /// Refuses a checkpoint whose stored fields are not the ones its own
    /// contents produce.
    ///
    /// Every signature this journal ever verified is verified again,
    /// against the party the channel names and over the same digest —
    /// the client's authorization, the provider's co-signature, the
    /// provider's result, and the client's binding and certificate. The
    /// result is rebuilt from the transcript beside it by
    /// [`hellas_rpc::protocol::work::terminal_result`], exactly as a record replay rebuilds it. The
    /// inputs are hashed against the digest the authorization commits
    /// to. The retained close start is checked against this channel and
    /// this role, and the fixed answer is re-derived from the contest
    /// and the certificate that determine it.
    ///
    /// What cannot be rerun is the height each of those steps was legal
    /// at: a checkpoint is the state a replay reached, not the blocks it
    /// crossed, and judging an old step by the cursor the checkpoint
    /// carries would refuse a journal that was legal at every step. That
    /// is the one thing this does not claim, and it is the reason the
    /// deadline rules stay where they are — on the records, at the
    /// heights they were taken.
    fn revalidate<V: SigVerifier>(
        &self,
        verifier: &V,
        metadata_only: bool,
    ) -> Result<(), ChannelStateError> {
        // The one number consensus sees, against the one terminal that
        // could have moved it. A ledger the terminal does not produce is
        // a channel that would credit a second payment.
        if self.ledger.credited_cumulative() != self.max_executable_certificate() {
            return Err(ChannelStateError::WrongChannel {
                field: "credited cumulative against the terminal",
            });
        }
        for job in self.jobs.values() {
            if job.work_id != work_id(&self.channel, &job.authorization) {
                return Err(ChannelStateError::WrongChannel { field: "work_id" });
            }
            self.check_authorization(&job.authorization, &job.prepared_input, metadata_only)?;
            if job.phase.only_role().is_some_and(|role| role != self.role)
                || job.provider_signature.is_some() != (job.phase != JobPhase::HalfSigned)
                || job.result.is_some() != job.phase.has_result()
            {
                return Err(ChannelStateError::WrongPhase {
                    step: "replaying a checkpoint",
                    phase: job.phase.name(),
                });
            }
            if !verifier.verify_sig(
                job.client_signature,
                self.client_key(),
                signing_hash(job.work_id),
            ) {
                return Err(ChannelStateError::BadSignature {
                    slot: "authorization",
                    party: "the client",
                });
            }
            if let Some(provider_signature) = job.provider_signature
                && !verifier.verify_sig(
                    provider_signature,
                    self.provider_key(),
                    signing_hash(job.work_id),
                )
            {
                return Err(ChannelStateError::BadSignature {
                    slot: "authorization",
                    party: "the provider",
                });
            }
            if let Some((result, provider_signature)) = &job.result {
                self.check_result_payload(job, result, &job.transcript, metadata_only)?;
                if !verifier.verify_sig(
                    *provider_signature,
                    self.provider_key(),
                    signing_hash(result_digest(&self.channel, result)),
                ) {
                    return Err(ChannelStateError::BadSignature {
                        slot: "result",
                        party: "the provider",
                    });
                }
            }
        }
        for terminal in self.terminals.values() {
            if self.jobs.contains_key(&terminal.work_id) {
                return Err(ChannelStateError::Terminated {
                    step: "replaying a checkpoint with a job still open",
                    outcome: terminal.outcome.name(),
                });
            }
            if let TerminalOutcome::Certified {
                certificate,
                binding,
                binding_signature,
                certificate_signature,
            } = &terminal.outcome
            {
                for (slot, signature, hash) in [
                    (
                        "binding",
                        *binding_signature,
                        signing_hash(payment_binding_digest(&self.channel, binding)),
                    ),
                    (
                        "certificate",
                        *certificate_signature,
                        certificate.digest(self.network()),
                    ),
                ] {
                    if !verifier.verify_sig(signature, self.client_key(), hash) {
                        return Err(ChannelStateError::BadSignature {
                            slot,
                            party: "the client",
                        });
                    }
                }
            }
        }
        if let Some(start) = &self.close_prepared {
            self.check_close_start(start)?;
        }
        if let Some(answer) = self.close_responded {
            let Some(contest) = self
                .close_opened
                .filter(|contest| contest.start_id == answer.start_id)
            else {
                return Err(ChannelStateError::WrongChannel {
                    field: "close response start_id",
                });
            };
            let Some((certificate, _)) = self.executable_certificate() else {
                return Err(ChannelStateError::WrongPhase {
                    step: "replaying a fixed contest answer",
                    phase: "owed no answer",
                });
            };
            if answer.response_digest
                != crate::work_close::response_body_digest(
                    &self.channel,
                    contest.start_id,
                    &certificate,
                )
            {
                return Err(ChannelStateError::WrongChannel {
                    field: "close response digest",
                });
            }
        }
        Ok(())
    }

    /// Returns the channel every record here is bound to.
    #[must_use]
    pub const fn channel(&self) -> &PaidChannel {
        &self.channel
    }

    /// Returns what this endpoint has credited.
    #[must_use]
    pub const fn ledger(&self) -> &CreditLedger {
        &self.ledger
    }

    /// Returns which half of the channel this journal is.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Returns what the funded payment edge can settle.
    ///
    /// Fixed when the store was opened, from the finalized read that
    /// established the channel is live. An endpoint built over a
    /// readiness decision taken at other funding would bound its
    /// payments by a different number than this one.
    #[must_use]
    pub const fn settlement(&self) -> WorkPaymentSettlement {
        self.settlement
    }

    /// Returns one active job by its stable identifier.
    #[must_use]
    pub fn job_by_id(&self, work_id: Digest) -> Option<&JobState> {
        self.jobs.get(&work_id)
    }

    /// Iterates all active jobs in deterministic work-id order.
    pub fn jobs(&self) -> impl ExactSizeIterator<Item = &JobState> {
        self.jobs.values()
    }

    /// Returns an archived terminal by work ID.
    #[must_use]
    pub fn terminal_by_id(&self, work_id: Digest) -> Option<&JobTerminal> {
        self.terminals.get(&work_id)
    }

    /// Iterates the append-only terminal archive in deterministic order.
    pub fn terminals(&self) -> impl ExactSizeIterator<Item = &JobTerminal> {
        self.terminals.values()
    }

    /// Returns the largest proposal nonce ever admitted.
    #[must_use]
    pub const fn proposal_nonce_high_water(&self) -> u64 {
        self.proposal_nonce_high_water
    }

    /// Returns the retained payment with the largest cumulative amount.
    ///
    /// What a recovered endpoint re-sends. The job it paid for is closed
    /// by its own terminal, so these bytes are the only remaining copy of
    /// what was agreed, and offering them again is idempotent rather than
    /// a second payment.
    #[must_use]
    pub fn last_payment(&self) -> Option<PaidCertificate> {
        self.terminals
            .values()
            .filter_map(Self::payment_from_terminal)
            .max_by_key(|payment| payment.certificate.earned_cumulative())
    }

    /// Returns the retained payment for one work ID.
    #[must_use]
    pub fn payment(&self, work_id: Digest) -> Option<PaidCertificate> {
        self.terminals
            .get(&work_id)
            .and_then(Self::payment_from_terminal)
    }

    fn payment_from_terminal(terminal: &JobTerminal) -> Option<PaidCertificate> {
        let TerminalOutcome::Certified {
            certificate,
            binding,
            binding_signature,
            certificate_signature,
        } = &terminal.outcome
        else {
            return None;
        };
        Some(PaidCertificate {
            work_id: terminal.work_id,
            certificate: *certificate,
            binding: **binding,
            binding_signature: *binding_signature,
            certificate_signature: *certificate_signature,
        })
    }

    /// Returns whether the job in flight was left running by a process
    /// that did not come back.
    ///
    /// True means exactly one thing: the backend may or may not have
    /// been invoked, and nothing local can say which. No automatic step
    /// resolves it, and a [`ChannelRecord::JobResult`] is refused while
    /// it holds.
    #[must_use]
    pub fn is_indeterminate(&self) -> bool {
        !self.indeterminate.is_empty()
    }

    /// Whether one active invocation was interrupted by a restart.
    #[must_use]
    pub fn job_is_indeterminate(&self, work_id: Digest) -> bool {
        self.indeterminate.contains_key(&work_id)
    }

    /// Returns the largest cumulative the paid certificate names.
    ///
    /// The most this channel has been shown it earned. A certificate the
    /// client signed is one it cannot repudiate, so a close that named
    /// less than this would be a close below what was already earned.
    /// Nothing here builds a close, and nothing here enforces that; this
    /// is the value such a builder must start from.
    ///
    /// Selects the largest cumulative certificate across completed jobs.
    #[must_use]
    pub fn max_executable_certificate(&self) -> u64 {
        self.last_payment()
            .map_or(0, |payment| payment.certificate.earned_cumulative())
    }

    /// Returns the finalized block this endpoint has processed through.
    ///
    /// Contiguous by construction, and contiguous all the way back to
    /// the block that opened the channel: the store is anchored at that
    /// origin when it is opened, and every record since named the block
    /// before it as its parent. That is what makes it usable as a clock
    /// — a height reached by skipping is a height at which this
    /// endpoint does not know what happened, and there is no height
    /// here that was reached by skipping.
    ///
    /// There is no "before the first block" case, and that is the whole
    /// point of the origin: an endpoint whose clock could be absent is
    /// an endpoint every deadline rule passes for.
    #[must_use]
    pub const fn cursor(&self) -> (u64, [u8; 32]) {
        self.cursor
    }

    /// Returns the close start this endpoint signed and retains.
    ///
    /// What a resubmission sends, and only while
    /// [`Self::includable_close_start`] still offers it: the record
    /// itself is never taken back — nothing on this journal is — but a
    /// signature whose window has passed is history rather than a
    /// pending close.
    #[must_use]
    pub const fn close_prepared(&self) -> Option<&PaymentCloseStart> {
        self.close_prepared.as_ref()
    }

    /// Returns the retained close start while `height` is still inside
    /// the window it could be included in.
    ///
    /// The one predicate that decides both halves of a resubmission: it
    /// is why an endpoint offers the retained bytes again instead of
    /// signing, and it is why the journal refuses to replace them. A
    /// second spelling of it would let the two disagree about which
    /// start this channel is closing with.
    #[must_use]
    pub fn includable_close_start(&self, height: u64) -> Option<&PaymentCloseStart> {
        self.close_prepared
            .as_ref()
            .filter(|start| height <= start.valid_through_height())
    }

    /// Returns the finalized contest on this channel's payment edge,
    /// and the party that opened it.
    #[must_use]
    pub const fn close_opened(&self) -> Option<(StartId, Party)> {
        match self.close_opened {
            Some(contest) => Some((contest.start_id, contest.opener)),
            None => None,
        }
    }

    /// Returns the finalized contest in full, including the window and
    /// the amount an answer must strictly exceed.
    ///
    /// Where [`Self::close_opened`] answers "is there a contest, and
    /// whose", this answers "may this endpoint still answer it, and with
    /// what floor" — the two facts a restart services the response from.
    #[must_use]
    pub const fn open_contest(&self) -> Option<OpenContest> {
        self.close_opened
    }

    /// Returns the answer this endpoint has already fixed for the
    /// contest on this edge, if it has fixed one.
    ///
    /// Present says the answer is chosen, not that anyone has it: the
    /// record is on the disk before the submission it authorises, so a
    /// crash in between leaves this present and consensus empty. What it
    /// is for is refusing a *different* answer to the same contest —
    /// [`Self::answerable_contest`] is what says whether one is still
    /// owed.
    #[must_use]
    pub const fn close_responded(&self) -> Option<RespondedContest> {
        self.close_responded
    }

    /// Returns the contest this endpoint owes an answer to, with the
    /// certificate that answers it.
    ///
    /// Five conditions, and every one of them is frozen the moment the
    /// contest is journaled — which is why an endpoint that fails them
    /// gains nothing by waiting, and must not stop reading blocks over
    /// an answer it will never be able to give:
    ///
    /// - this journal is the provider's, because only a certificate's
    ///   beneficiary may spend it;
    /// - the edge has not already settled;
    /// - the opener is the client, since a contest this endpoint opened
    ///   is one it already put its own evidence into;
    /// - the cursor is strictly inside the response window, the kernel's
    ///   own rule for a late answer;
    /// - and the certificate on this disk strictly exceeds what the
    ///   contest claims, or the one answer the window admits would buy
    ///   nothing.
    ///
    /// The certificate rides along because the answer is not a choice:
    /// these two values determine it, so every caller that derives the
    /// answer derives the same one.
    #[must_use]
    pub fn answerable_contest(&self) -> Option<(OpenContest, (EarnedCertificate, Sig))> {
        if self.role != Role::Provider || self.close_settled.is_some() {
            return None;
        }
        let contest = self.close_opened?;
        if contest.opener != Party::Maker || self.cursor.0 >= contest.response_deadline {
            return None;
        }
        let certificate = self
            .executable_certificate()
            .filter(|(certificate, _)| certificate.earned_cumulative() > contest.claimed)?;
        Some((contest, certificate))
    }

    /// Returns the finalized close of this channel's payment edge.
    #[must_use]
    pub const fn close_settled(&self) -> Option<CloseSettlement> {
        self.close_settled
    }

    /// Returns the largest certificate held, with the client signature
    /// that makes it spendable.
    ///
    /// The pair rather than the amount, because a close carries both:
    /// [`Self::max_executable_certificate`] answers "how much", and this
    /// answers "with what".
    #[must_use]
    pub fn executable_certificate(&self) -> Option<(EarnedCertificate, Sig)> {
        self.last_payment()
            .map(|payment| (payment.certificate, payment.certificate_signature))
    }

    /// Whether this channel is closing now.
    ///
    /// True while a close start of this endpoint's could still be
    /// included, and from the moment a contest is finalized on this
    /// edge or the edge is gone. It is the cutoff: while it holds, no
    /// job is admitted and no certificate is credited, because a close
    /// cannot carry what it did not know about.
    ///
    /// A start that can no longer be included is not a closing channel,
    /// and that is [`Self::includable_close_start`]'s judgement rather
    /// than a second one. The cursor is contiguous, so every block in
    /// that start's window was read: had it opened a contest,
    /// [`Self::close_opened`] would say so. It did not, it never will,
    /// and a channel shut for good by a signature that reached no block
    /// is a channel whose certificate can never be spent — the endpoint
    /// would have to close it to be paid, and closing is the thing it
    /// could no longer do.
    #[must_use]
    pub fn is_closing(&self) -> bool {
        self.close_opened.is_some()
            || self.close_settled.is_some()
            || self.includable_close_start(self.cursor.0).is_some()
    }

    fn refuse_if_closing(&self, step: &'static str) -> Result<(), ChannelStateError> {
        if self.is_closing() {
            return Err(ChannelStateError::Closing { step });
        }
        Ok(())
    }

    const fn client_key(&self) -> Key {
        self.channel.client_key()
    }

    const fn provider_key(&self) -> Key {
        self.channel.provider_key()
    }

    const fn network(&self) -> NetworkId {
        self.channel.network()
    }

    fn require_role(&self, step: &'static str, role: Role) -> Result<(), ChannelStateError> {
        if self.role == role {
            Ok(())
        } else {
            Err(ChannelStateError::WrongRole {
                step,
                expected: match role {
                    Role::Client => "client",
                    Role::Provider => "provider",
                },
            })
        }
    }

    fn open_job(&self, work_id: Digest, step: &'static str) -> Result<JobState, ChannelStateError> {
        if let Some(job) = self.jobs.get(&work_id) {
            return Ok(job.clone());
        }
        // A late reply to a finished job is refused as terminated rather
        // than as a phase error: the job is not merely absent, it is over
        // for good, and no step reopens it.
        if let Some(terminal) = self.terminals.get(&work_id) {
            return Err(ChannelStateError::Terminated {
                step,
                outcome: terminal.outcome.name(),
            });
        }
        Err(ChannelStateError::WrongPhase {
            step,
            phase: "none",
        })
    }

    fn refuse_if_terminated(
        &self,
        work_id: Digest,
        step: &'static str,
    ) -> Result<(), ChannelStateError> {
        match self.terminals.get(&work_id) {
            Some(terminal) => Err(ChannelStateError::Terminated {
                step,
                outcome: terminal.outcome.name(),
            }),
            None => Ok(()),
        }
    }

    /// Applies one record, or says why it may not be applied.
    ///
    /// Every rule this endpoint has is here, and replay runs it too, so
    /// a journal that could not have been written a record at a time is
    /// not read back whole.
    pub(super) fn apply<V: SigVerifier>(
        &mut self,
        record: &ChannelRecord,
        verifier: &V,
        metadata_only: bool,
    ) -> Result<Applied, ChannelStateError> {
        match record {
            ChannelRecord::CursorAdvanced {
                height,
                parent,
                payload,
            } => self.apply_cursor(*height, parent, payload),
            ChannelRecord::JobProposed {
                authorization,
                client_signature,
                prepared_input,
            } => self.apply_proposed(
                authorization,
                *client_signature,
                prepared_input,
                verifier,
                metadata_only,
            ),
            ChannelRecord::JobAccepted {
                work_id,
                provider_signature,
            } => self.apply_accepted(*work_id, *provider_signature, verifier),
            ChannelRecord::JobRunning { work_id } => self.apply_running(*work_id),
            ChannelRecord::JobResult {
                work_id,
                result,
                provider_signature,
                transcript,
            } => self.apply_result(
                *work_id,
                result,
                *provider_signature,
                transcript,
                verifier,
                metadata_only,
            ),
            ChannelRecord::PlaintextReleased { work_id } => self.apply_plaintext(*work_id),
            ChannelRecord::ResultMatched { work_id } => self.apply_matched(*work_id),
            ChannelRecord::JobTerminated { work_id, outcome } => {
                self.apply_terminated(*work_id, outcome, verifier)
            }
            ChannelRecord::ClosePrepared { start } => self.apply_close_prepared(start),
            ChannelRecord::CloseOpened {
                start_id,
                opener,
                response_deadline,
                claimed,
            } => self.apply_close_opened(OpenContest {
                start_id: *start_id,
                opener: *opener,
                response_deadline: *response_deadline,
                claimed: *claimed,
            }),
            ChannelRecord::CloseResponded {
                start_id,
                response_digest,
            } => self.apply_close_responded(RespondedContest {
                start_id: *start_id,
                response_digest: *response_digest,
            }),
            ChannelRecord::CloseSettled {
                height,
                payload,
                provider_payout,
            } => self.apply_close_settled(CloseSettlement {
                height: *height,
                payload: *payload,
                provider_payout: *provider_payout,
            }),
        }
    }

    /// Moves the cursor on by exactly one contiguous block.
    ///
    /// The rule itself is [`Self::reading`], which is asked twice about
    /// every block: once by the watcher before it records anything the
    /// block *means*, and once here when the cursor itself is written.
    /// One function, so the two askings cannot disagree about which
    /// block this journal may read next.
    fn apply_cursor(
        &mut self,
        height: u64,
        parent: &[u8; 32],
        payload: &[u8; 32],
    ) -> Result<Applied, ChannelStateError> {
        match self.reading(height, parent, payload)? {
            Applied::Redundant => Ok(Applied::Redundant),
            Applied::Changed => {
                self.cursor = (height, *payload);
                Ok(Applied::Changed)
            }
        }
    }

    /// Whether this journal may read `height`, and whether reading it
    /// moves the cursor.
    ///
    /// Two rules, and they are the whole of what a cursor means here.
    /// The height must be the next one, so nothing is skipped; and the
    /// block must name the held block as its parent, so the chain that
    /// was read is one chain. A watcher that fetched heights alone
    /// would accept a block from a history this endpoint never saw.
    ///
    /// The block already held is [`Applied::Redundant`] rather than a
    /// refusal: a watcher that died after recording what a block meant
    /// and before recording that it read it re-reads that same block,
    /// and every record it re-offers is the retry it is.
    ///
    /// # Errors
    ///
    /// [`ChannelStateError::CursorNotNext`] for any other height and
    /// [`ChannelStateError::CursorNotContiguous`] for the next height
    /// on another chain.
    pub(crate) fn reading(
        &self,
        height: u64,
        parent: &[u8; 32],
        payload: &[u8; 32],
    ) -> Result<Applied, ChannelStateError> {
        let (held_height, held_payload) = self.cursor;
        if (height, *payload) == (held_height, held_payload) {
            return Ok(Applied::Redundant);
        }
        if height != held_height.saturating_add(1) {
            return Err(ChannelStateError::CursorNotNext {
                held: held_height,
                actual: height,
            });
        }
        if *parent != held_payload {
            return Err(ChannelStateError::CursorNotContiguous { height });
        }
        Ok(Applied::Changed)
    }

    /// Retains this endpoint's own signed close start, and shuts the
    /// channel.
    ///
    /// A start already held is returned as the retry it is. A
    /// *different* start replaces it only when the cursor has passed
    /// the last height the held one could have been included at — and
    /// that is not an approximation of the three facts §12 asks a
    /// snapshot for, it is those facts. The cursor is contiguous, so
    /// every block up to it was read: had any contest opened on this
    /// edge, [`ChannelRecord::CloseOpened`] would be on this disk, and
    /// had the edge been closed, [`ChannelRecord::CloseSettled`] would
    /// be. Both refuse below. What remains — the held signature can no
    /// longer be included anywhere — is exactly what the cursor says.
    fn apply_close_prepared(
        &mut self,
        start: &PaymentCloseStart,
    ) -> Result<Applied, ChannelStateError> {
        if self.close_prepared.as_ref() == Some(start) {
            return Ok(Applied::Redundant);
        }
        if self.close_opened.is_some() || self.close_settled.is_some() {
            return Err(ChannelStateError::Closing {
                step: "signing a close start",
            });
        }
        if let Some(job) = self.jobs.values().next() {
            return Err(ChannelStateError::WrongPhase {
                step: "signing a close start",
                phase: job.phase.name(),
            });
        }
        // The start is about this channel, and it is this endpoint's to
        // sign. Only the beneficiary of a certificate can be the
        // provider, so a journal signing in the other role would be
        // building a close for the other party.
        self.check_close_start(start)?;
        let (cursor_height, _) = self.cursor;
        if self.includable_close_start(cursor_height).is_some() {
            return Err(ChannelStateError::Conflict {
                what: "a close start that can still be included",
            });
        }
        self.close_prepared = Some(start.clone());
        Ok(Applied::Changed)
    }

    /// Records the contest a finalized start opened, and who opened it.
    ///
    /// Refused once the edge is gone, and that is the rule that makes
    /// the watcher's ordering visible: a block carrying a start and the
    /// close that ends it is one history read in the validator's order
    /// and another read backwards, and only one of them is a history
    /// this journal takes.
    ///
    /// Refused too while a job is open, and that is the cutoff itself.
    /// Nothing after this record credits a certificate, so a job still
    /// in flight is a job that can no longer be paid for, and leaving
    /// it open would leave an endpoint holding a result it may still
    /// release for a payment that can never arrive. The watcher ends it
    /// first — see `work_close::observe` — and this refusal is what
    /// makes that the only order a journal can be written or replayed
    /// in.
    fn apply_close_opened(&mut self, contest: OpenContest) -> Result<Applied, ChannelStateError> {
        if self.close_opened == Some(contest) {
            return Ok(Applied::Redundant);
        }
        if self.close_settled.is_some() {
            return Err(ChannelStateError::Closing {
                step: "opening a close contest",
            });
        }
        if self.close_opened.is_some() {
            return Err(ChannelStateError::Conflict {
                what: "this edge's close contest",
            });
        }
        self.refuse_open_job("opening a close contest")?;
        self.close_opened = Some(contest);
        Ok(Applied::Changed)
    }

    /// Records the one answer this endpoint gives the open contest.
    ///
    /// The answer is checked, not taken on trust, and against the two
    /// things that fix it: [`Self::answerable_contest`] must still owe
    /// one — provider role, client opener, open window, a superior
    /// certificate — and the digest must be the one those two derive.
    /// An arbitrary digest accepted here would be worse than useless:
    /// it would say this contest is answered while the answer that
    /// actually spends the certificate is still unsent, and the journal
    /// would then refuse that answer as a disagreement.
    ///
    /// The same answer again is the retry it is: an endpoint that died
    /// between this write and the submission it authorises re-derives
    /// the answer from the contest and the certificate — both of which
    /// are frozen by [`Self::apply_close_opened`], which shuts the
    /// channel to new work — and offers exactly these bytes again. A
    /// *different* answer to the same contest is refused, because the
    /// window admits one and a second would be this endpoint disagreeing
    /// with itself about what it already sent.
    fn apply_close_responded(
        &mut self,
        answer: RespondedContest,
    ) -> Result<Applied, ChannelStateError> {
        if self.close_responded == Some(answer) {
            return Ok(Applied::Redundant);
        }
        if self.close_responded.is_some() {
            return Err(ChannelStateError::Conflict {
                what: "this contest's answer",
            });
        }
        self.require_role("answering a close contest", Role::Provider)?;
        if self.close_settled.is_some() {
            return Err(ChannelStateError::Closing {
                step: "answering a close contest",
            });
        }
        let Some((contest, certificate)) = self.answerable_contest() else {
            return Err(ChannelStateError::WrongPhase {
                step: "answering a close contest",
                phase: "owed no answer",
            });
        };
        if contest.start_id != answer.start_id {
            return Err(ChannelStateError::WrongChannel {
                field: "close response start_id",
            });
        }
        if answer.response_digest
            != crate::work_close::response_body_digest(
                &self.channel,
                answer.start_id,
                &certificate.0,
            )
        {
            return Err(ChannelStateError::WrongChannel {
                field: "close response digest",
            });
        }
        self.close_responded = Some(answer);
        Ok(Applied::Changed)
    }

    /// Records the close that consumed this edge.
    ///
    /// It refuses an open job for the reason above, and it is a
    /// separate arrival rather than a consequence of one: a cooperative
    /// freeze consumes the edge with no contest in front of it, so this
    /// is reachable without [`Self::apply_close_opened`] ever running.
    fn apply_close_settled(
        &mut self,
        settlement: CloseSettlement,
    ) -> Result<Applied, ChannelStateError> {
        if self.close_settled == Some(settlement) {
            return Ok(Applied::Redundant);
        }
        if self.close_settled.is_some() {
            return Err(ChannelStateError::Conflict {
                what: "this edge's close",
            });
        }
        self.refuse_open_job("closing the payment edge")?;
        self.close_settled = Some(settlement);
        Ok(Applied::Changed)
    }

    fn refuse_open_job(&self, step: &'static str) -> Result<(), ChannelStateError> {
        match self.jobs.values().next() {
            Some(job) => Err(ChannelStateError::WrongPhase {
                step,
                phase: job.phase.name(),
            }),
            None => Ok(()),
        }
    }

    /// Checks one authorization and its inputs against the channel this
    /// journal is.
    ///
    /// One spelling, asked when the proposal arrives and again when a
    /// checkpoint carrying the open job is opened. The rest of the
    /// authorization's rules — the policy digest, the deadlines, the
    /// price against the finalized height — are `check_authorization`'s,
    /// and a second spelling of them here would be a second chance to
    /// spell them differently.
    fn check_authorization(
        &self,
        authorization: &PaidJobAuthorizationV1,
        prepared_input: &[u8],
        metadata_only: bool,
    ) -> Result<(), ChannelStateError> {
        let terms = self.channel.payment_terms();
        for (field, holds) in [
            (
                "channel_id",
                authorization.channel_id.as_bytes() == self.channel.id().as_bytes(),
            ),
            (
                "payment_edge",
                authorization.payment_edge == self.channel.payment_edge(),
            ),
            (
                "payment_terms_hash",
                authorization.payment_terms_hash == self.channel.payment_terms_hash(),
            ),
            ("bond_edge", authorization.bond_edge == terms.bond_edge),
            (
                "bond_terms_hash",
                authorization.bond_terms_hash == terms.bond_terms_hash(),
            ),
        ] {
            if !holds {
                return Err(ChannelStateError::WrongChannel { field });
            }
        }

        // The inputs this job will be executed from, against the digest
        // the authorization both parties sign commits to. A bundle that
        // does not hash to it is a job neither party agreed to run.
        if metadata_only {
            return if prepared_input.is_empty() {
                Ok(())
            } else {
                Err(ChannelStateError::Malformed)
            };
        }
        let bundle = PreparedPaidWorkInput::decode(prepared_input, MAX_RECORD_BYTES)
            .map_err(PaidWorkError::from)?;
        if bundle.digest(&self.channel)?.as_bytes()
            != authorization.prepared_input_digest.as_bytes()
        {
            return Err(ChannelStateError::Record(PaidWorkError::Mismatch {
                field: "prepared_input_digest",
            }));
        }
        Ok(())
    }

    /// Checks one retained close start against the channel and role it
    /// was signed for.
    ///
    /// One spelling, asked when the start is signed and again when a
    /// checkpoint carrying it is opened. It does not ask whether the
    /// start may still be *included* — that is the cursor's judgement
    /// and it moves — only whether it is this endpoint's start for this
    /// channel over the certificate this journal holds.
    fn check_close_start(&self, start: &PaymentCloseStart) -> Result<(), ChannelStateError> {
        for (field, holds) in [
            (
                "close start payment_edge",
                start.payment_edge() == self.channel.payment_edge(),
            ),
            (
                "close start payment_terms_hash",
                start.terms().hash() == self.channel.payment_terms_hash(),
            ),
            (
                "close start opener_role",
                start.opener_role()
                    == match self.role {
                        Role::Client => Party::Maker,
                        Role::Provider => Party::Taker,
                    },
            ),
            (
                "close start certificate",
                start.certificate().copied() == self.executable_certificate(),
            ),
        ] {
            if !holds {
                return Err(ChannelStateError::WrongChannel { field });
            }
        }
        Ok(())
    }

    fn apply_proposed<V: SigVerifier>(
        &mut self,
        authorization: &PaidJobAuthorizationV1,
        client_signature: Sig,
        prepared_input: &[u8],
        verifier: &V,
        metadata_only: bool,
    ) -> Result<Applied, ChannelStateError> {
        let work_id = work_id(&self.channel, authorization);
        if let Some(job) = self.jobs.get(&work_id) {
            if job.authorization == *authorization
                && job.client_signature == client_signature
                && job.prepared_input == prepared_input
            {
                return Ok(Applied::Redundant);
            }
            return Err(ChannelStateError::WrongPhase {
                step: "proposing a job",
                phase: job.phase.name(),
            });
        }
        self.refuse_if_terminated(work_id, "proposing a job")?;
        // A closing channel takes no new work. The close is built from
        // what is held now, so a job admitted after it would be a job
        // whose payment no close could carry.
        self.refuse_if_closing("proposing a job")?;

        self.check_authorization(authorization, prepared_input, metadata_only)?;
        if authorization.proposal_nonce <= self.proposal_nonce_high_water {
            return Err(ChannelStateError::WrongChannel {
                field: "proposal_nonce",
            });
        }
        if !verifier.verify_sig(client_signature, self.client_key(), signing_hash(work_id)) {
            return Err(ChannelStateError::BadSignature {
                slot: "authorization",
                party: "the client",
            });
        }

        // Compute credit is the provider's exposure and only the
        // provider's: the client is the party that would default on it.
        // The provider checks the one job's price against its limit
        // before it co-signs; there is no cross-job total to accumulate,
        // because there is no second job.
        if self.role == Role::Provider {
            self.check_compute_limit(authorization.price)?;
        }

        self.jobs.insert(
            work_id,
            JobState {
                authorization: *authorization,
                work_id,
                prepared_input: prepared_input.to_vec(),
                client_signature,
                provider_signature: None,
                phase: JobPhase::HalfSigned,
                result: None,
                transcript: Vec::new(),
            },
        );
        self.proposal_nonce_high_water = authorization.proposal_nonce;
        Ok(Applied::Changed)
    }

    fn apply_accepted<V: SigVerifier>(
        &mut self,
        work_id: Digest,
        provider_signature: Sig,
        verifier: &V,
    ) -> Result<Applied, ChannelStateError> {
        let mut job = self.open_job(work_id, "co-signing a job")?;
        if job.provider_signature == Some(provider_signature) {
            return Ok(Applied::Redundant);
        }
        if job.phase != JobPhase::HalfSigned {
            return Err(ChannelStateError::WrongPhase {
                step: "co-signing a job",
                phase: job.phase.name(),
            });
        }
        let (height, _) = self.cursor;
        // The provider must journal its signature before the deadline. The
        // client may recover that already released signature after a lost
        // response; recording evidence does not authorize new provider work.
        if self.role == Role::Provider && height > job.authorization.acceptance_deadline {
            return Err(ChannelStateError::AcceptanceLate {
                height,
                deadline: job.authorization.acceptance_deadline,
            });
        }
        if !verifier.verify_sig(
            provider_signature,
            self.provider_key(),
            signing_hash(job.work_id),
        ) {
            return Err(ChannelStateError::BadSignature {
                slot: "authorization",
                party: "the provider",
            });
        }
        job.provider_signature = Some(provider_signature);
        job.phase = JobPhase::Accepted;
        self.jobs.insert(work_id, job);
        Ok(Applied::Changed)
    }

    fn apply_running(&mut self, work_id: Digest) -> Result<Applied, ChannelStateError> {
        self.require_role("a running marker", Role::Provider)?;
        let mut job = self.open_job(work_id, "a running marker")?;
        match job.phase {
            JobPhase::Running | JobPhase::Streaming => return Ok(Applied::Redundant),
            JobPhase::Accepted => {}
            phase => {
                return Err(ChannelStateError::WrongPhase {
                    step: "a running marker",
                    phase: phase.name(),
                });
            }
        }
        let (height, _) = self.cursor;
        if height > job.authorization.terminal_deadline {
            return Err(ChannelStateError::DispatchLate {
                height,
                deadline: job.authorization.terminal_deadline,
            });
        }
        job.phase = JobPhase::Running;
        self.jobs.insert(work_id, job);
        Ok(Applied::Changed)
    }

    /// Records the provider's signed result and the transcript it
    /// summarises.
    ///
    /// The rule that makes this more than a signature check is the
    /// reproduction below: [`hellas_rpc::protocol::work::terminal_result`] is handed the stored
    /// events and this job's own authorization, and what it builds must
    /// be the result byte for byte. That establishes, on commit and on
    /// every replay, that the events are one verified signed chain for
    /// the request both parties authorized, under the key this channel
    /// calls the provider, and that both digests in the result are that
    /// chain's own.
    ///
    /// It subsumes a separate `result.work_id == job.work_id` check,
    /// which is why there is not one: the work id is a field of what is
    /// rebuilt, so a result naming another job cannot equal it.
    fn apply_result<V: SigVerifier>(
        &mut self,
        work_id: Digest,
        result: &PaidJobResultV1,
        provider_signature: Sig,
        transcript: &[u8],
        verifier: &V,
        metadata_only: bool,
    ) -> Result<Applied, ChannelStateError> {
        let mut job = self.open_job(work_id, "recording a result")?;
        if let Some((held, signature)) = &job.result {
            if held == result && *signature == provider_signature && job.transcript == transcript {
                return Ok(Applied::Redundant);
            }
            return Err(ChannelStateError::Conflict {
                what: "this job's result",
            });
        }
        // A running marker proves only that the backend may have been
        // invoked. If this process did not make that invocation, no
        // result it could produce now is evidence about it.
        if self.indeterminate.contains_key(&work_id) {
            return Err(ChannelStateError::Indeterminate);
        }
        // The provider may only record a result for an invocation it
        // marked; the client never sees that marker, and records the
        // result it was sent against the job it accepted.
        let expected = match self.role {
            Role::Provider => JobPhase::Running,
            Role::Client => JobPhase::Accepted,
        };
        if job.phase != expected
            && !(self.role == Role::Provider && job.phase == JobPhase::Streaming)
        {
            return Err(ChannelStateError::WrongPhase {
                step: "recording a result",
                phase: job.phase.name(),
            });
        }

        // A result is owed by a height, and both roles are bounded by
        // it. The height is this journal's own cursor, so what it
        // measures is when this endpoint had *processed* a block, not
        // when a peer said one existed; how fresh that cursor is stays
        // the caller's, in the sense `ReadyChannel` already documents.
        //
        // The provider is bounded here for the reason the client is,
        // read from the other side: a result recorded past the terminal
        // deadline is one the client's own journal will refuse a
        // receipt for, so it can never be paid for — and recording it
        // anyway would make it a result the ending ledger charges this
        // client for. Late compute is the provider's own loss, and this
        // is where that is decided.
        let (height, _) = self.cursor;
        if height > job.authorization.terminal_deadline {
            return Err(ChannelStateError::ReceiptLate {
                height,
                deadline: job.authorization.terminal_deadline,
            });
        }

        self.check_result_payload(&job, result, transcript, metadata_only)?;
        if !verifier.verify_sig(
            provider_signature,
            self.provider_key(),
            signing_hash(result_digest(&self.channel, result)),
        ) {
            return Err(ChannelStateError::BadSignature {
                slot: "result",
                party: "the provider",
            });
        }
        job.result = Some((*result, provider_signature));
        job.transcript = transcript.to_vec();
        job.phase = if job.phase == JobPhase::Streaming {
            JobPhase::Delivered
        } else {
            JobPhase::Ready
        };
        self.jobs.insert(work_id, job);
        Ok(Applied::Changed)
    }

    /// Records that this client's own re-execution reproduced the answer
    /// and it matched.
    ///
    /// It checks that there is a delivered result to have an opinion
    /// about and that this journal is a client's. What it cannot check is
    /// the reproduction itself: the engine is the caller's, and this
    /// records a decision rather than making one. That is why matching is
    /// a step of its own rather than a flag on the result — a receipt is
    /// timely or late whatever a re-execution later says, and the two are
    /// decided at different heights.
    fn apply_matched(&mut self, work_id: Digest) -> Result<Applied, ChannelStateError> {
        self.require_role("recording a reproduction match", Role::Client)?;
        let mut job = self.open_job(work_id, "recording a reproduction match")?;
        match job.phase {
            JobPhase::Matched => return Ok(Applied::Redundant),
            JobPhase::Ready => {}
            phase => {
                return Err(ChannelStateError::WrongPhase {
                    step: "recording a reproduction match",
                    phase: phase.name(),
                });
            }
        }
        job.phase = JobPhase::Matched;
        self.jobs.insert(work_id, job);
        Ok(Applied::Changed)
    }

    fn apply_plaintext(&mut self, work_id: Digest) -> Result<Applied, ChannelStateError> {
        self.require_role("releasing plaintext", Role::Provider)?;
        let mut job = self.open_job(work_id, "releasing plaintext")?;
        if job.phase.delivered() {
            return Ok(Applied::Redundant);
        }
        if !matches!(job.phase, JobPhase::Ready | JobPhase::Running) {
            return Err(ChannelStateError::WrongPhase {
                step: "releasing plaintext",
                phase: job.phase.name(),
            });
        }
        self.check_delivery_limit(job.authorization.price)?;
        job.phase = if job.phase == JobPhase::Running {
            JobPhase::Streaming
        } else {
            JobPhase::Delivered
        };
        self.jobs.insert(work_id, job);
        Ok(Applied::Changed)
    }

    /// Records the permanent terminal for the named job.
    ///
    /// One function for all five outcomes, because they are one decision:
    /// each job ends once, and the record that ends it is the
    /// only thing that ever fills the terminal. [`TerminalOutcome::Certified`]
    /// is the join with consensus — the certificate is money, the binding
    /// is what the money bought — and the other four are the ways a job
    /// stops without one.
    fn apply_terminated<V: SigVerifier>(
        &mut self,
        work_id: Digest,
        outcome: &TerminalOutcome,
        verifier: &V,
    ) -> Result<Applied, ChannelStateError> {
        // The terminal already written, offered again. This is the crash
        // between writing it and acting on it: the job is closed, and
        // re-committing the same outcome must be the retry it is rather
        // than a second job's terminal or a step a closed job cannot
        // take. Answered before the open-job rule below for that reason.
        if let Some(held) = self.terminals.get(&work_id) {
            if held.outcome == *outcome {
                return Ok(Applied::Redundant);
            }
            return Err(ChannelStateError::Terminated {
                step: "terminating the job",
                outcome: held.outcome.name(),
            });
        }
        if matches!(outcome, TerminalOutcome::Certified { .. }) && !self.jobs.contains_key(&work_id)
        {
            return Err(ChannelStateError::WrongChannel {
                field: "binding work_id",
            });
        }
        let job = self.open_job(work_id, "terminating the job")?;
        match outcome {
            TerminalOutcome::Certified {
                certificate,
                binding,
                binding_signature,
                certificate_signature,
            } => self.terminate_certified(
                &job,
                certificate,
                binding,
                *binding_signature,
                *certificate_signature,
                verifier,
            ),
            TerminalOutcome::Refuted {
                result_digest: named,
                reproduction_digest,
            } => {
                self.require_role("refuting a result", Role::Client)?;
                if job.phase != JobPhase::Ready {
                    return Err(ChannelStateError::WrongPhase {
                        step: "refuting a result",
                        phase: job.phase.name(),
                    });
                }
                let Some((result, _)) = &job.result else {
                    return Err(ChannelStateError::WrongPhase {
                        step: "refuting a result",
                        phase: job.phase.name(),
                    });
                };
                // The refuted digest is this job's own signed result's,
                // not a number the record chose: a refutation is a
                // statement about the result the delivery recorded.
                if named.as_bytes() != result_digest(&self.channel, result).as_bytes() {
                    return Err(ChannelStateError::WrongChannel {
                        field: "refuted result_digest",
                    });
                }
                self.rest_at(JobTerminal {
                    work_id: job.work_id,
                    phase: job.phase,
                    outcome: TerminalOutcome::Refuted {
                        result_digest: *named,
                        reproduction_digest: *reproduction_digest,
                    },
                });
                Ok(Applied::Changed)
            }
            TerminalOutcome::Expired { .. }
            | TerminalOutcome::Failed { .. }
            | TerminalOutcome::Indeterminate => {
                self.rest_at(JobTerminal {
                    work_id: job.work_id,
                    phase: job.phase,
                    outcome: outcome.clone(),
                });
                Ok(Applied::Changed)
            }
        }
    }

    /// Credits one client payment and rests the job at a certified
    /// terminal.
    fn terminate_certified<V: SigVerifier>(
        &mut self,
        job: &JobState,
        certificate: &EarnedCertificate,
        binding: &PaymentBindingV1,
        binding_signature: Sig,
        certificate_signature: Sig,
        verifier: &V,
    ) -> Result<Applied, ChannelStateError> {
        // A provider credits only plaintext it released. A client may
        // pay an authenticated result as soon as it is durably Ready;
        // Matched remains the stronger, opt-in local-reexecution state.
        let payable = match self.role {
            Role::Provider => job.phase == JobPhase::Delivered,
            Role::Client => matches!(job.phase, JobPhase::Ready | JobPhase::Matched),
        };
        if !payable {
            return Err(ChannelStateError::WrongPhase {
                step: "crediting a payment",
                phase: job.phase.name(),
            });
        }
        let Some((result, _)) = job.result else {
            // Unreachable: both phases above are phases a result was
            // recorded to reach. It is a refusal rather than an `expect`
            // because nothing here panics on stored state.
            return Err(ChannelStateError::WrongPhase {
                step: "crediting a payment",
                phase: job.phase.name(),
            });
        };

        // A client pays by the height it signed to pay by, and this is
        // the last step where refusing costs it nothing. Past that height
        // the provider may end the job as expired and bear its cost
        // itself; a certificate signed afterwards is money the provider
        // can still close on. The provider is not bounded here: what
        // stops it crediting a late payment is that the job's terminal
        // is the only step left, and whichever terminal reaches the disk
        // first is the one that happened.
        if self.role == Role::Client {
            let (height, _) = self.cursor;
            if height > job.authorization.payment_deadline {
                return Err(ChannelStateError::PaymentLate {
                    height,
                    deadline: job.authorization.payment_deadline,
                });
            }
        }
        for (slot, signature, hash) in [
            (
                "binding",
                binding_signature,
                signing_hash(payment_binding_digest(&self.channel, binding)),
            ),
            (
                "certificate",
                certificate_signature,
                certificate.digest(self.network()),
            ),
        ] {
            if !verifier.verify_sig(signature, self.client_key(), hash) {
                return Err(ChannelStateError::BadSignature {
                    slot,
                    party: "the client",
                });
            }
        }

        // The rule that joins the private evidence to the one number
        // consensus sees. It runs here, on commit and on replay both,
        // over the job this journal itself recorded.
        self.ledger.credit_payment(
            &self.channel,
            &job.authorization,
            &result,
            binding,
            certificate,
            self.settlement,
        )?;

        self.rest_at(JobTerminal {
            work_id: job.work_id,
            phase: job.phase,
            outcome: TerminalOutcome::Certified {
                certificate: *certificate,
                binding: Box::new(*binding),
                binding_signature,
                certificate_signature,
            },
        });
        Ok(Applied::Changed)
    }

    /// Installs this channel's one permanent terminal and closes the job.
    fn rest_at(&mut self, terminal: JobTerminal) {
        let work_id = terminal.work_id;
        self.jobs.remove(&work_id);
        self.indeterminate.remove(&work_id);
        self.terminals.insert(work_id, terminal);
    }

    /// Checks the one job's price against the compute limit.
    ///
    /// There is no cross-job total to accumulate: the channel admits one
    /// job, so a price that fits the limit is the whole of what fits.
    fn check_compute_limit(&self, price: u64) -> Result<(), ChannelStateError> {
        let limit = self.channel.channel_policy().compute_credit_limit;
        let reserved = self
            .jobs
            .values()
            .map(|job| job.authorization.price)
            .fold(0_u64, u64::saturating_add);
        if reserved.saturating_add(price) > limit {
            return Err(ChannelStateError::OverCredit {
                ledger: "compute",
                used: 0,
                reserved,
                price,
                limit,
            });
        }
        Ok(())
    }

    /// Checks the one job's price against the delivery limit.
    fn check_delivery_limit(&self, price: u64) -> Result<(), ChannelStateError> {
        let limit = self.channel.channel_policy().delivery_credit_limit;
        let reserved = self
            .jobs
            .values()
            .filter(|job| job.phase.delivered())
            .map(|job| job.authorization.price)
            .fold(0_u64, u64::saturating_add);
        if reserved.saturating_add(price) > limit {
            return Err(ChannelStateError::OverCredit {
                ledger: "delivery",
                used: 0,
                reserved,
                price,
                limit,
            });
        }
        Ok(())
    }
}
