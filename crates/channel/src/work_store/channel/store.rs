use super::*;

/// The durable channel journal: the state above and the file it is
/// replayed from.
pub struct ChannelStore {
    journal: Journal,
    pub(super) state: Channel,
    pub(super) contents: BTreeMap<
        Digest,
        (
            hellas_store::content::LocalStore,
            hellas_store::content::Scope,
        ),
    >,
    pub(super) content: hellas_store::content::DiskStore,
}

impl std::fmt::Debug for ChannelStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelStore")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl ChannelStore {
    /// Finish provider unaccepted content cleanup and release the journal writer.
    /// The host must first stop observers and execution; retained roots stay pinned.
    pub async fn close(&mut self) -> Result<(), WorkStoreError> {
        let pending = self
            .contents
            .iter()
            .filter(|_| self.state.role == Role::Provider)
            .filter_map(|(work, (_, scope))| {
                if let hellas_store::content::ScopeKind::Work { reservation, .. } = scope.kind {
                    Some((*work, reservation))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let mut result = Ok(());
        for (work, reservation) in pending {
            result = result.and(self.discard_unaccepted_content(work, reservation).await);
        }
        self.journal.close().await;
        result
    }

    pub(crate) fn check_authority(&self) -> Result<(), WorkStoreError> {
        self.journal.check_authority()?;
        Ok(())
    }

    /// Opens one channel's journal, replaying and re-checking every
    /// record it holds.
    ///
    /// `settlement` is what the funded payment edge can settle, taken
    /// from the finalized read that established the channel is live. It
    /// is a channel constant: a payment edge's value is fixed when it is
    /// opened, and every payment this store admits is bounded by it.
    ///
    /// `origin` is where the channel begins: the finalized block that
    /// carried its payment Open, which the setup handshake recorded.
    /// The cursor starts there rather than at nothing, and that is the
    /// whole of why it is required. A store that began with no cursor
    /// would have its watcher anchor at whatever height it first
    /// caught up to — skipping every block between the channel opening
    /// and that catch-up, and with them every close and every payment
    /// those blocks carried. The origin's payment edge must be this
    /// channel's, so the height cannot be another channel's.
    ///
    /// A job left in its running phase by the process that did not come
    /// back makes the state indeterminate. Opening does not resolve it,
    /// does not invoke anything, and refuses a result for it.
    ///
    /// # Errors
    ///
    /// [`WorkStoreError::Journal`] when a file is held, corrupt, or
    /// another journal, and [`WorkStoreError::Channel`] when the origin
    /// is another channel's or a replayed record does not obey the
    /// transition rules.
    pub async fn open<V: SigVerifier>(
        root: &Path,
        channel: PaidChannel,
        settlement: WorkPaymentSettlement,
        role: Role,
        origin: SetupOrigin,
        content: hellas_store::content::DiskStore,
        verifier: &V,
    ) -> Result<Self, WorkStoreError> {
        Self::open_inner(
            root,
            channel,
            Some(settlement),
            role,
            Some(origin),
            content,
            verifier,
            false,
        )
        .await?
        .ok_or_else(|| ChannelStateError::Malformed.into())
    }

    /// Replays an initialized channel without creating an empty replacement.
    /// Settlement callers must never forget a previously signed payment.
    pub async fn open_existing<V: SigVerifier>(
        root: &Path,
        channel: PaidChannel,
        settlement: WorkPaymentSettlement,
        role: Role,
        origin: SetupOrigin,
        content: hellas_store::content::DiskStore,
        verifier: &V,
    ) -> Result<Self, WorkStoreError> {
        Self::open_inner(
            root,
            channel,
            Some(settlement),
            role,
            Some(origin),
            content,
            verifier,
            true,
        )
        .await?
        .ok_or_else(|| ChannelStateError::Malformed.into())
    }

    /// Recover the journal's initialized funding binding without a chain read.
    /// Missing journals and empty pre-initialization headers carry no channel effects.
    pub async fn recover<V: SigVerifier>(
        root: &Path,
        channel: PaidChannel,
        role: Role,
        content: hellas_store::content::DiskStore,
        verifier: &V,
    ) -> Result<Option<Self>, WorkStoreError> {
        match Self::open_inner(root, channel, None, role, None, content, verifier, true).await {
            Err(WorkStoreError::Journal(JournalError::Missing { .. })) => Ok(None),
            result => result,
        }
    }

    pub fn journal_key(channel: &PaidChannel) -> [u8; 32] {
        channel_key(channel).into_bytes()
    }

    #[allow(clippy::too_many_arguments)]
    async fn open_inner<V: SigVerifier>(
        root: &Path,
        channel: PaidChannel,
        settlement: Option<WorkPaymentSettlement>,
        role: Role,
        origin: Option<SetupOrigin>,
        content: hellas_store::content::DiskStore,
        verifier: &V,
        existing: bool,
    ) -> Result<Option<Self>, WorkStoreError> {
        content.claim_work().await?;
        if origin.is_some_and(|origin| origin.payment_edge != channel.payment_edge()) {
            return Err(ChannelStateError::WrongChannel {
                field: "setup origin payment_edge",
            }
            .into());
        }
        let key = channel_key(&channel).into_bytes();
        let stem = format!("channel-{}", hex(key));
        let replayed = hellas_rpc::observe::Timing::start();
        let id = JournalId {
            kind: JournalKind::Channel,
            role,
            key,
        };
        let (mut journal, replay) = if existing {
            Journal::open_existing(root, &stem, id, content.durability()).await?
        } else {
            Journal::open_latest(root, &stem, id, content.durability()).await?
        };
        let mut state = match &replay.checkpoint {
            Some(bytes) => {
                let settlement = match settlement {
                    Some(settlement) => settlement,
                    None => Channel::checkpoint_settlement(bytes, &channel)?,
                };
                Channel::from_checkpoint(bytes, channel, settlement, role, verifier)?
            }
            None if !replay.records.is_empty() => return Err(ChannelStateError::Malformed.into()),
            None => {
                let Some(settlement) = settlement else {
                    return Ok(None);
                };
                let origin = origin.ok_or(ChannelStateError::Malformed)?;
                let state = Channel::new(channel, settlement, role, origin);
                // Persist the actual funding binding before any channel effect.
                journal.rotate(&state.checkpoint_for_storage()).await?;
                state
            }
        };
        for bytes in &replay.records {
            let record = ChannelRecord::decode(bytes)?;
            state.apply(&record, verifier, true)?;
        }
        state.book.indeterminate = state
            .book
            .jobs
            .values()
            .filter(|job| matches!(job.phase, JobPhase::Running | JobPhase::Streaming))
            .map(|job| job.work_id)
            .collect();
        journal.observe_replay(replayed, replay.records.len());
        let mut store = Self {
            journal,
            state,
            content,
            contents: BTreeMap::new(),
        };
        // A journal reopened past a deadline must not keep an active job the
        // watcher would have ended on the block that crossed it. A crash can
        // land between the cursor record and the expiry, and a process from
        // before a conclusive rule existed may have advanced past a deadline
        // it never applied. The cursor block is the last finalized height
        // this endpoint read, so it is what says the job is over now.
        let (height, payload) = store.state().cursor();
        for (work_id, outcome) in crate::work_close::expiry_at(store.state(), height, payload) {
            store
                .commit(ChannelRecord::JobTerminated { work_id, outcome }, verifier)
                .await?;
        }
        store.restore_content().await?;
        store.release_unresumable_proposal(verifier).await?;
        store.reconcile_content(false).await?;
        Ok(Some(store))
    }

    /// Releases a pending proposal this journal can no longer send.
    ///
    /// A proposal is resumable only from the exact bytes it was signed over.
    /// Ephemeral input is never journaled, and retained input can be sent
    /// only when its whole upload closure survived. When neither holds, the
    /// marker would refuse every later proposal forever while the job it
    /// names can never leave its half-signed phase except by expiry.
    /// Clearing the marker is a durable exchange record: the nonce stays
    /// burned and the job stays open for a late acceptance, so this frees
    /// the channel's one proposal slot without deciding that the provider
    /// owes or is owed anything.
    async fn release_unresumable_proposal<V: SigVerifier>(
        &mut self,
        verifier: &V,
    ) -> Result<(), WorkStoreError> {
        if self.state.role() != Role::Client {
            return Ok(());
        }
        let Some(work_id) = self.state.job_book().pending_proposal() else {
            return Ok(());
        };
        let Some(job) = self.state.job_by_id(work_id) else {
            return Ok(());
        };
        if job.phase() != JobPhase::HalfSigned || self.recoverable_content(work_id)?.is_some() {
            return Ok(());
        }
        self.commit(
            ChannelRecord::ProposalExchange {
                work_id,
                pending: false,
            },
            verifier,
        )
        .await?;
        Ok(())
    }

    /// Returns what this endpoint durably knows.
    #[must_use]
    pub const fn state(&self) -> &Channel {
        &self.state
    }

    /// Reinstalls caller-supplied bytes in memory after metadata-only replay.
    /// The retained authorization authenticates every byte; no body is appended.
    pub(crate) fn restore_client_input(
        &mut self,
        work_id: Digest,
        bytes: Vec<u8>,
    ) -> Result<(), WorkStoreError> {
        if self.state.role() != Role::Client {
            return Err(ChannelStateError::Malformed.into());
        }
        self.state.restore_input(work_id, bytes.into())?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn pause_next_statement_for_test(
        &mut self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        self.journal.pause_next_statement().await
    }

    /// Journals one committed step under the configured durability policy.
    ///
    /// The rule this exists to enforce: call it *before* the bytes it
    /// records leave the process, and before the side effect it
    /// authorises happens. A record the state already holds is not
    /// written twice, so retrying after a crash between the write and
    /// the release costs nothing and changes nothing.
    ///
    /// # Errors
    ///
    /// [`WorkStoreError::Channel`] when the step is not one this state
    /// may take — checked before anything is written — and
    /// [`WorkStoreError::Journal`] when an append or its sync fails.
    pub fn commit<'a, V: SigVerifier>(
        &'a mut self,
        record: ChannelRecord,
        verifier: &V,
    ) -> impl std::future::Future<Output = Result<&'a Channel, WorkStoreError>> {
        self.commit_with_input(record, None, verifier)
    }

    pub(crate) fn commit_with_input<'a, V: SigVerifier>(
        &'a mut self,
        mut record: ChannelRecord,
        supplied: Option<&'a PreparedInvocation>,
        verifier: &V,
    ) -> impl std::future::Future<Output = Result<&'a Channel, WorkStoreError>> {
        // Like SetupStore::commit, own the validated candidate and content I/O
        // in this journal boundary rather than every setup/settlement poll frame.
        Box::pin(async move {
            self.check_authority()?;
            if let ChannelRecord::JobResult { work_id, .. }
            | ChannelRecord::ResultVerified { work_id } = &record
            {
                if let Some(input) = supplied {
                    let job = self
                        .state()
                        .job_by_id(*work_id)
                        .ok_or(ChannelStateError::Malformed)?;
                    let policy =
                        InvocationPolicy::from_canonical_bytes(input.application_policy.as_bytes())
                            .map_err(PaidWorkError::from)
                            .map_err(ChannelStateError::from)?;
                    let facts = crate::job::check_paid_input(
                        self.state().channel(),
                        job.authorization(),
                        &policy,
                        input,
                    )
                    .map_err(ChannelStateError::from)?;
                    if self.state().retained_roots().contains_key(work_id)
                        && let Some(job) = self.state.book.jobs.get_mut(work_id)
                    {
                        job.prepared_input = bytes::Bytes::new();
                    }
                    if matches!(record, ChannelRecord::ResultVerified { .. }) {
                        self.load_retained_transcript(*work_id, facts.max_spool_bytes, false)
                            .await?;
                    }
                } else {
                    self.load_retained_content(*work_id).await?;
                }
            }
            self.reconcile_content(false).await?;
            let staged = self.prepare_record(&mut record)?;
            // Applied to a copy first: a record the rules refuse must leave
            // neither the file nor the state touched. A cheap exact check
            // first: the stream replay path offers a redundant release per
            // emitted frame, and the copy would clone the whole transcript.
            if self.state.is_redundant(&record) {
                return Ok(&self.state);
            }
            let previous_jobs = self.state.jobs().count();
            let mut next = self.state.clone();
            // The `false` keeps commit-time validation at full strength even
            // for a metadata-only journal: bodies are verified — digest and
            // transcript-to-result authentication — before they are stripped
            // from the bytes written. Only replay and checkpoint validation
            // downgrade for body-less records.
            if next.apply_with_input(&record, verifier, false, supplied)? == Applied::Changed {
                // The signature this record carries leaves after this
                // returns, so the state that authorises it has to be one a
                // rotation can still carry. The proposed job is charged the
                // fixed tail it can still add — the result it will be
                // answered with and the terminal that pays for it — because
                // by then there is no refusal left that costs nothing.
                if let Some(tail) = record.checkpoint_tail() {
                    let len = next.checkpoint_for_storage().len().saturating_add(tail);
                    if len > MAX_CHECKPOINT_BYTES {
                        return Err(JournalError::CheckpointTooLarge { len }.into());
                    }
                }
                self.rotate_if_full(record.is_new_work()).await?;
                self.stage_record(&record, staged).await?;
                self.journal.append(&record.encode_for_storage()).await?;
                self.state = next;
                self.reconcile_content(false).await?;
                if self.state.jobs().count() < previous_jobs {
                    self.rotate().await?;
                }
            }
            self.reconcile_content(false).await?;
            Ok(&self.state)
        })
    }

    /// Moves the journal on to its next generation, carrying this state
    /// as its first frame.
    ///
    /// What [`Self::commit`] does for itself at the soft limit, and what
    /// an operator may ask for at any time. It is the step that makes a
    /// close duty outlive the file it is written in: the successor's
    /// first frame is everything the predecessor said, so the
    /// predecessor's bytes go and none of its facts do.
    ///
    /// # Errors
    ///
    /// [`WorkStoreError::Journal`] when the checkpoint does not fit one
    /// frame or an install step fails.
    pub async fn rotate(&mut self) -> Result<(), WorkStoreError> {
        self.journal
            .rotate(&self.state.checkpoint_for_storage())
            .await?;
        Ok(())
    }

    /// Rotates at the soft limit, and decides who may go on without it.
    ///
    /// New work stops when a rotation cannot complete, because admitting
    /// it would be promising a duty this journal has no room to finish.
    /// A duty already exported can use the reserve after a rotation refused
    /// before writing. [`Journal::append`] still refuses after a failed write,
    /// until replay, or once the generation's reserve is exhausted.
    async fn rotate_if_full(&mut self, new_work: bool) -> Result<(), WorkStoreError> {
        if !self.journal.at_soft_limit() {
            return Ok(());
        }
        match self
            .journal
            .rotate(&self.state.checkpoint_for_storage())
            .await
        {
            Ok(()) => Ok(()),
            Err(error) if new_work => Err(error.into()),
            Err(_) => Ok(()),
        }
    }

    /// Returns how many records the channel journal holds.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.journal.len()
    }

    /// Returns whether the channel journal holds no records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.journal.is_empty()
    }
}

/// Returns the key a channel journal is named and bound by.
///
/// The channel id, which already binds the network, both edges, and
/// both terms bodies. A journal opened for a channel whose terms,
/// edges, or network differ by one byte is a journal with another key,
/// and the header check refuses it.
fn channel_key(channel: &PaidChannel) -> Digest {
    let mut hasher = XetFileHasher::new();
    hasher.update(CHANNEL_KEY);
    hasher.update(channel.id().as_bytes());
    hasher.finalize()
}
