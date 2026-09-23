use super::*;

/// The durable channel journal: the state above and the file it is
/// replayed from.
#[derive(Debug)]
pub struct ChannelStore {
    journal: Journal,
    state: ChannelState,
    torn_tail: bool,
    metadata_only: bool,
}

impl ChannelStore {
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
    pub fn open<V: SigVerifier>(
        root: &Path,
        channel: PaidChannel,
        settlement: WorkPaymentSettlement,
        role: Role,
        origin: SetupOrigin,
        verifier: &V,
    ) -> Result<Self, WorkStoreError> {
        Self::open_inner(root, channel, settlement, role, origin, verifier, false)
    }

    /// Opens a provider journal that stores accounting evidence only.
    ///
    /// Inputs and output transcripts are verified before commit and retained
    /// in memory. Append and checkpoint encodings omit both bodies. After a
    /// restart an accepted request cannot run and a completed response cannot
    /// be replayed; a signed payment for an already delivered result can still
    /// be credited. Existing payload-bearing journals are refused.
    pub fn open_metadata_only<V: SigVerifier>(
        root: &Path,
        channel: PaidChannel,
        settlement: WorkPaymentSettlement,
        origin: SetupOrigin,
        verifier: &V,
    ) -> Result<Self, WorkStoreError> {
        Self::open_inner(
            root,
            channel,
            settlement,
            Role::Provider,
            origin,
            verifier,
            true,
        )
    }

    fn open_inner<V: SigVerifier>(
        root: &Path,
        channel: PaidChannel,
        settlement: WorkPaymentSettlement,
        role: Role,
        origin: SetupOrigin,
        verifier: &V,
        metadata_only: bool,
    ) -> Result<Self, WorkStoreError> {
        if origin.payment_edge != channel.payment_edge() {
            return Err(ChannelStateError::WrongChannel {
                field: "setup origin payment_edge",
            }
            .into());
        }
        let key = channel_key(&channel).into_bytes();
        let replayed = hellas_rpc::observe::Timing::start();
        let (journal, replay) = Journal::open_latest(
            root,
            &format!("channel-{}", hex(&key)),
            JournalId {
                kind: if metadata_only {
                    JournalKind::MetadataChannel
                } else {
                    JournalKind::Channel
                },
                role,
                key,
                generation: 0,
            },
        )?;
        let mut state = match &replay.checkpoint {
            Some(bytes) => ChannelState::from_checkpoint(
                bytes,
                channel,
                settlement,
                role,
                verifier,
                metadata_only,
            )?,
            None => ChannelState::new(channel, settlement, role, origin),
        };
        for bytes in &replay.records {
            let record = ChannelRecord::decode(bytes)?;
            state.apply(&record, verifier, metadata_only)?;
        }
        state.indeterminate = state
            .jobs
            .values()
            .filter(|job| matches!(job.phase, JobPhase::Running | JobPhase::Streaming))
            .map(|job| (job.work_id, ()))
            .collect();
        journal.observe_replay(replayed, replay.records.len());
        let store = Self {
            journal,
            state,
            torn_tail: replay.truncated_tail,
            metadata_only,
        };
        Ok(store)
    }

    /// Returns whether opening removed an interrupted write.
    ///
    /// True says the last thing this endpoint tried to record did not
    /// finish reaching the disk, and the state above is the state
    /// before it. Nothing was acknowledged, so nothing here is wrong —
    /// but a clean shutdown does not produce it, and an operator who
    /// sees it has been told the truth about a crash.
    #[must_use]
    pub const fn recovered_torn_tail(&self) -> bool {
        self.torn_tail
    }

    /// Returns what this endpoint durably knows.
    #[must_use]
    pub const fn state(&self) -> &ChannelState {
        &self.state
    }

    /// Whether this journal excludes request and response bodies from disk.
    #[must_use]
    pub const fn metadata_only(&self) -> bool {
        self.metadata_only
    }

    /// Journals one step, and returns only once it is on the disk.
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
    pub fn commit<V: SigVerifier>(
        &mut self,
        record: ChannelRecord,
        verifier: &V,
    ) -> Result<&ChannelState, WorkStoreError> {
        // Applied to a copy first: a record the rules refuse must leave
        // neither the file nor the state touched.
        let mut next = self.state.clone();
        if next.apply(&record, verifier, false)? == Applied::Changed {
            // The signature this record carries leaves after this
            // returns, so the state that authorises it has to be one a
            // rotation can still carry. The proposed job is charged the
            // fixed tail it can still add — the result it will be
            // answered with and the terminal that pays for it — because
            // by then there is no refusal left that costs nothing.
            if let Some(tail) = record.checkpoint_tail() {
                let len = next
                    .checkpoint_for_storage(self.metadata_only)
                    .len()
                    .saturating_add(tail);
                if len > MAX_CHECKPOINT_BYTES {
                    return Err(JournalError::CheckpointTooLarge { len }.into());
                }
            }
            self.rotate_if_full(record.is_new_work())?;
            self.journal
                .append(&record.encode_for_storage(self.metadata_only))?;
            self.state = next;
        }
        Ok(&self.state)
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
    pub fn rotate(&mut self) -> Result<(), WorkStoreError> {
        self.journal
            .rotate(&self.state.checkpoint_for_storage(self.metadata_only))?;
        Ok(())
    }

    /// Rotates at the soft limit, and decides who may go on without it.
    ///
    /// New work stops when a rotation cannot complete, because admitting
    /// it would be promising a duty this journal has no room to finish.
    /// A duty already exported does not stop: the reserve above the soft
    /// limit is exactly the room the cursor advances, the close and the
    /// answer finish in, and it is [`Journal::append`] that refuses when
    /// even that is gone.
    fn rotate_if_full(&mut self, new_work: bool) -> Result<(), WorkStoreError> {
        if !self.journal.at_soft_limit() {
            return Ok(());
        }
        match self
            .journal
            .rotate(&self.state.checkpoint_for_storage(self.metadata_only))
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
