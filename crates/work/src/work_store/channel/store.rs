use super::*;

/// The durable channel journal: the state above and the file it is
/// replayed from.
#[derive(Debug)]
pub struct ChannelStore {
    journal: Journal,
    state: Channel,
    metadata_only: bool,
    payloads: payload::PayloadStore,
    pub(crate) uploads: crate::content::UploadStore,
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
    pub async fn open<V: SigVerifier>(
        root: &Path,
        channel: PaidChannel,
        settlement: WorkPaymentSettlement,
        role: Role,
        origin: SetupOrigin,
        verifier: &V,
    ) -> Result<Self, WorkStoreError> {
        Self::open_inner(root, channel, settlement, role, origin, verifier, false).await
    }

    /// Opens a journal that stores accounting evidence only.
    ///
    /// Inputs and output transcripts are verified before commit and retained
    /// in memory. Append and checkpoint encodings omit both bodies. After a
    /// restart an accepted request cannot run and a completed response cannot
    /// be replayed; a signed payment for an already delivered result can still
    /// be credited. Existing payload-bearing journals are refused.
    pub async fn open_metadata_only<V: SigVerifier>(
        root: &Path,
        channel: PaidChannel,
        settlement: WorkPaymentSettlement,
        role: Role,
        origin: SetupOrigin,
        verifier: &V,
    ) -> Result<Self, WorkStoreError> {
        Self::open_inner(root, channel, settlement, role, origin, verifier, true).await
    }

    async fn open_inner<V: SigVerifier>(
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
        let stem = format!("channel-{}", hex(key));
        let payloads = payload::PayloadStore::new(root, &stem);
        let replayed = hellas_rpc::observe::Timing::start();
        let (journal, replay) = Journal::open_latest(
            root,
            &format!("channel-{}", hex(key)),
            JournalId {
                kind: if metadata_only {
                    JournalKind::MetadataChannel
                } else {
                    JournalKind::Channel
                },
                role,
                key,
            },
        )
        .await?;
        let uploads = if metadata_only {
            crate::content::UploadStore::memory(channel.id(), Default::default())
        } else {
            crate::content::UploadStore::durable(root, &stem, channel.id())?
        };
        let mut state = match &replay.checkpoint {
            Some(bytes) => Channel::from_checkpoint(
                bytes,
                channel,
                settlement,
                role,
                verifier,
                metadata_only,
                &payloads,
            )?,
            None => Channel::new(channel, settlement, role, origin),
        };
        let mut referenced: std::collections::BTreeSet<String> = state
            .jobs()
            .map(|job| hellas_rpc::ContentId::hash(job.prepared_input()).to_string())
            .collect();
        for bytes in &replay.records {
            let mut record = ChannelRecord::decode(bytes)?;
            if !metadata_only && let ChannelRecord::JobProposed { prepared_input, .. } = &mut record
            {
                *prepared_input = payloads.read(prepared_input)?;
                referenced.insert(hellas_rpc::ContentId::hash(prepared_input).to_string());
            }
            state.apply(&record, verifier, metadata_only)?;
        }
        state.book.indeterminate = state
            .book
            .jobs
            .values()
            .filter(|job| matches!(job.phase, JobPhase::Running | JobPhase::Streaming))
            .map(|job| job.work_id)
            .collect();
        let live: std::collections::BTreeSet<String> = state
            .jobs()
            .map(|job| hellas_rpc::ContentId::hash(job.prepared_input()).to_string())
            .collect();
        let retired_payloads = !metadata_only && referenced != live;
        if !metadata_only {
            payloads.prune_ids(&referenced)?;
        }
        journal.observe_replay(replayed, replay.records.len());
        let mut store = Self {
            journal,
            state,
            metadata_only,
            payloads,
            uploads,
        };
        // A terminal append can survive a crash before its payload cleanup.
        // Retire those replay references durably before removing their files.
        if retired_payloads {
            store.rotate().await?;
        }
        store.gc_uploads()?;
        Ok(store)
    }

    /// Returns what this endpoint durably knows.
    #[must_use]
    pub const fn state(&self) -> &Channel {
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
    pub async fn commit<V: SigVerifier>(
        &mut self,
        record: ChannelRecord,
        verifier: &V,
    ) -> Result<&Channel, WorkStoreError> {
        // Applied to a copy first: a record the rules refuse must leave
        // neither the file nor the state touched. A cheap exact check
        // first: the stream replay path offers a redundant release per
        // emitted frame, and the copy would clone the whole transcript.
        if self.state.is_redundant(&record) {
            return Ok(&self.state);
        }
        let mut next = self.state.clone();
        let previous_jobs = self.state.jobs().count();
        // The `false` keeps commit-time validation at full strength even
        // for a metadata-only journal: bodies are verified — digest and
        // transcript-to-result reproduction — before they are stripped
        // from the bytes written. Only replay and checkpoint validation
        // downgrade for body-less records.
        if next.apply(&record, verifier, false)? == Applied::Changed {
            // The signature this record carries leaves after this
            // returns, so the state that authorises it has to be one a
            // rotation can still carry. The proposed job is charged the
            // fixed tail it can still add — the result it will be
            // answered with and the terminal that pays for it — because
            // by then there is no refusal left that costs nothing.
            if let Some(tail) = record.checkpoint_tail() {
                let len = payload::checkpoint(&next, self.metadata_only)
                    .len()
                    .saturating_add(tail);
                if len > MAX_CHECKPOINT_BYTES {
                    return Err(JournalError::CheckpointTooLarge { len }.into());
                }
            }
            self.rotate_if_full(record.is_new_work()).await?;
            let mut stored = record;
            if !self.metadata_only
                && let ChannelRecord::JobProposed { prepared_input, .. } = &mut stored
            {
                *prepared_input = self.payloads.write(prepared_input)?;
            }
            self.journal
                .append(&stored.encode_for_storage(self.metadata_only))
                .await?;
            self.state = next;
            if !self.metadata_only && self.state.jobs().count() < previous_jobs {
                self.rotate().await?;
            }
        }
        self.gc_uploads()?;
        Ok(&self.state)
    }

    pub(crate) fn gc_uploads(&mut self) -> Result<(), WorkStoreError> {
        self.uploads.gc(
            self.state.cursor().0,
            self.state.close_prepared().is_some()
                || self.state.close_opened().is_some()
                || self.state.close_settled().is_some(),
        )?;
        Ok(())
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
            .rotate(&payload::checkpoint(&self.state, self.metadata_only))
            .await?;
        if !self.metadata_only {
            self.payloads.prune(&self.state)?;
        }
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
            .rotate(&payload::checkpoint(&self.state, self.metadata_only))
            .await
        {
            Ok(()) => {
                if !self.metadata_only {
                    self.payloads.prune(&self.state)?;
                }
                Ok(())
            }
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
