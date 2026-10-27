use super::*;

/// The durable channel journal: the state above and the file it is
/// replayed from.
#[derive(Debug)]
pub struct ChannelStore {
    journal: Journal,
    state: Channel,
    contents: BTreeMap<Digest, crate::content::InvocationContent>,
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
        if origin.payment_edge != channel.payment_edge() {
            return Err(ChannelStateError::WrongChannel {
                field: "setup origin payment_edge",
            }
            .into());
        }
        let key = channel_key(&channel).into_bytes();
        let stem = format!("channel-{}", hex(key));
        let replayed = hellas_rpc::observe::Timing::start();
        let (journal, replay) = Journal::open_latest(
            root,
            &format!("channel-{}", hex(key)),
            JournalId {
                kind: JournalKind::Channel,
                role,
                key,
            },
        )
        .await?;
        let mut uploads = crate::content::UploadStore::durable(root, &stem, channel.id())?;
        let mut state = match &replay.checkpoint {
            Some(bytes) => Channel::from_checkpoint(bytes, channel, settlement, role, verifier)?,
            None => Channel::new(channel, settlement, role, origin),
        };
        for bytes in &replay.records {
            let record = ChannelRecord::decode(bytes)?;
            state.apply(&record, verifier, true)?;
        }
        // Acceptance is durable before promotion. Recover that gap before deadline GC.
        for job in state.book.jobs.values_mut() {
            if job.authorization.retention == hellas_rpc::Retention::Retain {
                let reference = job.authorization.input_content;
                let input =
                    match uploads.read(job.work_id, reference, hellas_rpc::Retention::Retain) {
                        Ok(input) => input,
                        Err(crate::content::ContentError::Missing)
                            if job.phase == JobPhase::HalfSigned =>
                        {
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    };
                if job.provider_signature.is_some() {
                    uploads.publish_accepted(job.work_id, &input, hellas_rpc::Retention::Retain)?;
                }
                job.prepared_input = input;
                if let Some((result, _)) = &job.result {
                    job.transcript = uploads.retained(result.transcript_content)?;
                }
            }
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
            uploads,
            contents: BTreeMap::new(),
        };
        store.gc_uploads()?;
        Ok(store)
    }

    pub(crate) fn remember_content(
        &mut self,
        work: Digest,
        content: crate::content::InvocationContent,
    ) {
        self.contents.insert(work, content);
    }
    pub(crate) fn invocation_content(
        &self,
        work: Digest,
        policy: &InvocationPolicy,
    ) -> Result<crate::content::InvocationContent, WorkStoreError> {
        if let Some(content) = self.contents.get(&work) {
            return Ok(content.clone());
        }
        let job = self
            .state
            .job_by_id(work)
            .ok_or(ChannelStateError::Malformed)?;
        let input = PreparedInvocation::from_canonical_bytes(
            job.prepared_input(),
            crate::content::MAX_CONTENT_BYTES,
        )
        .map_err(PaidWorkError::from)
        .map_err(ChannelStateError::from)?;
        let manifest = input
            .manifest()
            .map_err(PaidWorkError::from)
            .map_err(ChannelStateError::from)?;
        let root = self
            .uploads
            .root(work, manifest.root(), job.authorization().retention)?;
        let objects = crate::job::content_closure(
            policy,
            &manifest,
            &root,
            job.authorization().input_content,
        )
        .map_err(ChannelStateError::from)?;
        Ok(self
            .uploads
            .invocation_content(work, &objects, job.authorization().retention)?)
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
        self.state.restore_client_input(work_id, bytes)?;
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
        self.promote_accepted_content()?;
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
        if next.apply(&record, verifier, false)? == Applied::Changed {
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
            if let ChannelRecord::JobProposed {
                authorization,
                prepared_input,
                ..
            } = &record
                && authorization.retention == hellas_rpc::Retention::Retain
            {
                if next.role() == Role::Client {
                    self.uploads.retain(prepared_input)?;
                } else {
                    let input = PreparedInvocation::from_canonical_bytes(
                        prepared_input,
                        crate::content::MAX_CONTENT_BYTES,
                    )
                    .map_err(PaidWorkError::from)
                    .map_err(ChannelStateError::from)?;
                    let policy =
                        InvocationPolicy::from_canonical_bytes(input.application_policy.as_bytes())
                            .map_err(PaidWorkError::from)
                            .map_err(ChannelStateError::from)?;
                    self.uploads.stage_complete(
                        work_id(next.channel(), authorization),
                        authorization.input_content,
                        authorization.acceptance_deadline,
                        authorization.retention,
                        policy.limits.max_upload_bytes,
                        prepared_input,
                    )?;
                }
            }
            // Retain the exact signed transcript before its reference becomes durable.
            if let ChannelRecord::JobResult {
                work_id,
                result,
                transcript,
                ..
            } = &record
            {
                let job = next
                    .job_by_id(*work_id)
                    .ok_or(ChannelStateError::Malformed)?;
                if job.authorization().retention == hellas_rpc::Retention::Retain
                    && self.uploads.retain(transcript)? != result.transcript_content
                {
                    return Err(crate::content::ContentError::Hash.into());
                }
            }
            self.journal.append(&record.encode_for_storage()).await?;
            self.state = next;
            self.contents
                .retain(|id, _| self.state.job_by_id(*id).is_some());
            if let ChannelRecord::JobAccepted { work_id, .. } = &record {
                let job = self
                    .state
                    .job_by_id(*work_id)
                    .ok_or(ChannelStateError::Malformed)?;
                self.uploads.publish_accepted(
                    *work_id,
                    job.prepared_input(),
                    job.authorization().retention,
                )?;
            }
            if self.state.jobs().count() < previous_jobs {
                self.rotate().await?;
            }
        }
        self.gc_uploads()?;
        Ok(&self.state)
    }

    fn promote_accepted_content(&mut self) -> Result<(), WorkStoreError> {
        for job in self.state.jobs() {
            if job.authorization().retention == hellas_rpc::Retention::Retain
                && job.provider_signature().is_some()
                && self.uploads.has_stage(job.work_id())
            {
                let bytes = self.uploads.read(
                    job.work_id(),
                    job.authorization().input_content,
                    hellas_rpc::Retention::Retain,
                )?;
                self.uploads.publish_accepted(
                    job.work_id(),
                    &bytes,
                    hellas_rpc::Retention::Retain,
                )?;
            }
        }
        Ok(())
    }

    pub(crate) fn gc_uploads(&mut self) -> Result<(), WorkStoreError> {
        self.promote_accepted_content()?;
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
