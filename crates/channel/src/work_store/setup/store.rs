use super::*;

/// The durable setup journal: the state above, plus the file it is
/// replayed from.
#[derive(Debug)]
pub struct SetupStore {
    root: PathBuf,
    journal: Journal,
    state: SetupState,
    content: hellas_store::ContentStore,
}

impl SetupStore {
    /// Opens the setup journal for one bond, replaying and re-checking
    /// every record it holds.
    ///
    /// Replay runs the same transition rules as [`Self::commit`], with
    /// the same signature verification, so a journal that would not be
    /// accepted a record at a time is not accepted whole.
    ///
    /// # Errors
    ///
    /// [`WorkStoreError::Journal`] when the file is held, corrupt, or
    /// some other journal, and [`WorkStoreError::Setup`] when a
    /// replayed record does not obey the transition rules.
    pub async fn open<V: SigVerifier>(
        root: &Path,
        network: NetworkId,
        bond_edge: EdgeId,
        role: Role,
        verifier: &V,
    ) -> Result<Self, WorkStoreError> {
        let key = setup_key(network, bond_edge);
        let id = JournalId {
            kind: JournalKind::Setup,
            role,
            key: key.into_bytes(),
        };
        let replayed = hellas_rpc::observe::Timing::start();
        let (journal, replay) = Journal::open_latest(root, &setup_stem(key), id).await?;
        let mut state = match &replay.checkpoint {
            Some(bytes) => SetupState::from_checkpoint(bytes, network, bond_edge, role, verifier)?,
            None => SetupState::new(network, bond_edge, role),
        };
        for bytes in &replay.records {
            let record = SetupRecord::decode(bytes)?;
            check_signatures(&record, verifier)?;
            state.apply(&record)?;
        }
        journal.observe_replay(replayed, replay.records.len());
        Ok(Self {
            root: root.to_path_buf(),
            journal,
            state,
            content: hellas_store::ContentStore::new(),
        })
    }

    pub fn set_content_store(&mut self, content: hellas_store::ContentStore) {
        self.content = content;
    }

    pub(crate) fn content_store(&self) -> hellas_store::ContentStore {
        self.content.clone()
    }

    /// Returns what the handshake has durably reached.
    #[must_use]
    pub const fn state(&self) -> &SetupState {
        &self.state
    }

    /// Returns the root under which recovered channel journals are mounted.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns which endpoint owns this setup journal.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.state.role
    }

    /// Journals one step, and returns only once it is on the disk.
    ///
    /// The rule this exists to enforce: call it *before* exporting the
    /// revision's signature, and before broadcasting a transaction. A
    /// record the state already holds is not written twice, so a retry
    /// after a crash between the write and the release is free.
    ///
    /// # Errors
    ///
    /// [`WorkStoreError::Setup`] when the step is not one this state
    /// may take — which is checked before anything is written — and
    /// [`WorkStoreError::Journal`] when the append or its sync fails.
    pub fn commit<'a, V: SigVerifier>(
        &'a mut self,
        record: SetupRecord,
        verifier: &V,
    ) -> impl std::future::Future<Output = Result<&'a SetupState, WorkStoreError>> {
        // Keep the retained setup copy and journal-write future off callers'
        // poll stacks; witnesses are bounded inline in the no-alloc kernel.
        Box::pin(async move {
            check_signatures(&record, verifier)?;
            // Applied to a copy first: a record that the rules refuse must
            // leave neither the file nor the state touched.
            let mut next = self.state.clone();
            if next.apply(&record)? == Applied::Changed {
                // A revision is exported after this returns, so the state
                // that authorises it has to be one a rotation can still
                // carry. Refused here, before the append and before the
                // signature leaves, rather than at the rotation that finds
                // out too late.
                if record.exports_signature() {
                    let len = next.checkpoint()?.len();
                    if len > MAX_CHECKPOINT_BYTES {
                        return Err(JournalError::CheckpointTooLarge { len }.into());
                    }
                }
                self.rotate_if_full(record.is_new_work()).await?;
                self.journal.append(&record.encode()?).await?;
                self.state = next;
            }
            Ok(&self.state)
        })
    }

    /// Moves the journal on to its next generation, carrying this state
    /// as its first frame.
    ///
    /// What [`Self::commit`] does for itself at the soft limit, and what
    /// an operator may ask for at any time. The state is unchanged
    /// either way: a rotation moves bytes, never facts.
    ///
    /// # Errors
    ///
    /// [`WorkStoreError::Journal`] when the checkpoint does not fit one
    /// frame or an install step fails.
    pub async fn rotate(&mut self) -> Result<(), WorkStoreError> {
        self.journal.rotate(&self.state.checkpoint()?).await?;
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
        match self.journal.rotate(&self.state.checkpoint()?).await {
            Ok(()) => Ok(()),
            Err(error) if new_work => Err(error.into()),
            Err(_) => Ok(()),
        }
    }

    /// Returns how many records the journal holds.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.journal.len()
    }

    /// Returns whether the journal holds no records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.journal.is_empty()
    }
}

/// Verifies every signature a bundle record carries.
///
/// Run on commit and on replay, so the journal cannot hold a revision
/// whose signatures were never checked — including the one a recovered
/// endpoint is about to re-export.
fn check_signatures<V: SigVerifier>(
    record: &SetupRecord,
    verifier: &V,
) -> Result<(), SetupStateError> {
    let bundle = match record {
        SetupRecord::Offer { offer, .. } => {
            offer.check().map_err(|_| SetupStateError::Malformed)?;
            return check_bundle_signatures(Some(&offer.offer().proposal.encode()), verifier);
        }
        SetupRecord::Bundle { bundle } | SetupRecord::ArmedBundle { bundle, .. } => bundle,
        _ => return Ok(()),
    };
    check_bundle_signatures(Some(bundle), verifier)
}

/// Verifies every signature one retained revision carries.
///
/// The one spelling of it, so a revision that arrived as a record, a
/// revision replayed from a frame, and a revision recovered from a
/// checkpoint are all checked by the same code against the same keys.
pub(super) fn check_bundle_signatures<V: SigVerifier>(
    bundle: Option<&[u8]>,
    verifier: &V,
) -> Result<(), SetupStateError> {
    let Some(bundle) = bundle else {
        return Ok(());
    };
    let decoded = WorkChannelSetupBundleV2::decode(bundle)?;
    decoded.check(verifier)?;
    Ok(())
}

/// Returns the name every generation of one setup journal shares.
fn setup_stem(key: Digest) -> String {
    format!("setup-{}", hex(key.into_bytes()))
}

/// Returns the key a setup journal is named and bound by.
#[must_use]
pub fn setup_key(network: NetworkId, bond_edge: EdgeId) -> Digest {
    let mut hasher = XetFileHasher::new();
    hasher.update(SETUP_KEY);
    hasher.update(network.as_str().as_bytes());
    hasher.update(&bond_edge.to_bytes());
    hasher.finalize()
}

/// One setup journal found under a root, named by what is inside it.
///
/// The two values [`SetupStore::open`] is keyed by, and nothing else: a
/// path is not carried, because the store derives its own from the key
/// and a second copy could only ever disagree with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveredSetup {
    /// The bond this journal's handshake stakes.
    pub bond_edge: EdgeId,
    /// Which endpoint wrote it.
    pub role: Role,
}

/// A setup journal under the root that names no setup this node can
/// open.
#[derive(Debug)]
pub struct UnidentifiedSetup {
    /// The file, so an operator is told which one to go and look at.
    pub path: PathBuf,
    /// What stopped it being named.
    pub reason: SetupDiscoveryError,
}

/// Why one setup journal could not be named from what is in it.
#[derive(Debug, thiserror::Error)]
pub enum SetupDiscoveryError {
    /// The file is not a journal this binary can read.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// A record in it is not a setup record.
    #[error(transparent)]
    Record(#[from] SetupStateError),
    /// It is a journal of another kind, or under another key than its
    /// name carries.
    #[error("the file is not the setup journal its own name makes it")]
    NotThisSetup,
    /// It holds no revision, so the bond is not in it to recover. A
    /// handshake that armed its history floor and crashed before its
    /// first revision leaves exactly this.
    #[error("the journal holds no setup revision, so the bond it is keyed to is not in it")]
    NoRevision,
    /// Its revision names a bond, and this file is not the journal that
    /// bond and this network key to.
    #[error("the journal is not keyed to the configured network and the bond its revision names")]
    WrongKey,
}

/// What the setup journals under one root are about.
#[derive(Debug, Default)]
pub struct SetupDiscovery {
    /// Every journal whose bond and role were recovered from it, in the
    /// order its file name sorts.
    pub setups: Vec<DiscoveredSetup>,
    /// Every setup journal that could not be named, and why. Named
    /// rather than dropped: a file this node cannot open is a channel it
    /// may still owe a close, and a discovery that silently skipped it
    /// would be a node that quietly stopped answering.
    pub unidentified: Vec<UnidentifiedSetup>,
}

/// Enumerates the setup journals under `root`, recovering what each one
/// is about from the file itself.
///
/// [`SetupStore::open`] is keyed by a bond edge and a role, and a
/// restarting node is told neither: its configuration carries this root
/// and no more. Both are on the disk. The role is in the journal's own
/// header, and the bond edge is in the first revision it retained —
/// every later revision fixes the bond leg, so the first one is the
/// whole answer. What ties them to *this* file is the key: a journal is
/// named and bound by `setup_key(network, bond_edge)`, so a revision
/// whose bond does not reproduce the name is a revision that does not
/// belong to it, and is refused rather than believed.
///
/// Only `setup-<key>` journals are considered. A channel journal
/// beside them is another store's, and a file that is not either is not
/// this module's business.
///
/// # Errors
///
/// [`WorkStoreError::Journal`] when the root itself cannot be
/// enumerated. A root that does not exist yet is not one of those: a
/// node that has never opened a journal owns none, which is an answer.
/// Nor is one unreadable journal — that is reported by name in
/// [`SetupDiscovery::unidentified`], because the journals beside it are
/// still this node's to open.
pub async fn discover_setups(
    root: &Path,
    network: NetworkId,
) -> Result<SetupDiscovery, WorkStoreError> {
    let mut discovery = SetupDiscovery::default();
    for stem in Journal::stems(root)? {
        let Some(named) = setup_stem_key(&stem) else {
            continue;
        };
        match identify_setup(root, &stem, named, network).await {
            Ok(Some(setup)) => discovery.setups.push(setup),
            Ok(None) => {}
            Err(reason) => discovery.unidentified.push(UnidentifiedSetup {
                path: Journal::path(root, &stem),
                reason,
            }),
        }
    }
    Ok(discovery)
}

/// Returns the key a setup journal's stem carries, if it is one.
fn setup_stem_key(stem: &str) -> Option<[u8; 32]> {
    hellas_auth::hex::parse_lower(stem.strip_prefix("setup-")?).ok()
}

/// Recovers what one setup journal is about, or says why it cannot.
async fn identify_setup(
    root: &Path,
    stem: &str,
    named: [u8; 32],
    network: NetworkId,
) -> Result<Option<DiscoveredSetup>, SetupDiscoveryError> {
    let (id, replay) = Journal::inspect(root, stem).await?;
    if id.kind != JournalKind::Setup || id.key != named {
        return Err(SetupDiscoveryError::NotThisSetup);
    }
    // An empty initialized journal has exported no signature. A process can
    // stop between creating its header and atomically committing its offer.
    if replay.checkpoint.is_none() && replay.records.is_empty() {
        return Ok(None);
    }
    // A rotated journal keeps its revision in the checkpoint rather than
    // in a frame, so a discovery that read only the frames would report
    // every long-lived setup as holding no revision — and a setup it
    // cannot name is a close it stops answering.
    let mut retained = Vec::new();
    if let Some(bytes) = &replay.checkpoint {
        retained.extend(
            SetupState::decode_checkpoint(bytes)?
                .bundle_bytes()
                .map(<[u8]>::to_vec),
        );
    }
    for bytes in &replay.records {
        match SetupRecord::decode(bytes)? {
            SetupRecord::Bundle { bundle } | SetupRecord::ArmedBundle { bundle, .. } => {
                retained.push(bundle)
            }
            SetupRecord::Offer { offer, .. } => retained.push(offer.offer().proposal.encode()),
            _ => {}
        }
    }
    if let Some(bundle) = retained.first() {
        let decoded = WorkChannelSetupBundleV2::decode(bundle).map_err(SetupStateError::from)?;
        let bond_edge = decoded.bond_edge();
        if setup_key(network, bond_edge).into_bytes() != id.key {
            return Err(SetupDiscoveryError::WrongKey);
        }
        return Ok(Some(DiscoveredSetup {
            bond_edge,
            role: id.role,
        }));
    }
    Err(SetupDiscoveryError::NoRevision)
}
