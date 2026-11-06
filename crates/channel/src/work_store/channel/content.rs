use super::*;
use crate::content::{channel_pin, job_tree, read, stage, tree_reservation};
use hellas_store::content::{
    ContentStore, Cursor, DiskStore, Error, JobContent, JobId, LocalStore, PinValue, Scope,
    ScopeKind, Target, Tree,
};

impl ChannelStore {
    pub(crate) async fn discard_unaccepted_content(
        &mut self,
        work: Digest,
        reservation: u64,
    ) -> Result<(), WorkStoreError> {
        if !self.has_content_scope(work, reservation) {
            return Ok(());
        }
        if self
            .state()
            .job_by_id(work)
            .is_some_and(|job| job.provider_signature().is_some())
        {
            return Ok(());
        }
        if let Some(job) = self.state.book.jobs.get_mut(&work) {
            job.prepared_input = bytes::Bytes::new();
        }
        if let Some((store, scope)) = self.contents.remove(&work) {
            match store {
                LocalStore::Disk(node) => node.end_work(&scope).await?,
                LocalStore::Job(job) => job.end().await?,
                LocalStore::Memory(_) => return Err(Error::Denied.into()),
            }
        }
        Ok(())
    }
    pub(crate) fn reattach_input(
        &mut self,
        work: Digest,
        input: bytes::Bytes,
    ) -> Result<(), WorkStoreError> {
        self.state.restore_input(work, input)?;
        Ok(())
    }
    pub(crate) fn has_content_scope(&self, work: Digest, reservation: u64) -> bool {
        self.contents.get(&work).is_some_and(|(_, scope)| matches!(&scope.kind, ScopeKind::Work { reservation: current, .. } if *current == reservation))
    }
    pub(crate) fn other_pending_content(&self, work: Digest) -> bool {
        self.contents.keys().any(|id| {
            *id != work
                && self
                    .state()
                    .job_by_id(*id)
                    .is_none_or(|job| job.provider_signature().is_none())
        })
    }
    pub fn content_store(&self) -> DiskStore {
        self.content.clone()
    }

    pub(crate) fn invocation_content(
        &self,
        work: Digest,
    ) -> Result<(LocalStore, Scope), WorkStoreError> {
        self.contents
            .get(&work)
            .cloned()
            .ok_or_else(|| Error::Missing.into())
    }

    pub fn recoverable_content(
        &self,
        work: Digest,
    ) -> Result<Option<(LocalStore, Scope)>, WorkStoreError> {
        Ok(self
            .state()
            .retained_roots()
            .contains_key(&work)
            .then(|| self.contents.get(&work).cloned())
            .flatten())
    }

    pub async fn open_content(
        &mut self,
        work: Digest,
        retention: hellas_rpc::Retention,
        closure: Vec<ContentRef>,
        max_upload_bytes: u64,
    ) -> Result<(LocalStore, Scope), WorkStoreError> {
        if let Some(content) = self.contents.get(&work) {
            if content.0.retention() != retention {
                return Err(Error::Denied.into());
            }
            return Ok(content.clone());
        }
        let job = JobId {
            channel: self.state().channel().id(),
            id: work,
        };
        let content = match retention {
            hellas_rpc::Retention::Retain => {
                let scope = self
                    .content
                    .open_work(job, closure, max_upload_bytes)
                    .await?;
                (LocalStore::Disk(self.content.clone()), scope)
            }
            hellas_rpc::Retention::Ephemeral => {
                let job = JobContent::new(&self.content, job, closure, max_upload_bytes).await?;
                let scope = job.scope().clone();
                (LocalStore::Job(job), scope)
            }
        };
        self.contents.insert(work, content.clone());
        Ok(content)
    }

    pub async fn widen_content(
        &mut self,
        work: Digest,
        closure: Vec<ContentRef>,
        max_upload_bytes: u64,
    ) -> Result<(LocalStore, Scope), WorkStoreError> {
        let (store, scope) = self.invocation_content(work)?;
        let content = match store {
            LocalStore::Disk(node) => {
                let scope = node.widen_work(&scope, closure, max_upload_bytes).await?;
                (LocalStore::Disk(node), scope)
            }
            LocalStore::Memory(_) => return Err(Error::Denied.into()),
            LocalStore::Job(job) => {
                let job = job.widen(closure, max_upload_bytes).await?;
                let scope = job.scope().clone();
                (LocalStore::Job(job), scope)
            }
        };
        self.contents.insert(work, content.clone());
        Ok(content)
    }

    pub(crate) async fn read_content(
        &self,
        work: Digest,
        object: ContentRef,
    ) -> Result<bytes::Bytes, WorkStoreError> {
        if object.bytes() > crate::content::MAX_CONTENT_BYTES as u64 {
            return Err(Error::Invalid("prepared input byte limit").into());
        }
        Ok(crate::content::read_reader(
            self.open_content_reader(work, object)
                .await?
                .ok_or(Error::Missing)?,
            object,
            &self.content.ram_pool(),
        )
        .await?)
    }

    pub(crate) async fn open_content_reader(
        &self,
        work: Digest,
        object: ContentRef,
    ) -> Result<Option<hellas_store::content::VerifiedReader>, WorkStoreError> {
        let (store, scope) = self.invocation_content(work)?;
        Ok(match store {
            LocalStore::Disk(node) => node.open_staged(&scope, object).await?,
            LocalStore::Job(job) => {
                LocalStore::Job(job)
                    .open_verified(&scope, object, None)
                    .await?
            }
            LocalStore::Memory(_) => return Err(Error::Denied.into()),
        })
    }

    pub(crate) async fn reserve_retained(
        &self,
        work: Digest,
        max_spool_bytes: u64,
    ) -> Result<(), WorkStoreError> {
        let (_, scope) = self.invocation_content(work)?;
        let ScopeKind::Work { closure, .. } = &scope.kind else {
            return Err(Error::Denied.into());
        };
        self.content
            .reserve_output(
                &scope,
                max_spool_bytes
                    .checked_add(tree_reservation(closure, max_spool_bytes)?)
                    .ok_or(Error::Capacity)?,
            )
            .await?;
        Ok(())
    }

    pub(super) fn prepare_record(
        &self,
        record: &mut ChannelRecord,
    ) -> Result<Option<(Scope, crate::content::tree::JobTree)>, WorkStoreError> {
        let (work, transcript, given) = match record {
            ChannelRecord::JobProposed {
                authorization,
                retained_tree,
                ..
            } if authorization.retention == hellas_rpc::Retention::Retain
                && self.state().role() == Role::Client =>
            {
                (
                    work_id(self.state().channel(), authorization),
                    None,
                    retained_tree,
                )
            }
            ChannelRecord::JobAccepted {
                work_id,
                retained_tree,
                ..
            } if self.state().job_by_id(*work_id).is_some_and(|job| {
                job.authorization().retention == hellas_rpc::Retention::Retain
            }) =>
            {
                (*work_id, None, retained_tree)
            }
            ChannelRecord::JobResult {
                work_id,
                transcript,
                retained_tree,
                ..
            } if self.state().job_by_id(*work_id).is_some_and(|job| {
                job.authorization().retention == hellas_rpc::Retention::Retain
            }) =>
            {
                (*work_id, Some(&transcript[..]), retained_tree)
            }
            _ => return Ok(None),
        };
        // Earlier-record retries must keep the newer authoritative result tree.
        if transcript.is_none()
            && self
                .state()
                .job_by_id(work)
                .is_some_and(|job| job.result().is_some())
        {
            return Ok(None);
        }
        if transcript.is_some()
            && self
                .state()
                .job_by_id(work)
                .is_some_and(|job| job.result().is_some())
        {
            if given.is_none() {
                *given = self.state().retained_roots().get(&work).copied();
            }
            return Ok(None);
        }
        let (_, scope) = self.invocation_content(work)?;
        let ScopeKind::Work { closure, .. } = &scope.kind else {
            return Err(Error::Denied.into());
        };
        let tree = job_tree(closure, transcript.map(ContentRef::for_bytes))?;
        if given.is_some_and(|given| given != tree.root) {
            return Err(Error::Invalid("retained tree differs from staged closure").into());
        }
        *given = Some(tree.root);
        if self.state().retained_roots().get(&work) == Some(&tree.root) {
            return Ok(None);
        }
        Ok(Some((scope, tree)))
    }

    pub(super) async fn stage_record(
        &self,
        record: &ChannelRecord,
        prepared: Option<(Scope, crate::content::tree::JobTree)>,
    ) -> Result<(), WorkStoreError> {
        let Some((scope, tree)) = prepared else {
            return Ok(());
        };
        if let ChannelRecord::JobResult { transcript, .. } = record {
            stage(&self.content, &scope, transcript).await?;
        }
        for (_, bytes) in &tree.objects {
            stage(&self.content, &scope, bytes).await?;
        }
        Ok(())
    }

    fn proposal_pin(&self, work: Digest) -> bool {
        self.state().role() == Role::Client
            && self
                .state()
                .job_by_id(work)
                .is_some_and(|job| job.phase() == JobPhase::HalfSigned)
    }

    pub(crate) async fn reconcile_content(&mut self) -> Result<(), WorkStoreError> {
        let channel = self.state().channel().id();
        let mut cursor = Cursor::default();
        let mut existing = BTreeMap::new();
        loop {
            let page = self
                .content
                .pins(&Scope::Owner, &format!("channel/{channel}/"), cursor)
                .await?;
            existing.extend(page.pins);
            match page.next {
                Some(next) => cursor = next,
                None => break,
            }
        }
        let mut desired = BTreeMap::new();
        for (work, root) in self.state().retained_roots() {
            let pin = channel_pin(channel, *work, self.proposal_pin(*work))?;
            let expected = PinValue {
                target: Target::Tree(*root),
                policy: pin.policy.clone(),
                expires: None,
            };
            desired.insert(pin.name.clone(), expected.clone());
            if existing.get(&pin.name) == Some(&expected) {
                continue;
            }
            if let Some((LocalStore::Disk(_), scope)) = self.contents.get(work) {
                self.content
                    .promote_work(scope, Target::Tree(*root), pin)
                    .await?;
            } else {
                let scope = self
                    .content
                    .open_work(JobId { channel, id: *work }, vec![], 0)
                    .await?;
                self.content
                    .promote_work(&scope, Target::Tree(*root), pin)
                    .await?;
                self.content.end_work(&scope).await?;
            }
        }
        for (name, value) in existing {
            if !desired.contains_key(&name) {
                self.content
                    .set_pin(&Scope::Owner, &name, Some(&value), None)
                    .await?;
            }
        }
        let ended = self
            .contents
            .keys()
            .copied()
            .filter(|work| {
                self.state().terminal_by_id(*work).is_some()
                    || self
                        .state()
                        .job_by_id(*work)
                        .is_some_and(|job| job.result().is_some())
                    || self.state().close_settled().is_some()
            })
            .collect::<Vec<_>>();
        for work in ended {
            let Some((store, scope)) = self.contents.remove(&work) else {
                continue;
            };
            match store {
                LocalStore::Disk(node) => node.end_work(&scope).await?,
                LocalStore::Job(job) => job.end().await?,
                LocalStore::Memory(_) => return Err(Error::Denied.into()),
            }
        }
        Ok(())
    }

    pub(super) async fn restore_content(&mut self) -> Result<(), WorkStoreError> {
        self.reconcile_content().await?;
        for (work, root) in self.state().retained_roots() {
            let scope = self
                .content
                .open_work(
                    JobId {
                        channel: self.state().channel().id(),
                        id: *work,
                    },
                    vec![],
                    0,
                )
                .await?;
            self.content
                .promote_work(
                    &scope,
                    Target::Tree(*root),
                    channel_pin(self.state().channel().id(), *work, self.proposal_pin(*work))?,
                )
                .await?;
            self.content.end_work(&scope).await?;
        }
        let jobs = self
            .state()
            .jobs()
            .filter(|job| {
                job.authorization().retention == hellas_rpc::Retention::Retain
                    && self.state().retained_roots().contains_key(&job.work_id())
            })
            .map(|job| (job.work_id(), *job.authorization(), job.result().is_some()))
            .collect::<Vec<_>>();
        for (work, authorization, result) in jobs {
            let store = LocalStore::Disk(self.content.clone());
            let input = read(
                &store,
                &Scope::Owner,
                authorization.input_content,
                crate::content::MAX_CONTENT_BYTES as u64,
            )
            .await?;
            let prepared =
                PreparedInvocation::from_canonical_bytes(&input, crate::content::MAX_CONTENT_BYTES)
                    .map_err(PaidWorkError::from)
                    .map_err(ChannelStateError::from)?;
            let policy =
                InvocationPolicy::from_canonical_bytes(prepared.application_policy.as_bytes())
                    .map_err(PaidWorkError::from)
                    .map_err(ChannelStateError::from)?;
            let leaves = self
                .tree_objects(self.state().retained_roots()[&work])
                .await?;
            let closure = if self.state().role() == Role::Client {
                leaves
            } else {
                let manifest = prepared
                    .manifest()
                    .map_err(PaidWorkError::from)
                    .map_err(ChannelStateError::from)?;
                let root = if policy.content_closure(&manifest, &[]).is_ok() {
                    bytes::Bytes::new()
                } else {
                    let object = leaves
                        .iter()
                        .find(|object| object.id() == manifest.root())
                        .ok_or(Error::Missing)?;
                    read(
                        &store,
                        &Scope::Owner,
                        *object,
                        crate::content::MAX_PROGRAM_ROOT_BYTES as u64,
                    )
                    .await?
                };
                crate::job::content_closure(&policy, &manifest, &root, authorization.input_content)
                    .map_err(ChannelStateError::from)?
            };
            let facts = crate::job::check_paid_input(
                self.state().channel(),
                &authorization,
                &policy,
                &prepared,
            )
            .map_err(ChannelStateError::from)?;
            if !result {
                let (_, scope) = self
                    .open_content(
                        work,
                        authorization.retention,
                        closure.clone(),
                        policy.limits.max_upload_bytes,
                    )
                    .await?;
                let initial = job_tree(&closure, None)?;
                let total = facts
                    .max_spool_bytes
                    .checked_add(tree_reservation(&closure, facts.max_spool_bytes)?)
                    .ok_or(Error::Capacity)?;
                self.content
                    .restore_output(&scope, total, initial.bytes().ok_or(Error::Capacity)?)
                    .await?;
            }
            let transcript = if let Some((result, _)) =
                self.state().job_by_id(work).and_then(|job| job.result())
            {
                Some(
                    read(
                        &store,
                        &Scope::Owner,
                        result.transcript_content,
                        facts.max_spool_bytes,
                    )
                    .await?,
                )
            } else {
                None
            };
            let job = self
                .state
                .book
                .jobs
                .get_mut(&work)
                .ok_or(ChannelStateError::Malformed)?;
            job.prepared_input = input;
            if let Some(transcript) = transcript {
                job.transcript = transcript;
            }
        }
        Ok(())
    }

    async fn tree_objects(&self, root: ContentRef) -> Result<Vec<ContentRef>, WorkStoreError> {
        let mut pending = vec![root];
        let mut seen = BTreeSet::new();
        let mut objects = BTreeSet::new();
        let store = LocalStore::Disk(self.content.clone());
        while let Some(node) = pending.pop() {
            if !seen.insert(node) {
                continue;
            }
            let bytes = read(
                &store,
                &Scope::Owner,
                node,
                hellas_store::content::MAX_TREE_BYTES as u64,
            )
            .await?;
            for (name, target) in Tree::decode(&bytes)?.entries() {
                if node == root && name == "transcript" {
                    continue;
                }
                match target {
                    Target::Tree(child) => pending.push(*child),
                    Target::Object(object) => {
                        objects.insert(*object);
                    }
                }
            }
        }
        Ok(objects.into_iter().collect())
    }
}
