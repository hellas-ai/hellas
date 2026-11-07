use super::{reservation::Reservation, *};
use bytes::Bytes;
use hellas_auth::authority::UnixMillis;
use hellas_rpc::{ContentId, ContentRef};
use hellas_xet::Chunk;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub(crate) struct Core {
    pub(crate) state: Arc<Mutex<State>>,
    pub(crate) pool: Reservations,
    pub(crate) changed: Arc<tokio::sync::Notify>,
    pub(crate) http: ureq::Agent,
    #[cfg(test)]
    pub(crate) hf_hub: Option<String>,
    pub(crate) disk: Option<Arc<super::disk::Disk>>,
    pub(crate) gate: Arc<tokio::sync::Mutex<()>>,
    pub(crate) lower: Option<Box<Core>>,
    needed: Option<Arc<Mutex<Option<u64>>>>,
}
pub(crate) struct Stored {
    last_read: std::sync::atomic::AtomicU64,
    pub data: super::storage::Data,
    pub chunks: Vec<Chunk>,
}
impl Stored {
    pub(crate) fn new(data: super::storage::Data, chunks: Vec<Chunk>) -> Self {
        Self {
            data,
            chunks,
            last_read: std::sync::atomic::AtomicU64::new(0),
        }
    }
}
struct Work {
    root_recovery: bool,
    input_reserved: u64,
    output_remaining: u64,
    output_allowance: u64,
    upload_limit: u64,
    job: JobId,
    closure: Closure,
    charge: Arc<Reservation>,
    staged: BTreeMap<ContentId, Arc<Stored>>,
}
type AcquiredOwner = (std::sync::Weak<Mutex<State>>, ReservationId);
type AcquiredOwners = BTreeMap<PinName, Vec<AcquiredOwner>>;
pub(crate) struct State {
    pub(crate) peers: Option<hellas_wire::iroh::Pool>,
    #[cfg(test)]
    tree_reads: std::sync::atomic::AtomicU64,
    pub(crate) objects: BTreeMap<ContentId, Arc<Stored>>,
    pub(crate) pins: BTreeMap<PinName, PinValue>,
    pub(crate) declarations: BTreeMap<PinName, Digest>,
    acquired: AcquiredOwners,
    pub(crate) on_miss: Arc<dyn OnMiss>,
    work: BTreeMap<ReservationId, Work>,
    active: BTreeSet<(ReservationId, ContentId)>,
    pub(crate) generation: u64,
    events: VecDeque<(PinEvent, Option<PinValue>, usize)>,
    event_bytes: usize,
    reads: std::sync::atomic::AtomicU64,
}
impl Core {
    fn state(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| Error::Invalid("store lock"))
    }

    pub fn new(pool: Reservations) -> Self {
        Self {
            pool,
            disk: None,
            gate: Arc::new(tokio::sync::Mutex::new(())),
            lower: None,
            needed: None,
            http: crate::hf::http().clone(),
            #[cfg(test)]
            hf_hub: None,
            changed: Arc::new(tokio::sync::Notify::new()),
            state: Arc::new(Mutex::new(State {
                peers: None,
                #[cfg(test)]
                tree_reads: std::sync::atomic::AtomicU64::new(0),
                objects: BTreeMap::new(),
                pins: BTreeMap::new(),
                declarations: BTreeMap::new(),
                acquired: BTreeMap::new(),
                on_miss: Arc::new(Refuse),
                work: BTreeMap::new(),
                active: BTreeSet::new(),
                generation: 0,
                events: VecDeque::new(),
                event_bytes: 0,
                reads: std::sync::atomic::AtomicU64::new(0),
            })),
        }
    }
    pub(crate) fn publish_acquired(
        &self,
        objects: Vec<(ContentRef, super::storage::Data, Vec<Chunk>)>,
        target: Target,
        pin: PinTarget,
        requester: Option<(Core, Scope)>,
    ) -> Result<()> {
        let owner = requester
            .map(|(core, scope)| {
                let ScopeKind::Work { reservation, .. } = scope.kind else {
                    return Err(Error::Denied);
                };
                Ok((Arc::downgrade(&core.state), reservation))
            })
            .transpose()?;
        let name = pin.name.clone();
        let mut state = self.state()?;
        let objects = objects
            .into_iter()
            .map(|(object, data, chunks)| (object.id(), Arc::new(Stored::new(data, chunks))))
            .collect();
        state.publish(objects, target, pin)?;
        if let Some(owner) = owner {
            state.add_acquired(name, owner);
        }
        self.changed.notify_waiters();
        Ok(())
    }
    /// Called by the authenticated application opening, first with the root only.
    pub fn open_work(&self, job: JobId, closure: Closure, max_upload_bytes: u64) -> Result<Scope> {
        let state = self.state()?;
        if let Some((id, work)) = state.work.iter().find(|(_, work)| work.job == job) {
            if work.root_recovery {
                return Err(Error::Denied);
            }
            return Ok(Scope::work(job, work.closure.clone(), *id));
        }
        let closure = canonical_closure(closure)?;
        let scope = Scope::work(job, closure.clone(), 0);
        let mut missing = self.missing(&state, &scope, &closure)?;
        let staged = match &self.disk {
            Some(disk) => disk.recover_staged(job)?,
            None => BTreeMap::new(),
        };
        for object in &closure {
            if staged.contains_key(&object.id()) && state.present(&scope, *object)? {
                missing = missing.checked_add(object.bytes()).ok_or(Error::Capacity)?;
            }
        }
        let held_input = closure
            .iter()
            .filter(|object| staged.contains_key(&object.id()))
            .try_fold(0u64, |n, object| {
                n.checked_add(object.bytes()).ok_or(Error::Capacity)
            })?;
        if missing > max_upload_bytes {
            return Err(Error::Capacity);
        }
        let acquired = match &self.lower {
            Some(lower) => lower.state()?.acquired_pins(&scope, &closure)?,
            None => state.acquired_pins(&scope, &closure)?,
        };
        let charge = self.reserve(missing.saturating_sub(held_input))?;
        let reservation = self.data_pool().next_id()?;
        drop(state);
        let scope = Scope::work(job, closure.clone(), reservation);
        self.lower
            .as_deref()
            .unwrap_or(self)
            .protect_acquired(self, &scope, acquired)?;
        self.state()?.work.insert(
            reservation,
            Work {
                root_recovery: false,
                input_reserved: missing,
                output_remaining: 0,
                output_allowance: 0,
                upload_limit: max_upload_bytes,
                job,
                closure: closure.clone(),
                charge,
                staged,
            },
        );
        Ok(scope)
    }
    /// Widen only after the application has verified and parsed the root.
    pub fn widen_work(
        &self,
        scope: &Scope,
        closure: Closure,
        max_upload_bytes: u64,
    ) -> Result<Scope> {
        let mut state = self.state()?;
        state.check(scope)?;
        let ScopeKind::Work {
            job, reservation, ..
        } = &scope.kind
        else {
            return Err(Error::Denied);
        };
        let closure = canonical_closure(closure)?;
        let work = state.work.get(reservation).ok_or(Error::Denied)?;
        if max_upload_bytes > work.upload_limit {
            return Err(Error::Denied);
        }
        if work.closure.iter().any(|object| !closure.contains(object)) {
            return Err(Error::Invalid("closure cannot narrow"));
        }
        let mut new_scope = Scope::work(*job, closure.clone(), *reservation);
        new_scope.live = scope.live.clone();
        let missing = self.missing(&state, &new_scope, &closure)?;
        if missing > max_upload_bytes {
            return Err(Error::Capacity);
        }
        let acquired = match &self.lower {
            Some(lower) => lower.state()?.acquired_pins(&new_scope, &closure)?,
            None => state.acquired_pins(&new_scope, &closure)?,
        };
        let work = state.work.get_mut(reservation).ok_or(Error::Denied)?;
        if missing > work.input_reserved {
            let recovered = if self.disk.is_some() {
                closure
                    .iter()
                    .filter(|object| {
                        !work.closure.contains(object) && work.staged.contains_key(&object.id())
                    })
                    .map(|object| object.bytes())
                    .sum::<u64>()
            } else {
                0
            };
            self.extend(
                &work.charge,
                (missing - work.input_reserved).saturating_sub(recovered),
            )?;
            work.input_reserved = missing;
        }
        drop(state);
        self.lower
            .as_deref()
            .unwrap_or(self)
            .protect_acquired(self, &new_scope, acquired)?;
        self.state()?
            .work
            .get_mut(reservation)
            .ok_or(Error::Denied)?
            .closure = closure;
        Ok(new_scope)
    }
    pub(crate) fn work_bytes(&self, scope: &Scope) -> Result<u64> {
        let state = self.state()?;
        state.check(scope)?;
        let ScopeKind::Work { reservation, .. } = &scope.kind else {
            return Err(Error::Denied);
        };
        state
            .work
            .get(reservation)
            .ok_or(Error::Denied)?
            .staged
            .values()
            .try_fold(0u64, |total, stored| {
                total.checked_add(stored.data.len()).ok_or(Error::Capacity)
            })
    }
    /// The host has atomically taken these bytes into live job RAM accounting.
    pub fn accept_work(&self, scope: &Scope) -> Result<()> {
        let state = self.state()?;
        state.check(scope)?;
        let ScopeKind::Work { reservation, .. } = &scope.kind else {
            return Err(Error::Denied);
        };
        state
            .work
            .get(reservation)
            .ok_or(Error::Denied)?
            .charge
            .transfer();
        Ok(())
    }
    pub fn end_work(&self, scope: &Scope) -> Result<()> {
        let ScopeKind::Work {
            job, reservation, ..
        } = &scope.kind
        else {
            return Err(Error::Denied);
        };
        let mut state = self.state()?;
        if state
            .work
            .get(reservation)
            .is_some_and(|work| work.job != *job)
        {
            return Err(Error::Denied);
        }
        if let Some(work) = state.work.get(reservation)
            && let Some(disk) = &self.disk
        {
            for stored in work.staged.values() {
                if let super::storage::Data::File(file) = &stored.data {
                    file.discard_private()?;
                }
            }
            disk.discard_job(work.job)?;
        }
        if self.disk.is_some() {
            state.unpin_acquired(&(Arc::downgrade(&self.state), *reservation))?;
        }
        state.work.remove(reservation);
        self.changed.notify_waiters();
        Ok(())
    }
    pub(crate) fn check(&self, scope: &Scope) -> Result<()> {
        self.state()?.check(scope)
    }
    fn session(
        &self,
        state: &mut State,
        scope: &Scope,
        object: ContentRef,
        pin: Option<PinTarget>,
        missing: u64,
    ) -> Result<super::upload::LocalSession> {
        state.check(scope)?;
        let (reservation, charge) = match &scope.kind {
            ScopeKind::Owner => {
                if pin.is_none() {
                    return Err(Error::Invalid("owner upload requires pin"));
                }
                (self.data_pool().next_id()?, self.reserve(object.bytes())?)
            }
            ScopeKind::Work {
                reservation,
                closure,
                ..
            } => {
                if pin.is_some() || !closure.contains(&object) {
                    return Err(Error::Denied);
                }
                let work = state.work.get_mut(reservation).ok_or(Error::Denied)?;
                if missing > work.upload_limit {
                    return Err(Error::Capacity);
                }
                if missing > work.input_reserved {
                    self.extend(&work.charge, missing - work.input_reserved)?;
                    work.input_reserved = missing;
                }
                (*reservation, work.charge.clone())
            }
            _ => return Err(Error::Denied),
        };
        if state.active.contains(&(reservation, object.id())) {
            return Err(Error::Conflict);
        }
        let bytes = super::storage::Buffer::new(self, object.bytes(), charge.clone())?;
        if !state.active.insert((reservation, object.id())) {
            return Err(Error::Conflict);
        }
        Ok(super::upload::LocalSession {
            store: self.clone(),
            scope: scope.clone(),
            pin,
            object,
            reservation,
            bytes: Some(bytes),
            output: false,
            finished: false,
        })
    }
    pub(crate) fn publish(
        &self,
        session: &mut super::upload::LocalSession,
        chunks: Vec<Chunk>,
    ) -> Result<()> {
        let mut state = self.state()?;
        state.check(&session.scope)?;
        if session.pin.is_some() && state.generation == u64::MAX {
            return Err(Error::Capacity);
        }
        let bytes = session
            .bytes
            .take()
            .ok_or(Error::Invalid("upload already published"))?;
        let stored = Arc::new(Stored::new(
            bytes.finish(session.object, chunks.clone())?,
            chunks,
        ));
        if let Some(pin) = &session.pin {
            PinName::new(pin.name.as_str().to_owned())?;
            state.publish(
                BTreeMap::from([(session.object.id(), stored)]),
                Target::Object(session.object),
                pin.clone(),
            )?;
            self.changed.notify_waiters();
        } else if let ScopeKind::Work { reservation, .. } = &session.scope.kind {
            // Completed disk staging has a durable canonical name before the
            // application can journal its reference. Scope protection stays live.
            if let (Some(_), ScopeKind::Work { job, .. }) = (&self.disk, &session.scope.kind)
                && let super::storage::Data::File(file) = &stored.data
            {
                file.stage(*job)?;
            }
            state
                .work
                .get_mut(reservation)
                .ok_or(Error::Denied)?
                .staged
                .insert(session.object.id(), stored);
        } else {
            return Err(Error::Denied);
        }
        state
            .active
            .remove(&(session.reservation, session.object.id()));
        session.finished = true;
        Ok(())
    }
    pub(crate) fn abandon(&self, reservation: ReservationId, object: ContentId, output: u64) {
        if let Ok(mut state) = self.state.lock() {
            state.active.remove(&(reservation, object));
            if let Some(work) = state.work.get_mut(&reservation) {
                work.output_remaining += output;
            }
        }
    }
}
pub(super) fn canonical_closure(closure: Closure) -> Result<Closure> {
    let mut objects = BTreeMap::new();
    for object in closure {
        if objects
            .insert(object.id(), object)
            .is_some_and(|old| old != object)
        {
            return Err(Error::Invalid("inconsistent closure lengths"));
        }
    }
    Ok(objects.into_values().collect())
}
fn available(stored: &Stored, object: ContentRef) -> Result<bool> {
    if stored.data.len() != object.bytes() {
        return Err(Error::Invalid("content length contract"));
    }
    Ok(stored.data.available())
}
fn checked_bytes(stored: &Stored, object: ContentRef) -> Result<Bytes> {
    if stored.data.len() != object.bytes() || !stored.data.available() {
        return Err(Error::Invalid("content length contract"));
    }
    stored.data.load(object)
}
fn live(pin: &PinValue) -> bool {
    pin.expires
        .is_none_or(|expires| UnixMillis::now().is_ok_and(|now| now < expires))
}
fn readable(scope: &Scope, name: &PinName, pin: &PinValue) -> bool {
    if !live(pin) {
        return false;
    }
    matches!(scope.kind, ScopeKind::Owner)
        || match (&pin.policy, &scope.kind) {
            (PinPolicy::Public, ScopeKind::Work { .. }) => false,
            (PinPolicy::Public, _) => true,
            (PinPolicy::Jobs, ScopeKind::Work { .. }) => true,
            (PinPolicy::Channel(channel), ScopeKind::Work { job, .. }) => *channel == job.channel,
            (PinPolicy::Granted, ScopeKind::Grant(grant)) => grant.pin == *name,
            _ => false,
        }
}
fn metadata_readable(scope: &Scope, name: &PinName, pin: &PinValue) -> bool {
    readable(scope, name, pin)
        && match &scope.kind {
            ScopeKind::Work { closure, .. } => closure.contains(&pin.target.object()),
            _ => true,
        }
}

impl State {
    fn check(&self, scope: &Scope) -> Result<()> {
        if let ScopeKind::Work {
            job,
            reservation,
            closure,
        } = &scope.kind
            && self
                .work
                .get(reservation)
                .is_none_or(|work| work.job != *job || work.closure != *closure)
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
    fn check_object(&self, target: Target) -> Result<()> {
        self.objects
            .get(&target.object().id())
            .ok_or(Error::Missing)?
            .data
            .check(target.object())
    }
    fn load(&self, target: Target) -> Result<Bytes> {
        #[cfg(test)]
        self.tree_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        checked_bytes(
            self.objects
                .get(&target.object().id())
                .ok_or(Error::Missing)?,
            target.object(),
        )
    }
    /// Postorder computes each tree's longest suffix once, including shared DAGs.
    fn walk(&self, roots: impl IntoIterator<Item = Target>) -> Result<BTreeSet<ContentRef>> {
        let mut reached = BTreeSet::new();
        let mut depths = BTreeMap::<ContentId, (ContentRef, usize)>::new();
        let mut active = BTreeSet::new();
        let mut pending = roots
            .into_iter()
            .map(|root| (root, 0usize, None::<Tree>))
            .collect::<Vec<_>>();
        while let Some((target, prefix, tree)) = pending.pop() {
            let check_path = |suffix: usize| {
                if prefix + suffix + usize::from(prefix != 0 && suffix != 0) > MAX_PATH_BYTES {
                    Err(Error::Invalid("tree path length"))
                } else {
                    Ok(())
                }
            };
            check_path(0)?;
            reached.insert(target.object());
            let Target::Tree(object) = target else {
                continue;
            };
            if let Some(tree) = tree {
                let depth = tree
                    .entries()
                    .iter()
                    .try_fold(0usize, |depth, (name, child)| {
                        let suffix = match child {
                            Target::Tree(object) => {
                                depths
                                    .get(&object.id())
                                    .ok_or(Error::Invalid("tree dependency"))?
                                    .1
                            }
                            Target::Object(_) => 0,
                        };
                        Ok::<_, Error>(depth.max(name.len() + suffix + usize::from(suffix != 0)))
                    })?;
                check_path(depth)?;
                active.remove(&object.id());
                depths.insert(object.id(), (object, depth));
                continue;
            }
            if let Some((previous, depth)) = depths.get(&object.id()) {
                if *previous != object {
                    return Err(Error::Invalid("conflicting tree lengths"));
                }
                check_path(*depth)?;
                continue;
            }
            if !active.insert(object.id()) {
                return Err(Error::Invalid("tree cycle"));
            }
            let tree = Tree::decode(&self.load(target)?)?;
            let children = tree
                .entries()
                .iter()
                .map(|(name, child)| {
                    check_path(name.len())?;
                    Ok((*child, prefix + usize::from(prefix != 0) + name.len(), None))
                })
                .collect::<Result<Vec<_>>>()?;
            pending.push((target, prefix, Some(tree)));
            pending.extend(children);
        }
        Ok(reached)
    }
    fn readable_refs(&self, scope: &Scope) -> Result<BTreeSet<ContentRef>> {
        self.walk(
            self.pins
                .iter()
                .filter(|(name, pin)| readable(scope, name, pin))
                .map(|(_, pin)| pin.target),
        )
    }
    fn acquired_pins(&self, scope: &Scope, closure: &[ContentRef]) -> Result<Vec<PinName>> {
        // Each consumer keeps the existing acquisition pin alive. Its current
        // policy/expiry still controls reads; Channel and ordinary pins stay separate.
        let requested = closure.iter().copied().collect::<BTreeSet<_>>();
        self.acquired
            .keys()
            .filter_map(|name| {
                let pin = self.pins.get(name)?;
                if pin.policy != PinPolicy::Jobs || !readable(scope, name, pin) {
                    return None;
                }
                Some(
                    self.walk([pin.target])
                        .map(|objects| (!objects.is_disjoint(&requested)).then(|| name.clone())),
                )
            })
            .collect::<Result<Vec<_>>>()
            .map(|names| names.into_iter().flatten().collect())
    }
    fn add_acquired(&mut self, name: PinName, owner: AcquiredOwner) {
        let owners = self.acquired.entry(name).or_default();
        if !owners
            .iter()
            .any(|current| current.0.ptr_eq(&owner.0) && current.1 == owner.1)
        {
            owners.push(owner);
        }
    }
    fn unpin_acquired(&mut self, owner: &AcquiredOwner) -> Result<()> {
        let mut names = Vec::new();
        for (name, owners) in &mut self.acquired {
            owners.retain(|current| {
                current.0.strong_count() != 0
                    && !(current.0.ptr_eq(&owner.0) && current.1 == owner.1)
            });
            if owners.is_empty() {
                names.push(name.clone());
            }
        }
        for name in names {
            self.acquired.remove(&name);
            if self.pins.contains_key(&name) {
                self.change_pin(name, None)?;
            }
        }
        Ok(())
    }
    fn present(&self, scope: &Scope, object: ContentRef) -> Result<bool> {
        Ok(self.readable_refs(scope)?.contains(&object)
            && self
                .objects
                .get(&object.id())
                .map(|stored| available(stored, object))
                .transpose()?
                .unwrap_or(false))
    }
    fn verified_present(&self, scope: &Scope, object: ContentRef) -> Result<bool> {
        let readable = self.readable_refs(scope)?;
        if !readable.contains(&object) {
            return if readable.iter().any(|held| held.id() == object.id()) {
                Err(Error::Invalid("content length contract"))
            } else {
                Ok(false)
            };
        }
        self.objects
            .get(&object.id())
            .map(|stored| available(stored, object))
            .transpose()
            .map(|present| present.unwrap_or(false))
    }
    fn held(&self, scope: &Scope, closure: &[ContentRef]) -> Result<BTreeSet<ContentId>> {
        let reachable = self.readable_refs(scope)?;
        Ok(closure
            .iter()
            .filter(|object| {
                reachable.contains(object)
                    && self.objects.get(&object.id()).is_some_and(|stored| {
                        stored.data.len() == object.bytes() && stored.data.available()
                    })
            })
            .map(|object| object.id())
            .collect())
    }
    fn missing(
        &self,
        scope: &Scope,
        closure: &[ContentRef],
        lower: &BTreeSet<ContentId>,
        held: &BTreeSet<ContentId>,
    ) -> Result<u64> {
        closure
            .iter()
            .filter(|object| {
                let owned = if let ScopeKind::Work { reservation, .. } = &scope.kind {
                    self.work
                        .get(reservation)
                        .is_some_and(|work| work.staged.contains_key(&object.id()))
                        || self.active.contains(&(*reservation, object.id()))
                } else {
                    false
                };
                owned || (!lower.contains(&object.id()) && !held.contains(&object.id()))
            })
            .try_fold(0u64, |total, object| {
                total.checked_add(object.bytes()).ok_or(Error::Capacity)
            })
    }
    fn resolve(&self, scope: &Scope, at: &Path) -> Result<Option<Target>> {
        self.check(scope)?;
        self.resolve_path(scope, at)
    }
    fn resolve_path(&self, scope: &Scope, at: &Path) -> Result<Option<Target>> {
        PinName::new(at.pin.as_str().to_owned())?;
        super::tree::validate_path(&at.path, true)?;
        let Some(pin) = self
            .pins
            .get(&at.pin)
            .filter(|pin| readable(scope, &at.pin, pin))
        else {
            return Ok(None);
        };
        let mut target = pin.target;
        if !at.path.is_empty() {
            for name in at.path.split('/') {
                let Target::Tree(_) = target else {
                    return Err(Error::Invalid("path through object"));
                };
                let tree = Tree::decode(&self.load(target)?)?;
                let Some((_, child)) = tree.entries().iter().find(|(entry, _)| entry == name)
                else {
                    return Ok(None);
                };
                target = *child;
            }
        }
        if let ScopeKind::Work { closure, .. } = &scope.kind
            && !closure.contains(&target.object())
        {
            return Ok(None);
        }
        self.check_object(target)?;
        Ok(Some(target))
    }
    fn change_pin(&mut self, name: PinName, value: Option<PinValue>) -> Result<()> {
        let generation = self.generation.checked_add(1).ok_or(Error::Capacity)?;
        self.declarations.remove(&name);
        let old = match &value {
            Some(value) => self.pins.insert(name.clone(), value.clone()),
            None => self.pins.remove(&name),
        };
        self.generation = generation;
        let event = PinEvent::Set {
            cursor: Cursor {
                generation,
                ..Default::default()
            },
            name,
            value,
        };
        let bytes = super::wire::event(&event).encoded_len();
        self.event_bytes += bytes;
        self.events.push_back((event, old, bytes));
        while self.event_bytes > body_limit() {
            if let Some((_, _, bytes)) = self.events.pop_front() {
                self.event_bytes -= bytes;
            }
        }
        Ok(())
    }
}
use prost::Message;
impl Core {
    fn stat_sync(&self, scope: &Scope, at: &Path) -> Result<Option<Stat>> {
        Ok(self
            .state()?
            .resolve(scope, at)?
            .map(|target| Stat { target }))
    }
    fn chunks_sync(&self, scope: &Scope, at: &Path, cursor: Cursor) -> Result<ChunkPage> {
        let state = self.state()?;
        let target = state.resolve(scope, at)?.ok_or(Error::Missing)?;
        let object = state
            .objects
            .get(&target.object().id())
            .ok_or(Error::Missing)?;
        chunk_page(target.object(), &object.chunks, cursor)
    }
    fn read_sync(
        &self,
        scope: &Scope,
        at: &Path,
        range: std::ops::Range<u64>,
    ) -> Result<ByteStream> {
        let state = self.state()?;
        let target = state.resolve(scope, at)?.ok_or(Error::Missing)?;
        let object = target.object();
        if range.start > range.end || range.end > object.bytes() {
            return Err(Error::Invalid("read range"));
        }
        let stored = state.objects.get(&object.id()).ok_or(Error::Missing)?;
        state.touch(stored);
        let chunks = stored.data.stream(object, &stored.chunks, range)?;
        let scope = scope.clone();
        let pin = at.pin.clone();
        let store = self.clone();
        let stream = futures::stream::try_unfold(
            (chunks, store, scope, pin, object),
            |(mut chunks, store, scope, pin, object)| async move {
                use futures::StreamExt;
                let Some(bytes) = chunks.next().await else {
                    return Ok(None);
                };
                {
                    let gate = store.effect_gate(&scope).await?;
                    {
                        let state = store.state()?;
                        state.check(&scope)?;
                        if state
                            .pins
                            .get(&pin)
                            .is_none_or(|value| !readable(&scope, &pin, value))
                        {
                            return Err(Error::Denied);
                        }
                    }
                    let damaged = bytes.as_ref().err().and_then(BadBacking::from_error);
                    if let Some(backing) = damaged {
                        let checking = scope.clone();
                        // Keep repair and its authority guard owned through IO.
                        store
                            .run(move |core| {
                                let _gate = gate;
                                core.repair_backing(&checking, &backing)
                            })
                            .await?;
                    }
                }
                Ok(Some((bytes?, (chunks, store, scope, pin, object))))
            },
        );
        Ok(ByteStream {
            object: target.object(),
            bytes: Box::pin(stream),
        })
    }
    fn upload_sync(
        &self,
        scope: &Scope,
        object: ContentRef,
        pin: Option<PinTarget>,
    ) -> Result<UploadSession> {
        self.require_ready()?;
        let local = {
            let mut state = self.state()?;
            state.check(scope)?;
            match &scope.kind {
                ScopeKind::Owner if pin.is_some() => {}
                ScopeKind::Work { closure, .. } if pin.is_none() && closure.contains(&object) => {}
                _ => return Err(Error::Denied),
            }
            let own = match &scope.kind {
                ScopeKind::Work { reservation, .. } => state
                    .work
                    .get(reservation)
                    .and_then(|work| work.staged.get(&object.id()))
                    .map(|stored| available(stored, object))
                    .transpose()?
                    .unwrap_or(false),
                _ => false,
            };
            if own {
                return Ok(UploadSession::present(object));
            }
            let closure = match &scope.kind {
                ScopeKind::Work { closure, .. } => closure.as_slice(),
                _ => std::slice::from_ref(&object),
            };
            let held = state.held(scope, closure)?;
            let lower = self.held_lower(scope, closure)?;
            if held.contains(&object.id()) || lower.contains(&object.id()) {
                if let Some(pin) = pin {
                    state.change_pin(
                        pin.name,
                        Some(PinValue {
                            target: Target::Object(object),
                            policy: pin.policy,
                            expires: None,
                        }),
                    )?;
                    self.changed.notify_waiters();
                }
                return Ok(UploadSession::present(object));
            }
            // Keep the progress check and reservation/allocation in one critical
            // section: a completed concurrent upload must not allocate twice.
            let missing = state.missing(scope, closure, &lower, &held)?;
            self.session(&mut state, scope, object, pin, missing)?
        };
        Ok(UploadSession::local(object, local))
    }
    pub(crate) fn set_pin_sync(
        &self,
        scope: &Scope,
        name: &PinName,
        expected: Option<&PinValue>,
        new: Option<PinValue>,
    ) -> Result<()> {
        if !matches!(scope.kind, ScopeKind::Owner) {
            return Err(Error::Denied);
        }
        PinName::new(name.as_str().to_owned())?;
        let mut state = self.state()?;
        if state.pins.get(name).filter(|pin| live(pin)) != expected {
            return Err(Error::Conflict);
        }
        if let Some(value) = &new {
            state.walk([value.target])?;
            state.check_object(value.target)?;
        }
        state.change_pin(name.clone(), new)?;
        self.changed.notify_waiters();
        Ok(())
    }
    fn pins_sync(&self, scope: &Scope, prefix: &str, cursor: Cursor) -> Result<PinPage> {
        let state = self.state()?;
        state.check(scope)?;
        let visible: Vec<_> = state
            .pins
            .iter()
            .filter(|(name, pin)| {
                name.as_str().starts_with(prefix)
                    && metadata_readable(scope, name, pin)
                    && cursor.after.as_ref().is_none_or(|after| *name > after)
            })
            .collect();
        // Owner snapshots can resume the existing watch; other scopes start a
        // bounded replay/resync without disclosing node activity in ListPins.
        let current = Cursor {
            generation: if matches!(scope.kind, ScopeKind::Owner) {
                if cursor.after.is_some() {
                    cursor.generation
                } else {
                    state.generation
                }
            } else {
                0
            },
            ..Default::default()
        };
        let mut pins = Vec::new();
        let mut encoded = 0;
        for (name, pin) in &visible {
            let item = hellas_rpc::pb::content::ListPinsResponse {
                pins: vec![super::wire::pin(name, pin)],
                ..Default::default()
            }
            .encoded_len();
            let envelope = hellas_rpc::pb::content::ListPinsResponse {
                pins: vec![],
                next: Some(super::wire::cursor(&Cursor {
                    after: Some((*name).clone()),
                    generation: current.generation,
                    ..Default::default()
                })),
                cursor: Some(super::wire::cursor(&current)),
            }
            .encoded_len();
            if encoded + item + envelope > body_limit() {
                break;
            }
            encoded += item;
            pins.push(((*name).clone(), (*pin).clone()));
        }
        let next = if pins.len() < visible.len() {
            Some(Cursor {
                after: Some(pins.last().ok_or(Error::Capacity)?.0.clone()),
                generation: current.generation,
                ..Default::default()
            })
        } else {
            None
        };
        Ok(PinPage {
            pins,
            next,
            cursor: current,
        })
    }
    fn watch_sync(&self, scope: &Scope, prefix: &str, from: Cursor) -> Result<PinEvents> {
        self.state()?.check(scope)?;
        let store = self.clone();
        let scope = scope.clone();
        let prefix = prefix.to_owned();
        Ok(Box::pin(futures::stream::unfold(
            (store, scope, prefix, Some(from.generation)),
            |(store, scope, prefix, seen)| async move {
                let mut seen = seen?;
                loop {
                    let wake = store.changed.clone().notified_owned();
                    tokio::pin!(wake);
                    wake.as_mut().enable();
                    let next = {
                        let _gate = match store.effect_gate(&scope).await {
                            Ok(gate) => gate,
                            Err(error) => {
                                return Some((Err(error), (store.clone(), scope, prefix, None)));
                            }
                        };
                        let state = store.state.lock().unwrap();
                        if let Err(error) = state.check(&scope) {
                            return Some((Err(error), (store.clone(), scope, prefix, None)));
                        }
                        let oldest =
                            state
                                .events
                                .front()
                                .map_or(state.generation, |(event, _, _)| match event {
                                    PinEvent::Set { cursor, .. } | PinEvent::Resync { cursor } => {
                                        cursor.generation.saturating_sub(1)
                                    }
                                });
                        if seen < oldest || seen > state.generation {
                            seen = state.generation;
                            Some(PinEvent::Resync {
                                cursor: Cursor {
                                    generation: seen,
                                    ..Default::default()
                                },
                            })
                        } else {
                            let mut next = None;
                            for (event, old, _) in &state.events {
                                let PinEvent::Set {
                                    cursor,
                                    name,
                                    value,
                                } = event
                                else {
                                    continue;
                                };
                                if cursor.generation <= seen {
                                    continue;
                                }
                                seen = cursor.generation;
                                if !name.as_str().starts_with(&prefix) {
                                    continue;
                                }
                                let current = state.pins.get(name);
                                if current == value.as_ref()
                                    && current
                                        .is_some_and(|pin| metadata_readable(&scope, name, pin))
                                {
                                    next = Some(event.clone());
                                    break;
                                }
                                let formerly_visible = old
                                    .as_ref()
                                    .is_some_and(|old| metadata_readable(&scope, name, old))
                                    || value.as_ref().is_some_and(|value| {
                                        metadata_readable(&scope, name, value)
                                    });
                                if formerly_visible {
                                    // A replay must not disclose a pin's old target after its
                                    // authority changes. Resync carries no private name or value.
                                    seen = state.generation;
                                    next = Some(PinEvent::Resync {
                                        cursor: Cursor {
                                            generation: seen,
                                            ..Default::default()
                                        },
                                    });
                                    break;
                                }
                            }
                            next
                        }
                    };
                    if let Some(next) = next {
                        return Some((Ok(next), (store, scope, prefix, Some(seen))));
                    }
                    wake.await;
                }
            },
        )))
    }
    pub(crate) fn require_ready(&self) -> Result<()> {
        if self.disk.as_ref().is_some_and(|disk| !disk.ready()) {
            return Err(Error::Denied);
        }
        if let Some(lower) = &self.lower {
            lower.require_ready()?;
        }
        Ok(())
    }
    pub(crate) fn collect_sync(&self, scope: &Scope, goal: Option<u64>) -> Result<Collected> {
        self.require_ready()?;
        self.collect_unpinned(scope, goal)
    }
    pub(crate) fn collect_unpinned(&self, scope: &Scope, goal: Option<u64>) -> Result<Collected> {
        if !matches!(scope.kind, ScopeKind::Owner) {
            return Err(Error::Denied);
        }
        if let Some(bytes) = goal
            && (self.data_pool().fits(bytes)?
                || bytes
                    .checked_add(self.data_pool().held())
                    .is_none_or(|held| held > self.data_pool().limit()))
        {
            return Ok(Collected::default());
        }
        let mut state = self.state()?;
        let mut reached: BTreeSet<ContentId> = state
            .walk(
                state
                    .pins
                    .values()
                    .filter(|pin| live(pin))
                    .map(|pin| pin.target),
            )?
            .into_iter()
            .map(|object| object.id())
            .collect();
        for work in state.work.values() {
            reached.extend(work.closure.iter().map(|object| object.id()));
            reached.extend(work.staged.keys().copied());
        }
        let mut candidates = Vec::new();
        for (id, object) in &state.objects {
            if reached.contains(id) {
                continue;
            }
            if let super::storage::Data::File(file) = &object.data
                && !file.owned()
            {
                continue;
            }
            candidates.push((
                object.last_read.load(std::sync::atomic::Ordering::Relaxed),
                *id,
            ));
        }
        candidates.sort_unstable();
        let mut collected = Collected::default();
        for (_, id) in candidates {
            let object = state.objects.get(&id).unwrap().clone();
            let bytes = match &object.data {
                super::storage::Data::Ram(_) => {
                    state.objects.remove(&id);
                    object.data.len()
                }
                super::storage::Data::File(file) => {
                    let bytes = file.collect()?;
                    if !object.data.available() {
                        state.objects.remove(&id);
                    }
                    bytes
                }
            };
            collected.objects += 1;
            collected.bytes += bytes;
            if let Some(bytes) = goal
                && self.data_pool().fits(bytes)?
            {
                break;
            }
        }
        Ok(collected)
    }
}

impl Core {
    pub(crate) fn data_pool(&self) -> &Reservations {
        self.disk.as_ref().map_or(&self.pool, |disk| &disk.quota)
    }
    pub(crate) async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(Core) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let core = self.clone();
        if self.disk.is_some() || self.lower.is_some() {
            tokio::task::spawn_blocking(move || f(core))
                .await
                .map_err(|_| Error::Invalid("content worker"))?
        } else {
            f(core)
        }
    }
    pub(crate) async fn effect_gate(&self, scope: &Scope) -> Result<EffectGate> {
        // Lock order: authority writer, Core gate, fresh time check, local effect/commit.
        let authority = match &scope.live {
            Some(live) => Some((live.acquire)().await?),
            None => None,
        };
        let gate = self.gate.clone().lock_owned().await;
        let lower = match &self.lower {
            Some(lower) => Some(lower.gate.clone().lock_owned().await),
            None => None,
        };
        if let Some(check) = &authority {
            check()?;
        }
        Ok((gate, lower, authority))
    }
    pub(crate) async fn effect<T: Send + 'static>(
        &self,
        scope: &Scope,
        f: impl FnOnce(Core) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let core = self.clone();
        let scope = scope.clone();
        // The effect owns its serialization and database commit independently of
        // the request future. Cancellation cannot undo RAM after SQLite commits.
        tokio::spawn(async move {
            let gate = core.effect_gate(&scope).await?;
            let before = {
                let state = core.state()?;
                (
                    state.pins.clone(),
                    state.generation,
                    state.events.clone(),
                    state.event_bytes,
                    state.acquired.clone(),
                    state.declarations.clone(),
                )
            };
            let rollback = PinCommit {
                core: core.clone(),
                before: Some(before),
                _gate: gate,
            };
            // The worker owns rollback and serialization until it actually stops,
            // including when the request future is cancelled during file IO.
            let (result, mut rollback) = core.run(move |core| Ok((f(core), rollback))).await?;
            let result = result?;
            if let Some(disk) = &core.disk {
                let pending = {
                    let state = core.state.lock().unwrap();
                    let before = rollback.before.as_ref().unwrap();
                    if state.generation == before.1 && state.declarations == before.5 {
                        None
                    } else {
                        let mut changes: Vec<_> = state
                            .pins
                            .iter()
                            .filter(|(name, value)| before.0.get(*name) != Some(*value))
                            .map(|(name, value)| (name.clone(), Some(value.clone())))
                            .collect();
                        changes.extend(
                            before
                                .0
                                .keys()
                                .filter(|name| !state.pins.contains_key(*name))
                                .map(|name| (name.clone(), None)),
                        );
                        let mut declarations: Vec<_> = state
                            .declarations
                            .iter()
                            .filter(|(name, digest)| before.5.get(*name) != Some(*digest))
                            .map(|(name, digest)| (name.clone(), Some(*digest)))
                            .collect();
                        declarations.extend(
                            before
                                .5
                                .keys()
                                .filter(|name| !state.declarations.contains_key(*name))
                                .map(|name| (name.clone(), None)),
                        );
                        Some((state.generation, changes, declarations))
                    }
                };
                if let Some((generation, changes, declarations)) = pending {
                    disk.persist(generation, changes, declarations).await?;
                }
            }
            rollback.before = None;
            core.changed.notify_waiters();
            Ok(result)
        })
        .await
        .map_err(|_| Error::Invalid("content effect task"))?
    }
    pub(crate) async fn access<T: Send + 'static>(
        &self,
        scope: &Scope,
        f: impl FnOnce(Core) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let gate = self.effect_gate(scope).await?;
        self.run(move |core| {
            let _gate = gate;
            f(core)
        })
        .await
    }
}
type EffectGate = (
    tokio::sync::OwnedMutexGuard<()>,
    Option<tokio::sync::OwnedMutexGuard<()>>,
    Option<AuthorityGuard>,
);
type PinSnapshot = (
    BTreeMap<PinName, PinValue>,
    u64,
    VecDeque<(PinEvent, Option<PinValue>, usize)>,
    usize,
    AcquiredOwners,
    BTreeMap<PinName, Digest>,
);
struct PinCommit {
    core: Core,
    before: Option<PinSnapshot>,
    _gate: EffectGate,
}
impl Drop for PinCommit {
    fn drop(&mut self) {
        if let Some((pins, generation, events, event_bytes, acquired, declarations)) =
            self.before.take()
        {
            let mut state = self.core.state.lock().unwrap();
            state.pins = pins;
            state.generation = generation;
            state.events = events;
            state.event_bytes = event_bytes;
            state.acquired = acquired;
            state.declarations = declarations;
        }
    }
}
#[async_trait::async_trait]
impl ContentStore for Core {
    async fn stat(&self, s: &Scope, at: &Path) -> Result<Option<Stat>> {
        let (s, at) = (s.clone(), at.clone());
        self.access(&s.clone(), move |c| c.stat_sync(&s, &at)).await
    }
    async fn chunks(&self, s: &Scope, at: &Path, page: Cursor) -> Result<ChunkPage> {
        let (s, at) = (s.clone(), at.clone());
        self.access(&s.clone(), move |c| c.chunks_sync(&s, &at, page))
            .await
    }
    async fn read(&self, s: &Scope, at: &Path, range: std::ops::Range<u64>) -> Result<ByteStream> {
        let (s, at) = (s.clone(), at.clone());
        self.access(&s.clone(), move |c| c.read_sync(&s, &at, range))
            .await
    }
    async fn upload(
        &self,
        s: &Scope,
        object: ContentRef,
        pin: Option<PinTarget>,
    ) -> Result<UploadSession> {
        if self.disk.as_ref().is_some_and(|disk| !disk.ready()) {
            return Err(Error::Denied);
        }
        let scope = s.clone();
        self.admit(&scope.clone(), move |core| {
            core.upload_sync(&scope, object, pin.clone())
        })
        .await
    }
    async fn acquire(
        &self,
        s: &Scope,
        source: Source,
        expect: Option<ContentRef>,
        pin: PinTarget,
    ) -> Result<Acquisition> {
        self.acquire_scoped(s, source, expect, pin, None).await
    }
    async fn set_pin(
        &self,
        s: &Scope,
        name: &PinName,
        expected: Option<&PinValue>,
        new: Option<PinValue>,
    ) -> Result<()> {
        let (s, name, expected) = (s.clone(), name.clone(), expected.cloned());
        self.effect(&s.clone(), move |c| {
            c.set_pin_sync(&s, &name, expected.as_ref(), new)
        })
        .await
    }
    async fn pins(&self, s: &Scope, prefix: &str, page: Cursor) -> Result<PinPage> {
        let (s, prefix) = (s.clone(), prefix.to_owned());
        self.access(&s.clone(), move |c| c.pins_sync(&s, &prefix, page))
            .await
    }
    async fn watch(&self, s: &Scope, prefix: &str, from: Cursor) -> Result<PinEvents> {
        let (s, prefix) = (s.clone(), prefix.to_owned());
        self.access(&s.clone(), move |c| c.watch_sync(&s, &prefix, from))
            .await
    }
    async fn collect(&self, s: &Scope) -> Result<Collected> {
        let s = s.clone();
        self.access(&s.clone(), move |c| c.collect_sync(&s, None))
            .await
    }
}

impl Core {
    pub(crate) async fn write_local(
        &self,
        mut local: super::upload::LocalSession,
        bytes: Bytes,
    ) -> Result<super::upload::LocalSession> {
        use std::io::Write;
        self.access(&local.scope.clone(), move |core| {
            core.check(&local.scope)?;
            local
                .bytes
                .as_mut()
                .ok_or(Error::Invalid("upload already published"))?
                .write_all(&bytes)?;
            Ok(local)
        })
        .await
    }
}

impl Core {
    pub(crate) fn target_present(&self, target: Target) -> Result<bool> {
        let state = self.state()?;
        let objects = match state.walk([target]) {
            Ok(objects) => objects,
            Err(Error::Missing) => return Ok(false),
            Err(error) => return Err(error),
        };
        Ok(objects.into_iter().all(|object| {
            state.objects.get(&object.id()).is_some_and(|stored| {
                stored.data.len() == object.bytes() && stored.data.available()
            })
        }))
    }
    pub(crate) fn check_acquisition(
        &self,
        pin: &PinTarget,
        requester: &Option<(Core, Scope)>,
    ) -> Result<()> {
        if let Some((requester, scope)) = requester {
            requester.check(scope)?;
            if self
                .state()?
                .pins
                .get(&pin.name)
                .is_some_and(|value| value.policy != PinPolicy::Jobs)
            {
                return Err(Error::Denied);
            }
        }
        Ok(())
    }
    pub(crate) async fn acquire_scoped(
        &self,
        s: &Scope,
        source: Source,
        expect: Option<ContentRef>,
        pin: PinTarget,
        requester: Option<(Core, Scope)>,
    ) -> Result<Acquisition> {
        if !matches!(s.kind, ScopeKind::Owner) {
            return Err(Error::Denied);
        }
        if self.disk.as_ref().is_some_and(|disk| !disk.ready()) {
            return Err(Error::Denied);
        }
        let scope = s.clone();
        self.retry_capacity(s, move |core| {
            let (scope, source, pin, requester) = (
                scope.clone(),
                source.clone(),
                pin.clone(),
                requester.clone(),
            );
            async move {
                let (checking_pin, checking_requester) = (pin.clone(), requester.clone());
                core.access(&scope, move |core| {
                    core.require_ready()?;
                    core.check_acquisition(&checking_pin, &checking_requester)
                })
                .await?;
                super::acquire::memory(&core, &scope, source, expect, pin, requester).await
            }
        })
        .await
    }

    pub(crate) fn missing_refs(
        &self,
        scope: &Scope,
        closure: &[ContentRef],
    ) -> Result<Vec<ContentRef>> {
        let state = self.state()?;
        state.check(scope)?;
        let ScopeKind::Work {
            closure: admitted,
            reservation,
            ..
        } = &scope.kind
        else {
            return Err(Error::Denied);
        };
        if admitted.iter().any(|object| !closure.contains(object)) {
            return Err(Error::Denied);
        }
        let held = state.held(scope, closure)?;
        let lower = self.held_lower(scope, closure)?;
        let work = state.work.get(reservation).ok_or(Error::Denied)?;
        closure.iter().try_fold(Vec::new(), |mut missing, object| {
            let present = match work.staged.get(&object.id()) {
                Some(stored) => available(stored, *object)?,
                None => held.contains(&object.id()) || lower.contains(&object.id()),
            };
            if !present {
                missing.push(*object);
            }
            Ok(missing)
        })
    }

    fn protect_acquired(&self, requester: &Core, scope: &Scope, names: Vec<PinName>) -> Result<()> {
        let ScopeKind::Work { reservation, .. } = &scope.kind else {
            return Err(Error::Denied);
        };
        let mut state = self.state()?;
        for name in names {
            state.add_acquired(name, (Arc::downgrade(&requester.state), *reservation));
        }
        Ok(())
    }

    pub(crate) fn clear_acquired(&self, owner: AcquiredOwner) -> Result<()> {
        self.state()?.unpin_acquired(&owner)
    }
    pub(crate) fn clear_orphan_acquired(&self) -> Result<()> {
        if self.disk.as_ref().is_none_or(|disk| disk.ready()) {
            return Ok(());
        }
        let mut state = self.state()?;
        let pins = state
            .pins
            .iter()
            .filter(|(name, _)| {
                let parts = name.as_str().split('/').collect::<Vec<_>>();
                parts.len() == 5 && parts[0] == "work" && parts[3] == "acquired"
            })
            .map(|(name, pin)| (name.clone(), pin.clone()))
            .collect::<Vec<_>>();
        for (name, pin) in pins {
            let parts = name.as_str().split('/').collect::<Vec<_>>();
            let reached = if pin.policy == PinPolicy::Jobs && live(&pin) {
                state.walk([pin.target])?
            } else {
                BTreeSet::new()
            };
            let owners = state
                .work
                .iter()
                .filter(|(_, work)| {
                    (work.job.channel.to_string() == parts[1]
                        && work.job.id.to_string() == parts[2])
                        || work.closure.iter().any(|object| reached.contains(object))
                })
                .map(|(reservation, _)| (Arc::downgrade(&self.state), *reservation))
                .collect::<Vec<_>>();
            if owners.is_empty() {
                state.change_pin(name.clone(), None)?;
                state.acquired.remove(&name);
            } else {
                for owner in owners {
                    state.add_acquired(name.clone(), owner);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn restore_output(&self, scope: &Scope, total: u64, consumed: u64) -> Result<()> {
        let recovering = !self.disk.as_ref().ok_or(Error::Denied)?.ready();
        let remaining = total.checked_sub(consumed).ok_or(Error::Capacity)?;
        let mut state = self.state()?;
        state.check(scope)?;
        let ScopeKind::Work { reservation, .. } = &scope.kind else {
            return Err(Error::Denied);
        };
        let work = state.work.get_mut(reservation).ok_or(Error::Denied)?;
        if work.output_allowance != 0 {
            return if work.output_allowance == total {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if recovering {
            work.charge.restore(remaining)?;
        } else {
            self.extend(&work.charge, remaining)?;
        }
        work.output_allowance = total;
        work.output_remaining = remaining;
        Ok(())
    }
    pub(crate) fn reserve_output(&self, scope: &Scope, bytes: u64) -> Result<()> {
        let mut state = self.state()?;
        state.check(scope)?;
        let ScopeKind::Work { reservation, .. } = &scope.kind else {
            return Err(Error::Denied);
        };
        let work = state.work.get_mut(reservation).ok_or(Error::Denied)?;
        let extra = bytes.saturating_sub(work.output_allowance);
        if extra == 0 {
            return Ok(());
        }
        let remaining = work
            .output_remaining
            .checked_add(extra)
            .ok_or(Error::Capacity)?;
        self.extend(&work.charge, extra)?;
        work.output_allowance = work.output_allowance.max(bytes);
        work.output_remaining = remaining;
        Ok(())
    }
}

impl Core {
    fn missing(&self, state: &State, scope: &Scope, closure: &[ContentRef]) -> Result<u64> {
        state.missing(
            scope,
            closure,
            &self.held_lower(scope, closure)?,
            &state.held(scope, closure)?,
        )
    }
    fn held_lower(&self, scope: &Scope, closure: &[ContentRef]) -> Result<BTreeSet<ContentId>> {
        match &self.lower {
            Some(lower) => lower
                .state
                .lock()
                .map_err(|_| Error::Invalid("lower lock"))?
                .held(scope, closure),
            None => Ok(BTreeSet::new()),
        }
    }
    pub(crate) fn repair_backing(&self, scope: &Scope, backing: &BadBacking) -> Result<()> {
        // Recheck through current state before retiring the failed entry: any
        // replacement verification uses its own FileObject and quota accounting.
        match self.verified(scope, backing.file.object, None, true) {
            Ok(_) | Err(Error::Missing) => backing.file.invalidate(&backing.entry),
            Err(error) => Err(error),
        }
    }
    pub(crate) fn verified(
        &self,
        scope: &Scope,
        object: ContentRef,
        at: Option<&Path>,
        job_upper: bool,
    ) -> Result<Option<super::local::VerifiedReader>> {
        let state = self.state()?;
        state.check(scope)?;
        if let ScopeKind::Work {
            reservation,
            closure,
            ..
        } = &scope.kind
        {
            if !closure.contains(&object) {
                return Err(Error::Denied);
            }
            if job_upper
                && let Some(stored) = state
                    .work
                    .get(reservation)
                    .and_then(|work| work.staged.get(&object.id()))
            {
                let reader = super::local::reader(&stored.data, object, self, scope)?;
                state.touch(stored);
                return Ok(Some(reader));
            }
        }
        let readable = match at {
            Some(at) => state
                .resolve(scope, at)?
                .is_some_and(|target| target.object() == object),
            None => state.verified_present(scope, object)?,
        };
        if readable && let Some(stored) = state.objects.get(&object.id()) {
            let reader = super::local::reader(&stored.data, object, self, scope)?;
            state.touch(stored);
            return Ok(Some(reader));
        }
        if job_upper && let Some(lower) = &self.lower {
            let lower = lower
                .state
                .lock()
                .map_err(|_| Error::Invalid("lower lock"))?;
            let readable = match at {
                Some(at) => lower
                    .resolve_path(scope, at)?
                    .is_some_and(|target| target.object() == object),
                None => lower.verified_present(scope, object)?,
            };
            if readable && let Some(stored) = lower.objects.get(&object.id()) {
                let reader = super::local::reader(&stored.data, object, self, scope)?;
                lower.touch(stored);
                return Ok(Some(reader));
            }
        }
        Ok(None)
    }
}

impl Core {
    pub(crate) fn stage_output(&self, scope: &Scope, object: ContentRef) -> Result<UploadSession> {
        let mut state = self.state()?;
        state.check(scope)?;
        let ScopeKind::Work { reservation, .. } = &scope.kind else {
            return Err(Error::Denied);
        };
        let work = state.work.get(reservation).ok_or(Error::Denied)?;
        if work.staged.contains_key(&object.id()) {
            return Ok(UploadSession::present(object));
        }
        if object.bytes() > work.output_remaining {
            return Err(Error::Capacity);
        }
        if state.active.contains(&(*reservation, object.id())) {
            return Err(Error::Conflict);
        }
        let charge = work.charge.clone();
        let buffer = super::storage::Buffer::new(self, object.bytes(), charge)?;
        state.active.insert((*reservation, object.id()));
        state.work.get_mut(reservation).unwrap().output_remaining -= object.bytes();
        Ok(UploadSession::local(
            object,
            super::upload::LocalSession {
                store: self.clone(),
                scope: scope.clone(),
                pin: None,
                object,
                reservation: *reservation,
                bytes: Some(buffer),
                output: true,
                finished: false,
            },
        ))
    }
}

impl Core {
    pub(crate) fn promote_work(&self, scope: &Scope, target: Target, pin: PinTarget) -> Result<()> {
        let mut state = self.state()?;
        state.check(scope)?;
        let ScopeKind::Work { reservation, .. } = &scope.kind else {
            return Err(Error::Denied);
        };
        let staged = state
            .work
            .get(reservation)
            .ok_or(Error::Denied)?
            .staged
            .clone();
        state.publish(staged, target, pin)?;
        Ok(())
    }
    pub(crate) fn restore_root(
        &self,
        job: JobId,
        target: Target,
        mut pin: PinTarget,
        previous: Option<PinName>,
    ) -> Result<Option<Scope>> {
        let existing = {
            let state = self.state()?;
            state
                .work
                .iter()
                .find(|(_, work)| work.job == job)
                .map(|(id, work)| {
                    (
                        Scope::work(job, work.closure.clone(), *id),
                        work.root_recovery,
                    )
                })
        };
        let (scope, temporary) = match existing {
            Some(existing) => existing,
            None => {
                let scope = self.open_work(job, vec![], 0)?;
                let ScopeKind::Work { reservation, .. } = scope.kind else {
                    return Err(Error::Denied);
                };
                self.state()?
                    .work
                    .get_mut(&reservation)
                    .ok_or(Error::Denied)?
                    .root_recovery = true;
                (scope, true)
            }
        };
        {
            let state = self.state()?;
            if let Some(value) = state
                .pins
                .get(&pin.name)
                .or_else(|| previous.as_ref().and_then(|name| state.pins.get(name)))
            {
                pin.policy = value.policy.clone();
            }
        }
        let name = pin.name.clone();
        self.promote_work(&scope, target, pin)?;
        if let Some(previous) = previous.filter(|previous| *previous != name) {
            let mut state = self.state()?;
            if state.pins.contains_key(&previous) {
                state.change_pin(previous, None)?;
            }
        }
        if temporary {
            let mut state = self.state()?;
            let closure = state.walk([target])?.into_iter().collect();
            let ScopeKind::Work { reservation, .. } = scope.kind else {
                return Err(Error::Denied);
            };
            state
                .work
                .get_mut(&reservation)
                .ok_or(Error::Denied)?
                .closure = closure;
        }
        Ok(temporary.then_some(scope))
    }
    pub(crate) fn live_jobs(&self) -> Result<BTreeSet<JobId>> {
        Ok(self.state()?.work.values().map(|work| work.job).collect())
    }
}

impl Core {
    pub(crate) fn capacity<T>(&self, bytes: u64, result: Result<T>) -> Result<T> {
        if self.disk.is_some()
            && matches!(&result, Err(Error::Capacity))
            && let Some(needed) = &self.needed
        {
            *needed.lock().map_err(|_| Error::Invalid("store lock"))? = Some(bytes);
        }
        result
    }
    pub(crate) fn reserve(&self, bytes: u64) -> Result<Arc<Reservation>> {
        self.capacity(bytes, self.data_pool().reserve(bytes))
    }
    fn extend(&self, charge: &Reservation, bytes: u64) -> Result<()> {
        self.capacity(bytes, charge.extend(bytes))
    }
    pub(crate) async fn retry_capacity<T, F, Fut>(&self, scope: &Scope, f: F) -> Result<T>
    where
        T: Send,
        F: Fn(Core) -> Fut + Send,
        Fut: std::future::Future<Output = Result<T>> + Send,
    {
        loop {
            // Attempt-local failure context, never shared State or an admission permit.
            let needed = Arc::new(Mutex::new(None));
            let mut core = self.clone();
            core.needed = Some(needed.clone());
            let pending = f(core);
            let result = pending.await;
            if !matches!(&result, Err(Error::Capacity))
                || self.disk.as_ref().is_none_or(|disk| !disk.ready())
            {
                return result;
            }
            let bytes = needed
                .lock()
                .map_err(|_| Error::Invalid("store lock"))?
                .take();
            let Some(bytes) = bytes else {
                return result;
            };
            let checking = scope.clone();
            if !self
                .access(scope, move |core| {
                    core.check(&checking)?;
                    core.collect_sync(&Scope::Owner, Some(bytes))?;
                    core.data_pool().fits(bytes)
                })
                .await?
            {
                return result;
            }
        }
    }
    pub(crate) async fn admit<T: Send + 'static>(
        &self,
        scope: &Scope,
        f: impl Fn(Core) -> Result<T> + Clone + Send + 'static,
    ) -> Result<T> {
        let checking = scope.clone();
        self.retry_capacity(scope, move |core| {
            let (scope, f) = (checking.clone(), f.clone());
            async move { core.effect(&scope, f).await }
        })
        .await
    }
}

impl State {
    fn publish(
        &mut self,
        objects: BTreeMap<ContentId, Arc<Stored>>,
        target: Target,
        pin: PinTarget,
    ) -> Result<BTreeSet<ContentId>> {
        if self.generation == u64::MAX {
            return Err(Error::Capacity);
        }
        let mut previous = Vec::new();
        for (id, stored) in objects {
            if let Some(old) = self.objects.get(&id) {
                stored.data.merge(&old.data);
            }
            previous.push((id, self.objects.insert(id, stored)));
        }
        let reached = match self.walk([target]).and_then(|reached| {
            self.check_object(target)?;
            Ok(reached
                .into_iter()
                .map(|object| object.id())
                .collect::<BTreeSet<_>>())
        }) {
            Ok(reached) => reached,
            Err(error) => {
                self.restore(previous, &BTreeSet::new());
                return Err(error);
            }
        };
        let mut published = BTreeSet::new();
        for (id, _) in &previous {
            if reached.contains(id) {
                if let Err(error) = self.objects[id].data.publish() {
                    self.restore(previous, &published);
                    return Err(error);
                }
                published.insert(*id);
            }
        }
        self.restore(previous, &published);
        self.change_pin(
            pin.name,
            Some(PinValue {
                target,
                policy: pin.policy,
                expires: None,
            }),
        )?;
        Ok(reached)
    }
    fn restore(
        &mut self,
        previous: Vec<(ContentId, Option<Arc<Stored>>)>,
        published: &BTreeSet<ContentId>,
    ) {
        for (id, old) in previous {
            if published.contains(&id) {
                continue;
            }
            if let Some(old) = old {
                self.objects.insert(id, old);
            } else {
                self.objects.remove(&id);
            }
        }
    }
}

impl State {
    fn touch(&self, stored: &Stored) {
        stored.last_read.store(
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .saturating_add(1),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
    pub(crate) fn reload(&mut self, objects: BTreeMap<ContentId, Arc<Stored>>) {
        for (id, stored) in &objects {
            if let Some(old) = self.objects.get(id) {
                stored.last_read.store(
                    old.last_read.load(std::sync::atomic::Ordering::Relaxed),
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
        }
        self.objects = objects;
    }
}

impl Core {
    pub(crate) fn hf(&self, repo: crate::hf::Repo) -> crate::hf::HfCas {
        let cas = crate::hf::HfCas::new(repo);
        #[cfg(test)]
        if let Some(hub) = &self.hf_hub {
            return cas.with_hub(hub.clone());
        }
        cas
    }
}

#[cfg(test)]
mod tests;
